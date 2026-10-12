"""Application state: owns the database, settings, scanner, DNS monitor and scheduler."""

from __future__ import annotations

import logging
import threading
import time

from .db import Database
from .dns_monitor import DnsMonitor
from .netinfo import NetworkInfo, detect
from .scanner import Scanner
from .settings import Settings
from .winutil import is_admin, npcap_status, scapy_available

log = logging.getLogger(__name__)

NETWORK_RECHECK_SECONDS = 60
RETENTION_CHECK_SECONDS = 3600


class AppState:
    def __init__(self, db_path: str):
        self.db = Database(db_path)
        self.settings = Settings(self.db)
        self._net: NetworkInfo | None = None
        self._net_lock = threading.Lock()
        self._system: dict | None = None
        self.scanner = Scanner(self.db, self.settings, self.network, self.capture_ok)
        self.dns = DnsMonitor(self.db, self.settings)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.next_auto_scan: float | None = None

    # ── environment ─────────────────────────────────────────────────────────

    def network(self, refresh: bool = False) -> NetworkInfo:
        with self._net_lock:
            if refresh or self._net is None:
                s = self.settings
                self._net = detect(s["interface_override"], s["subnet_override"], s["max_scan_hosts"])
            return self._net

    def system(self, refresh: bool = False) -> dict:
        if refresh or self._system is None:
            self._system = {"admin": is_admin(), "npcap": npcap_status(), "scapy": scapy_available()}
        return self._system

    def capture_ok(self) -> bool:
        s = self.system()
        n = s["npcap"]
        return bool(s["scapy"] and n["installed"] and n["running"] and (s["admin"] or not n["admin_only"]))

    def apply_settings(self, redetect: bool = False) -> None:
        net = self.network(refresh=redetect)
        self.dns.apply(net, self.capture_ok())

    # ── lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> None:
        self.system(refresh=True)
        self.apply_settings(redetect=True)
        self._stop.clear()
        self._thread = threading.Thread(target=self._scheduler, name="scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.dns.shutdown()
        self.db.close()

    def _scheduler(self) -> None:
        last_scan_at = 0.0
        last_net_check = time.monotonic()
        last_retention = 0.0
        first = True
        while not self._stop.wait(2 if first else 5):
            now = time.monotonic()
            s = self.settings
            try:
                if s["auto_scan"]:
                    due = last_scan_at + s["scan_interval_seconds"]
                    if first or now >= due:
                        if self.scanner.scan_in_background("startup" if first else "auto"):
                            last_scan_at = now
                    self.next_auto_scan = time.time() + max(0.0, last_scan_at + s["scan_interval_seconds"] - now)
                else:
                    self.next_auto_scan = None
                first = False

                if now - last_net_check >= NETWORK_RECHECK_SECONDS:
                    last_net_check = now
                    old = self._net
                    new = self.network(refresh=True)
                    if old is None or (old.ip, old.scan_subnet, old.guid) != (new.ip, new.scan_subnet, new.guid):
                        log.info("Network changed: %s -> %s", old and old.scan_subnet, new.scan_subnet)
                        self.dns.apply(new, self.capture_ok())
                        self.scanner.scan_in_background("auto")
                        last_scan_at = now

                if now - last_retention >= RETENTION_CHECK_SECONDS:
                    last_retention = now
                    removed = self.db.purge_activity_older_than(s["retention_days"])
                    if removed:
                        log.info("Retention: removed %d old activity rows", removed)
            except Exception:
                log.exception("Scheduler iteration failed")

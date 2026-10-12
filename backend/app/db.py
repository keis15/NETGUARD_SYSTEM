"""
SQLite persistence for devices, scans, DNS activity and settings.

One shared connection guarded by a re-entrant lock: the scanner thread,
the DNS recorder thread and the API handlers all go through this class.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
TS_FMT = "%Y-%m-%d %H:%M:%S"


def now_str() -> str:
    return datetime.now().strftime(TS_FMT)


def ago_str(seconds: float) -> str:
    return (datetime.now() - timedelta(seconds=seconds)).strftime(TS_FMT)


@dataclass
class ActivityFilter:
    device: str | None = None      # MAC or IP
    q: str | None = None           # substring search on the domain
    domain: str | None = None      # exact full or base domain
    date_from: str | None = None   # YYYY-MM-DD
    date_to: str | None = None     # YYYY-MM-DD
    time_from: str | None = None   # HH:MM (time of day)
    time_to: str | None = None     # HH:MM (time of day)
    source: str | None = None      # 'sniffer' | 'dns_server'
    blocked: bool | None = None    # True = only blocked, False = only allowed
    since: str | None = None       # absolute lower bound, TS_FMT

    def where(self) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if self.device:
            clauses.append("(a.device_mac = ? OR a.device_ip = ?)")
            args += [self.device.lower(), self.device]
        if self.q:
            esc = self.q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("a.domain LIKE ? ESCAPE '\\'")
            args.append(f"%{esc}%")
        if self.domain:
            clauses.append("(a.base_domain = ? OR a.domain = ?)")
            args += [self.domain.lower(), self.domain.lower()]
        if self.date_from:
            clauses.append("a.bucket_start >= ?")
            args.append(f"{self.date_from} 00:00:00")
        if self.date_to:
            clauses.append("a.bucket_start <= ?")
            args.append(f"{self.date_to} 23:59:59")
        if self.since:
            clauses.append("a.bucket_start >= ?")
            args.append(self.since)
        tf, tt = self.time_from, self.time_to
        tod = "substr(a.bucket_start, 12, 5)"
        if tf and tt and tf > tt:
            # Overnight window, e.g. 22:00 -> 06:00
            clauses.append(f"({tod} >= ? OR {tod} <= ?)")
            args += [tf, tt]
        else:
            if tf:
                clauses.append(f"{tod} >= ?")
                args.append(tf)
            if tt:
                clauses.append(f"{tod} <= ?")
                args.append(tt)
        if self.source:
            clauses.append("a.source = ?")
            args.append(self.source)
        if self.blocked is not None:
            clauses.append("a.blocked = ?")
            args.append(int(self.blocked))
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


PERIOD_EXPR = {
    "minute": "substr(a.bucket_start, 1, 16)",
    "hour": "substr(a.bucket_start, 1, 13) || ':00'",
    "day": "substr(a.bucket_start, 1, 10)",
    "total": "''",
}
SORT_EXPR = {
    "recent": "last_seen DESC",
    "requests": "requests DESC, last_seen DESC",
    "domain": "domain ASC, last_seen DESC",
    "device": "device_label ASC, last_seen DESC",
}
DEVICE_LABEL = "COALESCE(d.friendly_name, d.hostname, a.device_ip)"


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Additive upgrades for databases created by earlier versions."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(devices)")}
        if "network" not in cols:
            self._conn.execute("ALTER TABLE devices ADD COLUMN network TEXT")
        acols = {r[1] for r in self._conn.execute("PRAGMA table_info(dns_activity)")}
        if "blocked" not in acols:
            self._conn.execute("ALTER TABLE dns_activity ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0")

    # ── helpers ─────────────────────────────────────────────────────────────

    def _all(self, sql: str, args: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(args)).fetchall()]

    def _one(self, sql: str, args: Iterable[Any] = ()) -> dict | None:
        with self._lock:
            row = self._conn.execute(sql, tuple(args)).fetchone()
            return dict(row) if row else None

    def _exec(self, sql: str, args: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── settings ────────────────────────────────────────────────────────────

    def get_settings(self) -> dict[str, Any]:
        return {r["key"]: json.loads(r["value"]) for r in self._all("SELECT key, value FROM settings")}

    def set_settings(self, values: dict[str, Any]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(k, json.dumps(v)) for k, v in values.items()],
            )
            self._conn.commit()

    # ── devices ─────────────────────────────────────────────────────────────

    def upsert_device(self, mac: str, ip: str, hostname: str | None, vendor: str | None,
                      is_self: bool, is_gateway: bool, randomized: bool, seen_at: str,
                      network: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO devices(mac, ip, hostname, vendor, is_self, is_gateway,
                                    randomized_mac, first_seen, last_seen, seen_count, network)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip             = excluded.ip,
                    hostname       = COALESCE(excluded.hostname, devices.hostname),
                    vendor         = COALESCE(excluded.vendor, devices.vendor),
                    is_self        = excluded.is_self,
                    is_gateway     = excluded.is_gateway,
                    randomized_mac = excluded.randomized_mac,
                    last_seen      = excluded.last_seen,
                    seen_count     = devices.seen_count + 1,
                    network        = COALESCE(excluded.network, devices.network)
                """,
                (mac, ip, hostname, vendor, int(is_self), int(is_gateway), int(randomized), seen_at, seen_at,
                 network),
            )
            # Attribute recent un-attributed DNS activity from this IP to the device.
            self._conn.execute(
                "UPDATE dns_activity SET device_mac = ? "
                "WHERE device_mac IS NULL AND device_ip = ? AND bucket_start >= ?",
                (mac, ip, ago_str(3600)),
            )
            self._conn.commit()

    def list_devices(self) -> list[dict]:
        return self._all("SELECT * FROM devices ORDER BY is_self DESC, is_gateway DESC, last_seen DESC")

    def get_device(self, mac: str) -> dict | None:
        return self._one("SELECT * FROM devices WHERE mac = ?", (mac.lower(),))

    def set_friendly_name(self, mac: str, name: str | None) -> bool:
        return self._exec("UPDATE devices SET friendly_name = ? WHERE mac = ?",
                          (name or None, mac.lower())) > 0

    def delete_device(self, mac: str) -> bool:
        return self._exec("DELETE FROM devices WHERE mac = ?", (mac.lower(),)) > 0

    def ip_mac_map(self) -> dict[str, str]:
        """Most recent MAC for every IP (latest last_seen wins)."""
        rows = self._all("SELECT ip, mac FROM devices WHERE ip IS NOT NULL ORDER BY last_seen ASC")
        return {r["ip"]: r["mac"] for r in rows}

    # ── scans ───────────────────────────────────────────────────────────────

    def start_scan(self, subnet: str, method: str, trigger: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans(started_at, subnet, method, trigger) VALUES (?, ?, ?, ?)",
                (now_str(), subnet, method, trigger),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, devices_found: int | None, error: str | None = None,
                    method: str | None = None) -> None:
        self._exec(
            "UPDATE scans SET finished_at = ?, devices_found = ?, error = ?, "
            "method = COALESCE(?, method) WHERE id = ?",
            (now_str(), devices_found, error, method, scan_id),
        )

    def list_scans(self, limit: int = 20) -> list[dict]:
        return self._all("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    def last_scan(self) -> dict | None:
        return self._one("SELECT * FROM scans WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1")

    # ── DNS activity ────────────────────────────────────────────────────────

    def add_dns_batch(self, rows: list[tuple]) -> None:
        """rows: (device_ip, device_mac, domain, base_domain, bucket_start,
                  first_ts, last_ts, count, source, blocked)"""
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO dns_activity(device_ip, device_mac, domain, base_domain, bucket_start,
                                         first_ts, last_ts, request_count, source, blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_ip, domain, bucket_start, source) DO UPDATE SET
                    request_count = dns_activity.request_count + excluded.request_count,
                    first_ts      = MIN(dns_activity.first_ts, excluded.first_ts),
                    last_ts       = MAX(dns_activity.last_ts, excluded.last_ts),
                    device_mac    = COALESCE(excluded.device_mac, dns_activity.device_mac),
                    blocked       = excluded.blocked
                """,
                rows,
            )
            self._conn.commit()

    def query_activity(self, f: ActivityFilter, group: str = "minute", by: str = "domain",
                       sort: str = "recent", limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
        period = PERIOD_EXPR.get(group, PERIOD_EXPR["minute"])
        dom = "a.base_domain" if by == "base_domain" else "a.domain"
        order = SORT_EXPR.get(sort, SORT_EXPR["recent"])
        where, args = f.where()
        inner = f"""
            SELECT COALESCE(a.device_mac, a.device_ip)      AS device_key,
                   MAX(a.device_ip)                           AS device_ip,
                   a.device_mac                               AS device_mac,
                   {DEVICE_LABEL}                             AS device_label,
                   d.vendor                                   AS vendor,
                   COALESCE(d.is_self, 0)                     AS is_self,
                   d.network                                  AS network,
                   {dom}                                      AS domain,
                   {period}                                   AS period,
                   MIN(a.first_ts)                            AS first_seen,
                   MAX(a.last_ts)                             AS last_seen,
                   SUM(a.request_count)                       AS requests,
                   MAX(a.blocked)                             AS blocked,
                   GROUP_CONCAT(DISTINCT a.source)            AS sources
            FROM dns_activity a
            LEFT JOIN devices d ON d.mac = a.device_mac
            {where}
            GROUP BY device_key, {dom}, period
        """
        total = self._one(f"SELECT COUNT(*) AS n FROM ({inner})", args)["n"]
        rows = self._all(f"{inner} ORDER BY {order} LIMIT ? OFFSET ?", [*args, limit, offset])
        return rows, total

    def activity_totals(self, f: ActivityFilter) -> dict:
        where, args = f.where()
        return self._one(
            f"""SELECT COALESCE(SUM(a.request_count), 0)                           AS requests,
                       COUNT(DISTINCT a.base_domain)                               AS domains,
                       COUNT(DISTINCT COALESCE(a.device_mac, a.device_ip))         AS devices,
                       COALESCE(SUM(CASE WHEN a.blocked THEN a.request_count END), 0) AS blocked
                FROM dns_activity a {where}""",
            args,
        )

    def top_domains(self, f: ActivityFilter, limit: int = 10) -> list[dict]:
        where, args = f.where()
        return self._all(
            f"""SELECT a.base_domain AS domain, SUM(a.request_count) AS requests,
                       COUNT(DISTINCT COALESCE(a.device_mac, a.device_ip)) AS devices
                FROM dns_activity a {where}
                GROUP BY a.base_domain ORDER BY requests DESC LIMIT ?""",
            [*args, limit],
        )

    def top_devices(self, f: ActivityFilter, limit: int = 10) -> list[dict]:
        where, args = f.where()
        return self._all(
            f"""SELECT COALESCE(a.device_mac, a.device_ip) AS device_key,
                       {DEVICE_LABEL} AS device_label, MAX(a.device_ip) AS device_ip,
                       d.network AS network,
                       SUM(a.request_count) AS requests,
                       COUNT(DISTINCT a.base_domain) AS domains
                FROM dns_activity a LEFT JOIN devices d ON d.mac = a.device_mac
                {where}
                GROUP BY device_key ORDER BY requests DESC LIMIT ?""",
            [*args, limit],
        )

    def timeline(self, f: ActivityFilter, bucket: str = "hour") -> list[dict]:
        expr = {"hour": "substr(a.bucket_start, 1, 13) || ':00'",
                "day": "substr(a.bucket_start, 1, 10)",
                "hour_of_day": "substr(a.bucket_start, 12, 2)"}[bucket]
        where, args = f.where()
        return self._all(
            f"""SELECT {expr} AS t, SUM(a.request_count) AS requests,
                       COUNT(DISTINCT a.base_domain) AS domains
                FROM dns_activity a {where} GROUP BY t ORDER BY t""",
            args,
        )

    def activity_devices(self) -> list[dict]:
        """Every device that appears in DNS activity (for filter dropdowns)."""
        return self._all(
            f"""SELECT COALESCE(a.device_mac, a.device_ip) AS device_key,
                       {DEVICE_LABEL} AS device_label, MAX(a.device_ip) AS device_ip,
                       d.network AS network
                FROM dns_activity a LEFT JOIN devices d ON d.mac = a.device_mac
                GROUP BY device_key ORDER BY device_label"""
        )

    def purge_activity_older_than(self, days: int) -> int:
        return self._exec("DELETE FROM dns_activity WHERE bucket_start < ?", (ago_str(days * 86400),))

    def clear_activity(self) -> int:
        return self._exec("DELETE FROM dns_activity")

    def count_new_devices(self, since: str) -> int:
        return self._one("SELECT COUNT(*) AS n FROM devices WHERE first_seen >= ?", (since,))["n"]

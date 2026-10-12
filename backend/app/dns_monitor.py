"""
Privacy-preserving, domain-level DNS monitoring.

Two independent sources feed one recorder:

1. DnsSniffer (passive, needs Npcap)
   Captures DNS *queries* on the Wi-Fi adapter. On a normal Wi-Fi network this PC
   only sees its own queries: other devices talk to the router directly, and
   WPA2/WPA3 encrypt each client's traffic with its own key.

2. DnsForwarder (opt-in, reliable for the whole network)
   A small DNS forwarder on UDP/TCP port 53. When the router's DHCP settings hand
   out this PC's IP as the DNS server, every device sends its lookups here. Each
   query is logged (name + client IP + time) and relayed unchanged to the upstream
   resolver. Answers are never modified.

Only the queried name, client IP and timestamp are stored. No payloads, URLs,
cookies, form data or message content are captured, and nothing is decrypted.
"""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable

from .db import TS_FMT, Database, now_str
from .dns_parse import base_domain, build_block_response, parse_query, should_record
from .filtering import BlockPageServer, FilterPolicy
from .netinfo import NetworkInfo
from .settings import Settings

log = logging.getLogger(__name__)


# ── recorder ────────────────────────────────────────────────────────────────

class DnsRecorder:
    """Thread-safe queue that aggregates queries per device/domain/minute and writes in batches."""

    def __init__(self, db: Database, settings: Settings, flush_interval: float = 2.0):
        self.db = db
        self.settings = settings
        self.flush_interval = flush_interval
        self._q: queue.Queue = queue.Queue(maxsize=200_000)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ip_mac: dict[str, str] = {}
        self._ip_mac_at = 0.0
        self.counts = {"sniffer": 0, "dns_server": 0, "dropped": 0}
        self.pre_flush: list[Callable[[], None]] = []   # e.g. release de-duplication holds

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="dns-recorder", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.flush()

    def record(self, client_ip: str, name: str, qtype: int, source: str, ts: datetime | None = None,
               blocked: bool = False) -> bool:
        if not should_record(name, qtype, self.settings["ignore_local_names"]):
            return False
        try:
            self._q.put_nowait((ts or datetime.now(), client_ip, name, source, blocked))
            self.counts[source] = self.counts.get(source, 0) + 1
            if blocked:
                self.counts["blocked"] = self.counts.get("blocked", 0) + 1
            return True
        except queue.Full:
            self.counts["dropped"] += 1
            return False

    def _loop(self) -> None:
        while not self._stop.wait(self.flush_interval):
            try:
                self.flush()
            except Exception:
                log.exception("DNS flush failed")

    def flush(self) -> int:
        for hook in self.pre_flush:
            try:
                hook()
            except Exception:
                log.exception("pre-flush hook failed")
        agg: dict[tuple, list] = defaultdict(lambda: [None, None, 0])
        while True:
            try:
                ts, ip, name, source, blocked = self._q.get_nowait()
            except queue.Empty:
                break
            bucket = ts.strftime("%Y-%m-%d %H:%M:00")
            entry = agg[(ip, name, bucket, source, int(blocked))]
            t = ts.strftime(TS_FMT)
            entry[0] = t if entry[0] is None or t < entry[0] else entry[0]
            entry[1] = t if entry[1] is None or t > entry[1] else entry[1]
            entry[2] += 1
        if not agg:
            return 0
        if time.monotonic() - self._ip_mac_at > 30:
            self._ip_mac = self.db.ip_mac_map()
            self._ip_mac_at = time.monotonic()
        rows = [(ip, self._ip_mac.get(ip), name, base_domain(name), bucket, first, last, count, source, blocked)
                for (ip, name, bucket, source, blocked), (first, last, count) in agg.items()]
        self.db.add_dns_batch(rows)
        return len(rows)


# ── passive sniffer ─────────────────────────────────────────────────────────

class DnsSniffer:
    """Captures DNS queries on the Wi-Fi adapter and, optionally, on VMware VMnet adapters.

    VMware NAT re-sends each VM lookup from this PC's own Wi-Fi address. While VMnet capture is
    active, this PC's lookups are held for HOLD_SECONDS and dropped if a VM asked for the same name,
    so a VM's browsing is attributed to the VM and not counted a second time as "this PC".
    """

    HOLD_SECONDS = 2.5
    MATCH_WINDOW = 3.0
    FILTER = "udp dst port 53 or tcp dst port 53"   # client queries only, never responses

    def __init__(self, recorder: DnsRecorder, server_upstream: Callable[[], str | None]):
        self.recorder = recorder
        self.server_upstream = server_upstream   # returns upstream IP while the forwarder runs
        self._sniffer = None
        self._vm_sniffers: list[dict] = []       # {"name", "mode", "subnet", "sniffer", "error"}
        self._net: NetworkInfo | None = None
        self.error: str | None = None
        self.started_at: str | None = None
        self._lock = threading.Lock()
        self._vm_recent: dict[str, float] = {}   # qname -> monotonic time a VM last asked
        self._held: list[tuple] = []             # this PC's queries awaiting de-duplication
        recorder.pre_flush.append(self._release_held)

    @property
    def running(self) -> bool:
        return bool(self._sniffer and getattr(self._sniffer, "running", False))

    @property
    def vm_capture_active(self) -> bool:
        return any(v["sniffer"] is not None and getattr(v["sniffer"], "running", False) for v in self._vm_sniffers)

    def vm_status(self) -> list[dict]:
        return [{"name": v["name"], "mode": v["mode"], "subnet": v["subnet"],
                 "running": bool(v["sniffer"] and getattr(v["sniffer"], "running", False)),
                 "error": v["error"]} for v in self._vm_sniffers]

    def _start_one(self, guid, ip, label, on_packet):
        from scapy.all import AsyncSniffer

        from .scanner import scapy_iface_for
        iface = scapy_iface_for(guid, ip)
        if iface is None:
            raise RuntimeError(f"Npcap cannot see interface {label}")
        s = AsyncSniffer(iface=iface, filter=self.FILTER, prn=on_packet, store=False)
        s.start()
        return s

    def start(self, net: NetworkInfo, vm_networks: list[dict] | None = None) -> None:
        self.stop()
        self.error = None
        self._net = net
        try:
            self._sniffer = self._start_one(net.guid, net.ip, net.interface, self._on_packet)
            self.started_at = now_str()
        except Exception as e:
            self._sniffer = None
            self.error = str(e)
            log.warning("DNS sniffer could not start: %s", e)
        for v in vm_networks or []:
            entry = {"name": v["name"], "mode": v["mode"], "subnet": v["subnet"], "sniffer": None, "error": None}
            try:
                entry["sniffer"] = self._start_one(v["guid"], v["host_ip"], v["name"],
                                                   lambda pkt: self._on_packet(pkt, vm=True))
            except Exception as e:
                entry["error"] = str(e)
                log.warning("DNS capture on %s could not start: %s", v["name"], e)
            self._vm_sniffers.append(entry)

    def stop(self) -> None:
        for s in [self._sniffer, *(v["sniffer"] for v in self._vm_sniffers)]:
            if s is not None:
                try:
                    if s.running:
                        s.stop()
                except Exception:
                    pass
        self._sniffer = None
        self._vm_sniffers = []
        self.started_at = None
        self._release_held(force=True)

    def _release_held(self, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            ready = [h for h in self._held if force or now - h[0] >= self.HOLD_SECONDS]
            self._held = [h for h in self._held if not (force or now - h[0] >= self.HOLD_SECONDS)]
            vm_recent = dict(self._vm_recent)
            self._vm_recent = {n: t for n, t in self._vm_recent.items() if now - t < 60}
        for mono, ts, src, name, qtype in ready:
            t = vm_recent.get(name)
            if t is not None and abs(t - mono) <= self.MATCH_WINDOW:
                continue  # VMware NAT relaying a VM's lookup: already recorded for the VM
            self.recorder.record(src, name, qtype, "sniffer", ts)

    def _on_packet(self, pkt, vm: bool = False) -> None:
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6

            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                return
            if UDP in pkt:
                payload = bytes(pkt[UDP].payload)
            elif TCP in pkt:
                raw = bytes(pkt[TCP].payload)
                if len(raw) < 14:
                    return
                payload = raw[2:]  # strip the 2-byte TCP length prefix
            else:
                return

            net = self._net
            my_ip = net.ip if net else None
            own = net.own_ips() if net else set()
            upstream = self.server_upstream()
            if upstream and my_ip:
                # The forwarder already logs these: avoid double counting.
                if dst in own or (src == my_ip and dst == upstream):
                    return
            if src in own:
                src = my_ip or src  # this PC's IPv6 / VMnet addresses -> its Wi-Fi IPv4 identity

            for name, qtype in parse_query(payload):
                if vm and src != my_ip:
                    with self._lock:
                        self._vm_recent[name] = time.monotonic()
                    self.recorder.record(src, name, qtype, "sniffer")
                elif not vm and src == my_ip and self.vm_capture_active:
                    with self._lock:
                        self._held.append((time.monotonic(), datetime.now(), src, name, qtype))
                elif not vm:
                    self.recorder.record(src, name, qtype, "sniffer")
                # vm and src == my_ip: this PC talking to VMware's DNS proxy; seen again on Wi-Fi
        except Exception:
            log.debug("packet parse error", exc_info=True)


# ── DNS forwarder ───────────────────────────────────────────────────────────

class DnsForwarder:
    def __init__(self, recorder: DnsRecorder):
        self.recorder = recorder
        self.bind = "0.0.0.0"
        self.port = 53
        self.upstream: str | None = None
        self.upstream_port = 53
        self.filter = None            # FilterPolicy | None
        self.block_ip: str | None = None
        self.error: str | None = None
        self.started_at: str | None = None
        self._stop = threading.Event()
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._pool: ThreadPoolExecutor | None = None

    @property
    def running(self) -> bool:
        return self._udp is not None and not self._stop.is_set()

    def start(self, bind: str, port: int, upstream: str) -> None:
        self.stop()
        self.error = None
        self.bind, self.port, self.upstream = bind, port, upstream
        self._stop.clear()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                udp.ioctl(socket.SIO_UDP_CONNRESET, False)  # ignore ICMP port-unreachable resets
            udp.bind((bind, port))
            udp.settimeout(1.0)
            tcp.bind((bind, port))
            tcp.listen(64)
            tcp.settimeout(1.0)
        except OSError as e:
            udp.close()
            tcp.close()
            self.error = (f"Cannot listen on {bind}:{port} ({e}). Another DNS service may be using the port "
                          f"(e.g. Internet Connection Sharing / Mobile Hotspot).")
            log.warning(self.error)
            return
        self._udp, self._tcp = udp, tcp
        self._pool = ThreadPoolExecutor(max_workers=64, thread_name_prefix="dns-fwd")
        self._threads = [threading.Thread(target=self._udp_loop, name="dns-udp", daemon=True),
                         threading.Thread(target=self._tcp_loop, name="dns-tcp", daemon=True)]
        for t in self._threads:
            t.start()
        self.started_at = now_str()
        log.info("DNS forwarder listening on %s:%s -> %s", bind, port, upstream)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3)
        self._threads = []
        for s in (self._udp, self._tcp):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        self._udp = self._tcp = None
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
        self.started_at = None

    def _process(self, client_ip: str, data: bytes) -> bytes | None:
        """Log the query and, if a filter blocks it, return the block response to send back."""
        questions = parse_query(data)
        blocked = False
        if self.filter is not None and questions:
            name, _ = questions[0]
            blocked = self.filter.is_blocked(name, base_domain(name))
        for name, qtype in questions:
            self.recorder.record(client_ip, name, qtype, "dns_server", blocked=blocked)
        if blocked:
            return build_block_response(data, self.block_ip)
        return None

    def _udp_loop(self) -> None:
        sock = self._udp
        while not self._stop.is_set() and sock:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_udp, sock, data, addr)

    def _upstream_udp(self, data: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
            up.settimeout(4)
            up.connect((self.upstream, self.upstream_port))
            up.send(data)
            return up.recv(65535)

    def _upstream_tcp(self, data: bytes) -> bytes:
        """TCP to upstream; many home routers don't serve DNS over TCP, so fall back to UDP."""
        try:
            with socket.create_connection((self.upstream, self.upstream_port), timeout=4) as up:
                up.settimeout(8)
                up.sendall(len(data).to_bytes(2, "big") + data)
                rlen = int.from_bytes(self._recv_exact(up, 2), "big")
                return self._recv_exact(up, rlen)
        except (OSError, ConnectionError):
            return self._upstream_udp(data)

    def _handle_udp(self, sock: socket.socket, data: bytes, addr) -> None:
        blocked = self._process(addr[0], data)
        if blocked is not None:
            try:
                sock.sendto(blocked, addr)
            except OSError:
                pass
            return
        try:
            sock.sendto(self._upstream_udp(data), addr)
        except OSError as e:
            log.debug("upstream UDP failure for %s: %s", addr, e)

    def _tcp_loop(self) -> None:
        sock = self._tcp
        while not self._stop.is_set() and sock:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_tcp, conn, addr)

    @staticmethod
    def _recv_exact(s: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def _handle_tcp(self, conn: socket.socket, addr) -> None:
        conn.settimeout(10)
        try:
            with conn:
                while not self._stop.is_set():
                    length = int.from_bytes(self._recv_exact(conn, 2), "big")
                    msg = self._recv_exact(conn, length)
                    blocked = self._process(addr[0], msg)
                    resp = blocked if blocked is not None else self._upstream_tcp(msg)
                    conn.sendall(len(resp).to_bytes(2, "big") + resp)
        except (OSError, ConnectionError):
            pass


# ── manager ─────────────────────────────────────────────────────────────────

class DnsMonitor:
    def __init__(self, db: Database, settings: Settings):
        self.settings = settings
        self.recorder = DnsRecorder(db, settings)
        self.forwarder = DnsForwarder(self.recorder)
        self.sniffer = DnsSniffer(self.recorder, lambda: self.forwarder.upstream if self.forwarder.running else None)
        self.block_page = BlockPageServer()
        self._lock = threading.Lock()

    def upstream_for(self, net: NetworkInfo) -> str:
        up = self.settings["dns_upstream"] or net.gateway or "1.1.1.1"
        if up == net.ip:
            up = "1.1.1.1"  # never forward to ourselves (would loop)
        return up

    def _apply_filtering(self, net: NetworkInfo) -> None:
        """Attach the current filter policy to the forwarder and run the block page server."""
        s = self.settings
        if s["filtering_enabled"]:
            self.forwarder.filter = FilterPolicy(s["filter_mode"], s["blocklist"], s["allowlist"])
            self.forwarder.block_ip = s["block_page_ip"] or net.ip
            want = ("0.0.0.0", s["block_page_port"], s["block_message"])
            if (not self.block_page.running
                    or (self.block_page.bind, self.block_page.port, self.block_page.message) != want):
                self.block_page.start(*want)
        else:
            self.forwarder.filter = None
            self.forwarder.block_ip = None
            self.block_page.stop()
            self.block_page.error = None

    def apply(self, net: NetworkInfo, capture_ok: bool) -> None:
        """(Re)start or stop components to match the current settings."""
        with self._lock:
            self.recorder.start()
            s = self.settings
            self._apply_filtering(net)
            if s["dns_server_enabled"] and net.ok:
                want = (s["dns_server_bind"], s["dns_server_port"], self.upstream_for(net))
                if not self.forwarder.running or (self.forwarder.bind, self.forwarder.port,
                                                  self.forwarder.upstream) != want:
                    self.forwarder.start(*want)
            else:
                self.forwarder.stop()
                self.forwarder.error = None

            if s["dns_sniffer_enabled"] and capture_ok and net.ok:
                vm_nets = net.vm_networks if s["monitor_vmware"] else []
                current = self.sniffer._net
                same_vms = [v["name"] for v in self.sniffer.vm_status()] == [v["name"] for v in vm_nets]
                if (not self.sniffer.running or not current or not same_vms
                        or (current.guid, current.ip) != (net.guid, net.ip)):
                    self.sniffer.start(net, vm_nets)
            else:
                self.sniffer.stop()
                self.sniffer.error = None if capture_ok or not s["dns_sniffer_enabled"] else \
                    "Packet capture unavailable (Npcap missing, stopped, or admin-only without admin rights)."

    def shutdown(self) -> None:
        with self._lock:
            self.sniffer.stop()
            self.forwarder.stop()
            self.block_page.stop()
            self.recorder.stop()

    def status(self) -> dict:
        s = self.settings
        return {
            "sniffer": {"enabled": s["dns_sniffer_enabled"], "running": self.sniffer.running,
                        "error": self.sniffer.error, "started_at": self.sniffer.started_at,
                        "queries_seen": self.recorder.counts.get("sniffer", 0),
                        "vm_interfaces": self.sniffer.vm_status()},
            "vmware": {"enabled": s["monitor_vmware"]},
            "filtering": {
                "enabled": s["filtering_enabled"], "mode": s["filter_mode"],
                "rules": len(s["allowlist"] if s["filter_mode"] == "allowlist" else s["blocklist"]),
                "active": s["filtering_enabled"] and self.forwarder.running,
                "blocked_hits": self.recorder.counts.get("blocked", 0),
                "block_page": {"running": self.block_page.running, "port": self.block_page.port,
                               "error": self.block_page.error},
            },
            "dns_server": {"enabled": s["dns_server_enabled"], "running": self.forwarder.running,
                           "error": self.forwarder.error, "started_at": self.forwarder.started_at,
                           "bind": self.forwarder.bind, "port": self.forwarder.port,
                           "upstream": self.forwarder.upstream,
                           "queries_seen": self.recorder.counts.get("dns_server", 0)},
            "dropped": self.recorder.counts.get("dropped", 0),
        }

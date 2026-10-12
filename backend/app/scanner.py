"""
Network discovery for the local subnet.

Two methods run in parallel and their results are merged:

1. Npcap ARP (when packet capture is available): broadcast ARP "who-has" for every
   address with Scapy. Some Wi-Fi drivers drop injected frames, so this can come back
   empty on Wi-Fi even though Npcap is working.

2. Windows ping sweep (always): ping every address so Windows ARP-resolves it, then
   read the neighbor table (Get-NetNeighbor) and keep entries in state 'Reachable'.
   Devices that ignore ping still answer ARP, so they still show up. `arp -a` is the
   fallback if PowerShell is unavailable.

Only discovery traffic is sent. Nothing is spoofed and no traffic is redirected.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable

from .db import Database, now_str
from .netinfo import NetworkInfo, norm_mac, vmware_leases
from .settings import Settings
from .winutil import powershell, run

log = logging.getLogger(__name__)

_ARP_LINE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)")
_IGNORED_MAC_PREFIXES = ("ff:ff:ff:ff:ff:ff", "01:00:5e", "33:33", "00:00:00:00:00:00")


# ── vendor lookup ───────────────────────────────────────────────────────────

def is_randomized_mac(mac: str) -> bool:
    """Locally administered bit set: phones/PCs using a 'private Wi-Fi address'."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


_manuf = None


def vendor_for(mac: str) -> str | None:
    if is_randomized_mac(mac):
        return None  # random MACs carry no manufacturer prefix
    global _manuf
    try:
        if _manuf is None:
            from scapy.all import conf
            _manuf = conf.manufdb
        short, long = _manuf.lookup(mac)
        name = long or short
        if not name or re.fullmatch(r"[0-9a-fA-F:]+", name):
            return None
        return name
    except Exception:
        return None


# ── discovery methods ───────────────────────────────────────────────────────

def scapy_iface_for(guid: str | None, ip: str | None):
    from scapy.all import conf
    for i in conf.ifaces.values():
        if guid and getattr(i, "guid", None) == guid:
            return i
    for i in conf.ifaces.values():
        if ip and getattr(i, "ip", None) == ip:
            return i
    return None


def _scapy_iface(net: NetworkInfo):
    return scapy_iface_for(net.guid, net.ip)


def arp_scan(subnet: str, net: NetworkInfo, timeout: float = 2.0) -> dict[str, str]:
    from scapy.all import ARP, Ether, srp

    iface = _scapy_iface(net)
    if iface is None:
        raise RuntimeError(f"Scapy/Npcap cannot see interface {net.interface}")
    found: dict[str, str] = {}
    for _ in range(2):  # two passes: Wi-Fi clients in power-save sometimes miss the first
        ans, _unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                          iface=iface, timeout=timeout, inter=0.002, verbose=False)
        for _sent, recv in ans:
            mac = norm_mac(recv[ARP].hwsrc)
            if mac:
                found[recv[ARP].psrc] = mac
    return found


def read_arp_table(local_ip: str | None, subnet: str) -> dict[str, str]:
    net = ipaddress.IPv4Network(subnet, strict=False)
    found: dict[str, str] = {}
    in_section = local_ip is None
    for line in run(["arp", "-a"], timeout=10).splitlines():
        if line.lower().startswith("interface:"):
            in_section = local_ip is None or f" {local_ip} " in f"{line} "
            continue
        if not in_section:
            continue
        m = _ARP_LINE.match(line)
        if not m:
            continue
        ip, mac = m.group(1), norm_mac(m.group(2))
        if not mac or mac.startswith(_IGNORED_MAC_PREFIXES):
            continue
        addr = ipaddress.IPv4Address(ip)
        if addr in net and addr not in (net.network_address, net.broadcast_address):
            found[ip] = mac
    return found


def read_neighbors(if_index: int | None, subnet: str) -> dict[str, str] | None:
    """Windows neighbor table, keeping only entries Windows has just confirmed ('Reachable').
    Returns None if PowerShell is unavailable so the caller can fall back to `arp -a`."""
    if if_index is None:
        return None
    raw = powershell(
        f"Get-NetNeighbor -InterfaceIndex {int(if_index)} -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress, LinkLayerAddress, @{n='State';e={[string]$_.State}} | "
        "ConvertTo-Json -Compress", timeout=20).strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        data = [data]
    net = ipaddress.IPv4Network(subnet, strict=False)
    found: dict[str, str] = {}
    for n in data:
        mac = norm_mac(n.get("LinkLayerAddress"))
        if n.get("State") != "Reachable" or not mac or mac.startswith(_IGNORED_MAC_PREFIXES):
            continue
        addr = ipaddress.IPv4Address(n["IPAddress"])
        if addr in net and addr not in (net.network_address, net.broadcast_address):
            found[str(addr)] = mac
    return found


def ping_sweep(subnet: str, local_ip: str | None, if_index: int | None = None) -> dict[str, str]:
    """Ping every address so Windows ARP-resolves it, then read what Windows learned."""
    hosts = [str(h) for h in ipaddress.IPv4Network(subnet, strict=False).hosts() if str(h) != local_ip]
    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(lambda ip: run(["ping", "-n", "1", "-w", "600", ip], timeout=5), hosts))
    found = read_neighbors(if_index, subnet)
    return found if found is not None else read_arp_table(local_ip, subnet)


def discover(subnet: str, net: NetworkInfo, use_arp: bool) -> tuple[dict[str, str], str, str | None]:
    """Run Npcap ARP (if available) and the Windows ping sweep in parallel and merge.

    Some Wi-Fi drivers silently drop frames injected through Npcap, so ARP alone can
    return nothing; the ping sweep uses the normal Windows network stack instead.
    Returns (ip->mac, method label, warning).
    """
    warning = None
    arp_found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        arp_future = pool.submit(arp_scan, subnet, net) if use_arp else None
        ping_found = ping_sweep(subnet, net.ip, net.index)
        if arp_future:
            try:
                arp_found = arp_future.result()
            except Exception as e:
                warning = f"Npcap ARP scan failed ({e}); results come from the Windows ping sweep."
    if use_arp and not warning and not arp_found and ping_found:
        warning = ("Npcap ARP got no replies (this Wi-Fi driver likely does not transmit injected frames); "
                   "results come from the Windows ping sweep.")
    method = "arp+ping" if use_arp else "ping"
    return {**ping_found, **arp_found}, method, warning


def vmware_vm_running() -> bool:
    try:
        import psutil
        return any((p.info["name"] or "").lower() == "vmware-vmx.exe" for p in psutil.process_iter(["name"]))
    except Exception:
        return True  # can't tell: scan anyway


def discover_vmware(vnet: dict) -> dict[str, str]:
    """Find VMs on one VMnet adapter (ping sweep + neighbor table), minus VMware's own service IPs."""
    found = ping_sweep(vnet["subnet"], vnet["host_ip"], vnet.get("index"))
    skip = {vnet["host_ip"], *vnet.get("service_ips", [])}
    return {ip: mac for ip, mac in found.items() if ip not in skip}


def vm_network_label(vnet: dict) -> str:
    return f"VMware {vnet['name']} ({vnet['mode']})"


def resolve_hostnames(ips: list[str], budget: float = 6.0) -> dict[str, str]:
    def lookup(ip: str) -> str | None:
        try:
            name = socket.gethostbyaddr(ip)[0]
            return None if name == ip else name
        except OSError:
            return None

    pool = ThreadPoolExecutor(max_workers=32)
    futures = {pool.submit(lookup, ip): ip for ip in ips}
    done, _ = wait(futures, timeout=budget)
    pool.shutdown(wait=False, cancel_futures=True)
    return {futures[f]: f.result() for f in done if f.result()}


# ── scanner service ─────────────────────────────────────────────────────────

class ScanBusy(RuntimeError):
    pass


class Scanner:
    def __init__(self, db: Database, settings: Settings,
                 get_network: Callable[[], NetworkInfo], capture_ok: Callable[[], bool]):
        self.db = db
        self.settings = settings
        self.get_network = get_network
        self.capture_ok = capture_ok
        self._lock = threading.Lock()
        self.status: dict = {"running": False, "phase": "idle", "started_at": None,
                             "trigger": None, "last_result": None}

    @property
    def running(self) -> bool:
        return self._lock.locked()

    def scan_in_background(self, trigger: str = "manual") -> bool:
        if self.running:
            return False
        threading.Thread(target=self._safe_scan, args=(trigger,), name="scan", daemon=True).start()
        return True

    def _safe_scan(self, trigger: str) -> None:
        try:
            self.scan(trigger)
        except ScanBusy:
            pass
        except Exception:
            log.exception("Scan failed")

    def scan(self, trigger: str = "manual") -> dict:
        if not self._lock.acquire(blocking=False):
            raise ScanBusy("A scan is already running")
        t0 = time.monotonic()
        self.status.update(running=True, phase="preparing", started_at=now_str(), trigger=trigger)
        scan_id = None
        try:
            net = self.get_network()
            if not net.ok or not net.scan_subnet:
                raise RuntimeError(net.error or "Network not detected")
            subnet = net.scan_subnet
            use_arp = self.capture_ok()
            scan_id = self.db.start_scan(subnet, "arp+ping" if use_arp else "ping", trigger)

            self.status["phase"] = "discovering devices"
            vm_nets = net.vm_networks if self.settings["monitor_vmware"] and vmware_vm_running() else []
            vm_found: dict[str, tuple[str, str]] = {}   # ip -> (mac, network label)
            with ThreadPoolExecutor(max_workers=1 + len(vm_nets)) as pool:
                vm_futures = [(v, pool.submit(discover_vmware, v)) for v in vm_nets]
                found, method, warning = discover(subnet, net, use_arp)
                for v, fut in vm_futures:
                    try:
                        for ip, mac in fut.result().items():
                            vm_found[ip] = (mac, vm_network_label(v))
                    except Exception as e:
                        log.warning("VMware scan of %s failed: %s", v["name"], e)
            if warning:
                log.info(warning)

            if net.ip and net.mac:
                found[net.ip] = net.mac  # this PC never answers its own ARP

            hostnames: dict[str, str] = {}
            if self.settings["resolve_hostnames"] and found:
                self.status["phase"] = "resolving hostnames"
                hostnames = resolve_hostnames(list(found))
            if net.ip and net.ip not in hostnames:
                hostnames[net.ip] = socket.gethostname()

            self.status["phase"] = "saving"
            seen_at = now_str()
            wifi_label = f"Wi-Fi {net.ssid}" if net.ssid else ("Wi-Fi" if net.is_wifi else net.interface)
            for ip, mac in found.items():
                self.db.upsert_device(
                    mac=mac, ip=ip, hostname=hostnames.get(ip), vendor=vendor_for(mac),
                    is_self=(ip == net.ip), is_gateway=(ip == net.gateway),
                    randomized=is_randomized_mac(mac), seen_at=seen_at, network=wifi_label,
                )
            leases = vmware_leases() if vm_found else {}
            for ip, (mac, label) in vm_found.items():
                lease = leases.get(ip) or {}
                self.db.upsert_device(
                    mac=mac, ip=ip, hostname=lease.get("hostname") if lease.get("mac") == mac else None,
                    vendor=vendor_for(mac), is_self=False, is_gateway=False,
                    randomized=is_randomized_mac(mac), seen_at=seen_at, network=label,
                )
            total = len(found) + len(vm_found)
            self.db.finish_scan(scan_id, total, warning, method)
            result = {"scan_id": scan_id, "subnet": subnet, "method": method, "devices_found": total,
                      "vm_devices_found": len(vm_found), "vm_networks_scanned": [v["name"] for v in vm_nets],
                      "duration_seconds": round(time.monotonic() - t0, 1), "finished_at": seen_at,
                      "warning": warning, "error": None}
            self.status["last_result"] = result
            return result
        except Exception as e:
            if scan_id is not None:
                self.db.finish_scan(scan_id, None, str(e))
            self.status["last_result"] = {"scan_id": scan_id, "error": str(e), "finished_at": now_str(),
                                          "duration_seconds": round(time.monotonic() - t0, 1)}
            raise
        finally:
            self.status.update(running=False, phase="idle")
            self._lock.release()

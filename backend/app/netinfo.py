"""
Automatic detection of the active Wi-Fi interface, local IP, subnet and gateway.

Primary method: PowerShell Get-NetIPConfiguration / Get-NetAdapter (native Windows).
Fallback:      psutil + a UDP "connect" trick for the local IP + `route print` for the gateway.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from dataclasses import asdict, dataclass, field

from .winutil import powershell, run

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
foreach ($c in Get-NetIPConfiguration) {
    $a = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex
    if (-not $a -or $a.Status -ne 'Up') { continue }
    $gw = $null
    if ($c.IPv4DefaultGateway) { $gw = @($c.IPv4DefaultGateway)[0].NextHop }
    foreach ($ip in @($c.IPv4Address)) {
        if (-not $ip) { continue }
        $out += [pscustomobject]@{
            alias = $c.InterfaceAlias; description = $c.InterfaceDescription
            index = $c.InterfaceIndex; guid = $a.InterfaceGuid; mac = $a.MacAddress
            media = $a.PhysicalMediaType; ip = $ip.IPAddress; prefix = [int]$ip.PrefixLength
            gateway = $gw
        }
    }
}
ConvertTo-Json -InputObject @($out) -Compress
"""

_WIFI_WORDS = ("wi-fi", "wifi", "wireless", "wlan", "802.11")


@dataclass
class NetworkInfo:
    ok: bool = False
    interface: str | None = None          # Windows alias, e.g. "Wi-Fi"
    description: str | None = None        # adapter model
    index: int | None = None              # Windows interface index
    guid: str | None = None
    npcap_device: str | None = None       # \Device\NPF_{GUID}
    mac: str | None = None
    ip: str | None = None
    prefix: int | None = None
    netmask: str | None = None
    subnet: str | None = None             # detected subnet, CIDR
    scan_subnet: str | None = None        # what is actually scanned (may be narrowed / overridden)
    gateway: str | None = None
    is_wifi: bool = False
    ssid: str | None = None
    method: str | None = None             # 'powershell' | 'fallback'
    candidates: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    ipv6: list[str] = field(default_factory=list)
    vm_networks: list[dict] = field(default_factory=list)   # VMware VMnet adapters on this PC

    def to_dict(self) -> dict:
        return asdict(self)

    def own_ips(self) -> set[str]:
        """Every address belonging to this PC (Wi-Fi, IPv6, VMware host adapters)."""
        ips = {self.ip, *self.ipv6, *(v["host_ip"] for v in self.vm_networks)}
        ips.discard(None)
        return ips


# ── VMware virtual networks ─────────────────────────────────────────────────

VMWARE_DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "VMware"


def _vmware_nat_devices() -> dict[str, str]:
    """VMnet name -> NAT gateway IP, from vmnetnat.conf (normally only VMnet8)."""
    try:
        text = (VMWARE_DATA / "vmnetnat.conf").read_text(errors="replace")
    except OSError:
        return {}
    ip = re.search(r"^\s*ip\s*=\s*([\d.]+)", text, re.M)
    dev = re.search(r"^\s*device\s*=\s*(\S+)", text, re.M)
    return {dev.group(1).lower(): ip.group(1)} if ip and dev else {}


def vmware_leases() -> dict[str, dict]:
    """IP -> {mac, hostname} from VMware's DHCP server (latest lease per IP wins)."""
    try:
        text = (VMWARE_DATA / "vmnetdhcp.leases").read_text(errors="replace")
    except OSError:
        return {}
    leases: dict[str, dict] = {}
    for m in re.finditer(r"lease\s+([\d.]+)\s*\{(.*?)\}", text, re.S):
        body = m.group(2)
        mac = re.search(r"hardware ethernet\s+([0-9a-fA-F:]+)", body)
        host = re.search(r'client-hostname\s+"([^"]*)"', body)
        leases[m.group(1)] = {"mac": norm_mac(mac.group(1)) if mac else None,
                              "hostname": host.group(1) if host else None}
    return leases


def _vmware_networks(cands: list[dict]) -> list[dict]:
    nat = _vmware_nat_devices()
    nets = []
    for c in cands:
        if "vmware virtual ethernet" not in (c.get("description") or "").lower():
            continue
        name = re.search(r"(VMnet\d+)", f"{c.get('alias')} {c.get('description')}", re.I)
        vmnet = name.group(1) if name else c.get("alias")
        net = ipaddress.IPv4Interface(f"{c['ip']}/{c['prefix']}").network
        nat_ip = nat.get(vmnet.lower())
        nets.append({
            "name": vmnet, "alias": c["alias"], "index": c.get("index"), "guid": c.get("guid"),
            "host_ip": c["ip"], "subnet": str(net), "mode": "NAT" if nat_ip else "Host-only",
            # VMware's own service addresses: NAT gateway/DNS proxy (.2) and DHCP server (.254)
            "service_ips": [ip for ip in (nat_ip, str(net.broadcast_address - 1)) if ip],
        })
    return nets


def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexdigits) != 12:
        return None
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)).lower()


def _looks_wifi(c: dict) -> bool:
    text = " ".join(str(c.get(k) or "") for k in ("alias", "description", "media")).lower()
    return any(w in text for w in _WIFI_WORDS)


def _ssid_map() -> dict[str, str]:
    """Interface alias -> SSID from `netsh wlan show interfaces` (may be empty if location is off)."""
    out = run(["netsh", "wlan", "show", "interfaces"], timeout=8)
    result: dict[str, str] = {}
    name = None
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "name":
            name = val
        elif key == "ssid" and name and val:
            result[name] = val
    return result


def _powershell_candidates() -> list[dict]:
    raw = powershell(_PS_SCRIPT).strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    cands = []
    for c in data:
        ip = c.get("ip")
        if not ip or ip.startswith("169.254.") or ip.startswith("127."):
            continue
        cands.append({
            "alias": c.get("alias"), "description": c.get("description"), "index": c.get("index"),
            "guid": c.get("guid"), "mac": norm_mac(c.get("mac")), "media": c.get("media"),
            "ip": ip, "prefix": int(c.get("prefix") or 24), "gateway": c.get("gateway") or None,
        })
    return cands


def _fallback_candidates() -> list[dict]:
    """Without PowerShell: find the IP used for the default route and match it in psutil."""
    import psutil

    local_ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET address; no packet is sent for UDP connect
            local_ip = s.getsockname()[0]
    except OSError:
        pass
    gateway = None
    for line in run(["route", "print", "-4", "0.0.0.0"], timeout=8).splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateway = parts[2]
            break
    cands = []
    for alias, addrs in psutil.net_if_addrs().items():
        mac = next((norm_mac(a.address) for a in addrs if a.family == psutil.AF_LINK), None)
        for a in addrs:
            if a.family == socket.AF_INET and a.address == local_ip and a.netmask:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{a.netmask}").prefixlen
                cands.append({"alias": alias, "description": alias, "guid": None, "mac": mac,
                              "media": None, "ip": a.address, "prefix": prefix, "gateway": gateway})
    return cands


def _own_ipv6(alias: str | None) -> list[str]:
    try:
        import psutil
        addrs = psutil.net_if_addrs().get(alias or "", [])
        return [a.address.split("%")[0] for a in addrs if a.family == socket.AF_INET6]
    except Exception:
        return []


def detect(interface_override: str = "", subnet_override: str = "", max_hosts: int = 1024) -> NetworkInfo:
    info = NetworkInfo()
    cands = _powershell_candidates()
    info.method = "powershell"
    if not cands:
        cands = _fallback_candidates()
        info.method = "fallback"
    info.candidates = cands
    info.vm_networks = _vmware_networks(cands)

    chosen = None
    if interface_override:
        chosen = next((c for c in cands if (c["alias"] or "").lower() == interface_override.lower()), None)
        if not chosen:
            info.warnings.append(f"Interface '{interface_override}' not found or not connected; using auto-detection.")
    if not chosen:
        # Prefer: Wi-Fi with a gateway > anything with a gateway > Wi-Fi > anything.
        ranked = sorted(cands, key=lambda c: (not (_looks_wifi(c) and c["gateway"]),
                                              not c["gateway"], not _looks_wifi(c)))
        chosen = ranked[0] if ranked else None

    if not chosen and not subnet_override:
        info.error = "No connected IPv4 network interface was found. Connect to Wi-Fi or set a subnet in Settings."
        return info

    if chosen:
        net = ipaddress.IPv4Interface(f"{chosen['ip']}/{chosen['prefix']}").network
        info.interface = chosen["alias"]
        info.description = chosen["description"]
        info.index = chosen.get("index")
        info.guid = chosen["guid"]
        info.npcap_device = f"\\Device\\NPF_{chosen['guid']}" if chosen["guid"] else None
        info.mac = chosen["mac"]
        info.ip = chosen["ip"]
        info.prefix = chosen["prefix"]
        info.netmask = str(net.netmask)
        info.subnet = str(net)
        info.gateway = chosen["gateway"]
        info.is_wifi = _looks_wifi(chosen)
        info.ssid = _ssid_map().get(chosen["alias"]) if info.is_wifi else None
        info.ipv6 = _own_ipv6(chosen["alias"])
        if not info.is_wifi:
            info.warnings.append("The active interface does not look like Wi-Fi (wired or virtual adapter?).")
        if not info.gateway:
            info.warnings.append("No default gateway detected on this interface.")

    scan = info.subnet
    if subnet_override:
        scan = subnet_override
        info.warnings.append(f"Using subnet from Settings: {subnet_override}")
    elif scan and ipaddress.IPv4Network(scan).num_addresses > max_hosts:
        narrowed = str(ipaddress.IPv4Interface(f"{info.ip}/24").network)
        info.warnings.append(f"Subnet {scan} is large; scanning only {narrowed}. "
                             f"Set a subnet in Settings to scan a different range.")
        scan = narrowed
    info.scan_subnet = scan
    info.ok = bool(scan)
    return info

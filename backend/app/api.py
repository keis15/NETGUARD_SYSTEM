"""REST API consumed by the React frontend. Everything lives under /api."""

from __future__ import annotations

import csv
import io
import re
import time
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .db import ActivityFilter, ago_str
from .settings import SettingsError
from .state import AppState
from .winutil import powershell, run

router = APIRouter()

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
DATE_RE = r"^\d{4}-\d{2}-\d{2}$"
TIME_RE = r"^\d{2}:\d{2}$"


def st(request: Request) -> AppState:
    return request.app.state.wm


def _device_view(d: dict, offline_after: int) -> dict:
    cutoff = ago_str(offline_after)
    d = dict(d)
    d["online"] = d["last_seen"] >= cutoff
    d["label"] = d.get("friendly_name") or d.get("hostname") or d.get("ip")
    d["is_vm"] = (d.get("network") or "").startswith("VMware")
    for k in ("is_self", "is_gateway", "randomized_mac"):
        d[k] = bool(d[k])
    return d


def _devices(s: AppState) -> list[dict]:
    off = s.settings["offline_after_seconds"]
    return [_device_view(d, off) for d in s.db.list_devices()]


def _activity_filter(device, q, domain, date_from, date_to, time_from, time_to, source) -> ActivityFilter:
    return ActivityFilter(device=device or None, q=(q or "").strip() or None, domain=domain or None,
                          date_from=date_from or None, date_to=date_to or None,
                          time_from=time_from or None, time_to=time_to or None, source=source or None)


# ── system / network ────────────────────────────────────────────────────────

def _firewall_rule_exists() -> bool:
    # "WiFiMon DNS (UDP)" is the rule name used before the rename to NetGuard
    for name in ("NetGuard DNS (UDP)", "WiFiMon DNS (UDP)"):
        if name in run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], timeout=8):
            return True
    return False


def _network_category(alias: str | None) -> str | None:
    if not alias:
        return None
    out = powershell(f"(Get-NetConnectionProfile -InterfaceAlias '{alias.replace(chr(39), '')}').NetworkCategory",
                     timeout=10).strip()
    return out or None


def _guidance(s: AppState, sysinfo: dict, net, extra: dict) -> list[dict]:
    g: list[dict] = []
    npcap = sysinfo["npcap"]
    if not npcap["installed"]:
        g.append({"level": "error", "title": "Npcap is not installed",
                  "detail": "Without Npcap the scanner falls back to a ping sweep and passive DNS capture is disabled.",
                  "action": "Download Npcap from https://npcap.com/#download, run the installer as Administrator, "
                            "tick 'Install Npcap in WinPcap API-compatible Mode', leave 'Restrict Npcap driver's "
                            "access to Administrators only' unticked, then restart NetGuard."})
    elif not npcap["running"]:
        g.append({"level": "error", "title": "Npcap driver is installed but not running",
                  "action": "Open an Administrator terminal and run:  sc start npcap   (or reboot)."})
    elif npcap["admin_only"] and not sysinfo["admin"]:
        g.append({"level": "error", "title": "Npcap is restricted to Administrators",
                  "detail": "Npcap was installed with 'admin-only' access, and NetGuard is not elevated.",
                  "action": "Run start.bat with 'Run as administrator', or reinstall Npcap without the "
                            "admin-only option."})
    else:
        g.append({"level": "ok", "title": f"Packet capture available (Npcap {npcap.get('version') or ''})".strip(),
                  "detail": "ARP scanning and passive DNS capture are enabled."})

    if not net.ok:
        g.append({"level": "error", "title": "Network not detected", "detail": net.error,
                  "action": "Connect to Wi-Fi, then press 'Re-detect network' or set a subnet in Settings."})
    elif not net.is_wifi:
        g.append({"level": "warn", "title": "Active interface is not Wi-Fi",
                  "detail": f"Using {net.interface} ({net.description}).",
                  "action": "If that is wrong, set the interface name in Settings."})

    if s.settings["dns_server_enabled"]:
        fwd = s.dns.forwarder
        if fwd.error:
            g.append({"level": "error", "title": "DNS forwarder could not start", "detail": fwd.error})
        if not extra.get("firewall_rule"):
            g.append({"level": "warn", "title": "No Windows Firewall rule for inbound DNS",
                      "detail": "Other devices cannot reach the DNS forwarder until port 53 is allowed.",
                      "action": 'Administrator terminal:  netsh advfirewall firewall add rule name="NetGuard DNS (UDP)" '
                                'dir=in action=allow protocol=UDP localport=53 profile=private  and the same with '
                                'name="NetGuard DNS (TCP)" protocol=TCP'})
        if extra.get("network_category") == "Public":
            g.append({"level": "warn", "title": "Wi-Fi network profile is 'Public'",
                      "detail": "Windows blocks most inbound connections on Public networks.",
                      "action": "Settings > Network & internet > Wi-Fi > (your network) > Network profile type: Private."})
        if net.gateway:
            g.append({"level": "info", "title": "Point your router's DHCP DNS at this PC",
                      "detail": f"In the router admin page (usually http://{net.gateway}), set the DHCP 'Primary DNS' "
                                f"to {net.ip}, and reserve {net.ip} for this PC so it never changes. "
                                f"Devices pick it up when they reconnect or renew their lease."})
    else:
        g.append({"level": "info", "title": "Website activity currently covers this PC only",
                  "detail": "Passive capture on Wi-Fi cannot see other devices' DNS lookups. "
                            "Enable the DNS forwarder in Settings for network-wide domain visibility."})
    return g


@router.get("/health")
def health():
    return {"ok": True, "time": datetime.now().isoformat(timespec="seconds")}


@router.get("/system")
def system(request: Request, refresh: bool = False):
    s = st(request)
    sysinfo = s.system(refresh=refresh)
    net = s.network(refresh=refresh)
    extra: dict[str, Any] = {}
    if s.settings["dns_server_enabled"]:
        extra["firewall_rule"] = _firewall_rule_exists()
        extra["network_category"] = _network_category(net.interface)
    return {**sysinfo, **extra, "capture_ok": s.capture_ok(), "network": net.to_dict(),
            "dns": s.dns.status(), "guidance": _guidance(s, sysinfo, net, extra)}


@router.post("/network/redetect")
def redetect(request: Request):
    s = st(request)
    s.system(refresh=True)
    s.apply_settings(redetect=True)
    return s.network().to_dict()


# ── dashboard ───────────────────────────────────────────────────────────────

def _hour_series(rows: list[dict], hours: int = 24) -> list[dict]:
    by_t = {r["t"]: r for r in rows}
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    out = []
    for i in range(hours - 1, -1, -1):
        t = (now - timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
        r = by_t.get(t, {})
        out.append({"t": t, "label": t[11:16], "requests": r.get("requests", 0), "domains": r.get("domains", 0)})
    return out


@router.get("/dashboard")
def dashboard(request: Request):
    s = st(request)
    devices = _devices(s)
    my_pc = next((d for d in devices if d["is_self"]), None)
    gateway = next((d for d in devices if d["is_gateway"]), None)
    f24 = ActivityFilter(since=ago_str(86400))
    return {
        "counts": {
            "total": len(devices),
            "online": sum(d["online"] for d in devices),
            "offline": sum(not d["online"] for d in devices),
            "others": sum(not d["is_self"] for d in devices),
            "others_online": sum(d["online"] and not d["is_self"] for d in devices),
            "new_24h": s.db.count_new_devices(ago_str(86400)),
            "vms": sum(d["is_vm"] for d in devices),
            "vms_online": sum(d["is_vm"] and d["online"] for d in devices),
        },
        "my_pc": my_pc,
        "gateway": gateway,
        "last_scan": s.db.last_scan(),
        "scan": s.scanner.status,
        "network": s.network().to_dict(),
        "dns": s.dns.status(),
        "activity_24h": {
            "totals": s.db.activity_totals(f24),
            "timeline": _hour_series(s.db.timeline(f24, "hour")),
            "top_domains": s.db.top_domains(f24, 8),
            "top_devices": s.db.top_devices(f24, 5),
        },
        "recent_devices": sorted(devices, key=lambda d: d["first_seen"], reverse=True)[:5],
    }


# ── devices ─────────────────────────────────────────────────────────────────

class RenameBody(BaseModel):
    friendly_name: str | None = Field(None, max_length=64)


def _check_mac(mac: str) -> str:
    mac = mac.lower()
    if not MAC_RE.match(mac):
        raise HTTPException(400, "Invalid MAC address")
    return mac


@router.get("/devices")
def devices(request: Request, status: Literal["all", "online", "offline"] = "all", q: str = ""):
    rows = _devices(st(request))
    if status != "all":
        rows = [d for d in rows if d["online"] == (status == "online")]
    if q:
        ql = q.lower()
        rows = [d for d in rows if any(ql in str(d.get(k) or "").lower()
                                       for k in ("ip", "mac", "hostname", "vendor", "friendly_name", "network"))]
    return rows


@router.patch("/devices/{mac}")
def rename_device(mac: str, body: RenameBody, request: Request):
    s = st(request)
    mac = _check_mac(mac)
    name = (body.friendly_name or "").strip() or None
    if not s.db.set_friendly_name(mac, name):
        raise HTTPException(404, "Device not found")
    return _device_view(s.db.get_device(mac), s.settings["offline_after_seconds"])


@router.delete("/devices/{mac}")
def delete_device(mac: str, request: Request):
    if not st(request).db.delete_device(_check_mac(mac)):
        raise HTTPException(404, "Device not found")
    return {"deleted": mac}


# ── scanning ────────────────────────────────────────────────────────────────

@router.post("/scan", status_code=202)
def start_scan(request: Request):
    s = st(request)
    if not s.scanner.scan_in_background("manual"):
        raise HTTPException(409, "A scan is already running")
    return {"started": True}


@router.get("/scan/status")
def scan_status(request: Request):
    s = st(request)
    nxt = s.next_auto_scan
    return {**s.scanner.status,
            "auto_scan": s.settings["auto_scan"],
            "interval_seconds": s.settings["scan_interval_seconds"],
            "next_auto_scan_in": None if nxt is None else max(0, round(nxt - time.time())),
            "capture_ok": s.capture_ok(),
            "last_scan": s.db.last_scan()}


@router.get("/scans")
def scans(request: Request, limit: int = Query(20, ge=1, le=200)):
    return st(request).db.list_scans(limit)


# ── website activity ────────────────────────────────────────────────────────

@router.get("/activity")
def activity(request: Request,
             device: str | None = None, q: str | None = Query(None, max_length=253),
             domain: str | None = Query(None, max_length=253),
             date_from: str | None = Query(None, pattern=DATE_RE), date_to: str | None = Query(None, pattern=DATE_RE),
             time_from: str | None = Query(None, pattern=TIME_RE), time_to: str | None = Query(None, pattern=TIME_RE),
             source: Literal["sniffer", "dns_server"] | None = None,
             blocked: bool | None = None,
             group: Literal["minute", "hour", "day", "total"] = "minute",
             by: Literal["domain", "base_domain"] = "base_domain",
             sort: Literal["recent", "requests", "domain", "device"] = "recent",
             limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0)):
    s = st(request)
    f = _activity_filter(device, q, domain, date_from, date_to, time_from, time_to, source)
    f.blocked = blocked
    rows, total = s.db.query_activity(f, group=group, by=by, sort=sort, limit=limit, offset=offset)
    return {"rows": rows, "total": total, "totals": s.db.activity_totals(f)}


@router.get("/dns/status")
def dns_status(request: Request):
    return st(request).dns.status()


@router.get("/filter")
def get_filter(request: Request):
    s = st(request)
    cfg = s.settings.all()
    return {
        "enabled": cfg["filtering_enabled"], "mode": cfg["filter_mode"],
        "blocklist": cfg["blocklist"], "allowlist": cfg["allowlist"],
        "block_message": cfg["block_message"], "block_page_ip": cfg["block_page_ip"],
        "block_page_port": cfg["block_page_port"],
        "effective_block_ip": cfg["block_page_ip"] or s.network().ip,
        "status": s.dns.status()["filtering"],
        "forwarder_running": s.dns.forwarder.running,
    }


@router.get("/filter/test")
def test_filter(request: Request, domain: str = Query(..., max_length=253)):
    from .dns_parse import base_domain
    from .filtering import FilterPolicy, clean_domain
    s = st(request).settings
    name = clean_domain(domain)
    if not name:
        raise HTTPException(400, "Enter a domain like youtube.com")
    policy = FilterPolicy(s["filter_mode"], s["blocklist"], s["allowlist"])
    blocked = s["filtering_enabled"] and policy.is_blocked(name, base_domain(name))
    return {"domain": name, "base_domain": base_domain(name), "blocked": blocked,
            "mode": s["filter_mode"], "enabled": s["filtering_enabled"]}


@router.get("/activity/devices")
def activity_devices(request: Request):
    return st(request).db.activity_devices()


@router.get("/activity/top-domains")
def activity_top(request: Request, device: str | None = None, q: str | None = None,
                 date_from: str | None = Query(None, pattern=DATE_RE), date_to: str | None = Query(None, pattern=DATE_RE),
                 time_from: str | None = Query(None, pattern=TIME_RE), time_to: str | None = Query(None, pattern=TIME_RE),
                 limit: int = Query(10, ge=1, le=100)):
    f = _activity_filter(device, q, None, date_from, date_to, time_from, time_to, None)
    return st(request).db.top_domains(f, limit)


@router.delete("/activity")
def clear_activity(request: Request):
    return {"deleted": st(request).db.clear_activity()}


# ── reports ─────────────────────────────────────────────────────────────────

@router.get("/reports/summary")
def report_summary(request: Request, days: int = Query(7, ge=1, le=365)):
    s = st(request)
    since_dt = (datetime.now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    since = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    f = ActivityFilter(since=since)
    daily = {r["t"]: r for r in s.db.timeline(f, "day")}
    daily_series = []
    for i in range(days):
        d = (since_dt + timedelta(days=i)).strftime("%Y-%m-%d")
        r = daily.get(d, {})
        daily_series.append({"t": d, "requests": r.get("requests", 0), "domains": r.get("domains", 0)})
    hod = {r["t"]: r["requests"] for r in s.db.timeline(f, "hour_of_day")}
    devices = _devices(s)
    vendors: dict[str, int] = {}
    for d in devices:
        key = "Private (randomized) MAC" if d["randomized_mac"] else (d["vendor"] or "Unknown")
        vendors[key] = vendors.get(key, 0) + 1
    return {
        "days": days, "since": since,
        "totals": s.db.activity_totals(f),
        "devices": {"total": len(devices), "online": sum(d["online"] for d in devices),
                    "new": s.db.count_new_devices(since)},
        "daily": daily_series,
        "hour_of_day": [{"hour": f"{h:02d}", "requests": hod.get(f"{h:02d}", 0)} for h in range(24)],
        "top_domains": s.db.top_domains(f, 15),
        "top_devices": s.db.top_devices(f, 10),
        "vendors": sorted(({"vendor": k, "count": v} for k, v in vendors.items()), key=lambda x: -x["count"]),
        "scans": s.db.list_scans(10),
    }


def _csv(rows: list[dict], columns: list[str], filename: str) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/reports/activity.csv")
def report_activity_csv(request: Request,
                        device: str | None = None, q: str | None = None, domain: str | None = None,
                        date_from: str | None = Query(None, pattern=DATE_RE), date_to: str | None = Query(None, pattern=DATE_RE),
                        time_from: str | None = Query(None, pattern=TIME_RE), time_to: str | None = Query(None, pattern=TIME_RE),
                        group: Literal["minute", "hour", "day", "total"] = "minute",
                        by: Literal["domain", "base_domain"] = "base_domain"):
    f = _activity_filter(device, q, domain, date_from, date_to, time_from, time_to, None)
    rows, _ = st(request).db.query_activity(f, group=group, by=by, sort="recent", limit=100_000)
    return _csv(rows, ["period", "device_label", "device_ip", "device_mac", "domain", "requests",
                       "blocked", "first_seen", "last_seen", "sources"],
                f"netguard-activity-{datetime.now():%Y%m%d-%H%M}.csv")


@router.get("/reports/devices.csv")
def report_devices_csv(request: Request):
    return _csv(_devices(st(request)), ["label", "friendly_name", "ip", "mac", "hostname", "vendor", "online",
                                        "is_self", "is_gateway", "randomized_mac", "first_seen", "last_seen"],
                f"netguard-devices-{datetime.now():%Y%m%d-%H%M}.csv")


# ── settings ────────────────────────────────────────────────────────────────

@router.get("/settings")
def get_settings(request: Request):
    return st(request).settings.all()


@router.put("/settings")
def put_settings(body: dict[str, Any], request: Request):
    s = st(request)
    try:
        changed = s.settings.update(body)
    except SettingsError as e:
        raise HTTPException(400, str(e)) from None
    redetect = bool({"interface_override", "subnet_override", "max_scan_hosts"} & changed.keys())
    s.apply_settings(redetect=redetect)
    return {"settings": s.settings.all(), "changed": sorted(changed), "dns": s.dns.status()}

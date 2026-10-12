"""Application settings: defaults, validation, persistence in the settings table."""

from __future__ import annotations

import ipaddress
import threading
from typing import Any

from .db import Database

DEFAULTS: dict[str, Any] = {
    # Scanning
    "auto_scan": True,
    "scan_interval_seconds": 120,
    "offline_after_seconds": 300,      # device shown offline if not seen for this long
    "resolve_hostnames": True,
    "subnet_override": "",             # only used if auto-detection fails or is wrong
    "interface_override": "",          # Windows interface alias, e.g. "Wi-Fi"
    "max_scan_hosts": 1024,            # larger subnets are narrowed to the local /24
    "monitor_vmware": True,            # also scan + capture DNS on VMware VMnet adapters (NAT / host-only VMs)

    # DNS / domain monitoring
    "dns_sniffer_enabled": True,       # passive capture of DNS queries visible to this PC (Npcap)
    "dns_server_enabled": False,       # act as the network's DNS forwarder (router must point to this PC)
    "dns_server_bind": "0.0.0.0",
    "dns_server_port": 53,
    "dns_upstream": "",                # empty = default gateway, falls back to 1.1.1.1
    "ignore_local_names": True,        # skip .local / .arpa / single-label names
    "retention_days": 30,

    # Website access control (applies to devices that use this PC as their DNS server)
    "filtering_enabled": False,
    "filter_mode": "blocklist",        # 'blocklist' (block these) | 'allowlist' (only allow these)
    "blocklist": [],                   # domains to block, e.g. ["tiktok.com", "facebook.com"]
    "allowlist": [],                   # the only domains allowed, in allowlist mode
    "block_message": "You are not allowed to access this website. Please contact your Administrator.",
    "block_page_ip": "",               # IP the block page is served on; empty = this PC's Wi-Fi IP
    "block_page_port": 80,
}

_ENUMS = {"filter_mode": {"blocklist", "allowlist"}}
_DOMAIN_LISTS = {"blocklist", "allowlist"}

_BOUNDS = {
    "scan_interval_seconds": (30, 86400),
    "offline_after_seconds": (60, 86400),
    "max_scan_hosts": (16, 4096),
    "dns_server_port": (1, 65535),
    "retention_days": (1, 3650),
    "block_page_port": (1, 65535),
}


class SettingsError(ValueError):
    pass


def _validate(key: str, value: Any) -> Any:
    if key not in DEFAULTS:
        raise SettingsError(f"Unknown setting: {key}")
    if key in _DOMAIN_LISTS:
        from .filtering import clean_domain
        if not isinstance(value, list):
            raise SettingsError(f"{key} must be a list of domains")
        cleaned = []
        for item in value:
            if not isinstance(item, str):
                raise SettingsError(f"{key} entries must be text")
            d = clean_domain(item)
            if d and d not in cleaned:
                cleaned.append(d)
        return cleaned
    if key in _ENUMS:
        if value not in _ENUMS[key]:
            raise SettingsError(f"{key} must be one of: {', '.join(sorted(_ENUMS[key]))}")
        return value
    default = DEFAULTS[key]
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise SettingsError(f"{key} must be true or false")
        return value
    if isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
            raise SettingsError(f"{key} must be a whole number")
        lo, hi = _BOUNDS.get(key, (None, None))
        if lo is not None and not lo <= value <= hi:
            raise SettingsError(f"{key} must be between {lo} and {hi}")
        return int(value)
    if not isinstance(value, str):
        raise SettingsError(f"{key} must be text")
    value = value.strip()
    if key == "subnet_override" and value:
        try:
            value = str(ipaddress.IPv4Network(value, strict=False))
        except ValueError:
            raise SettingsError("subnet_override must look like 192.168.1.0/24") from None
    if key in ("dns_upstream", "dns_server_bind", "block_page_ip") and value:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise SettingsError(f"{key} must be an IPv4 address") from None
    if key == "block_message" and len(value) > 300:
        raise SettingsError("block_message must be 300 characters or fewer")
    return value


class Settings:
    def __init__(self, db: Database):
        self._db = db
        self._lock = threading.Lock()
        stored = db.get_settings()
        self._values = {k: stored.get(k, v) for k, v in DEFAULTS.items()}

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._values[key]

    def all(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._values)

    def update(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Validate and persist; returns the dict of keys that actually changed."""
        clean = {k: _validate(k, v) for k, v in changes.items()}
        with self._lock:
            changed = {k: v for k, v in clean.items() if self._values.get(k) != v}
            self._values.update(clean)
        if clean:
            self._db.set_settings(clean)
        return changed

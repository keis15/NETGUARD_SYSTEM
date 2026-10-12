"""Small Windows helpers: run hidden subprocesses, admin check, Npcap detection."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def run(cmd: list[str], timeout: float = 15) -> str:
    """Run a command without flashing a console window; return stdout ('' on failure)."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW,
        )
        return out.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def powershell(script: str, timeout: float = 20) -> str:
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", script], timeout=timeout)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return os.name != "nt" and os.geteuid() == 0  # type: ignore[attr-defined]


def npcap_status() -> dict:
    """Detect Npcap: DLL present, service running, and 'admin-only' install option."""
    windir = os.environ.get("WINDIR", r"C:\Windows")
    installed = (Path(windir) / "System32" / "Npcap" / "wpcap.dll").exists()
    running = False
    admin_only = False
    version = None
    if sys.platform == "win32":
        running = "RUNNING" in run(["sc", "query", "npcap"], timeout=5)
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as k:
                try:
                    admin_only = bool(winreg.QueryValueEx(k, "AdminOnly")[0])
                except OSError:
                    pass
        except OSError:
            pass
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst") as k:
                version = winreg.QueryValueEx(k, "DisplayVersion")[0]
        except OSError:
            pass
    return {"installed": installed, "running": running, "admin_only": admin_only, "version": version}


def scapy_available() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False

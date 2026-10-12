"""
Website access control for the DNS forwarder.

Two modes, applied to every device that uses this PC as its DNS server:

- blocklist: the listed sites are refused ("burned"); everything else is allowed.
- allowlist: ONLY the listed sites are allowed; everything else is refused (kiosk mode).

A refused domain is answered with this PC's IP, where a small HTTP server shows the
"not allowed" message. Because HTTPS presents a certificate for the real site, the message
page renders cleanly only over http://; for https:// the browser shows its own
"can't reach / not secure" error, but the site is still blocked.
"""

from __future__ import annotations

import logging
import re
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger(__name__)

_SCHEME = re.compile(r"^[a-z]+://")


def clean_domain(raw: str) -> str | None:
    """Normalise a user-entered rule: strip scheme/path/port, 'www.' and leading '*.'."""
    if not raw:
        return None
    d = raw.strip().lower()
    d = _SCHEME.sub("", d).split("/")[0].split(":")[0].strip(".")
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("www."):
        d = d[4:]
    if not d or "." not in d or not re.fullmatch(r"[a-z0-9.-]+", d):
        return None
    return d


class FilterPolicy:
    """Immutable decision helper built from the current settings."""

    def __init__(self, mode: str, blocklist: list[str], allowlist: list[str]):
        self.mode = mode
        self.block = set(blocklist)
        self.allow = set(allowlist)

    @staticmethod
    def _matches(name: str, rules: set[str]) -> bool:
        # A rule blocks the domain itself and every subdomain: "youtube.com" -> m.youtube.com too.
        return any(name == r or name.endswith("." + r) for r in rules)

    def is_blocked(self, name: str, base: str) -> bool:
        name = (name or "").lower().rstrip(".")
        if self.mode == "allowlist":
            return not (self._matches(name, self.allow) or self._matches(base, self.allow))
        return self._matches(name, self.block) or self._matches(base, self.block)

    @property
    def active_rules(self) -> set[str]:
        return self.allow if self.mode == "allowlist" else self.block


class BlockPageServer:
    """Serves the 'you are not allowed' page for any request to a blocked site."""

    def __init__(self):
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.bind = "0.0.0.0"
        self.port = 80
        self.message = ""
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self, bind: str, port: int, message: str) -> None:
        self.stop()
        self.error = None
        self.bind, self.port, self.message = bind, port, message
        msg = message

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                host = escape(self.headers.get("Host", "this website"))
                body = _PAGE.replace("{{HOST}}", host).replace("{{MESSAGE}}", escape(msg)).encode("utf-8")
                self.send_response(403)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_HEAD = do_POST = _serve

            def log_message(self, *a):
                pass

        try:
            self._server = ThreadingHTTPServer((bind, port), Handler)
        except OSError as e:
            self.error = (f"Cannot show the block page on {bind}:{port} ({e}). "
                          f"Another program may use port {port}. Blocking still works; only the message page is off.")
            log.warning(self.error)
            return
        self._thread = threading.Thread(target=self._server.serve_forever, name="block-page", daemon=True)
        self._thread.start()
        log.info("Block page server listening on %s:%s", bind, port)

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None
        self._thread = None


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access blocked</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0b1017;color:#e6edf6;font:16px/1.6 'Segoe UI',system-ui,sans-serif;padding:24px}
.card{max-width:520px;text-align:center;background:#141c28;border:1px solid #243044;border-radius:14px;padding:40px 32px}
.ic{width:72px;height:72px;margin:0 auto 20px;border-radius:50%;display:grid;place-items:center;
background:rgba(248,113,113,.14);color:#f87171}
h1{font-size:22px;margin:0 0 10px}p{color:#a3b1c6;margin:0 0 8px}
.host{font-family:ui-monospace,Consolas,monospace;color:#22d3ee;word-break:break-all}
.foot{margin-top:22px;font-size:13px;color:#6f7f96;border-top:1px solid #243044;padding-top:16px}</style></head>
<body><div class="card">
<div class="ic"><svg width="38" height="38" viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3.1-9H8.9V6a3.1 3.1 0 0 1 6.2 0v2z"/></svg></div>
<h1>Access to this website is blocked</h1>
<p>You are not allowed to access <span class="host">{{HOST}}</span> on this network.</p>
<p>{{MESSAGE}}</p>
<div class="foot">Blocked by NetGuard &middot; Contact your network administrator.</div>
</div></body></html>"""

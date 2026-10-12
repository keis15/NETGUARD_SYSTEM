"""Website access control: domain cleaning, block/allow policy, DNS block responses, forwarder, DB."""

import socket
import struct
import threading

import pytest

from backend.app.db import ActivityFilter, Database
from backend.app.dns_monitor import DnsForwarder, DnsRecorder
from backend.app.dns_parse import build_block_response
from backend.app.filtering import FilterPolicy, clean_domain
from backend.app.settings import Settings, SettingsError
from backend.tests.test_dns_parse import build_query


def test_clean_domain():
    assert clean_domain("https://www.YouTube.com/watch?v=1") == "youtube.com"
    assert clean_domain("*.tiktok.com") == "tiktok.com"
    assert clean_domain("facebook.com:443") == "facebook.com"
    assert clean_domain("not a domain") is None
    assert clean_domain("localhost") is None


def test_blocklist_policy():
    p = FilterPolicy("blocklist", ["youtube.com", "tiktok.com"], [])
    assert p.is_blocked("youtube.com", "youtube.com")
    assert p.is_blocked("m.youtube.com", "youtube.com")      # subdomains too
    assert not p.is_blocked("google.com", "google.com")


def test_allowlist_policy():
    p = FilterPolicy("allowlist", [], ["school.edu"])
    assert not p.is_blocked("school.edu", "school.edu")
    assert not p.is_blocked("portal.school.edu", "school.edu")
    assert p.is_blocked("youtube.com", "youtube.com")        # everything else blocked
    assert p.is_blocked("google.com", "google.com")


def test_build_block_response_a_record():
    resp = build_block_response(build_query("youtube.com", 1), "192.168.1.88")
    qr = int.from_bytes(resp[2:4], "big")
    assert qr & 0x8000                                        # is a response
    assert int.from_bytes(resp[6:8], "big") == 1             # one answer
    assert resp[-4:] == socket.inet_aton("192.168.1.88")     # points at the block page


def test_build_block_response_non_a_is_empty():
    resp = build_block_response(build_query("youtube.com", 28), "192.168.1.88")  # AAAA
    assert int.from_bytes(resp[6:8], "big") == 0             # no answer -> client falls back to IPv4


def test_settings_validate_filter_lists_and_mode(tmp_path):
    db = Database(tmp_path / "s.db")
    s = Settings(db)
    changed = s.update({"filtering_enabled": True, "filter_mode": "allowlist",
                        "blocklist": ["https://TikTok.com/foo", "tiktok.com", "bad entry"]})
    assert s["blocklist"] == ["tiktok.com"]                  # cleaned + de-duped, junk dropped
    assert s["filter_mode"] == "allowlist"
    with pytest.raises(SettingsError):
        s.update({"filter_mode": "nonsense"})
    with pytest.raises(SettingsError):
        s.update({"blocklist": "tiktok.com"})                # must be a list


@pytest.fixture
def upstream():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            # answer A -> 203.0.113.9 so we can tell a forwarded reply from a block reply
            ans = (data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01" + b"\x00\x00\x00\x00"
                   + data[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + socket.inet_aton("203.0.113.9"))
            sock.sendto(ans, addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set(); t.join(1); sock.close()


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_forwarder_blocks_and_logs(upstream):
    db = Database(":memory:")
    rec = DnsRecorder(db, Settings(db))
    fwd = DnsForwarder(rec)
    fwd.upstream_port = upstream
    fwd.filter = FilterPolicy("blocklist", ["tiktok.com"], [])
    fwd.block_ip = "192.168.1.88"
    port = _free_port()
    fwd.start("127.0.0.1", port, "127.0.0.1")
    assert fwd.running, fwd.error
    try:
        def query(name):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
                c.settimeout(3)
                c.sendto(build_query(name, 1), ("127.0.0.1", port))
                return c.recvfrom(4096)[0]

        blocked = query("www.tiktok.com")       # must be redirected to the block page IP
        assert blocked[-4:] == socket.inet_aton("192.168.1.88")
        allowed = query("github.com")            # must be forwarded to upstream
        assert allowed[-4:] == socket.inet_aton("203.0.113.9")

        rec.flush()
        rows, _ = db.query_activity(ActivityFilter(), group="total", by="base_domain")
        by_dom = {r["domain"]: r for r in rows}
        assert by_dom["tiktok.com"]["blocked"] == 1
        assert by_dom["github.com"]["blocked"] == 0
        assert db.activity_totals(ActivityFilter())["blocked"] == 1
        assert db.query_activity(ActivityFilter(blocked=True))[1] == 1
    finally:
        fwd.stop()

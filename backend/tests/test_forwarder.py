"""DNS forwarder end-to-end against a fake local upstream (no internet, no admin, no port 53)."""

import socket
import threading

import pytest

from backend.app.db import ActivityFilter, Database
from backend.app.dns_monitor import DnsForwarder, DnsRecorder
from backend.app.settings import Settings
from backend.tests.test_dns_parse import build_query


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def fake_upstream():
    """UDP-only upstream (like many home routers): echoes the query with the QR bit set."""
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
            sock.sendto(data[:2] + bytes([data[2] | 0x80]) + data[3:], addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set()
    t.join(1)
    sock.close()


def test_forwarder_udp_and_tcp(fake_upstream):
    db = Database(":memory:")
    rec = DnsRecorder(db, Settings(db))
    fwd = DnsForwarder(rec)
    fwd.upstream_port = fake_upstream
    port = _free_port()
    fwd.start("127.0.0.1", port, "127.0.0.1")
    assert fwd.running, fwd.error
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(3)
            c.sendto(build_query("youtube.com"), ("127.0.0.1", port))
            reply, _ = c.recvfrom(4096)
            assert reply[2] & 0x80  # it is a response

        # TCP client; upstream has no TCP, so the forwarder must fall back to UDP
        with socket.create_connection(("127.0.0.1", port), timeout=3) as t:
            q = build_query("www.github.com")
            t.sendall(len(q).to_bytes(2, "big") + q)
            n = int.from_bytes(t.recv(2), "big")
            assert n == len(q)

        rec.flush()
        rows, _ = db.query_activity(ActivityFilter(), group="total", by="base_domain")
        assert {r["domain"] for r in rows} == {"youtube.com", "github.com"}
        assert all(r["sources"] == "dns_server" and r["device_ip"] == "127.0.0.1" for r in rows)
    finally:
        fwd.stop()
    assert not fwd.running

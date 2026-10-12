from datetime import datetime

import pytest

from backend.app.db import ActivityFilter, Database, now_str
from backend.app.dns_monitor import DnsRecorder
from backend.app.netinfo import norm_mac
from backend.app.scanner import is_randomized_mac, read_arp_table
from backend.app.settings import Settings, SettingsError


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


def test_norm_mac():
    assert norm_mac("CC-3D-82-C5-97-8E") == "cc:3d:82:c5:97:8e"
    assert norm_mac("cc3d82c5978e") == "cc:3d:82:c5:97:8e"
    assert norm_mac("nope") is None


def test_randomized_mac_detection():
    assert is_randomized_mac("da:a1:19:00:00:01")      # 0xda has the local bit set
    assert not is_randomized_mac("cc:3d:82:c5:97:8e")


def test_settings_validation_and_persistence(db):
    s = Settings(db)
    assert s["scan_interval_seconds"] == 120
    changed = s.update({"scan_interval_seconds": 300, "subnet_override": "192.168.5.7/24"})
    assert set(changed) == {"scan_interval_seconds", "subnet_override"}
    assert s["subnet_override"] == "192.168.5.0/24"
    assert Settings(db)["scan_interval_seconds"] == 300    # reloaded from SQLite
    with pytest.raises(SettingsError):
        s.update({"scan_interval_seconds": 5})
    with pytest.raises(SettingsError):
        s.update({"dns_upstream": "not-an-ip"})
    with pytest.raises(SettingsError):
        s.update({"unknown": 1})


def test_device_upsert_and_rename(db):
    t = now_str()
    db.upsert_device("aa:bb:cc:00:00:01", "192.168.1.15", "phone", "Apple", False, False, False, t)
    db.upsert_device("aa:bb:cc:00:00:01", "192.168.1.16", None, None, False, False, False, t)
    d = db.get_device("aa:bb:cc:00:00:01")
    assert d["ip"] == "192.168.1.16" and d["hostname"] == "phone" and d["seen_count"] == 2
    assert db.set_friendly_name("AA:BB:CC:00:00:01", "Living room TV")
    assert db.get_device("aa:bb:cc:00:00:01")["friendly_name"] == "Living room TV"


def test_recorder_aggregates_per_minute_and_filters(db):
    s = Settings(db)
    db.upsert_device("aa:bb:cc:00:00:01", "192.168.1.15", None, None, False, False, False, now_str())
    rec = DnsRecorder(db, s)
    ts = datetime(2026, 10, 7, 14, 32, 5)
    for i in range(15):
        rec.record("192.168.1.15", "www.youtube.com", 1, "dns_server", ts.replace(second=i))
    rec.record("192.168.1.15", "printer.local", 1, "dns_server", ts)       # ignored
    rec.record("192.168.1.20", "news.bbc.co.uk", 1, "sniffer", ts.replace(hour=9))
    rec.flush()

    rows, total = db.query_activity(ActivityFilter(), group="minute", by="base_domain")
    assert total == 2
    yt = next(r for r in rows if r["domain"] == "youtube.com")
    assert yt["requests"] == 15 and yt["period"] == "2026-10-07 14:32"
    assert yt["device_mac"] == "aa:bb:cc:00:00:01"

    # flushing again must add to the same minute bucket
    rec.record("192.168.1.15", "www.youtube.com", 1, "dns_server", ts)
    rec.flush()
    rows, _ = db.query_activity(ActivityFilter(q="youtube"), group="total")
    assert rows[0]["requests"] == 16

    assert db.query_activity(ActivityFilter(device="192.168.1.20"))[1] == 1
    assert db.query_activity(ActivityFilter(time_from="14:00", time_to="15:00"))[1] == 1
    assert db.query_activity(ActivityFilter(time_from="22:00", time_to="10:00"))[1] == 1   # overnight
    assert db.query_activity(ActivityFilter(date_from="2026-10-08"))[1] == 0
    assert db.query_activity(ActivityFilter(q="100%_"))[1] == 0                             # LIKE escaping
    assert db.top_domains(ActivityFilter())[0]["domain"] == "youtube.com"


def test_read_arp_table_parses_windows_output(monkeypatch):
    sample = """
Interface: 192.168.1.88 --- 0x18
  Internet Address      Physical Address      Type
  192.168.1.254         a0-b1-c2-d3-e4-f5     dynamic
  192.168.1.15          11-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 172.20.0.1 --- 0x2a
  172.20.0.5            77-77-77-77-77-77     dynamic
"""
    monkeypatch.setattr("backend.app.scanner.run", lambda cmd, timeout=0: sample)
    assert read_arp_table("192.168.1.88", "192.168.1.0/24") == {
        "192.168.1.254": "a0:b1:c2:d3:e4:f5",
        "192.168.1.15": "11:22:33:44:55:66",
    }

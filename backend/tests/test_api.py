from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from backend.app.db import now_str
from backend.app.main import create_app
from backend.app.netinfo import NetworkInfo


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "test.db"), background=False)
    with TestClient(app) as c:
        wm = app.state.wm
        # Pretend network so tests don't depend on the host machine
        wm._net = NetworkInfo(ok=True, interface="Wi-Fi", ip="192.168.1.88", prefix=24, subnet="192.168.1.0/24",
                              scan_subnet="192.168.1.0/24", gateway="192.168.1.254", is_wifi=True,
                              mac="cc:3d:82:c5:97:8e")
        wm._system = {"admin": False, "npcap": {"installed": True, "running": True, "admin_only": False,
                                                "version": "1.79"}, "scapy": True}
        t = now_str()
        wm.db.upsert_device("cc:3d:82:c5:97:8e", "192.168.1.88", "MYPC", "Intel", True, False, False, t)
        wm.db.upsert_device("11:22:33:44:55:66", "192.168.1.15", None, None, False, False, False, t)
        rec = wm.dns.recorder
        for _ in range(15):
            rec.record("192.168.1.15", "www.youtube.com", 1, "dns_server", datetime.now())
        rec.flush()
        yield c


def test_dashboard(client):
    r = client.get("/api/dashboard").json()
    assert r["counts"]["total"] == 2 and r["counts"]["online"] == 2 and r["counts"]["others"] == 1
    assert r["my_pc"]["ip"] == "192.168.1.88"
    assert r["activity_24h"]["totals"]["requests"] == 15
    assert len(r["activity_24h"]["timeline"]) == 24


def test_rename_device(client):
    r = client.patch("/api/devices/11:22:33:44:55:66", json={"friendly_name": "Kid's tablet"})
    assert r.status_code == 200 and r.json()["label"] == "Kid's tablet"
    assert client.patch("/api/devices/bad", json={"friendly_name": "x"}).status_code == 400
    assert client.patch("/api/devices/00:00:00:00:00:01", json={"friendly_name": "x"}).status_code == 404


def test_activity_filters(client):
    r = client.get("/api/activity", params={"q": "youtube", "group": "total"}).json()
    assert r["total"] == 1 and r["rows"][0]["requests"] == 15 and r["rows"][0]["domain"] == "youtube.com"
    assert client.get("/api/activity", params={"device": "192.168.1.88"}).json()["total"] == 0
    assert client.get("/api/activity", params={"date_from": "07-10-2026"}).status_code == 422


def test_settings_roundtrip(client):
    r = client.put("/api/settings", json={"scan_interval_seconds": 600})
    assert r.status_code == 200 and r.json()["settings"]["scan_interval_seconds"] == 600
    assert client.put("/api/settings", json={"scan_interval_seconds": 1}).status_code == 400


def test_reports_and_csv(client):
    r = client.get("/api/reports/summary", params={"days": 7}).json()
    assert len(r["daily"]) == 7 and r["totals"]["requests"] == 15
    csv_text = client.get("/api/reports/activity.csv").text
    assert csv_text.splitlines()[0].startswith("period,device_label")
    assert "youtube.com" in csv_text


def test_system_guidance(client):
    r = client.get("/api/system").json()
    assert r["capture_ok"] is True
    assert any(g["level"] == "ok" for g in r["guidance"])

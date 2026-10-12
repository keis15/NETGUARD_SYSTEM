"""VMware support: lease parsing, VMnet detection, VM DNS attribution + de-duplication, DB migration."""

import sqlite3
from types import SimpleNamespace

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from backend.app import netinfo
from backend.app.db import ActivityFilter, Database
from backend.app.dns_monitor import DnsRecorder, DnsSniffer
from backend.app.netinfo import NetworkInfo
from backend.app.settings import Settings
from backend.tests.test_dns_parse import build_query

LEASES = """
# comment
lease 192.168.40.133 {
	starts 5 2026/09/25 09:10:29;
	hardware ethernet 00:0c:29:eb:4f:d0;
	client-hostname "ishimwe";
}
lease 192.168.40.132 {
	hardware ethernet 00:0C:29:B8:92:AC;
	client-hostname "WIN-NTCEQ0RHVAG";
}
"""


def test_vmware_leases_and_networks(tmp_path, monkeypatch):
    (tmp_path / "vmnetdhcp.leases").write_text(LEASES)
    (tmp_path / "vmnetnat.conf").write_text("[host]\nip = 192.168.40.2/24\nnetmask = 255.255.255.0\ndevice = VMnet8\n")
    monkeypatch.setattr(netinfo, "VMWARE_DATA", tmp_path)

    leases = netinfo.vmware_leases()
    assert leases["192.168.40.133"] == {"mac": "00:0c:29:eb:4f:d0", "hostname": "ishimwe"}
    assert leases["192.168.40.132"]["mac"] == "00:0c:29:b8:92:ac"

    cands = [
        {"alias": "Wi-Fi 3", "description": "Intel Wireless", "ip": "192.168.1.88", "prefix": 24, "gateway": "192.168.1.254"},
        {"alias": "VMware Network Adapter VMnet8", "description": "VMware Virtual Ethernet Adapter for VMnet8",
         "ip": "192.168.40.1", "prefix": 24, "gateway": None, "guid": "{G8}", "index": 11},
        {"alias": "VMware Network Adapter VMnet1", "description": "VMware Virtual Ethernet Adapter for VMnet1",
         "ip": "192.168.119.1", "prefix": 24, "gateway": None, "guid": "{G1}", "index": 13},
    ]
    nets = {n["name"]: n for n in netinfo._vmware_networks(cands)}
    assert nets["VMnet8"]["mode"] == "NAT" and nets["VMnet8"]["service_ips"] == ["192.168.40.2", "192.168.40.254"]
    assert nets["VMnet1"]["mode"] == "Host-only" and nets["VMnet1"]["subnet"] == "192.168.119.0/24"


def _pkt(src, dst, name):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=50000, dport=53) / Raw(build_query(name))


def test_vm_lookups_attributed_to_vm_and_nat_copy_dropped():
    db = Database(":memory:")
    rec = DnsRecorder(db, Settings(db))
    sniffer = DnsSniffer(rec, lambda: None)
    sniffer._net = NetworkInfo(ok=True, ip="192.168.1.88", vm_networks=[
        {"name": "VMnet8", "mode": "NAT", "subnet": "192.168.40.0/24", "host_ip": "192.168.40.1"}])
    sniffer._vm_sniffers = [{"name": "VMnet8", "mode": "NAT", "subnet": "192.168.40.0/24",
                             "sniffer": SimpleNamespace(running=True), "error": None}]

    # VM asks VMware's DNS proxy; VMware NAT then re-sends it from this PC's Wi-Fi IP
    sniffer._on_packet(_pkt("192.168.40.133", "192.168.40.2", "www.rse.rw"), vm=True)
    sniffer._on_packet(_pkt("192.168.1.88", "192.168.1.254", "www.rse.rw"))
    # this PC's own browsing must still be recorded
    sniffer._on_packet(_pkt("192.168.1.88", "192.168.1.254", "www.wikipedia.org"))
    # this PC talking to the VMware proxy itself is not a VM
    sniffer._on_packet(_pkt("192.168.40.1", "192.168.40.2", "example.com"), vm=True)

    sniffer._release_held(force=True)
    rec.flush()
    rows, _ = db.query_activity(ActivityFilter(), group="total", by="base_domain")
    got = {(r["device_ip"], r["domain"], r["requests"]) for r in rows}
    assert got == {("192.168.40.133", "rse.rw", 1), ("192.168.1.88", "wikipedia.org", 1)}


def test_host_lookups_not_delayed_without_vm_capture():
    db = Database(":memory:")
    rec = DnsRecorder(db, Settings(db))
    sniffer = DnsSniffer(rec, lambda: None)
    sniffer._net = NetworkInfo(ok=True, ip="192.168.1.88")
    sniffer._on_packet(_pkt("192.168.1.88", "192.168.1.254", "rse.rw"))
    assert sniffer._held == []
    rec.flush()
    assert db.query_activity(ActivityFilter())[1] == 1


def test_migration_adds_network_column(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT, "
                "friendly_name TEXT, is_self INTEGER NOT NULL DEFAULT 0, is_gateway INTEGER NOT NULL DEFAULT 0, "
                "randomized_mac INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
                "seen_count INTEGER NOT NULL DEFAULT 1)")
    con.execute("INSERT INTO devices(mac, ip, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:ff', '1.2.3.4', 'x', 'x')")
    con.commit()
    con.close()
    db = Database(path)
    db.upsert_device("00:0c:29:eb:4f:d0", "192.168.40.133", "ishimwe", "VMware", False, False, False,
                     "2026-10-07 15:00:00", network="VMware VMnet8 (NAT)")
    assert db.get_device("00:0c:29:eb:4f:d0")["network"] == "VMware VMnet8 (NAT)"
    assert db.get_device("aa:bb:cc:dd:ee:ff")["network"] is None

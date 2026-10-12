import struct

from backend.app.dns_parse import base_domain, parse_query, should_record


def build_query(name: str, qtype: int = 1, flags: int = 0x0100) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, flags, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def test_parse_standard_query():
    assert parse_query(build_query("www.YouTube.com", 1)) == [("www.youtube.com", 1)]


def test_parse_https_record_query():
    assert parse_query(build_query("example.org", 65)) == [("example.org", 65)]


def test_responses_are_ignored():
    assert parse_query(build_query("youtube.com", 1, flags=0x8180)) == []


def test_truncated_and_junk_packets():
    pkt = build_query("youtube.com")
    assert parse_query(pkt[:15]) == []
    assert parse_query(b"") == []
    assert parse_query(b"\x00" * 11) == []


def test_compression_pointer_loop_is_rejected():
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    # pointer to itself at offset 12
    assert parse_query(header + b"\xc0\x0c" + b"\x00\x01\x00\x01") == []


def test_should_record_filters_local_and_reverse_names():
    assert should_record("youtube.com", 1)
    assert not should_record("printer.local", 1)
    assert not should_record("1.1.168.192.in-addr.arpa", 12)
    assert not should_record("wpad", 1)
    assert should_record("wpad", 1, ignore_local=False)
    assert not should_record("bad name!.com", 1)


def test_base_domain_uses_public_suffix_list():
    assert base_domain("r3---sn-abc.googlevideo.com") == "googlevideo.com"
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert base_domain("youtube.com") == "youtube.com"

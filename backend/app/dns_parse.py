"""
Minimal DNS *question* parser.

Only the header and the question section are read: the queried name and type.
Answers, EDNS options and every other byte of the packet are ignored.
"""

from __future__ import annotations

import re

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
               28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

IGNORED_SUFFIXES = (".local", ".arpa", ".lan", ".home", ".localdomain", ".internal",
                    ".localhost", ".invalid", ".test", ".example")
_VALID_NAME = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")


def _read_name(data: bytes, pos: int) -> tuple[str | None, int]:
    labels: list[str] = []
    end = None
    hops = 0
    total = 0
    while True:
        if pos >= len(data):
            return None, pos
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                return None, pos
            if end is None:
                end = pos + 2
            hops += 1
            if hops > 16:
                return None, pos
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            continue
        if length & 0xC0:
            return None, pos  # reserved label types
        pos += 1
        label = data[pos:pos + length]
        if len(label) < length:
            return None, pos
        total += length + 1
        if total > 255:
            return None, pos
        labels.append(label.decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels).lower(), (end if end is not None else pos)


def parse_query(data: bytes) -> list[tuple[str, int]]:
    """Return [(qname, qtype)] for a standard DNS query; [] for responses or junk."""
    if len(data) < 12:
        return []
    flags = int.from_bytes(data[2:4], "big")
    if flags & 0x8000:              # QR=1 -> response
        return []
    if (flags >> 11) & 0xF != 0:    # opcode must be QUERY
        return []
    qdcount = int.from_bytes(data[4:6], "big")
    if qdcount == 0 or qdcount > 4:
        return []
    pos = 12
    out: list[tuple[str, int]] = []
    for _ in range(qdcount):
        name, pos = _read_name(data, pos)
        if name is None or pos + 4 > len(data):
            break
        qtype = int.from_bytes(data[pos:pos + 2], "big")
        pos += 4
        out.append((name, qtype))
    return out


def should_record(name: str, qtype: int, ignore_local: bool = True) -> bool:
    if not name or not _VALID_NAME.match(name):
        return False
    if qtype == 12:  # PTR: reverse lookups, not websites
        return False
    if ignore_local and ("." not in name or name.endswith(IGNORED_SUFFIXES)):
        return False
    return True


def _question_end(data: bytes) -> int | None:
    """Byte offset just past the first question's name+type+class (no compression in questions)."""
    _, pos = _read_name(data, 12)
    if pos is None or pos + 4 > len(data):
        return None
    return pos + 4


def build_block_response(data: bytes, block_ip: str | None) -> bytes | None:
    """Craft a DNS reply that sends a blocked domain to `block_ip` (A records only).

    AAAA / HTTPS / other query types get an empty NOERROR answer, so the client falls back to the
    IPv4 block-page address. With no block_ip, an NXDOMAIN is returned (the site simply fails).
    """
    import socket as _socket

    if len(data) < 12 or int.from_bytes(data[4:6], "big") != 1:
        return None
    qend = _question_end(data)
    if qend is None:
        return None
    qtype = int.from_bytes(data[qend - 4:qend - 2], "big")
    req_flags = int.from_bytes(data[2:4], "big")
    flags = 0x8000 | (req_flags & 0x0100) | 0x0080          # QR=1, copy RD, RA=1
    answer = b""
    ancount = 0
    if qtype == 1 and block_ip:                              # A record -> block page IP
        try:
            answer = (b"\xc0\x0c" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
                      + (5).to_bytes(4, "big") + (4).to_bytes(2, "big") + _socket.inet_aton(block_ip))
            ancount = 1
        except OSError:
            answer, ancount = b"", 0
    if qtype == 1 and not block_ip:
        flags |= 0x0003                                      # NXDOMAIN
    header = data[0:2] + flags.to_bytes(2, "big") + (1).to_bytes(2, "big") + ancount.to_bytes(2, "big") \
        + (0).to_bytes(2, "big") + (0).to_bytes(2, "big")
    return header + data[12:qend] + answer


_extract = None


def base_domain(name: str) -> str:
    """Registrable domain using the bundled Public Suffix List (no network access)."""
    global _extract
    try:
        if _extract is None:
            import tldextract
            _extract = tldextract.TLDExtract(suffix_list_urls=())
        r = _extract(name)
        top = getattr(r, "top_domain_under_public_suffix", None) or r.registered_domain
        if top:
            return top
    except Exception:
        pass
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name

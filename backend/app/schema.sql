-- NetGuard SQLite schema
-- All timestamps are local PC time, "YYYY-MM-DD HH:MM:SS".

PRAGMA journal_mode = WAL;

-- One row per physical device, keyed by MAC address.
CREATE TABLE IF NOT EXISTS devices (
    mac             TEXT PRIMARY KEY,          -- lowercase aa:bb:cc:dd:ee:ff
    ip              TEXT,                      -- last IPv4 seen
    hostname        TEXT,                      -- reverse DNS, when available
    vendor          TEXT,                      -- OUI manufacturer, when available
    friendly_name   TEXT,                      -- set by the administrator
    is_self         INTEGER NOT NULL DEFAULT 0,
    is_gateway      INTEGER NOT NULL DEFAULT 0,
    randomized_mac  INTEGER NOT NULL DEFAULT 0, -- "private Wi-Fi address" (locally administered bit)
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    network         TEXT                       -- 'Wi-Fi <SSID>' or 'VMware VMnet8 (NAT)' etc.
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);

-- One row per scan run.
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    subnet         TEXT,
    method         TEXT,                       -- 'arp' (Npcap) or 'ping+arp-table'
    trigger        TEXT,                       -- 'manual' | 'auto' | 'startup'
    devices_found  INTEGER,
    error          TEXT
);

-- Domain-level DNS activity, aggregated per device / domain / minute.
-- Only the queried name, the requesting IP and the time are stored.
-- No payloads, URLs, cookies, form data or message content are ever recorded.
CREATE TABLE IF NOT EXISTS dns_activity (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip      TEXT NOT NULL,
    device_mac     TEXT,
    domain         TEXT NOT NULL,              -- full queried name, e.g. r3.googlevideo.com
    base_domain    TEXT NOT NULL,              -- registrable domain, e.g. googlevideo.com
    bucket_start   TEXT NOT NULL,              -- minute bucket, "YYYY-MM-DD HH:MM:00"
    first_ts       TEXT NOT NULL,
    last_ts        TEXT NOT NULL,
    request_count  INTEGER NOT NULL DEFAULT 1,
    source         TEXT NOT NULL,              -- 'sniffer' | 'dns_server'
    blocked        INTEGER NOT NULL DEFAULT 0, -- 1 if refused by access control
    UNIQUE (device_ip, domain, bucket_start, source)
);
CREATE INDEX IF NOT EXISTS idx_dns_bucket ON dns_activity(bucket_start);
CREATE INDEX IF NOT EXISTS idx_dns_base   ON dns_activity(base_domain);
CREATE INDEX IF NOT EXISTS idx_dns_device ON dns_activity(device_mac, device_ip);

-- Key/value application settings (JSON-encoded values).
CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

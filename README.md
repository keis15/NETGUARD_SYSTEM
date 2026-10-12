# NetGuard: home Wi-Fi network monitor for Windows

NetGuard runs on your Windows PC and monitors the Wi-Fi network you administer:

- **Device discovery**: IP, MAC, hostname, vendor, online/offline, first and last seen.
- **Domain-level activity**: which domain names each device looks up (DNS), when, and how often.
- **Dashboard, Devices, Network Scan, Website Activity, Reports, Settings** pages in a React UI.

It auto-detects your Wi-Fi interface, local IP, subnet and default gateway. You only type a subnet
if detection fails.

> **Privacy by design.** Only the queried *domain name*, the requesting device's IP and the time are
> stored. NetGuard never captures passwords, messages, cookies, form data, page content or full URLs.
> It never decrypts HTTPS, never intercepts or redirects traffic (no ARP spoofing / MITM), and never
> tries to bypass encryption.

---

## 1. What the app can and cannot see

| Layer | What is visible | Notes |
|---|---|---|
| **Network discovery** | Which devices are connected: IP, MAC, vendor (OUI), hostname | Works for every device on the subnet, using ARP and ping. Shows presence, not activity. |
| **DNS / domain monitoring** | The domain names a device looks up, e.g. `youtube.com` | One page visit triggers several lookups (A, AAAA, HTTPS records, CDNs), so counts are lookups, not page views. Apps and the OS also look up domains in the background. |
| **HTTP URL visibility** | Full URLs only for plain `http://` traffic | This is now rare. NetGuard does **not** record URLs, even for HTTP. |
| **HTTPS traffic** | Only the domain (via DNS, and the TLS SNI that NetGuard does not use) | The path (`/watch?v=...`), query, content, cookies, form data and passwords are encrypted. Nothing is decrypted. |
| **Encrypted DNS (DoH / DoT)** | **Nothing** | DNS-over-HTTPS (Chrome/Edge/Firefox "Secure DNS"), DNS-over-TLS (Android "Private DNS"), iCloud Private Relay and VPNs bypass normal DNS completely. |

### Why the PC cannot see every device's lookups by itself

On Wi-Fi, each device sends its DNS queries **directly to the router**. WPA2/WPA3 encrypt each
client's traffic with its own key, and Windows Wi-Fi drivers do not support monitor mode. Passive
capture on this PC therefore sees **only this PC's own lookups**, plus some broadcast/multicast
traffic. NetGuard will not claim otherwise.

**For network-wide visibility, devices must use this PC as their DNS server.** NetGuard includes an
opt-in DNS forwarder that logs each query name and passes it, unchanged, to your router (or another
upstream resolver). You then point the router's DHCP DNS setting at this PC. See section 6.
Alternatives that don't depend on this PC staying on: Pi-hole, AdGuard Home, or a router with DNS
query logging.

---

## 2. Project structure

```
wifimon/
├── run.py                    # starts the API + serves the built UI (http://127.0.0.1:8600)
├── start.bat                 # double-click launcher (right-click → Run as administrator if needed)
├── requirements.txt          # Python dependencies
├── pytest.ini
├── data/netguard.db           # SQLite database (created on first run)
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app factory, lifespan, SPA static serving
│   │   ├── api.py            # REST endpoints (/api/...)
│   │   ├── state.py          # wires services together + auto-scan scheduler
│   │   ├── schema.sql        # database schema
│   │   ├── db.py             # SQLite access layer + activity queries/filters
│   │   ├── settings.py       # defaults, validation, persistence
│   │   ├── netinfo.py        # auto-detect Wi-Fi interface / IP / subnet / gateway / SSID
│   │   ├── scanner.py        # Npcap ARP + Windows ping sweep discovery, vendor lookup
│   │   ├── dns_parse.py      # minimal DNS question parser + domain normalisation
│   │   ├── dns_monitor.py    # recorder, passive DNS sniffer, DNS forwarder
│   │   └── winutil.py        # admin check, Npcap detection, hidden subprocesses
│   └── tests/                # pytest suite (parser, DB, filters, API, forwarder)
└── frontend/                 # React + Vite + Recharts
    ├── package.json, vite.config.js, index.html
    └── src/
        ├── App.jsx, main.jsx, api.js, hooks.js, format.js, components.jsx, styles.css
        └── pages/  Dashboard, Devices, NetworkScan, WebsiteActivity, Reports, Settings
```

---

## 3. Installation (Windows 10/11)

### Prerequisites

1. **Python 3.10+**: https://www.python.org/downloads/windows/ (tick "Add python.exe to PATH").
2. **Node.js 18+ LTS**: https://nodejs.org/ (only needed to build the UI).
3. **Npcap** (strongly recommended): https://npcap.com/#download
   - Run the installer as Administrator.
   - ✅ Tick **"Install Npcap in WinPcap API-compatible Mode"**.
   - ⬜ Leave **"Restrict Npcap driver's access to Administrators only"** *unticked* if you want to run
     NetGuard as a normal user. If you tick it, you must run NetGuard as Administrator.
   - Without Npcap the app still works: discovery uses the Windows ping sweep and passive DNS capture
     is turned off. The DNS forwarder works without Npcap.

### Install and build

```powershell
cd "C:\Users\pc\Documents\SOLVIT CYBER PROJECT\netmon\wifimon"

# Backend
py -m pip install -r requirements.txt

# Frontend (one-time build; re-run after changing UI code)
cd frontend
npm install
npm run build
cd ..
```

### Run

```powershell
py run.py                 # opens http://127.0.0.1:8600 in your browser
# or double-click start.bat
```

Options: `--port 9000`, `--no-browser`, `--db path\to\file.db`, `--host 0.0.0.0`. The last one exposes the
dashboard to your LAN with **no login**, so it is not recommended.

**UI development** (hot reload): run `py run.py --no-browser` in one terminal and `cd frontend; npm run dev`
in another, then open http://localhost:5173. The Vite dev server proxies `/api` to port 8600.

---

## 4. Windows permissions: exactly what is needed

| Feature | Needs | Why |
|---|---|---|
| Auto-detect network, ping sweep, neighbor table | Standard user | Uses `Get-NetIPConfiguration`, `ping`, `Get-NetNeighbor` |
| Npcap ARP scan + passive DNS capture | Npcap installed and running. Admin **only if** Npcap was installed with "Administrators only" | Raw packet send/capture goes through the Npcap driver |
| DNS forwarder listening on port 53 | Standard user (Windows has no privileged ports) | |
| Allowing other devices to reach port 53 | **Administrator, once**, to add the firewall rule | Windows Firewall blocks inbound connections by default |
| Changing the network profile to Private | Administrator (Windows Settings) | Public profile blocks most inbound traffic |
| Changing router DHCP DNS | Router admin password | Done in the router's web page, not on Windows |

The **Settings → Permissions & setup** panel checks all of these live: admin status, Npcap
installed/running/admin-only/version, capture availability, firewall rule and network profile. It
shows the exact fix for anything missing.

Manual checks:

```powershell
sc query npcap                                    # STATE should be RUNNING
net session >nul 2>&1 && echo ADMIN || echo NOT ADMIN
Get-NetConnectionProfile                          # NetworkCategory: Private
```

---

## 5. How it works

### Network detection (`netinfo.py`)
`Get-NetIPConfiguration` + `Get-NetAdapter` list connected adapters with IPv4 address, prefix,
gateway, MAC and media type. The app picks the **Wi-Fi adapter that has a default gateway**
(media "Native 802.11" or a name containing Wi-Fi/Wireless/WLAN). If none has one, it picks any
adapter that has a gateway. The SSID comes from `netsh wlan show interfaces`. If PowerShell fails,
it falls back to psutil plus `route print`. Subnets larger than 1024 addresses are narrowed to the
PC's /24. Re-detection runs every 60 s, so switching Wi-Fi networks is handled automatically.

### Device discovery (`scanner.py`)
Two methods run **in parallel** and are merged:

1. **Npcap ARP sweep**: broadcast ARP "who-has" for every address in the subnet, sent twice.
2. **Windows ping sweep**: `ping` every address (64 at a time), which makes Windows ARP-resolve each
   one. The scanner then reads `Get-NetNeighbor` and keeps only entries in state **Reachable**, so
   stale cache entries are ignored. Devices that block ping still answer ARP, so they still appear.

The second method matters: many Wi-Fi drivers (including the Intel 7260 on this PC) **silently drop
frames injected through Npcap**, so ARP alone returns nothing on Wi-Fi. The ping sweep uses the
normal Windows network stack and always works.

Hostnames come from reverse DNS/NetBIOS (`gethostbyaddr`). Vendors come from Scapy's bundled IEEE
OUI database, which works offline. MACs with the "locally administered" bit set are flagged
**Private MAC**: phones use these randomized addresses, and they have no vendor.

A device is **online** if it was seen within *offline after* seconds (default 300). The default
scan interval is 120 s.

### Domain monitoring (`dns_monitor.py`, `dns_parse.py`)
- **Passive capture** (Npcap): BPF filter `udp dst port 53 or tcp dst port 53`. Only client
  *queries* are captured. Only the DNS header and question section are parsed.
- **DNS forwarder** (opt-in): UDP and TCP on port 53. It logs the question and relays the raw query
  to the upstream resolver, then returns the answer unmodified. If the upstream refuses DNS over TCP,
  as many home routers do, it relays over UDP instead.
- **Recorder**: filters out local names (`.local`, `.lan`, `.arpa`, single-label names, PTR lookups),
  works out the registrable domain with the bundled Public Suffix List (`i.ytimg.com` → `ytimg.com`),
  and aggregates per **device / domain / minute**. Writes go to SQLite in batches every 2 s. Activity
  older than *retention days* (default 30) is purged automatically.

### VMware virtual machines (Settings → Monitor VMware VMs, on by default)
VMware's virtual networks (VMnet8 = NAT, VMnet1 = host-only) are adapters on this PC, so their
traffic can be captured locally. While a VM is running (`vmware-vmx.exe`), each scan also sweeps
those subnets and names VMs using VMware's DHCP leases (`C:\ProgramData\VMware\vmnetdhcp.leases`).
DNS capture runs on every VMnet adapter, so a VM's lookups are attributed to the VM.

VMware NAT re-sends each VM lookup from this PC's Wi-Fi address. While VMnet capture is active,
this PC's own lookups are held for 2.5 s and dropped if a VM asked for the same name in the same
window. This prevents the VM's browsing from also being counted as "this PC". If the virtual switch
does not show the VM's packets on the host adapter, the lookups still appear, attributed to this PC.
**Bridged** VMs join the Wi-Fi like any other device, so they behave like other Wi-Fi devices.

---

## 6. Network-wide domain visibility (DNS forwarder setup)

1. **Reserve this PC's IP** in the router (DHCP reservation / static lease) so it never changes.
2. **Allow inbound DNS** (Administrator PowerShell):
   ```powershell
   netsh advfirewall firewall add rule name="NetGuard DNS (UDP)" dir=in action=allow protocol=UDP localport=53 profile=private
   netsh advfirewall firewall add rule name="NetGuard DNS (TCP)" dir=in action=allow protocol=TCP localport=53 profile=private
   ```
3. Set the Wi-Fi network profile to **Private** (Settings → Network & internet → Wi-Fi → your network).
4. In NetGuard **Settings**, enable **DNS forwarder**, keep port **53**, and save. Confirm it shows *Running*.
   Optionally set an upstream such as `1.1.1.1`. The default upstream is your router.
5. Test from another device or this PC: `nslookup example.com <this-PC-IP>`. A row should appear in
   Website Activity with source *forwarder*.
6. In the router's **DHCP/LAN settings**, set **Primary DNS = this PC's IP** and leave the secondary
   empty, because devices may otherwise use the secondary and bypass the forwarder.
7. Reconnect devices (toggle Wi-Fi) or wait for their DHCP lease to renew.

⚠️ While this is active, **if the PC is off or asleep, devices cannot resolve names (no internet)**.
Revert step 6 before turning the PC off for long. Some ISP routers don't allow changing the DHCP DNS.
In that case, use a Pi-hole/AdGuard device or set DNS manually on the devices you administer.
Devices using DoH/DoT, Private Relay, VPNs or hard-coded DNS servers will still bypass it.

To undo: restore the router's DHCP DNS, disable the forwarder, and delete the firewall rules:
`netsh advfirewall firewall delete rule name="NetGuard DNS (UDP)"` (and the TCP rule).

---

## 7. Database schema

See [backend/app/schema.sql](backend/app/schema.sql). Tables:

- **devices**: `mac` (PK), `ip`, `hostname`, `vendor`, `friendly_name`, `is_self`, `is_gateway`,
  `randomized_mac`, `first_seen`, `last_seen`, `seen_count`
- **scans**: `id`, `started_at`, `finished_at`, `subnet`, `method`, `trigger`, `devices_found`, `error`
- **dns_activity**: `device_ip`, `device_mac`, `domain`, `base_domain`, `bucket_start` (minute),
  `first_ts`, `last_ts`, `request_count`, `source`. Unique on (device_ip, domain, bucket_start, source).
- **settings**: `key`, `value` (JSON)

Timestamps are local PC time (`YYYY-MM-DD HH:MM:SS`). Inspect the database with any SQLite browser,
or with `py -c "import sqlite3;print(sqlite3.connect('data/netguard.db').execute('select count(*) from dns_activity').fetchone())"`.

## 8. REST API (selection)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/dashboard` | counts, my PC, last scan, 24 h timeline, top domains |
| GET | `/api/devices?status=online&q=` | device list |
| PATCH | `/api/devices/{mac}` `{"friendly_name": "..."}` | rename |
| POST | `/api/scan` | start a scan (409 if one is running) |
| GET | `/api/scan/status`, `/api/scans` | progress, history |
| GET | `/api/activity?device=&q=&domain=&date_from=&date_to=&time_from=&time_to=&group=minute\|hour\|day\|total&by=base_domain\|domain&sort=` | filtered activity |
| GET | `/api/reports/summary?days=7`, `/api/reports/activity.csv`, `/api/reports/devices.csv` | reports, exports |
| GET/PUT | `/api/settings` | read/update settings |
| GET | `/api/system?refresh=true` | permissions, Npcap, network, setup guidance |

Interactive docs: http://127.0.0.1:8600/docs

---

## 9. Tests

```powershell
cd "C:\Users\pc\Documents\SOLVIT CYBER PROJECT\netmon\wifimon"
py -m pytest -q
```

The suite covers the DNS parser (including malformed packets and pointer loops), domain
normalisation, settings validation, device upsert/rename, per-minute aggregation and all activity
filters (including overnight time windows and LIKE escaping), Windows `arp -a` parsing, the API
endpoints, and an end-to-end DNS forwarder test (UDP, plus TCP falling back to UDP) against a fake
upstream. These tests need no admin rights, no internet access and no port 53.

Manual live checks:

```powershell
# network detection + one real scan
py -c "from backend.app.state import AppState; s=AppState(':memory:'); print(s.network().to_dict()); print(s.scanner.scan())"

# with the app running
Invoke-RestMethod http://127.0.0.1:8600/api/system | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post http://127.0.0.1:8600/api/scan
nslookup wikipedia.org          # then check Website Activity: wikipedia.org from "This PC"
```

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| UI says "frontend not built" / blank page | `cd frontend; npm install; npm run build`, then restart `run.py`. |
| "Backend offline" in the sidebar | `run.py` isn't running, or it's on another port. Check the terminal for errors. |
| `Address already in use` on 8600 | Another instance is running. Close it or use `py run.py --port 8601`. |
| Only this PC and the router are found | Normal if nothing else is connected. Phones in deep sleep may miss a scan, so wait for the next one. Guest/isolated Wi-Fi ("AP isolation") hides clients from each other. |
| Scan note: "Npcap ARP got no replies" | Your Wi-Fi driver drops injected frames. Harmless, because results come from the ping sweep. |
| Npcap shows "not installed" or "not running" | Install from npcap.com, or run `sc start npcap` as Administrator, or reboot. |
| "Npcap is restricted to Administrators" | Run `start.bat` as Administrator, or reinstall Npcap without that option. |
| Wrong interface chosen (VPN, Ethernet, Hyper-V) | Settings → Interface name: enter the adapter name from `Get-NetAdapter` (e.g. `Wi-Fi 3`). |
| Subnet wrong / "Network not detected" | Settings → Subnet override, e.g. `192.168.1.0/24`. Make sure Wi-Fi is connected. |
| SSID shows "—" | Windows 11 hides SSIDs from apps when Location services are off. Cosmetic only. |
| Vendor "Unknown" | Not in the OUI database, or a randomized MAC ("Private MAC" badge). |
| Website Activity is empty | Passive capture needs Npcap. Browse a site on this PC, then wait ~5 s. A browser using Secure DNS (DoH) bypasses capture: turn it off in browser settings (edge://settings/privacy → "Use secure DNS") for this PC. |
| Other devices never appear in activity | Expected without the DNS forwarder. Follow section 6. Then check the device's DNS server is this PC (on Windows: `ipconfig /all`). |
| Forwarder: "Cannot listen on 0.0.0.0:53" | Another DNS service holds port 53 (Mobile Hotspot / Internet Connection Sharing, Docker, another DNS server). Find it with `netstat -ano | findstr :53`. |
| Forwarder running but devices fail to resolve | Firewall rule missing or the profile is Public (Settings panel shows both). Or the upstream is unreachable: set upstream to `1.1.1.1`. |
| Lots of `microsoft.com`, `apple.com`, `googleapis.com` | OS and app background lookups. Search or filter by device and domain. |
| Counts look high | One page load makes many lookups (A + AAAA + HTTPS, CDNs). Use "Site" mode and Hour/Day grouping. |
| Reset everything | Stop the app and delete `data\netguard.db`. |

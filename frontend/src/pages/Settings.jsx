import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Callout, ErrorBanner, Icon, Panel, StatusDot, VisibilityExplainer, useToast } from '../components.jsx'
import { usePoll } from '../hooks.js'

export default function Settings() {
  const settings = usePoll(() => api.get('/settings'), 0)
  const sys = usePoll(() => api.get('/system'), 15000)
  const [form, setForm] = useState(null)
  const [saving, setSaving] = useState(false)
  const [toast, showToast] = useToast()

  useEffect(() => { if (settings.data && !form) setForm(settings.data) }, [settings.data, form])

  const dirty = form && settings.data && JSON.stringify(form) !== JSON.stringify(settings.data)
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))
  const num = (k) => (e) => set(k, e.target.value === '' ? '' : Number(e.target.value))
  const txt = (k) => (e) => set(k, e.target.value)
  const chk = (k) => (e) => set(k, e.target.checked)

  async function save() {
    setSaving(true)
    try {
      const changes = Object.fromEntries(Object.entries(form).filter(([k, v]) => settings.data[k] !== v))
      const res = await api.put('/settings', changes)
      settings.setData(res.settings)
      setForm(res.settings)
      showToast('Settings saved')
      sys.reload()
    } catch (e) {
      showToast(e.message)
    } finally {
      setSaving(false)
    }
  }

  async function refreshChecks() {
    await api.get('/system?refresh=true')
    sys.reload()
  }

  async function clearActivity() {
    if (!confirm('Delete ALL recorded website activity? This cannot be undone.')) return
    const r = await api.del('/activity')
    showToast(`Deleted ${r.deleted} rows`)
  }

  const s = sys.data
  return (
    <>
      <ErrorBanner error={settings.error || sys.error} />
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>Scanning, domain monitoring, permissions and privacy.</p>
        </div>
        <div className="actions">
          {dirty && <button onClick={() => setForm(settings.data)}>Discard</button>}
          <button className="primary" disabled={!dirty || saving} onClick={save}>{saving ? 'Saving…' : 'Save changes'}</button>
        </div>
      </div>

      <div className="grid cols-2" style={{ alignItems: 'start' }}>
        <div className="stack">
          {form && (
            <>
              <Panel title="Scanning" flush>
                <Row label="Automatic scanning" hint="Periodically discover devices in the background.">
                  <input type="checkbox" checked={form.auto_scan} onChange={chk('auto_scan')} />
                </Row>
                <Row label="Scan interval (seconds)" hint="30 – 86400. Each scan takes ~10–20 s on a /24 network.">
                  <input type="number" min={30} max={86400} value={form.scan_interval_seconds} onChange={num('scan_interval_seconds')} />
                </Row>
                <Row label="Mark offline after (seconds)" hint="Phones in sleep mode often skip a scan; keep this above 2× the interval.">
                  <input type="number" min={60} max={86400} value={form.offline_after_seconds} onChange={num('offline_after_seconds')} />
                </Row>
                <Row label="Resolve hostnames" hint="Reverse-DNS / NetBIOS name lookup for each device.">
                  <input type="checkbox" checked={form.resolve_hostnames} onChange={chk('resolve_hostnames')} />
                </Row>
              </Panel>

              <Panel title="VMware virtual machines" flush>
                <Row label="Monitor VMware VMs" hint="Discover VMs on VMnet adapters (NAT / host-only) and record their DNS lookups per VM. Bridged VMs appear as normal Wi-Fi devices.">
                  <input type="checkbox" checked={form.monitor_vmware} onChange={chk('monitor_vmware')} />
                </Row>
              </Panel>

              <Panel title="Network detection" sub="leave empty for automatic" flush>
                <Row label="Interface name" hint={`Windows adapter name, e.g. "Wi-Fi". Detected: ${s?.network?.interface || '—'}`}>
                  <input value={form.interface_override} placeholder="auto" onChange={txt('interface_override')} />
                </Row>
                <Row label="Subnet override" hint={`Only if detection is wrong. Detected: ${s?.network?.subnet || '—'}`}>
                  <input value={form.subnet_override} placeholder="auto (e.g. 192.168.1.0/24)" onChange={txt('subnet_override')} />
                </Row>
              </Panel>

              <Panel title="Domain monitoring" flush>
                <Row label="Passive DNS capture" hint="Uses Npcap to record DNS lookups seen by this PC's Wi-Fi adapter (normally only this PC's own).">
                  <input type="checkbox" checked={form.dns_sniffer_enabled} onChange={chk('dns_sniffer_enabled')} />
                </Row>
                <Row label="DNS forwarder (network-wide)" hint="Runs a DNS server on this PC. Requires pointing the router's DHCP DNS setting at this PC — see the setup steps.">
                  <input type="checkbox" checked={form.dns_server_enabled} onChange={chk('dns_server_enabled')} />
                </Row>
                <Row label="Forwarder port" hint="Must be 53 for devices to use it. Other ports are for testing only.">
                  <input type="number" min={1} max={65535} value={form.dns_server_port} onChange={num('dns_server_port')} />
                </Row>
                <Row label="Listen address" hint="0.0.0.0 = all adapters. Use this PC's IP to restrict to Wi-Fi.">
                  <input value={form.dns_server_bind} onChange={txt('dns_server_bind')} />
                </Row>
                <Row label="Upstream DNS server" hint={`Where queries are forwarded. Empty = your router (${s?.network?.gateway || 'gateway'}). Examples: 1.1.1.1, 9.9.9.9`}>
                  <input value={form.dns_upstream} placeholder="router" onChange={txt('dns_upstream')} />
                </Row>
                <Row label="Ignore local names" hint="Skip .local, .lan, .arpa and single-label names (printers, mDNS, reverse lookups).">
                  <input type="checkbox" checked={form.ignore_local_names} onChange={chk('ignore_local_names')} />
                </Row>
              </Panel>

              <Panel title="Data retention" flush>
                <Row label="Keep activity for (days)" hint="Older domain activity is deleted automatically.">
                  <input type="number" min={1} max={3650} value={form.retention_days} onChange={num('retention_days')} />
                </Row>
                <Row label="Delete all activity" hint="Removes every recorded domain lookup. Devices are kept.">
                  <button className="danger" onClick={clearActivity}><Icon name="trash" size={14} /> Clear activity</button>
                </Row>
              </Panel>
            </>
          )}
          <VisibilityExplainer open />
        </div>

        <div className="stack">
          <Panel title="Permissions & setup" actions={<button onClick={refreshChecks}><Icon name="refresh" size={14} /> Re-check</button>}>
            {!s ? <p className="muted">Checking…</p> : (
              <>
                <dl className="kv" style={{ marginBottom: 16 }}>
                  <dt>Administrator</dt><dd><StatusDot state={s.admin ? true : null} label={s.admin ? 'Yes (elevated)' : 'No (standard user)'} /></dd>
                  <dt>Npcap installed</dt><dd><StatusDot state={s.npcap.installed ? true : 'err'} label={s.npcap.installed ? `Yes ${s.npcap.version || ''}` : 'No'} /></dd>
                  <dt>Npcap driver</dt><dd><StatusDot state={s.npcap.running ? true : 'err'} label={s.npcap.running ? 'Running' : 'Not running'} /></dd>
                  <dt>Admin-only mode</dt><dd>{s.npcap.admin_only ? 'Yes' : 'No'}</dd>
                  <dt>Packet capture</dt><dd><StatusDot state={s.capture_ok ? true : 'err'} label={s.capture_ok ? 'Available' : 'Unavailable'} /></dd>
                  {s.dns.dns_server.enabled && <>
                    <dt>Firewall rule</dt><dd><StatusDot state={s.firewall_rule ? true : 'warn'} label={s.firewall_rule ? 'Present' : 'Missing'} /></dd>
                    <dt>Network profile</dt><dd>{s.network_category || '—'}</dd>
                  </>}
                </dl>
                {s.guidance.map((g) => <Callout key={g.title} {...g} />)}
              </>
            )}
          </Panel>

          <Panel title="Network-wide domain visibility: setup">
            <div className="prose">
              <p>To see domains for <strong>every</strong> device (not only this PC), the devices must send their DNS lookups to this PC:</p>
              <ol>
                <li>In your router, create a <strong>DHCP reservation</strong> so this PC always gets <code>{s?.network?.ip || 'the same IP'}</code>.</li>
                <li>Allow inbound DNS in Windows Firewall (Administrator terminal):
                  <div className="callout-action">{'netsh advfirewall firewall add rule name="NetGuard DNS (UDP)" dir=in action=allow protocol=UDP localport=53 profile=private\nnetsh advfirewall firewall add rule name="NetGuard DNS (TCP)" dir=in action=allow protocol=TCP localport=53 profile=private'}</div>
                </li>
                <li>Make sure the Wi-Fi network profile is <strong>Private</strong> (Settings → Network &amp; internet → Wi-Fi).</li>
                <li>Enable <strong>DNS forwarder</strong> above (port 53) and save. Check it shows "Running".</li>
                <li>In the router's DHCP / LAN settings, set <strong>Primary DNS</strong> to this PC's IP. Leave the secondary DNS empty
                  (if a secondary is set, devices may use it and bypass the forwarder). Some ISP routers do not allow changing DHCP DNS.</li>
                <li>Reconnect devices to Wi-Fi (or wait for their DHCP lease to renew).</li>
              </ol>
              <p><strong>Important:</strong> while this is configured, if this PC is off or asleep, devices lose name resolution
                (no internet). Undo step 5 before turning the PC off for long. Devices using encrypted DNS (DoH/DoT, Private Relay)
                or hard-coded DNS servers (e.g. 8.8.8.8) will still bypass it.</p>
              <p>Alternatives: if you run Pi-hole, AdGuard Home or a router with DNS query logging, those logs offer the same
                visibility without depending on this PC.</p>
            </div>
          </Panel>
        </div>
      </div>
      {toast}
    </>
  )
}

function Row({ label, hint, children }) {
  return (
    <div className="form-row">
      <div>
        <div>{label}</div>
        {hint && <div className="hint">{hint}</div>}
      </div>
      <div>{children}</div>
    </div>
  )
}

import { useState } from 'react'
import { api } from '../api.js'
import { Callout, ErrorBanner, Icon, Panel, StatusDot, useToast } from '../components.jsx'
import { fmtDateTime, fmtDuration, timeAgo } from '../format.js'
import { usePoll } from '../hooks.js'

const INTERVALS = [60, 120, 300, 600, 1800, 3600]

export default function NetworkScan() {
  const status = usePoll(() => api.get('/scan/status'), 2000)
  const history = usePoll(() => api.get('/scans?limit=25'), 5000)
  const sys = usePoll(() => api.get('/system'), 0)
  const [redetecting, setRedetecting] = useState(false)
  const [toast, showToast] = useToast()

  const s = status.data
  const net = sys.data?.network

  async function scanNow() {
    try {
      await api.post('/scan')
      status.reload()
    } catch (e) {
      showToast(e.message)
    }
  }

  async function saveSetting(patch) {
    try {
      await api.put('/settings', patch)
      status.reload()
      showToast('Saved')
    } catch (e) {
      showToast(e.message)
    }
  }

  async function redetect() {
    setRedetecting(true)
    try {
      await api.post('/network/redetect')
      await sys.reload()
    } finally {
      setRedetecting(false)
    }
  }

  const last = s?.last_result

  return (
    <>
      <ErrorBanner error={status.error || sys.error} />
      <div className="page-head">
        <div>
          <h1>Network Scan</h1>
          <p>Discovers devices on your local subnet. Only discovery traffic (ARP / ping) is sent.</p>
        </div>
        <div className="actions">
          <button className="primary" onClick={scanNow} disabled={!s || s.running}>
            <Icon name="refresh" size={16} /> {s?.running ? 'Scanning…' : 'Scan Network'}
          </button>
        </div>
      </div>

      <div className="grid cols-2-even" style={{ marginBottom: 16 }}>
        <Panel title="Detected network" actions={
          <button onClick={redetect} disabled={redetecting}><Icon name="refresh" size={14} /> {redetecting ? 'Detecting…' : 'Re-detect'}</button>
        }>
          {!net ? <p className="muted">Detecting…</p> : (
            <>
              <dl className="kv">
                <dt>Wi-Fi (SSID)</dt><dd>{net.ssid || '—'}</dd>
                <dt>Interface</dt><dd>{net.interface} {net.is_wifi ? <span className="badge ok">Wi-Fi</span> : <span className="badge warn">Not Wi-Fi</span>}</dd>
                <dt>Adapter</dt><dd>{net.description || '—'}</dd>
                <dt>Local IP</dt><dd>{net.ip || '—'}</dd>
                <dt>Subnet</dt><dd>{net.subnet || '—'} {net.scan_subnet !== net.subnet && net.scan_subnet && <span className="muted">(scanning {net.scan_subnet})</span>}</dd>
                <dt>Netmask</dt><dd>{net.netmask || '—'}</dd>
                <dt>Gateway</dt><dd>{net.gateway || '—'}</dd>
                <dt>MAC</dt><dd>{net.mac || '—'}</dd>
                <dt>Detected via</dt><dd>{net.method}</dd>
              </dl>
              {net.vm_networks?.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div className="small muted" style={{ marginBottom: 6 }}>VMware virtual networks on this PC (scanned while a VM is running)</div>
                  {net.vm_networks.map((v) => (
                    <div key={v.name} className="row small" style={{ marginBottom: 4 }}>
                      <span className="badge ok">{v.name}</span> <span className="mono">{v.subnet}</span> <span className="muted">{v.mode} · host {v.host_ip}</span>
                    </div>
                  ))}
                </div>
              )}
              {net.error && <div style={{ marginTop: 12 }}><Callout level="error" title="Detection failed" detail={net.error} /></div>}
              {net.warnings?.map((w) => <div key={w} style={{ marginTop: 12 }}><Callout level="warn" title={w} /></div>)}
            </>
          )}
        </Panel>

        <Panel title="Scan status">
          {!s ? <p className="muted">Loading…</p> : (
            <div className="stack">
              {s.running ? (
                <div>
                  <div className="row" style={{ marginBottom: 8 }}><StatusDot state="warn" pulse /> <strong>Scanning</strong> — {s.phase}</div>
                  <div className="progress"><div /></div>
                </div>
              ) : last ? (
                last.error
                  ? <Callout level="error" title="Last scan failed" detail={last.error} />
                  : <Callout level="ok" title={`Last scan found ${last.devices_found} device(s)${last.vm_devices_found ? ` (${last.vm_devices_found} VMware VM)` : ''}`}
                      detail={`${last.subnet} · ${last.method} · ${last.duration_seconds}s · ${timeAgo(last.finished_at)}`} />
              ) : <p className="muted">No scan in this session yet.</p>}
              {last?.warning && <Callout level="warn" title="Note" detail={last.warning} />}

              <div className="row">
                <input type="checkbox" id="auto" checked={s.auto_scan} onChange={(e) => saveSetting({ auto_scan: e.target.checked })} />
                <label htmlFor="auto"><strong>Automatic scanning</strong></label>
                <span className="spacer" />
                <select value={s.interval_seconds} disabled={!s.auto_scan}
                  onChange={(e) => saveSetting({ scan_interval_seconds: Number(e.target.value) })}>
                  {[...new Set([...INTERVALS, s.interval_seconds])].sort((a, b) => a - b).map((v) => (
                    <option key={v} value={v}>every {fmtDuration(v)}</option>
                  ))}
                </select>
              </div>
              {s.auto_scan && s.next_auto_scan_in != null && !s.running && (
                <div className="small muted">Next automatic scan in about {fmtDuration(s.next_auto_scan_in)}.</div>
              )}
              <div className="small muted">
                Method: {s.capture_ok
                  ? 'Npcap ARP sweep + Windows ping sweep (merged).'
                  : 'Windows ping sweep + neighbor table (Npcap unavailable — see Settings).'}
                {' '}Devices are marked offline when they have not answered for a while (Settings → offline after).
              </div>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Scan history" flush>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>Started</th><th>Trigger</th><th>Subnet</th><th>Method</th><th className="num">Devices</th><th>Duration</th><th>Result</th></tr>
            </thead>
            <tbody>
              {(history.data || []).map((h) => {
                const dur = h.finished_at ? (new Date(h.finished_at.replace(' ', 'T')) - new Date(h.started_at.replace(' ', 'T'))) / 1000 : null
                return (
                  <tr key={h.id}>
                    <td className="muted">{h.id}</td>
                    <td>{fmtDateTime(h.started_at)}</td>
                    <td><span className="badge">{h.trigger}</span></td>
                    <td className="mono">{h.subnet}</td>
                    <td>{h.method}</td>
                    <td className="num">{h.devices_found ?? '—'}</td>
                    <td>{dur == null ? <span className="muted">running</span> : `${Math.round(dur)}s`}</td>
                    <td className="wrap small">
                      {!h.finished_at ? <StatusDot state="warn" pulse label="Running" />
                        : h.devices_found == null ? <span style={{ color: 'var(--err)' }}>{h.error}</span>
                        : h.error ? <span style={{ color: 'var(--warn)' }}>{h.error}</span>
                        : <StatusDot state label="OK" />}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {history.data && !history.data.length && <div className="empty">No scans yet.</div>}
        </div>
      </Panel>
      {toast}
    </>
  )
}

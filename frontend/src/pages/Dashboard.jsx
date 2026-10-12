import { Link } from 'react-router-dom'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api.js'
import { ChartTip, ErrorBanner, Icon, Panel, StatCard, StatusDot } from '../components.jsx'
import { fmtNum, timeAgo } from '../format.js'
import { usePoll } from '../hooks.js'

export default function Dashboard() {
  const { data: d, error, reload } = usePoll(() => api.get('/dashboard'), 10000)

  async function scanNow() {
    try { await api.post('/scan') } catch { /* already running */ }
    setTimeout(reload, 1500)
  }

  if (!d) return <><ErrorBanner error={error} />{!error && <p className="muted">Loading…</p>}</>
  const { counts, my_pc: me, network: net, dns, activity_24h: act, last_scan: last } = d
  const scanning = d.scan?.running

  return (
    <>
      <ErrorBanner error={error} />
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p>{net.ssid ? <>Wi-Fi <strong>{net.ssid}</strong> · </> : null}{net.scan_subnet || 'Network not detected'}</p>
        </div>
        <div className="actions">
          <button className="primary" onClick={scanNow} disabled={scanning}>
            <Icon name="refresh" size={16} /> {scanning ? 'Scanning…' : 'Scan Network'}
          </button>
        </div>
      </div>

      <div className="grid stats">
        <StatCard label="Total devices" icon="devices" tone="accent" value={fmtNum(counts.total)}
          sub={counts.new_24h ? `${counts.new_24h} new in last 24h` : 'Known on this network'} />
        <StatCard label="Online now" icon="wifi" tone="ok" value={fmtNum(counts.online)}
          sub={`${counts.offline} offline`} />
        <StatCard label="My PC" icon="shield" tone="info" small value={me ? me.label : '—'}
          sub={me ? `${me.ip} · ${me.mac}` : 'Not scanned yet'} />
        <StatCard label="Other devices" icon="devices" tone="warn" value={fmtNum(counts.others)}
          sub={`${counts.others_online} online${counts.vms ? ` · ${counts.vms_online}/${counts.vms} VMs` : ''}`} />
        <StatCard label="Last scan" icon="scan" small value={last ? timeAgo(last.finished_at) : 'Never'}
          sub={last ? `${last.devices_found ?? 0} found · ${last.method}` : scanning ? 'Scanning now…' : ''} />
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="DNS lookups" sub={`last 24 hours · ${fmtNum(act.totals.requests)} total`}>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={act.timeline} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
              <defs>
                <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.45} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="label" tickLine={false} axisLine={false} interval={2} />
              <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip content={<ChartTip />} />
              <Area isAnimationActive={false} type="monotone" dataKey="requests" name="lookups" stroke="#22d3ee" strokeWidth={2} fill="url(#g1)" />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>
        <Panel title="Top domains" sub="last 24 hours" actions={<Link to="/activity" className="small">View all</Link>}>
          {act.top_domains.length ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={act.top_domains} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="domain" width={130} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar isAnimationActive={false} dataKey="requests" name="lookups" fill="#22d3ee" radius={[0, 4, 4, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="empty">No domain activity yet.</div>}
        </Panel>
      </div>

      <div className="grid cols-3">
        <Panel title="Network">
          <dl className="kv">
            <dt>Wi-Fi (SSID)</dt><dd>{net.ssid || '—'}</dd>
            <dt>Interface</dt><dd>{net.interface || '—'}</dd>
            <dt>This PC</dt><dd>{net.ip || '—'}</dd>
            <dt>Subnet</dt><dd>{net.scan_subnet || '—'}</dd>
            <dt>Gateway</dt><dd>{net.gateway || '—'}</dd>
          </dl>
          {net.warnings?.map((w) => <p key={w} className="small" style={{ color: 'var(--warn)', marginBottom: 0 }}>{w}</p>)}
        </Panel>
        <Panel title="Domain monitoring" actions={<Link to="/settings" className="small">Configure</Link>}>
          <div className="stack" style={{ gap: 12 }}>
            <MonitorRow name="Passive DNS capture" m={dns.sniffer} note="This PC's own lookups" />
            {dns.sniffer.vm_interfaces?.map((v) => (
              <MonitorRow key={v.name} name={`VMware ${v.name}`} m={{ ...v, enabled: true }}
                note={`VMs on ${v.subnet} (${v.mode})`} />
            ))}
            <MonitorRow name="DNS forwarder" m={dns.dns_server}
              note={dns.dns_server.running ? `Listening on port ${dns.dns_server.port} → ${dns.dns_server.upstream}` : 'Network-wide visibility (opt-in)'} />
            <div className="small muted">
              {fmtNum(act.totals.domains)} domains from {fmtNum(act.totals.devices)} device(s) in the last 24h.
            </div>
          </div>
        </Panel>
        <Panel title="Recently discovered" flush>
          {d.recent_devices.length ? (
            <table>
              <tbody>
                {d.recent_devices.map((x) => (
                  <tr key={x.mac}>
                    <td><StatusDot state={x.online} /></td>
                    <td>{x.label}<div className="small muted mono">{x.ip}</div></td>
                    <td className="num small muted">{timeAgo(x.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <div className="empty">Run a scan to discover devices.</div>}
        </Panel>
      </div>
    </>
  )
}

function MonitorRow({ name, m, note }) {
  const state = m.running ? true : m.error ? 'err' : m.enabled ? 'warn' : null
  const label = m.running ? 'Running' : m.error ? 'Error' : m.enabled ? 'Starting' : 'Off'
  return (
    <div>
      <div className="row">
        <StatusDot state={state} />
        <strong>{name}</strong>
        <span className="spacer" />
        <span className={`badge ${m.running ? 'ok' : m.error ? 'err' : ''}`}>{label}</span>
      </div>
      <div className="small muted" style={{ marginLeft: 17 }}>{m.error || note}</div>
    </div>
  )
}

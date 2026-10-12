import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, qs } from '../api.js'
import { ErrorBanner, Icon, Panel, SearchBox, Segmented, StatusDot, VisibilityExplainer } from '../components.jsx'
import { fmtNum } from '../format.js'
import { useDebounced, usePoll } from '../hooks.js'

const PAGE = 50
const EMPTY = { device: '', q: '', date_from: '', date_to: '', time_from: '', time_to: '', blocked: '' }

export default function WebsiteActivity() {
  const [params, setParams] = useSearchParams()
  const [f, setF] = useState(() => ({ ...EMPTY, ...Object.fromEntries([...params].filter(([k]) => k in EMPTY)) }))
  const [group, setGroup] = useState('minute')
  const [by, setBy] = useState('base_domain')
  const [sort, setSort] = useState('recent')
  const [page, setPage] = useState(0)
  const q = useDebounced(f.q, 300)

  const filters = { ...f, q }
  const query = qs({ ...filters, group, by, sort, limit: PAGE, offset: page * PAGE })
  const { data, error } = usePoll(() => api.get(`/activity${query}`), 10000, [query])
  const devices = usePoll(() => api.get('/activity/devices'), 30000)
  const sys = usePoll(() => api.get('/dns/status'), 15000)

  // keep the URL in sync so filtered views can be bookmarked / linked from the Devices page
  useEffect(() => {
    setParams(Object.fromEntries(Object.entries(filters).filter(([, v]) => v)), { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [f.device, q, f.date_from, f.date_to, f.time_from, f.time_to])

  const set = (k) => (v) => { setF((x) => ({ ...x, [k]: v })); setPage(0) }
  const onInput = (k) => (e) => set(k)(e.target.value)
  const active = Object.values(f).some(Boolean)
  const total = data?.total ?? 0
  const dns = sys.data
  const onlySelf = dns && !dns.dns_server.running

  return (
    <>
      <ErrorBanner error={error} />
      <div className="page-head">
        <div>
          <h1>Website Activity</h1>
          <p>Domain names looked up by devices on your network (DNS). Not full URLs, not page content.</p>
        </div>
        <div className="actions">
          <a className="btn" href={`/api/reports/activity.csv${qs({ ...filters, group, by })}`}><Icon name="download" size={16} /> Export CSV</a>
        </div>
      </div>

      {dns && (
        <div className="panel" style={{ padding: '12px 16px', marginBottom: 16, display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center' }}>
          <StatusDot state={dns.sniffer.running ? true : dns.sniffer.error ? 'err' : null}
            label={<>Passive capture: <strong>{dns.sniffer.running ? 'on' : 'off'}</strong></>} />
          <StatusDot state={dns.dns_server.running ? true : dns.dns_server.error ? 'err' : null}
            label={<>DNS forwarder: <strong>{dns.dns_server.running ? `on (port ${dns.dns_server.port})` : 'off'}</strong></>} />
          {dns.sniffer.vm_interfaces?.length > 0 && (
            <StatusDot state={dns.sniffer.vm_interfaces.some((v) => v.running) ? true : 'err'}
              label={<>VMware capture: <strong>{dns.sniffer.vm_interfaces.filter((v) => v.running).map((v) => v.name).join(', ') || 'off'}</strong></>} />
          )}
          {onlySelf && (
            <span className="small" style={{ color: 'var(--warn)' }}>
              Visible: this PC{dns.sniffer.vm_interfaces?.some((v) => v.running) ? ' and its VMware VMs (NAT / host-only)' : ''}. <Link to="/settings">Enable the DNS forwarder</Link> for other Wi-Fi devices.
            </span>
          )}
        </div>
      )}

      <div style={{ marginBottom: 16 }}><VisibilityExplainer /></div>

      <Panel flush>
        <div className="filters">
          <div className="field grow">
            <span className="label">Search domains</span>
            <SearchBox value={f.q} onChange={set('q')} placeholder="e.g. youtube, tiktok.com, netflix" />
          </div>
          <div className="field">
            <label htmlFor="dev">Device</label>
            <select id="dev" value={f.device} onChange={onInput('device')}>
              <option value="">All devices</option>
              {(devices.data || []).map((d) => (
                <option key={d.device_key} value={d.device_key}>{d.device_label} ({d.device_ip}){(d.network || '').startsWith('VMware') ? ' — VM' : ''}</option>
              ))}
              {f.device && !(devices.data || []).some((d) => d.device_key === f.device) && <option value={f.device}>{f.device}</option>}
            </select>
          </div>
          <div className="field"><label htmlFor="df">From date</label><input id="df" type="date" value={f.date_from} onChange={onInput('date_from')} /></div>
          <div className="field"><label htmlFor="dt">To date</label><input id="dt" type="date" value={f.date_to} onChange={onInput('date_to')} /></div>
          <div className="field"><label htmlFor="tf">From time</label><input id="tf" type="time" value={f.time_from} onChange={onInput('time_from')} /></div>
          <div className="field"><label htmlFor="tt">To time</label><input id="tt" type="time" value={f.time_to} onChange={onInput('time_to')} /></div>
          <div className="field">
            <label htmlFor="blk">Show</label>
            <select id="blk" value={f.blocked} onChange={onInput('blocked')}>
              <option value="">All</option>
              <option value="true">Blocked only</option>
              <option value="false">Allowed only</option>
            </select>
          </div>
          {active && <button className="ghost" onClick={() => { setF(EMPTY); setPage(0) }}>Clear filters</button>}
        </div>
        <div className="filters" style={{ paddingTop: 10, paddingBottom: 10 }}>
          <div className="field"><span className="label">Group by time</span>
            <Segmented value={group} onChange={(v) => { setGroup(v); setPage(0) }}
              options={[['minute', 'Minute'], ['hour', 'Hour'], ['day', 'Day'], ['total', 'Whole range']]} /></div>
          <div className="field"><span className="label">Domain</span>
            <Segmented value={by} onChange={(v) => { setBy(v); setPage(0) }}
              options={[['base_domain', 'Site (youtube.com)'], ['domain', 'Full name (i.ytimg.com)']]} /></div>
          <div className="field"><span className="label">Sort</span>
            <select value={sort} onChange={(e) => { setSort(e.target.value); setPage(0) }}>
              <option value="recent">Most recent</option>
              <option value="requests">Most requests</option>
              <option value="domain">Domain A–Z</option>
              <option value="device">Device A–Z</option>
            </select></div>
          <span className="spacer" />
          {data && (
            <div className="small text-2">
              {fmtNum(data.totals.requests)} lookups · {fmtNum(data.totals.domains)} sites · {fmtNum(data.totals.devices)} devices
            </div>
          )}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Device</th><th>Domain</th><th>Date</th><th>Time</th><th className="num">Requests</th><th>Source</th></tr>
            </thead>
            <tbody>
              {(data?.rows || []).map((r) => {
                const [date, time] = group === 'total'
                  ? [r.first_seen.slice(0, 10) === r.last_seen.slice(0, 10) ? r.first_seen.slice(0, 10) : `${r.first_seen.slice(0, 10)} → ${r.last_seen.slice(0, 10)}`,
                     `${r.first_seen.slice(11, 16)} – ${r.last_seen.slice(11, 16)}`]
                  : group === 'day' ? [r.period, `${r.first_seen.slice(11, 16)} – ${r.last_seen.slice(11, 16)}`]
                  : [r.period.slice(0, 10), r.period.slice(11, 16)]
                return (
                  <tr key={`${r.device_key}|${r.domain}|${r.period}`}>
                    <td>
                      <button className="ghost" style={{ padding: 0, color: 'var(--text)' }} title="Filter by this device"
                        onClick={() => set('device')(r.device_key)}>
                        <strong>{r.device_label}</strong>
                      </button>
                      {r.is_self ? <span className="badge accent" style={{ marginLeft: 6 }}>This PC</span> : null}
                      {(r.network || '').startsWith('VMware') ? <span className="badge ok" style={{ marginLeft: 6 }} title={r.network}>VM</span> : null}
                      <div className="small muted mono">{r.device_ip}</div>
                    </td>
                    <td className="mono">
                      <button className="ghost mono" style={{ padding: 0, color: r.blocked ? 'var(--err)' : 'var(--accent)' }} title="Search this domain"
                        onClick={() => set('q')(r.domain)}>{r.domain}</button>
                      {r.blocked ? <span className="badge err" style={{ marginLeft: 6 }} title="Blocked by Access Control">Blocked</span> : null}
                    </td>
                    <td className="nowrap">{date}</td>
                    <td className="nowrap">{time}</td>
                    <td className="num"><strong>{fmtNum(r.requests)}</strong></td>
                    <td>{(r.sources || '').split(',').map((s) => (
                      <span key={s} className={`badge ${s === 'dns_server' ? 'info' : ''}`} style={{ marginRight: 4 }}>
                        {s === 'dns_server' ? 'forwarder' : 'capture'}
                      </span>
                    ))}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {data && !data.rows.length && (
            <div className="empty">
              {active ? 'No activity matches these filters.' : 'No domain activity recorded yet. Browse a site on this PC, or enable the DNS forwarder for other devices.'}
            </div>
          )}
        </div>
        {total > PAGE && (
          <div className="pager">
            <span>Rows {page * PAGE + 1}–{Math.min(total, (page + 1) * PAGE)} of {fmtNum(total)}</span>
            <div className="actions">
              <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Previous</button>
              <button disabled={(page + 1) * PAGE >= total} onClick={() => setPage((p) => p + 1)}>Next</button>
            </div>
          </div>
        )}
      </Panel>
      <p className="small muted" style={{ marginTop: 12 }}>
        <Icon name="lock" size={13} style={{ verticalAlign: '-2px' }} /> Privacy: only the queried domain name, the requesting device's IP and the time are stored.
        Passwords, messages, cookies, form data, page content and full URLs are never captured, and HTTPS is never decrypted.
      </p>
    </>
  )
}

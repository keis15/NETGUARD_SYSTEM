import { useState } from 'react'

const PATHS = {
  dashboard: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
  devices: 'M4 6h16v10H4zM2 18h20v2H2z',
  scan: 'M12 2a10 10 0 1 0 10 10h-2a8 8 0 1 1-8-8V2zm0 4a6 6 0 1 0 6 6h-2a4 4 0 1 1-4-4V6zm0 4a2 2 0 1 0 2 2h-2v-2z',
  activity: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm6.9 6h-2.9a15.7 15.7 0 0 0-1.4-3.6A8 8 0 0 1 18.9 8zM12 4c.8 1.2 1.5 2.5 1.9 4h-3.8c.4-1.5 1.1-2.8 1.9-4zM4.3 14a8.2 8.2 0 0 1 0-4h3.4a16.5 16.5 0 0 0 0 4H4.3zm.8 2h3a15.7 15.7 0 0 0 1.3 3.6A8 8 0 0 1 5.1 16zM8 8H5.1a8 8 0 0 1 4.3-3.6C8.8 5.5 8.4 6.7 8 8zm4 12c-.8-1.2-1.5-2.5-1.9-4h3.8c-.4 1.5-1.1 2.8-1.9 4zm2.3-6H9.7a14.7 14.7 0 0 1 0-4h4.6a14.7 14.7 0 0 1 0 4zm.3 5.6c.6-1.1 1.1-2.3 1.4-3.6h2.9a8 8 0 0 1-4.3 3.6zm1.7-5.6a16.5 16.5 0 0 0 0-4h3.4a8.2 8.2 0 0 1 0 4h-3.4z',
  reports: 'M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm2 14h2v-6H7v6zm4 0h2V7h-2v10zm4 0h2v-4h-2v4z',
  settings: 'M19.4 13a7.6 7.6 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7.4 7.4 0 0 0-1.7-1L15 3.3h-4l-.4 2.6a7.4 7.4 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11a7.6 7.6 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1c.5.4 1.1.7 1.7 1l.4 2.6h4l.4-2.6c.6-.3 1.2-.6 1.7-1l2.5 1 2-3.5-2.1-1.6zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z',
  wifi: 'M12 18a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-5.7-3.3 1.4 1.4a6 6 0 0 1 8.5 0l1.4-1.4a8 8 0 0 0-11.3 0zM2.1 10.5l1.4 1.4a12 12 0 0 1 17 0l1.4-1.4a14 14 0 0 0-19.8 0z',
  search: 'M10 2a8 8 0 1 0 4.9 14.3l5.4 5.4 1.4-1.4-5.4-5.4A8 8 0 0 0 10 2zm0 2a6 6 0 1 1 0 12 6 6 0 0 1 0-12z',
  check: 'M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z',
  warn: 'M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z',
  error: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z',
  info: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z',
  refresh: 'M17.6 6.4A8 8 0 1 0 19.7 14h-2.1A6 6 0 1 1 12 6c1.7 0 3.1.7 4.2 1.8L13 11h7V4l-2.4 2.4z',
  download: 'M5 20h14v-2H5v2zM19 9h-4V3H9v6H5l7 7 7-7z',
  edit: 'M3 17.2V21h3.8l11-11-3.8-3.8-11 11zM20.7 7a1 1 0 0 0 0-1.4l-2.3-2.3a1 1 0 0 0-1.4 0l-1.8 1.8 3.8 3.8L20.7 7z',
  trash: 'M6 19a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z',
  shield: 'M12 1 3 5v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V5l-9-4z',
  lock: 'M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3.1-9H8.9V6a3.1 3.1 0 0 1 6.2 0v2z',
}

export function Icon({ name, size = 18, ...rest }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
      <path d={PATHS[name]} />
    </svg>
  )
}

export function Panel({ title, sub, actions, children, flush, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <div className="panel-head">
          <h2>{title}{sub && <span className="sub">{sub}</span>}</h2>
          {actions && <div className="actions">{actions}</div>}
        </div>
      )}
      <div className={`panel-body ${flush ? 'flush' : ''}`}>{children}</div>
    </section>
  )
}

export function StatCard({ label, value, sub, tone = '', icon, small }) {
  return (
    <div className={`panel stat tone-${tone}`}>
      <div className="stat-label">{icon && <Icon name={icon} size={15} />}{label}</div>
      <div className={`stat-value ${small ? 'small' : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export function StatusDot({ state, label, pulse }) {
  const cls = state === true || state === 'ok' ? 'on' : state === 'warn' ? 'warn' : state === 'err' ? 'err' : ''
  return (
    <span className="status">
      <span className={`dot ${cls} ${pulse ? 'pulse' : ''}`} />
      {label}
    </span>
  )
}

export function Callout({ level = 'info', title, detail, action }) {
  const icon = { ok: 'check', warn: 'warn', error: 'error', info: 'info' }[level] || 'info'
  return (
    <div className={`callout ${level}`}>
      <Icon name={icon} className="icon" />
      <div>
        <div className="callout-title">{title}</div>
        {detail && <div className="callout-detail">{detail}</div>}
        {action && <div className="callout-action">{action}</div>}
      </div>
    </div>
  )
}

export function Segmented({ value, options, onChange }) {
  return (
    <div className="segmented" role="group">
      {options.map(([v, label]) => (
        <button key={v} type="button" className={v === value ? 'on' : ''} onClick={() => onChange(v)}>{label}</button>
      ))}
    </div>
  )
}

export function SearchBox({ value, onChange, placeholder }) {
  return (
    <div className="search">
      <Icon name="search" size={15} />
      <input type="search" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
    </div>
  )
}

export function ErrorBanner({ error }) {
  return error ? <div className="error-banner">Backend error: {error}</div> : null
}

export function ChartTip({ active, payload, label, unit = 'lookups' }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tip">
      <div className="t">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey}><strong>{(p.value ?? 0).toLocaleString()}</strong> {p.name || unit}</div>
      ))}
    </div>
  )
}

export function useToast() {
  const [msg, setMsg] = useState(null)
  const show = (m) => {
    setMsg(m)
    setTimeout(() => setMsg(null), 3000)
  }
  const node = msg ? <div className="toast">{msg}</div> : null
  return [node, show]
}

// What the app can and cannot see. Shown on the Website Activity and Settings pages.
export function VisibilityExplainer({ open = false }) {
  return (
    <details className="panel explain" open={open}>
      <summary><Icon name="info" /> What this app can and cannot see</summary>
      <div className="panel-body flush">
        <div className="table-wrap">
          <table className="vis-table">
            <tbody>
              <tr>
                <td>Network discovery</td>
                <td>Which devices are connected (IP, MAC, vendor, hostname). Works for every device on your
                  subnet using ARP/ping. It reveals presence only, never activity.</td>
              </tr>
              <tr>
                <td>DNS / domain monitoring</td>
                <td>The <strong>domain names</strong> a device looks up (e.g. <code>youtube.com</code>), when, and how
                  often. One page visit usually triggers several lookups (A, AAAA, HTTPS records, CDNs), so counts
                  are lookups, not page views. Apps and the OS also make background lookups.</td>
              </tr>
              <tr>
                <td>HTTP URL visibility</td>
                <td>Full URLs are only readable for unencrypted <code>http://</code> traffic, which is now rare. This app does
                  <strong> not</strong> record URLs, even for HTTP.</td>
              </tr>
              <tr>
                <td>HTTPS traffic</td>
                <td>HTTPS encrypts the path, query string, page content, cookies, form data and passwords. Only the
                  domain is visible to the network. This app does not decrypt or intercept HTTPS in any way.</td>
              </tr>
              <tr>
                <td>Encrypted DNS (DoH / DoT)</td>
                <td>Browsers and phones using DNS-over-HTTPS (Chrome/Edge/Firefox "Secure DNS") or DNS-over-TLS (Android
                  "Private DNS", iCloud Private Relay) bypass normal DNS. Those lookups are <strong>invisible</strong> here.</td>
              </tr>
              <tr>
                <td>Passive capture on Wi-Fi</td>
                <td>On a normal Wi-Fi network this PC only sees its <strong>own</strong> DNS traffic. Other devices talk
                  directly to the router, and WPA2/WPA3 encrypt each client with its own key. To see every device's domains,
                  enable the DNS forwarder in Settings and set your router's DHCP DNS server to this PC's IP.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </details>
  )
}

import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, qs } from '../api.js'
import { ChartTip, ErrorBanner, Icon, Panel, Segmented, StatCard } from '../components.jsx'
import { fmtDateTime, fmtNum } from '../format.js'
import { usePoll } from '../hooks.js'

export default function Reports() {
  const [days, setDays] = useState(7)
  const { data: r, error } = usePoll(() => api.get(`/reports/summary?days=${days}`), 60000, [days])
  const since = r?.since?.slice(0, 10)

  return (
    <>
      <ErrorBanner error={error} />
      <div className="page-head">
        <div>
          <h1>Reports</h1>
          <p>{r ? `Since ${since}` : 'Loading…'}</p>
        </div>
        <div className="actions">
          <Segmented value={days} onChange={setDays} options={[[1, 'Today'], [7, '7 days'], [30, '30 days'], [90, '90 days']]} />
          <a className="btn" href={`/api/reports/activity.csv${qs({ date_from: since, group: 'day' })}`}><Icon name="download" size={16} /> Activity CSV</a>
          <a className="btn" href="/api/reports/devices.csv"><Icon name="download" size={16} /> Devices CSV</a>
        </div>
      </div>

      {r && (
        <>
          <div className="grid stats">
            <StatCard label="DNS lookups" tone="accent" value={fmtNum(r.totals.requests)} />
            <StatCard label="Unique sites" tone="info" value={fmtNum(r.totals.domains)} />
            <StatCard label="Active devices" tone="ok" value={fmtNum(r.totals.devices)} sub="with domain activity" />
            <StatCard label="Known devices" value={fmtNum(r.devices.total)} sub={`${r.devices.online} online now`} />
            <StatCard label="New devices" tone="warn" value={fmtNum(r.devices.new)} sub="first seen in period" />
          </div>

          <div className="grid cols-2-even" style={{ marginBottom: 16 }}>
            <Panel title="Lookups per day">
              <ResponsiveContainer width="100%" height={240}>
                <LineChart data={r.daily} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="t" tickFormatter={(t) => t.slice(5)} tickLine={false} axisLine={false} minTickGap={16} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip content={<ChartTip />} />
                  <Line isAnimationActive={false} type="monotone" dataKey="requests" name="lookups" stroke="#22d3ee" strokeWidth={2} dot={r.daily.length <= 31} />
                </LineChart>
              </ResponsiveContainer>
            </Panel>
            <Panel title="Activity by hour of day">
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={r.hour_of_day} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="hour" tickLine={false} axisLine={false} interval={2} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip content={<ChartTip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} labelFormatter={(h) => `${h}:00–${h}:59`} />
                  <Bar isAnimationActive={false} dataKey="requests" name="lookups" fill="#818cf8" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          </div>

          <div className="grid cols-2-even" style={{ marginBottom: 16 }}>
            <Panel title="Top sites" flush>
              <RankTable rows={r.top_domains} cols={[['domain', 'Site', 'mono'], ['devices', 'Devices', 'num'], ['requests', 'Lookups', 'num']]} />
            </Panel>
            <Panel title="Most active devices" flush>
              <RankTable rows={r.top_devices} cols={[['device_label', 'Device'], ['device_ip', 'IP', 'mono'], ['domains', 'Sites', 'num'], ['requests', 'Lookups', 'num']]} />
            </Panel>
          </div>

          <div className="grid cols-2-even">
            <Panel title="Device manufacturers" flush>
              <RankTable rows={r.vendors} cols={[['vendor', 'Vendor'], ['count', 'Devices', 'num']]} bar="count" />
            </Panel>
            <Panel title="Recent scans" flush>
              <RankTable rows={r.scans.map((s) => ({ ...s, started_at: fmtDateTime(s.started_at) }))}
                cols={[['started_at', 'Started'], ['trigger', 'Trigger'], ['method', 'Method'], ['devices_found', 'Found', 'num']]} />
            </Panel>
          </div>
        </>
      )}
    </>
  )
}

function RankTable({ rows, cols, bar = 'requests' }) {
  if (!rows?.length) return <div className="empty">No data for this period.</div>
  const max = Math.max(...rows.map((x) => x[bar] || 0), 1)
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{cols.map(([k, label, cls]) => <th key={k} className={cls === 'num' ? 'num' : ''}>{label}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {cols.map(([k, , cls]) => (
                <td key={k} className={cls || ''} style={k === bar ? {
                  background: `linear-gradient(to left, rgba(34,211,238,0.14) ${(row[k] / max) * 100}%, transparent 0)`,
                } : undefined}>
                  {typeof row[k] === 'number' ? fmtNum(row[k]) : row[k] ?? '—'}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

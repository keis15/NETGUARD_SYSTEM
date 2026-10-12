import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { ErrorBanner, Icon, Panel, SearchBox, Segmented, StatusDot, useToast } from '../components.jsx'
import { fmtDateTime, timeAgo } from '../format.js'
import { usePoll } from '../hooks.js'

const ipNum = (ip) => (ip || '').split('.').reduce((a, b) => a * 256 + Number(b), 0)

const COLUMNS = [
  ['online', 'Status'], ['label', 'Name'], ['ip', 'IP address'], ['mac', 'MAC address'],
  ['hostname', 'Hostname'], ['vendor', 'Vendor'], ['network', 'Network'], ['first_seen', 'First seen'], ['last_seen', 'Last seen'],
]

export default function Devices() {
  const { data, error, reload, setData } = usePoll(() => api.get('/devices'), 10000)
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('all')
  const [kind, setKind] = useState('all')
  const [sort, setSort] = useState(['ip', 1])
  const [editing, setEditing] = useState(null)
  const [name, setName] = useState('')
  const [toast, showToast] = useToast()

  const rows = useMemo(() => {
    let r = data || []
    if (status !== 'all') r = r.filter((d) => d.online === (status === 'online'))
    if (kind !== 'all') r = r.filter((d) => d.is_vm === (kind === 'vm'))
    if (q) {
      const ql = q.toLowerCase()
      r = r.filter((d) => ['label', 'ip', 'mac', 'hostname', 'vendor', 'network'].some((k) => String(d[k] || '').toLowerCase().includes(ql)))
    }
    const [key, dir] = sort
    return [...r].sort((a, b) => {
      const va = key === 'ip' ? ipNum(a.ip) : a[key] ?? ''
      const vb = key === 'ip' ? ipNum(b.ip) : b[key] ?? ''
      return (va > vb ? 1 : va < vb ? -1 : 0) * dir
    })
  }, [data, q, status, kind, sort])

  const online = (data || []).filter((d) => d.online).length

  function startEdit(d) {
    setEditing(d.mac)
    setName(d.friendly_name || '')
  }

  async function saveName(mac) {
    try {
      const updated = await api.patch(`/devices/${mac}`, { friendly_name: name })
      setData((list) => list.map((d) => (d.mac === mac ? updated : d)))
      setEditing(null)
      showToast('Name saved')
    } catch (e) {
      showToast(e.message)
    }
  }

  async function remove(d) {
    if (!confirm(`Forget ${d.label} (${d.mac})? It will reappear if it is seen again.`)) return
    await api.del(`/devices/${d.mac}`)
    reload()
  }

  const sortBy = (k) => setSort(([key, dir]) => [k, key === k ? -dir : 1])

  return (
    <>
      <ErrorBanner error={error} />
      <div className="page-head">
        <div>
          <h1>Devices</h1>
          <p>{data ? `${data.length} known · ${online} online` : 'Loading…'} — click the pencil to give a device a friendly name.</p>
        </div>
        <div className="actions">
          <a className="btn" href="/api/reports/devices.csv"><Icon name="download" size={16} /> Export CSV</a>
        </div>
      </div>

      <Panel flush>
        <div className="filters">
          <div className="field grow">
            <span className="label">Search</span>
            <SearchBox value={q} onChange={setQ} placeholder="Name, IP, MAC, hostname or vendor" />
          </div>
          <div className="field">
            <span className="label">Status</span>
            <Segmented value={status} onChange={setStatus}
              options={[['all', 'All'], ['online', 'Online'], ['offline', 'Offline']]} />
          </div>
          <div className="field">
            <span className="label">Type</span>
            <Segmented value={kind} onChange={setKind}
              options={[['all', 'All'], ['wifi', 'Wi-Fi devices'], ['vm', 'VMware VMs']]} />
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {COLUMNS.map(([k, label]) => (
                  <th key={k} className="sortable" onClick={() => sortBy(k)}>
                    {label}{sort[0] === k ? (sort[1] > 0 ? ' ▲' : ' ▼') : ''}
                  </th>
                ))}
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.mac}>
                  <td><StatusDot state={d.online} label={d.online ? 'Online' : 'Offline'} /></td>
                  <td>
                    {editing === d.mac ? (
                      <form className="inline-edit" onSubmit={(e) => { e.preventDefault(); saveName(d.mac) }}>
                        <input autoFocus value={name} maxLength={64} placeholder={d.hostname || 'Friendly name'}
                          onChange={(e) => setName(e.target.value)}
                          onKeyDown={(e) => e.key === 'Escape' && setEditing(null)} />
                        <button type="submit" className="primary">Save</button>
                        <button type="button" className="ghost" onClick={() => setEditing(null)}>Cancel</button>
                      </form>
                    ) : (
                      <div className="row">
                        <strong>{d.label}</strong>
                        {d.is_self && <span className="badge accent">This PC</span>}
                        {d.is_gateway && <span className="badge info">Router</span>}
                        {d.is_vm && <span className="badge ok">VM</span>}
                        <button className="ghost" title="Rename" onClick={() => startEdit(d)}><Icon name="edit" size={14} /></button>
                      </div>
                    )}
                  </td>
                  <td className="mono">{d.ip}</td>
                  <td className="mono">
                    {d.mac}
                    {d.randomized_mac && <span className="badge warn" style={{ marginLeft: 6 }} title="Private / randomized Wi-Fi address: the vendor cannot be identified and the MAC may change">Private MAC</span>}
                  </td>
                  <td>{d.hostname || <span className="muted">—</span>}</td>
                  <td>{d.vendor || <span className="muted">{d.randomized_mac ? 'Hidden (random MAC)' : 'Unknown'}</span>}</td>
                  <td className="small">{d.network || <span className="muted">—</span>}</td>
                  <td className="small" title={d.first_seen}>{fmtDateTime(d.first_seen)}</td>
                  <td className="small" title={d.last_seen}>{timeAgo(d.last_seen)}</td>
                  <td className="nowrap">
                    <Link className="btn" style={{ padding: '4px 10px' }} to={`/activity?device=${encodeURIComponent(d.mac)}`}>Activity</Link>{' '}
                    {!d.is_self && <button className="ghost danger" title="Forget device" onClick={() => remove(d)}><Icon name="trash" size={14} /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && !rows.length && <div className="empty">{data.length ? 'No devices match the filters.' : 'No devices yet — run a scan from the Network Scan page.'}</div>}
        </div>
      </Panel>
      {toast}
    </>
  )
}

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Callout, ErrorBanner, Icon, Panel, Segmented, StatusDot, useToast } from '../components.jsx'
import { fmtNum } from '../format.js'
import { usePoll } from '../hooks.js'

export default function AccessControl() {
  const { data, error, reload } = usePoll(() => api.get('/filter'), 8000)
  const [form, setForm] = useState(null)
  const [entry, setEntry] = useState('')
  const [test, setTest] = useState(null)
  const [saving, setSaving] = useState(false)
  const [toast, showToast] = useToast()

  useEffect(() => { if (data && !form) setForm(pick(data)) }, [data, form])

  function pick(d) {
    return {
      filtering_enabled: d.enabled, filter_mode: d.mode,
      blocklist: d.blocklist, allowlist: d.allowlist,
      block_message: d.block_message, block_page_port: d.block_page_port, block_page_ip: d.block_page_ip,
    }
  }

  const listKey = form?.filter_mode === 'allowlist' ? 'allowlist' : 'blocklist'
  const list = form?.[listKey] || []
  const dirty = form && data && JSON.stringify(form) !== JSON.stringify(pick(data))

  function addEntry(e) {
    e.preventDefault()
    const v = entry.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '')
    if (!v) return
    if (!list.includes(v)) setForm((f) => ({ ...f, [listKey]: [...f[listKey], v] }))
    setEntry('')
  }
  const removeEntry = (d) => setForm((f) => ({ ...f, [listKey]: f[listKey].filter((x) => x !== d) }))

  async function save() {
    setSaving(true)
    try {
      await api.put('/settings', form)
      await reload()
      setForm(null)
      showToast('Access rules saved')
    } catch (e) {
      showToast(e.message)
    } finally {
      setSaving(false)
    }
  }

  async function runTest() {
    if (!entry.trim()) return
    try { setTest(await api.get(`/filter/test?domain=${encodeURIComponent(entry.trim())}`)) }
    catch (e) { showToast(e.message) }
  }

  if (!form) return <><ErrorBanner error={error} />{!error && <p className="muted">Loading…</p>}</>
  const st = data.status
  const fwdOff = !data.forwarder_running

  return (
    <>
      <ErrorBanner error={error} />
      <div className="page-head">
        <div>
          <h1>Access Control</h1>
          <p>Block websites, or allow only certain ones, for every device using this PC for DNS.</p>
        </div>
        <div className="actions">
          {dirty && <button onClick={() => setForm(pick(data))}>Discard</button>}
          <button className="primary" disabled={!dirty || saving} onClick={save}>{saving ? 'Saving…' : 'Save rules'}</button>
        </div>
      </div>

      {fwdOff && (
        <div style={{ marginBottom: 16 }}>
          <Callout level="warn" title="The DNS forwarder is off, so blocking does nothing yet"
            detail="Access control only affects devices that use this PC as their DNS server." />
        </div>
      )}

      <div className="grid stats" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(170px,1fr))' }}>
        <div className="panel stat tone-accent">
          <div className="stat-label"><Icon name="lock" size={15} /> Status</div>
          <div className="stat-value small"><StatusDot state={st.active ? true : form.filtering_enabled ? 'warn' : null}
            label={st.active ? 'Enforcing' : form.filtering_enabled ? 'On (forwarder off)' : 'Off'} /></div>
          <div className="stat-sub">{form.filter_mode === 'allowlist' ? 'Allow-list mode' : 'Block-list mode'}</div>
        </div>
        <div className="panel stat tone-warn">
          <div className="stat-label"><Icon name="shield" size={15} /> Rules</div>
          <div className="stat-value">{fmtNum(list.length)}</div>
          <div className="stat-sub">{form.filter_mode === 'allowlist' ? 'sites allowed' : 'sites blocked'}</div>
        </div>
        <div className="panel stat tone-info">
          <div className="stat-label"><Icon name="error" size={15} /> Blocked hits</div>
          <div className="stat-value">{fmtNum(st.blocked_hits)}</div>
          <div className="stat-sub">this session</div>
        </div>
        <div className="panel stat">
          <div className="stat-label"><Icon name="info" size={15} /> Block page</div>
          <div className="stat-value small"><StatusDot state={st.block_page.running ? true : st.block_page.error ? 'err' : null}
            label={st.block_page.running ? `Port ${st.block_page.port}` : 'Off'} /></div>
          <div className="stat-sub">shows the message</div>
        </div>
      </div>

      <div className="grid cols-2" style={{ alignItems: 'start', marginTop: 16 }}>
        <Panel flush>
          <div className="form-row">
            <div><div>Turn on access control</div><div className="hint">Master switch for blocking.</div></div>
            <div><input type="checkbox" checked={form.filtering_enabled} onChange={(e) => setForm((f) => ({ ...f, filtering_enabled: e.target.checked }))} /></div>
          </div>
          <div className="form-row">
            <div><div>Mode</div><div className="hint">{form.filter_mode === 'allowlist'
              ? 'Allow-list: ONLY the sites below work. Everything else is blocked.'
              : 'Block-list: the sites below are blocked. Everything else works.'}</div></div>
            <Segmented value={form.filter_mode} onChange={(v) => setForm((f) => ({ ...f, filter_mode: v }))}
              options={[['blocklist', 'Block these'], ['allowlist', 'Allow only these']]} />
          </div>
          <div style={{ padding: '14px 16px' }}>
            <div className="field" style={{ marginBottom: 10 }}>
              <span className="label">{form.filter_mode === 'allowlist' ? 'Allowed websites' : 'Blocked websites'}</span>
              <form className="row" onSubmit={addEntry}>
                <input style={{ flex: 1 }} value={entry} onChange={(e) => { setEntry(e.target.value); setTest(null) }}
                  placeholder="e.g. tiktok.com" />
                <button type="submit" className="primary">Add</button>
                <button type="button" onClick={runTest} title="Check if a domain would be blocked">Test</button>
              </form>
              {test && (
                <div className="small" style={{ marginTop: 8, color: test.blocked ? 'var(--err)' : 'var(--ok)' }}>
                  <strong>{test.domain}</strong> would be <strong>{test.blocked ? 'BLOCKED' : 'allowed'}</strong>
                  {!test.enabled && ' (access control is currently off)'}
                </div>
              )}
            </div>
            {list.length === 0 ? (
              <div className="empty" style={{ padding: 24 }}>
                No sites yet. {form.filter_mode === 'allowlist' ? 'Add the sites that should be reachable.' : 'Add sites to block, e.g. tiktok.com.'}
              </div>
            ) : (
              <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
                {list.map((d) => (
                  <span key={d} className="badge" style={{ fontSize: 13, padding: '4px 8px', gap: 6 }}>
                    <span className="mono">{d}</span>
                    <button className="ghost" style={{ padding: 0, color: 'var(--err)' }} title="Remove" onClick={() => removeEntry(d)}>
                      <Icon name="trash" size={13} />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </Panel>

        <div className="stack">
          <Panel title="Block message & page" flush>
            <div className="form-row">
              <div><div>Message shown to users</div><div className="hint">Appears on the "access blocked" page.</div></div>
              <textarea rows={3} maxLength={300} value={form.block_message}
                onChange={(e) => setForm((f) => ({ ...f, block_message: e.target.value }))}
                style={{ font: 'inherit', color: 'var(--text)', background: 'var(--bg-elev)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: '7px 10px', resize: 'vertical' }} />
            </div>
            <div className="form-row">
              <div><div>Block page port</div><div className="hint">80 = normal web port, so the message shows automatically.</div></div>
              <input type="number" min={1} max={65535} value={form.block_page_port}
                onChange={(e) => setForm((f) => ({ ...f, block_page_port: Number(e.target.value) }))} />
            </div>
            <div style={{ padding: '12px 16px' }}>
              <a className="btn" href={`http://${data.effective_block_ip}:${form.block_page_port}`} target="_blank" rel="noreferrer">
                <Icon name="info" size={14} /> Preview the block page
              </a>
              {st.block_page.error && <div className="small" style={{ color: 'var(--err)', marginTop: 8 }}>{st.block_page.error}</div>}
            </div>
          </Panel>

          <Panel title="How blocking works">
            <div className="prose">
              <p>Blocking applies to <strong>any device set to use this PC for DNS</strong> (see <Link to="/settings">Settings</Link>).
                A blocked lookup is answered with this PC ({data.effective_block_ip}), where the message page is shown.</p>
              <ul>
                <li>A rule covers subdomains: <code>youtube.com</code> also blocks <code>m.youtube.com</code>.</li>
                <li>On <strong>http://</strong> sites the message page shows. On <strong>https://</strong> sites (most sites) the
                  browser instead shows its own "can't reach / not secure" error — the site is still blocked, just without the message.</li>
                <li>A device using encrypted DNS (DoH/DoT), a VPN, or hard-coded DNS bypasses this. Turn off the browser's
                  "Secure DNS" on devices you manage.</li>
                <li><strong>Allow-list</strong> is strict: once on, those devices reach only the listed sites and nothing else,
                  including app/update servers.</li>
              </ul>
            </div>
          </Panel>
        </div>
      </div>
      {toast}
    </>
  )
}

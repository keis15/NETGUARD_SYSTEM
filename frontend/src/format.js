// Backend timestamps are local PC time: "YYYY-MM-DD HH:MM:SS".

export function parseTs(ts) {
  if (!ts) return null
  const d = new Date(ts.replace(' ', 'T'))
  return isNaN(d) ? null : d
}

export function timeAgo(ts) {
  const d = parseTs(ts)
  if (!d) return '—'
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000))
  if (s < 10) return 'just now'
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function fmtDateTime(ts) {
  return ts ? ts.slice(0, 16) : '—'
}

export function fmtNum(n) {
  return (n ?? 0).toLocaleString()
}

export function fmtDuration(seconds) {
  if (seconds == null) return '—'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`
  return `${(seconds / 3600).toFixed(seconds % 3600 ? 1 : 0)} h`
}

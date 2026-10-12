// Thin fetch wrapper for the FastAPI backend.

async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      const body = await res.json()
      msg = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch { /* not JSON */ }
    throw new Error(msg || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  get: (p) => request(p),
  post: (p, body) => request(p, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  put: (p, body) => request(p, { method: 'PUT', body: JSON.stringify(body) }),
  patch: (p, body) => request(p, { method: 'PATCH', body: JSON.stringify(body) }),
  del: (p) => request(p, { method: 'DELETE' }),
}

// Build a query string, dropping empty values.
export function qs(params) {
  const entries = Object.entries(params).filter(([, v]) => v !== '' && v !== null && v !== undefined)
  return entries.length ? `?${new URLSearchParams(entries)}` : ''
}

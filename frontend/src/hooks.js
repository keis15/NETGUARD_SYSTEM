import { useCallback, useEffect, useRef, useState } from 'react'

// Fetch data with `loader`, refresh every `intervalMs` (0 = no polling) and when deps change.
export function usePoll(loader, intervalMs = 0, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const loaderRef = useRef(loader)
  loaderRef.current = loader

  const reload = useCallback(async () => {
    try {
      const d = await loaderRef.current()
      setData(d)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setLoading(true)
    reload()
    if (!intervalMs) return undefined
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') reload()
    }, intervalMs)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, intervalMs, ...deps])

  return { data, error, loading, reload, setData }
}

export function useDebounced(value, ms = 300) {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return v
}

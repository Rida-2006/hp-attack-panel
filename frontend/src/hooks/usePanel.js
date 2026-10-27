import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../services/api'
import { DEMO, useDemoPanel } from '../services/demo'

export function usePanel() {
  return DEMO ? useDemoPanel() : useLivePanel()
}

function useLivePanel() {
  const [attacks, setAttacks] = useState([])
  const [events, setEvents] = useState([])
  const [payloads, setPayloads] = useState([])
  const [target, setTarget] = useState(null)
  const [stream, setStream] = useState('connecting')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const mounted = useRef(false)
  const launching = useRef(false)
  const refresh = useCallback(async () => {
    const startedAt = Date.now()
    const [history, logs, library] = await Promise.all([api('/attacks'), api('/events'), api('/payloads')])
    if (!mounted.current) return
    setAttacks(old => {
      const records = new Map(history.map(a => [a.attack_id, a]))
      old.forEach(a => {
        if (new Date(a.timestamp).getTime() >= startedAt || (records.get(a.attack_id)?.status === 'running' && a.status !== 'running')) records.set(a.attack_id, a)
      })
      return [...records.values()].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 1000)
    })
    setEvents(old => [...new Map([...logs, ...old].map(e => [e.id, e])).values()].sort((a, b) => b.id - a.id).slice(0, 5000))
    setPayloads(library); setError('')
  }, [])
  const check = useCallback(async () => {
    try { const data = await api('/honeypot/status'); if (mounted.current) setTarget(data) }
    catch (e) { if (mounted.current) setError(e.message) }
  }, [])
  useEffect(() => {
    mounted.current = true
    let ws, retry, ping, disposed = false
    function connect() {
      if (disposed) return
      setStream('connecting')
      ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`)
      ws.onopen = () => {
        if (disposed) return
        setStream('connected'); refresh().catch(e => !disposed && setError(e.message))
        ping = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping') }, 15000)
      }
      ws.onmessage = event => {
        if (disposed) return
        try {
          const data = JSON.parse(event.data)
          if (!data.id || !data.type) return
          setEvents(old => [data, ...old.filter(e => e.id !== data.id)].slice(0, 5000))
          if (data.result) setAttacks(old => [data.result, ...old.filter(a => a.attack_id !== data.result.attack_id)].slice(0, 1000))
        } catch { /* Ignore non-event frames. */ }
      }
      ws.onerror = () => ws.close()
      ws.onclose = () => { clearInterval(ping); if (!disposed) { setStream('disconnected'); retry = setTimeout(connect, 3000) } }
    }
    refresh().catch(e => !disposed && setError(e.message)); check(); connect()
    const healthTimer = setInterval(check, 30000)
    return () => { disposed = true; mounted.current = false; clearTimeout(retry); clearInterval(ping); clearInterval(healthTimer); ws?.close() }
  }, [refresh, check])
  async function launch(path = '/attacks/random', body = {}) {
    if (launching.current) return
    launching.current = true; setBusy(true); setError('')
    try {
      const record = await api(path, body)
      setResult(record); setAttacks(old => [record, ...old.filter(a => a.attack_id !== record.attack_id)].slice(0, 1000))
      return record
    } catch (e) { setError(e.message); throw e }
    finally { setBusy(false); launching.current = false }
  }
  return { attacks, events, payloads, target, stream, error, busy, result, dismissResult: () => setResult(null), launch, check, refresh }
}

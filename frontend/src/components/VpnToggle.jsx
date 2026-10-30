import { useEffect, useState } from 'react'

async function request(path, action = false, signal) {
  const response = await fetch(`/api/vpn/${path}`, {
    method: action ? 'POST' : 'GET',
    headers: action ? { 'X-VPN-Control': '1' } : {}, signal,
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.detail || 'VPN request failed')
  return data
}

export default function VpnToggle() {
  const [state, setState] = useState('checking')
  const [ip, setIp] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    let timer
    async function poll() {
      try {
        const data = await request('status', false, controller.signal)
        setState(data.state)
      } catch (e) {
        if (!controller.signal.aborted) { setState('unavailable'); setError(e.message) }
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 2000)
      }
    }
    poll()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [])
  async function toggle() {
    setBusy(true); setError(''); setIp(null)
    try { setState((await request(state === 'running' ? 'stop' : 'start', true)).state) }
    catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function checkIp() {
    setBusy(true); setError('')
    try { setIp((await request('ip')).ip || 'Unavailable') }
    catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  return <section className="vpn-controls" aria-label="WireGuard VPN">
    <span role="status">VPN service: {state}</span>{' '}
    <button type="button" onClick={toggle} disabled={busy || !['running', 'stopped'].includes(state)}>
      {state === 'running' ? 'Turn VPN off' : 'Turn VPN on'}
    </button>{' '}
    <button type="button" onClick={checkIp} disabled={busy}>Check public IPv4</button>
    {ip && <span> · Public IPv4: {ip}</span>}
    {error && <p role="alert">{error}</p>}
    <small style={{ display: 'block' }}>wg2 routes this PC’s IPv4 traffic through the VPS. Service status does not confirm a handshake.</small>
  </section>
}

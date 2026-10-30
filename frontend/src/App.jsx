import { useEffect, useRef, useState } from 'react'
import { api } from './services/api'
import { usePanel } from './hooks/usePanel'
import { DEMO } from './services/demo'
import VpnToggle from './components/VpnToggle'

function Bolt() {
  return <svg className="hero-bolt" viewBox="0 0 150 190" aria-hidden="true">
    <defs>
      <linearGradient id="metal" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#FFF0BD"/><stop offset=".32" stopColor="#D8A84B"/><stop offset=".52" stopColor="#F6D68A"/><stop offset=".72" stopColor="#96621E"/><stop offset="1" stopColor="#F6D68A"/></linearGradient>
      <filter id="bolt-glow" x="-60%" y="-40%" width="220%" height="180%"><feDropShadow dx="0" dy="0" stdDeviation="5" floodColor="#FF174F" floodOpacity=".7"/><feDropShadow dx="2" dy="3" stdDeviation="1" floodColor="#000" floodOpacity=".8"/></filter>
    </defs>
    <path d="M80 8 22 104h45l-13 77 75-112H80l27-61Z" fill="url(#metal)" stroke="#F6D68A" strokeWidth="1.4" filter="url(#bolt-glow)"/>
  </svg>
}

function Globe() {
  return <svg className="hero-bolt" viewBox="0 0 150 190" fill="none" stroke="url(#metal)" strokeWidth="2.5" aria-hidden="true">
    <g filter="url(#bolt-glow)"><circle cx="75" cy="95" r="52"/><ellipse cx="75" cy="95" rx="23" ry="52"/><path d="M23 95h104M30 69h90M30 121h90"/></g>
  </svg>
}

export default function App() {
  const panel = usePanel()
  const { events, payloads, catalogue = [], target, stream, busy, error, launch, result } = panel
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [controlsExpanded, setControlsExpanded] = useState(false)
  const [rotationNotice, setRotationNotice] = useState('')
  const [rotating, setRotating] = useState(false)
  const rotationPending = useRef(false)
  const randomControl = useRef(null)
  const shellToggle = useRef(null)
  const commandSubmitting = useRef(false)
  const [shell, setShell] = useState(false)
  const [command, setCommand] = useState('')
  const [pending, setPending] = useState(false)
  const [lines, setLines] = useState([])
  const [clearedAt, setClearedAt] = useState(0)
  const terminal = useRef(null)
  const executionSection = useRef(null)
  const commandHistory = useRef([])
  const historyPosition = useRef(0)
  const working = busy || pending || rotating
  const visible = [
    ...events.filter(e => new Date(e.timestamp).getTime() >= clearedAt).map(e => ({ id: `event-${e.id}`, time: e.timestamp, kind: e.type, text: e.message, error: e.severity === 'error' })),
    ...lines,
  ].sort((a, b) => a.time.localeCompare(b.time)).slice(-200)

  useEffect(() => { if (result?.status === 'running') setTerminalOpen(true) }, [result])

  useEffect(() => { if (terminal.current) terminal.current.scrollTop = terminal.current.scrollHeight }, [events, lines])

  useEffect(() => {
    if (shell) {
      setTerminalOpen(true)
      if (window.matchMedia('(max-width: 900px)').matches) executionSection.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      document.getElementById('command')?.focus({ preventScroll: true })
    }
  }, [shell])

  function collapseControls() {
    setControlsExpanded(false)
    setRotationNotice('')
    const focusTarget = working ? shellToggle.current : randomControl.current
    focusTarget?.focus({ preventScroll: true })
  }

  async function runRandomTest() {
    setControlsExpanded(true)
    setTerminalOpen(true)
    try { await launch() }
    catch (e) {
      setLines(old => [...old, { id: crypto.randomUUID(), time: new Date().toISOString(), kind: 'error', text: e.message, error: true }].slice(-200))
    }
  }

  async function rotateIp() {
    if (working || rotationPending.current) return
    if (DEMO) { setRotationNotice('IP rotation not configured'); return }
    if (!window.confirm('Reconnect the configured wg2 VPN? This changes this PC’s IPv4 route and may briefly interrupt internet access. A single VPN exit may keep the same IP.')) return
    rotationPending.current = true
    setRotating(true); setRotationNotice('Checking VPN and public IP…')
    try {
      const response = await fetch('/api/vpn/rotate', { method: 'POST', headers: { 'X-VPN-Control': '1' } })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'VPN reconnection failed')
      setRotationNotice(data.message)
    } catch (e) { setRotationNotice(e.message) }
    finally { rotationPending.current = false; setRotating(false); panel.refresh().catch(() => {}) }
  }

  async function execute(event) {
    event.preventDefault()
    const submitted = command.trim()
    if (!submitted || working || commandSubmitting.current) return
    commandSubmitting.current = true
    commandHistory.current.push(submitted)
    historyPosition.current = commandHistory.current.length
    setCommand(''); setPending(true)
    const append = (text, error = false) => setLines(old => [...old, { id: crypto.randomUUID(), time: new Date().toISOString(), kind: 'console', text, error }].slice(-200))
    append(`❯ ${submitted}`)
    try {
      const data = await api('/console/execute', { command: submitted })
      if (data.clear) { setLines([]); setClearedAt(Date.now()) }
      else append(typeof data.output === 'string' ? data.output : JSON.stringify(data.output, null, 2))
      if (data.result) await panel.refresh()
    } catch (e) { append(e.message, true) }
    finally { commandSubmitting.current = false; setPending(false) }
  }

  return <main className={`attack-workspace ${terminalOpen ? 'split-active' : ''}`}>
    {DEMO && <div className="demo-notice">PUBLIC DEMO · Simulated requests and results. No honeypot traffic is sent.</div>}
    {!DEMO && <VpnToggle />}
    <header className="panel-header"><span className={`connection ${target?.status === 'connected' ? 'connected' : ''}`}><i/>{target?.name || 'Honeypot'} · {target?.status || 'checking'}</span></header>
    <div className="execution-layout"><section className="attack-hero" aria-labelledby="panel-title">
      <p className="eyebrow">AUTHORIZED ENVIRONMENTS ONLY</p>
      <h1 id="panel-title">Attack Panel</h1>
      <p className="hero-description">One controlled test. Every step visible.</p>
      <div className={`attack-controls ${controlsExpanded ? 'controls-expanded' : ''}`} onKeyDown={event => { if (event.key === 'Escape' && controlsExpanded) { event.preventDefault(); collapseControls() } }}>
        <button ref={randomControl} className={`random-hero ${working ? 'executing' : ''}`} disabled={working || !(DEMO ? payloads.length : catalogue.some(test => test.enabled))} onClick={runRandomTest} aria-label="Random Attack" aria-expanded={controlsExpanded} aria-controls="ip-rotation-control">
        <span className="hero-corner top-left"/><span className="hero-corner bottom-right"/>
        <span className="bolt-halo"/><Bolt/>
        <span className="hero-action-label">{rotating ? 'Reconnecting VPN…' : working ? 'Executing Attack…' : 'Random Attack'}</span>
        <span className="hero-action-caption">{working ? 'Waiting for the configured target' : 'Run one controlled honeypot test'}</span>
      </button>
        <button id="ip-rotation-control" className="random-hero rotate-control" aria-label="Rotate IP" aria-describedby="ip-rotation-status" aria-hidden={!controlsExpanded} tabIndex={controlsExpanded ? 0 : -1} disabled={working} onClick={rotateIp}>
          <span className="hero-corner top-left"/><span className="hero-corner bottom-right"/>
          <span className="bolt-halo"/><Globe/>
          <span className="hero-action-label">Rotate IP</span>
          <span id="ip-rotation-status" className="hero-action-caption">{rotating ? 'Verifying connection…' : 'Reconnect VPN · verify public IP'}</span>
        </button>
        <button className="clear-terminal controls-collapse" aria-label="Collapse attack controls" aria-hidden={!controlsExpanded} tabIndex={controlsExpanded ? 0 : -1} onClick={collapseControls}>Collapse controls</button>
        <span className="sr-only" role="status">{rotationNotice}</span>
      </div>
      {rotationNotice && <p className="hero-description" role="status">{rotationNotice}</p>}
      <div className="hero-meta"><span>{DEMO ? `${payloads.length} simulated payloads` : `${catalogue.filter(test => test.enabled).length} tripwire tests`}</span><span className="meta-divider"/><code>{target?.url || 'Loading target…'}</code></div>
      <button ref={shellToggle} className="custom-shell-toggle" onClick={() => setShell(s => !s)} aria-expanded={shell} aria-controls="custom-shell"><span aria-hidden="true">❯_</span> {shell ? 'Close Custom Shell' : 'Custom Shell'} <span aria-hidden="true">{shell ? '−' : '+'}</span></button>
      {result && <div className="selected-test" aria-live="polite"><span className="eyebrow">SELECTED TEST</span><h2>{result.cve_id || (result.catalogue ? 'Tripwire test' : 'Approved command')}</h2><p>{result.payload_name}</p><code>{result.attack_id}</code><code>{result.target_url}</code><p className="execution-state">{result.outcome || result.status} {result.http_status != null && `· HTTP ${result.http_status}`}</p>{result.catalogue && <small>Expected sensor.action: {result.expected_sensor_action || 'unspecified'}<br/>Response: {result.validation_result} · Event verification pending{result.catalogue.coverage_note && <><br/>{result.catalogue.coverage_note}</>}</small>}</div>}
      {error && <div className="error-notice" role="alert">{error}</div>}
    </section>
    <section ref={executionSection} className="execution-terminal" aria-labelledby="terminal-title" aria-hidden={!terminalOpen} inert={!terminalOpen ? '' : undefined}>
      <div className="terminal-toolbar"><div><span className="terminal-dots"><i/><i/><i/></span><h2 id="terminal-title">Live execution shell</h2></div><div><span className={`stream-label ${stream === 'connected' ? 'live' : ''}`}><i/>{stream === 'connected' ? 'STREAM CONNECTED' : stream === 'demo' ? 'SIMULATION' : 'RECONNECTING'}</span><button className="clear-terminal" onClick={() => { setLines([]); setClearedAt(Date.now()) }}>Clear view</button></div></div>
      <div ref={terminal} className="terminal-output" role="log" aria-live="polite" aria-relevant="additions" tabIndex={0} aria-label="Execution output">
        <div className="terminal-intro"><span>honeyguard</span> / attack runner<br/><span className="muted">{DEMO ? 'Simulation mode. No real requests are sent.' : 'Ready. Launch a random test or enter an approved command.'}</span></div>
        {!visible.length && <div className="terminal-wait"><span className="terminal-prompt">❯</span> Awaiting execution<span className="cursor"/></div>}
        {visible.map(line => <div className={`terminal-line ${line.error ? 'line-error' : ''}`} key={line.id}><time dateTime={line.time}>{new Date(line.time).toLocaleTimeString([], { hour12: false })}</time><span className={`line-kind kind-${line.kind}`}>{line.kind}</span><pre>{line.text}</pre></div>)}
        {working && <div className="terminal-working"><span className="spinner"/> Executing approved operation…</div>}
      </div>
      {shell && <form id="custom-shell" className="custom-shell" onSubmit={execute}><label htmlFor="command">Supported test commands <span>help · status · list attacks · test ssti · test sqli · test xss · clear</span></label><div><span className="terminal-prompt">❯</span><input id="command" aria-label="Custom Shell command" value={command} onChange={e => setCommand(e.target.value)} placeholder="Type help to see supported commands" autoComplete="off" spellCheck="false" onKeyDown={e => { if (e.key === 'ArrowUp' || e.key === 'ArrowDown') { e.preventDefault(); historyPosition.current = Math.max(0, Math.min(commandHistory.current.length, historyPosition.current + (e.key === 'ArrowUp' ? -1 : 1))); setCommand(commandHistory.current[historyPosition.current] || '') } }}/><button disabled={working || !command.trim()}>Execute ↗</button></div><small>Approved commands only. No operating-system shell or custom target URLs.</small></form>}
      <div className="terminal-footer"><span>Fixed target · {DEMO ? 'simulated' : 'panel-observed'} output</span><span>{result ? `${result.attack_id} · ${result.status === 'completed' ? `HTTP ${result.http_status}` : result.status}` : 'X-Attack-ID correlation enabled'}</span></div>
    </section>
    </div>
    <footer className="panel-footer"><span>HONEYGUARD <b> / </b> ATTACK PANEL</span><span>Monitoring and reports belong to Threat Intelligence.</span></footer>
  </main>
}

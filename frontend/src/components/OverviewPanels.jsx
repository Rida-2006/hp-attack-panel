import { useRef, useState } from 'react'
import { api } from '../services/api'

const shortcuts = ['help', 'status', 'list attacks', 'test ssti', 'test sqli', 'test xss', 'logs', 'history', 'clear']
const categories = { ssti: 'SSTI', sqli: 'SQLi', xss: 'XSS marker', traversal: 'Path traversal', recon: 'Recon', auth: 'Auth probe' }
const reasons = { 200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved', 302: 'Redirect', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Not Allowed', 429: 'Rate Limited', 500: 'Server Error', 502: 'Bad Gateway', 503: 'Unavailable' }

export function BeginnerPanel({ Icon, busy, enabled, launch, count }) {
  return <article className="card mode-card beginner-panel">
    <div className="mode-heading"><span className="mode-icon"><Icon name="bolt" size={24}/></span><h2>Attack Simulator <span>(Beginner Mode)</span></h2></div>
    <p>One click to run a predefined test against your honeypot.</p>
    <button className="button primary random-attack" disabled={busy || !enabled} onClick={() => launch().catch(() => {})}><Icon name="bolt" size={23}/>{busy ? 'Executing test…' : 'Random Attack'}<Icon name="arrow" size={19}/></button>
    <div className="mode-note">The system selects one of {count} approved test payloads and sends it to your configured lab target. Follow the real response in Recent Attacks and Live events.</div>
    <small>Approved payloads · fixed target · traceable results</small>
  </article>
}

export function AdvancedPanel({ Icon, busy, openFull, onResult, onBusy }) {
  const [command, setCommand] = useState('')
  const [pending, setPending] = useState(false)
  const [output, setOutput] = useState(null)
  const input = useRef(null)
  async function execute(event) {
    event.preventDefault()
    if (!command.trim() || pending || busy) return
    const submitted = command.trim()
    setPending(true); onBusy(true); setOutput({ command: submitted, text: 'Executing approved command…' })
    try {
      const data = await api('/console/execute', { command: submitted })
      setOutput(data.clear ? null : { command: submitted, text: typeof data.output === 'string' ? data.output : JSON.stringify(data.output, null, 2) })
      setCommand('')
      if (data.result) onResult(data.result)
    } catch (error) { setOutput({ command: submitted, text: error.message, error: true }) }
    finally { setPending(false); onBusy(false) }
  }
  return <article className="card mode-card advanced-panel">
    <div className="mode-heading"><span className="mode-icon"><Icon name="terminal" size={24}/></span><h2>Advanced Console <span>(Experienced Users)</span></h2></div>
    <p>Enter supported commands to run specific tests.</p>
    <form className="quick-command" onSubmit={execute}><input ref={input} aria-label="Overview console command" placeholder="Enter command (type 'help' for options)…" autoComplete="off" spellCheck="false" value={command} onChange={e => setCommand(e.target.value)}/><button className="button execute-button" disabled={busy || pending || !command.trim()}><Icon name="arrow" size={17}/>{pending ? 'Running…' : 'Execute'}</button></form>
    <div className="shortcut-label">Supported commands</div>
    <div className="command-shortcuts">{shortcuts.map(c => <button key={c} disabled={pending} onClick={() => { setCommand(c); input.current?.focus() }}>{c}</button>)}</div>
    <div className="quick-output" role="status">{output && <><div className="quick-output-prompt">❯ {output.command}</div><pre className={output.error ? 'console-error' : ''}>{output.text}</pre></>}</div>
    <button className="text-button full-console" onClick={openFull}>Open full console <Icon name="arrow" size={14}/></button>
  </article>
}

export function RecentAttacks({ attacks, inspect, viewAll, Icon }) {
  const recent = [...attacks].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 5)
  return <article className="card recent-attacks">
    <div className="section-title"><div className="recent-title"><Icon name="clock" size={22}/><div><h2>Recent Attacks</h2><p>Latest panel-observed executions</p></div></div><button className="text-button" onClick={viewAll}>View All <Icon name="arrow" size={15}/></button></div>
    {recent.length ? <div className="recent-rows">{recent.map(a => {
      const code = a.http_status
      const responseTone = a.status !== 'completed' ? a.status : code >= 400 ? 'http-error' : code >= 300 ? 'http-redirect' : 'http-ok'
      const response = a.status === 'completed' ? `${code}${reasons[code] ? ` ${reasons[code]}` : ''}` : a.status === 'failed' ? 'Request failed' : a.status === 'running' ? 'Running…' : 'Interrupted'
      return <button className="recent-attack-row" key={a.attack_id} onClick={() => inspect(a)} aria-label={`Inspect ${a.payload_name}, ${response}`}>
        <span className={`attack-category category-${a.attack_type}`}>{categories[a.attack_type] || a.attack_type}</span>
        <code title={a.path}>{a.path}</code>
        <time dateTime={a.timestamp} title={new Date(a.timestamp).toLocaleString()}>{new Date(a.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time>
        <span className={`recent-response ${responseTone}`}>{response}</span>
        <Icon name="arrow" size={13}/>
      </button>
    })}</div> : <div className="empty"><div className="empty-icon"><Icon name="clock" size={26}/></div><h3>No attacks yet</h3><p>Launch a random test or use the console to start your timeline.</p></div>}
    <div className="recent-footnote">An HTTP response does not confirm exploitation or honeypot detection.</div>
  </article>
}

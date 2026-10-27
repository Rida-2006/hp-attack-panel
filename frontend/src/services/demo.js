import { useEffect, useState } from 'react'
import rawPayloads from '../../../payloads.json'

export const DEMO = import.meta.env.VITE_DEMO_MODE === 'true'
const key = 'honeyguard-public-demo-v1'
const notes = {
  recon: ['Reconnaissance', 'Requests the root page to observe the exposed HTTP service.', 'Reduce unnecessary service exposure.'],
  auth: ['Authentication probe', 'Sends fixed lab credentials to observe authentication handling.', 'Apply authentication rate limits and monitoring.'],
  traversal: ['Path traversal', 'Tests handling of traversal-shaped input.', 'Normalize paths and restrict file access.'],
  sqli: ['SQL injection', 'Tests handling of SQL-shaped search input.', 'Use parameterized database queries.'],
  ssti: ['Template injection', 'Sends the arithmetic template expression {{7*7}}.', 'Keep untrusted input separate from templates.'],
  xss: ['Reflection marker', 'Sends an inert marker; no JavaScript is executed.', 'Apply context-aware output encoding.'],
}
const payloads = rawPayloads.map(p => { const [category_label, explanation, defense] = notes[p.tags[0]]; return { ...p, category: p.tags[0], category_label, explanation, defense } })
const target = { name: 'Simulated honeypot', url: 'demo://isolated-lab', environment: 'Public demonstration · simulated only', status: 'demo', log_integration: false, http_status: null, last_success: null }
let attacks = [], events = [], running = false, serial = 0
const listeners = new Set()
try { const saved = JSON.parse(localStorage.getItem(key) || '{}'); attacks = (saved.attacks || []).slice(0, 1000); events = (saved.events || []).slice(0, 5000); serial = Math.max(0, ...events.map(e => e.id)) } catch { /* Storage may be unavailable in private browsers. */ }
function notify() { try { localStorage.setItem(key, JSON.stringify({ attacks, events })) } catch { /* Keep the demo usable in memory. */ } listeners.forEach(f => f()) }
function emit(type, message, attack_id, extra = {}) { events = [{ id: ++serial, timestamp: new Date().toISOString(), source: 'simulation', severity: 'info', type, message, attack_id, ...extra }, ...events].slice(0, 5000); notify() }
async function execute(id, source = 'demo', replay_of = null) {
  if (running) throw Error('Wait for the simulated test to finish.')
  const p = payloads.find(p => p.id === id)
  if (!p) throw Error('Approved demo payload not found.')
  running = true; notify()
  const attack_id = `DEMO-${crypto.randomUUID().slice(0, 8).toUpperCase()}`
  const timestamp = new Date().toISOString()
  emit('attack', `[SIMULATED] ${p.name} started`, attack_id)
  emit('request', `[SIMULATED] ${p.method} ${p.path}`, attack_id, { method: p.method, path: p.path, body: p.body, headers: p.headers })
  try {
    await new Promise(resolve => setTimeout(resolve, 700))
    const http_status = { recon: 200, auth: 403, traversal: 404, sqli: 403, ssti: 200, xss: 200 }[p.category]
    const record = { attack_id, timestamp, payload_id: id, attack_type: p.category, payload_name: p.name, method: p.method, path: p.path, source, target_url: target.url, status: 'completed', http_status, duration_ms: 700, error: null, replay_of, honeypot_confirmed: false, simulated: true }
    attacks = [record, ...attacks].slice(0, 1000)
    emit('response', `[SIMULATED] HTTP ${http_status} · 700 ms`, attack_id, { result: record })
    return record
  } finally { running = false; notify() }
}
export async function demoApi(path, body) {
  if (path === '/payloads') return payloads
  if (path === '/attacks') return attacks
  if (path === '/events') return events
  if (path === '/honeypot/status' || path === '/honeypot/info') return { ...target, checked_at: new Date().toISOString() }
  if (path === '/attacks/random') return execute(payloads[Math.floor(Math.random() * payloads.length)].id)
  if (path === '/attacks/execute') return execute(body.payload_id)
  if (/^\/attacks\/[^/]+\/replay$/.test(path)) {
    const old = attacks.find(a => a.attack_id === path.split('/')[2]); if (!old) throw Error('Demo record not found.')
    return execute(old.payload_id, 'demo-replay', old.attack_id)
  }
  if (path === '/console/execute') {
    const c = body.command.trim().toLowerCase().replace(/\s+/g, ' ')
    if (c === 'help') return { output: 'PUBLIC DEMO · All results are simulated. No network tests are sent.\nhelp | status | list attacks | test <category> | logs | history | clear\nThis is an allowlisted test console, not an operating-system shell.' }
    if (c === 'status') return { output: target }
    if (c === 'list attacks') return { output: payloads.map(p => ({ id: p.id, category: p.category, name: p.name })) }
    if (c === 'history') return { output: attacks.slice(0, 20) }
    if (c === 'logs') return { output: events.slice(0, 20) }
    if (c === 'clear') return { clear: true, output: 'Console cleared.' }
    const p = c.startsWith('test ') && payloads.find(p => p.category === c.slice(5) || p.id === c.slice(5))
    if (p) { const result = await execute(p.id, 'demo-console'); return { output: result, result } }
    throw Error('Unsupported command. Type help for the approved commands.')
  }
  throw Error('This operation is unavailable in the public demo.')
}
export function useDemoPanel() {
  const [, update] = useState(0)
  const [error, setError] = useState(''), [result, setResult] = useState(null)
  useEffect(() => { const f = () => update(n => n + 1); listeners.add(f); return () => listeners.delete(f) }, [])
  async function launch(path = '/attacks/random', body = {}) { setError(''); try { const record = await demoApi(path, body); setResult(record); return record } catch (e) { setError(e.message); throw e } }
  return { attacks, events, payloads, target, stream: 'demo', error, busy: running, result, launch, dismissResult: () => setResult(null), check: async () => notify(), refresh: async () => notify() }
}
export function downloadDemoCSV() {
  const fields = ['attack_id', 'timestamp', 'attack_type', 'path', 'http_status', 'duration_ms', 'simulated']
  const csv = [fields, ...attacks.map(a => fields.map(f => a[f]))].map(row => row.map(v => `"${String(v ?? '').replaceAll('"', '""')}"`).join(',')).join('\r\n')
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); const a = document.createElement('a'); a.href = url; a.download = 'honeypot-simulated-history.csv'; a.click(); URL.revokeObjectURL(url)
}

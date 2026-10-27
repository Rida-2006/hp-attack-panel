import { DEMO, demoApi } from './demo'
export async function api(path, body, signal) {
  if (DEMO) return demoApi(path, body)
  const response = await fetch(`/api${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body), signal,
  })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new Error(typeof data.detail === 'string' ? data.detail : `Backend returned HTTP ${response.status}`)
  }
  return response.json()
}

"""Approved, allowlisted HTTP execution service; never executes OS commands."""
import asyncio
import json
import time
from uuid import uuid4
from urllib.parse import urlsplit, urlunsplit, urlencode
import httpx
from fastapi import HTTPException
from backend import storage, catalogue
from backend.config import validate_target, test_target_url, request_timeout
from backend.payloads import load_payloads
from backend.ws import WebSocketManager

ws_manager = WebSocketManager()
lock = asyncio.Lock()
last_started = 0.0
EDUCATION = {
    'recon': ('Reconnaissance', 'Requests the root page to observe the exposed HTTP service.', 'Reduce unnecessary service exposure and verbose server banners.'),
    'auth': ('Authentication probe', 'Sends a fixed test login to observe authentication handling.', 'Use rate limits, strong credentials, and authentication monitoring.'),
    'traversal': ('Path traversal', 'Requests a traversal-shaped path to observe target behavior.', 'Normalize paths and restrict file access to approved directories.'),
    'sqli': ('SQL injection', 'Sends a SQL-shaped search value to observe input handling.', 'Use parameterized queries instead of constructing SQL from input.'),
    'ssti': ('Template injection', 'Sends a harmless arithmetic template expression as a detection probe.', 'Keep untrusted input separate from templates.'),
    'xss': ('Reflected input marker', 'Sends an inert text marker to inspect reflection. No script is executed.', 'Apply context-aware output encoding and a Content Security Policy.'),
}


def library():
    result = []
    for p in load_payloads():
        category = p.get('tags', ['recon'])[0]
        title, explanation, defense = EDUCATION.get(category, EDUCATION['recon'])
        result.append({**p, 'category': category, 'category_label': title, 'explanation': explanation, 'defense': defense})
    return result


async def emit(kind, message, attack_id=None, severity='info', **extra):
    event = storage.save_event({'timestamp': storage.now(), 'type': kind, 'severity': severity, 'source': 'panel', 'message': message, 'attack_id': attack_id, **extra})
    await ws_manager.broadcast(event)
    return event


async def execute(payload_id, source='beginner', replay_of=None):
    global last_started
    payload = next((p for p in library() if p['id'] == payload_id), None)
    if not payload:
        raise HTTPException(404, 'Approved payload not found')
    base = validate_target()
    path = payload.get('path', '/')
    parts = urlsplit(path)
    if not path.startswith('/') or path.startswith('//') or parts.scheme or parts.netloc or '\\' in path:
        raise HTTPException(400, 'Payload must use a relative path on the configured target')
    return await execute_request(payload, base + path, source, replay_of)


async def execute_catalogue(test_id=None, source='random-button', replay_of=None):
    entry = next((e for e in catalogue.TESTS if e['id'] == test_id and e['enabled']), None) if test_id else catalogue.choose()
    if not entry or entry['module'] not in catalogue.MODULES:
        raise HTTPException(404, 'Enabled CVE validation test module not found')
    try:
        url = test_target_url()
        request_timeout()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    payload = catalogue.MODULES[entry['module']](entry, url)
    request_url = payload.pop('request_url', url)
    # A builder may change the path, never the allowlisted origin.
    if urlsplit(request_url)[:2] != urlsplit(url)[:2]:
        raise HTTPException(400, 'CVE module attempted to change the configured target origin')
    return await execute_request(payload, request_url, source, replay_of)


async def execute_test_post(source='random-button', replay_of=None):
    """A connectivity check only: no exploit payload, template expression, or shell command."""
    try:
        url = test_target_url()
        request_timeout()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    parts = urlsplit(url)
    payload = {
        'id': 'harmless-post', 'name': 'Harmless POST test', 'category': 'connectivity',
        'method': 'POST', 'path': parts.path or '/',
        'headers': {}, 'form': {'content': 'Honeyguard harmless POST test'},
    }
    return await execute_request(payload, url, source, replay_of)


async def execute_request(payload, url, source, replay_of=None):
    global last_started
    entry = payload.get('catalogue')
    try:
        timeout = min(request_timeout(), entry.get('timeout', 60)) if entry else request_timeout()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if lock.locked() or time.monotonic() - last_started < 1:
        raise HTTPException(429, 'Wait for the current test to finish and allow one second between launches')
    async with lock:
        last_started = time.monotonic()
        attack_id = f'ATK-{uuid4().hex[:10].upper()}'
        if not storage.claim_execution(attack_id, timeout + 30):
            raise HTTPException(429, 'Another test is already running')
        record = None
        try:
            body = payload.get('body', '')
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            if entry:
                parts = urlsplit(url)
                path = parts.path.replace('{attack_id}', attack_id)
                payload['path'] = path
                # Retain raw query bytes: CGI checks depend on their original encoding.
                query = parts.query + ('&' if parts.query else '') + urlencode({'hg_attack_id': attack_id})
                url = urlunsplit((parts.scheme, parts.netloc, path, query, ''))
            record = {'attack_id': attack_id, 'correlation_id': attack_id, 'timestamp': storage.now(), 'payload_id': payload['id'],
                      'attack_type': payload['category'], 'payload_name': payload['name'], 'method': payload['method'],
                      'path': payload['path'], 'source': source, 'target_url': url, 'status': 'running', 'outcome': 'RUNNING',
                      'http_status': None, 'duration_ms': None, 'error': None, 'replay_of': replay_of,
                      'honeypot_confirmed': False, 'response_body': None, 'success': False}
            if entry:
                record.update(cve_id=entry['cve_id'], test_type=entry['test_type'], catalogue=entry,
                              expected_sensor_action=entry.get('expected_sensor_action'), expected_response=entry.get('expected'),
                              test_timeout=timeout, validation_result='pending', detection_status='unverified', probe_outcome='pending')
            storage.save_attack(record)
            await emit('attack', f"{record.get('cve_id') or 'Tripwire'} {payload['name']} started", attack_id, result=record)
            await emit('target', f'Target URL: {url}', attack_id, target_url=url)
            headers = {**payload.get('headers', {}), 'X-Attack-ID': attack_id}
            request_body = payload.get('form', body)
            await emit('request', f"Sending HTTP {payload['method']} {url}\nHeaders: {json.dumps(headers)}\nBody: {json.dumps(request_body)}", attack_id,
                       method=payload['method'], path=payload['path'], headers=headers, body=request_body)
            start = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                    options = {'data': payload['form']} if 'form' in payload else {'content': body}
                    if payload.get('chunked'):
                        async def bounded_chunks():
                            yield body.encode('utf-8')
                        options = {'content': bounded_chunks()}
                    response = await asyncio.wait_for(client.request(payload['method'], url, headers=headers, **options), timeout=timeout)
                record.update(http_status=response.status_code, response_body=response.text, http_success=200 <= response.status_code < 300)
                if entry and entry.get('expected'):
                    validation = catalogue.validate_response(entry, response)
                    record.update(validation=validation, success=validation['passed'], status='completed' if validation['passed'] else 'failed',
                                  outcome='SUCCESS' if validation['passed'] else 'FAILED',
                                  validation_result='response_matched' if validation['passed'] else 'response_mismatch',
                                  response_excerpt=response.text[:4096], response_truncated=len(response.text) > 4096,
                                  error=None if validation['passed'] else 'Response does not match the configured status, content type and body expectations')
                else:
                    record.update(status='completed', success=record['http_success'], outcome='SUCCESS' if record['http_success'] else 'FAILED',
                                  error=None if record['http_success'] else f'HTTP {response.status_code} response')
            except (httpx.TimeoutException, TimeoutError) as exc:
                record.update(status='failed', outcome='TIMEOUT', error=f'{type(exc).__name__}: target request timed out')
            except httpx.HTTPError as exc:
                record.update(status='failed', outcome='FAILED', error=f'{type(exc).__name__}: target unavailable or request failed')
            except ValueError as exc:
                record.update(status='failed', outcome='FAILED', error=str(exc))
            except Exception:
                record.update(status='failed', outcome='FAILED', error='Unexpected execution failure; check backend logs')
            if entry:
                record['probe_outcome'] = 'response_received' if record['http_status'] is not None else 'transport_failed'
                if record['http_status'] is None:
                    record['validation_result'] = 'not_run: transport failed'
            record['duration_ms'] = round((time.perf_counter() - start) * 1000, 1)
            storage.save_attack(record)
            if record['http_status'] is not None:
                await emit('response', f"HTTP {record['http_status']} · {record['duration_ms']} ms", attack_id, http_status=record['http_status'])
                await emit('body', record.get('response_excerpt', record['response_body']), attack_id, empty_body=not record['response_body'], truncated=record.get('response_truncated', False))
            else:
                await emit('error', record['error'], attack_id, severity='error')
            completion = f"{record['outcome']}: {payload['name']} · {record['duration_ms']} ms"
            if entry:
                completion += f". Response validation: {record['validation_result']}. Expected sensor.action: {record.get('expected_sensor_action')}; event verification pending."
            if record['error']:
                completion += ' · ' + record['error']
            await emit('complete', completion, attack_id, severity='info' if record['success'] else 'error', result=record)
            return record
        finally:
            try:
                if record and record['status'] == 'running':
                    record.update(status='interrupted', outcome='FAILED', success=False, error='Execution cancelled or backend interrupted')
                    storage.save_attack(record)
            finally:
                storage.release_execution(attack_id)

"""Approved, fixed-destination simulation service; never executes OS commands."""
import asyncio
import json
import time
from uuid import uuid4
from urllib.parse import urlsplit
import httpx
from fastapi import HTTPException
from backend import storage
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
    if lock.locked() or time.monotonic() - last_started < 1:
        raise HTTPException(429, 'Wait for the current test to finish and allow one second between launches')
    async with lock:
        last_started = time.monotonic()
        attack_id = f'ATK-{uuid4().hex[:10].upper()}'
        body = payload.get('body', '')
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        record = {'attack_id': attack_id, 'timestamp': storage.now(), 'payload_id': payload['id'], 'attack_type': payload['category'], 'payload_name': payload['name'], 'method': payload['method'], 'path': payload['path'], 'source': source, 'target_url': url, 'status': 'running', 'http_status': None, 'duration_ms': None, 'error': None, 'replay_of': replay_of, 'honeypot_confirmed': False, 'response_body': None, 'success': False}
        storage.save_attack(record)
        await emit('attack', f"{payload['name']} started", attack_id)
        await emit('target', f'Target URL: {url}', attack_id, target_url=url)
        await emit('request', f"Sending HTTP {payload['method']} {url}", attack_id, method=payload['method'], path=payload['path'], headers=payload.get('headers', {}), body=payload.get('form', body))
        start = time.perf_counter()
        try:
            headers = {**payload.get('headers', {}), 'X-Attack-ID': attack_id}
            async with httpx.AsyncClient(timeout=request_timeout(), follow_redirects=False, trust_env=False) as client:
                options = {'data': payload['form']} if 'form' in payload else {'content': body}
                response = await client.request(payload['method'], url, headers=headers, **options)
            record.update(status='completed', http_status=response.status_code, response_body=response.text, success=200 <= response.status_code < 300)
        except httpx.TimeoutException as exc:
            record.update(status='failed', error=f'{type(exc).__name__}: target request timed out')
        except httpx.HTTPError as exc:
            record.update(status='failed', error=f'{type(exc).__name__}: target unavailable or request failed')
        except ValueError as exc:
            record.update(status='failed', error=str(exc))
        except Exception:
            record.update(status='failed', error='Unexpected execution failure; check backend logs')
        record['duration_ms'] = round((time.perf_counter() - start) * 1000, 1)
        storage.save_attack(record)
        if record['status'] == 'completed':
            await emit('response', f"HTTP {record['http_status']} · {record['duration_ms']} ms", attack_id, http_status=record['http_status'])
            await emit('body', record['response_body'], attack_id, empty_body=not record['response_body'])
        else:
            await emit('error', record['error'], attack_id, severity='error')
        outcome = 'Success' if record['success'] else 'HTTP error response' if record['status'] == 'completed' else 'Failed'
        await emit('complete', f"{outcome}: {payload['name']} finished in {record['duration_ms']} ms", attack_id, severity='info' if record['success'] else 'error', result=record)
        return record

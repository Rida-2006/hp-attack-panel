import csv
import io
import random
from collections import Counter
from datetime import datetime, timezone
from time import monotonic
import httpx
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, Field
from backend import storage
from backend.config import ALLOWED_ORIGINS, HONEYPOT_NAME, validate_target
from backend.execution import execute, library, ws_manager

router = APIRouter()
health_cache = {'checked_at': None, 'last_success': None, 'status': 'unchecked', 'http_status': None}
health_time = 0.0


class Launch(BaseModel):
    payload_id: str = Field(max_length=100)


class Command(BaseModel):
    command: str = Field(min_length=1, max_length=160)


@router.get('/api/payloads')
async def payloads():
    return library()


@router.get('/api/honeypot/info')
async def info():
    return {'name': HONEYPOT_NAME, 'url': validate_target(), 'environment': 'Authorized lab', 'log_integration': False, 'retention_days': 7}


@router.get('/api/honeypot/status')
async def status():
    global health_cache, health_time
    if monotonic() - health_time < 10 and health_cache['checked_at']:
        return {**await info(), **health_cache}
    health_time = monotonic()
    checked_at = storage.now()
    try:
        async with httpx.AsyncClient(timeout=3, follow_redirects=False, trust_env=False) as client:
            result = await client.get(validate_target())
        health_cache = {**health_cache, 'status': 'connected', 'http_status': result.status_code, 'checked_at': checked_at, 'last_success': checked_at}
    except httpx.HTTPError:
        health_cache = {**health_cache, 'status': 'disconnected', 'http_status': None, 'checked_at': checked_at}
    return {**await info(), **health_cache}


@router.post('/api/attacks/random')
async def random_attack():
    return await execute(random.choice(library())['id'])


@router.post('/api/attacks/execute')
async def launch(body: Launch):
    return await execute(body.payload_id, 'library')


@router.post('/api/attacks/{attack_id}/replay')
async def replay(attack_id: str):
    record = next((a for a in storage.attacks() if a['attack_id'] == attack_id), None)
    if not record:
        raise HTTPException(404, 'History record not found')
    return await execute(record['payload_id'], 'replay', replay_of=attack_id)


@router.get('/api/attacks')
async def history():
    return storage.attacks()


@router.get('/api/events')
async def events():
    return storage.events()


@router.get('/api/analytics')
async def analytics():
    records = storage.attacks()
    completed = [a for a in records if a['status'] == 'completed']
    today = datetime.now(timezone.utc).date()
    hourly = [0] * 24
    for a in records:
        dt = datetime.fromisoformat(a['timestamp'])
        if dt.date() == today:
            hourly[dt.hour] += 1
    return {'total': len(records), 'completed': len(completed), 'failed': sum(a['status'] == 'failed' for a in records), 'average_ms': round(sum(a['duration_ms'] for a in completed) / len(completed), 1) if completed else None, 'by_type': dict(Counter(a['attack_type'] for a in records)), 'hourly': hourly, 'suspicious_events': None, 'unique_source_ips': None, 'uptime': None}


@router.post('/api/console/execute')
async def console(body: Command):
    command = ' '.join(body.command.lower().split())
    if command == 'help':
        return {'output': 'help | status | list attacks | test <category> | logs | history | clear\nApproved categories: ' + ', '.join(p['category'] for p in library()) + '\nThis is an allowlisted test console, not an operating-system shell.'}
    if command == 'status':
        return {'output': await status()}
    if command == 'list attacks':
        return {'output': [{'id': p['id'], 'category': p['category'], 'name': p['name']} for p in library()]}
    if command == 'logs':
        return {'output': storage.events()[:20]}
    if command == 'history':
        return {'output': storage.attacks()[:20]}
    if command == 'clear':
        return {'clear': True, 'output': 'Console cleared. Stored history is preserved.'}
    if command.startswith('test '):
        payload = next((p for p in library() if p['category'] == command[5:] or p['id'] == command[5:]), None)
        if payload:
            result = await execute(payload['id'], 'console')
            return {'output': result, 'result': result}
    raise HTTPException(400, 'Unsupported command. Type help for the approved commands.')


@router.get('/api/reports/attacks.csv')
async def report():
    out = io.StringIO(newline='')
    fields = ['attack_id', 'timestamp', 'attack_type', 'payload_id', 'method', 'path', 'status', 'http_status', 'duration_ms', 'source', 'honeypot_confirmed', 'error']
    writer = csv.DictWriter(out, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for record in storage.attacks():
        writer.writerow({k: ("'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')) else v) for k, v in record.items()})
    return Response(out.getvalue(), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename="honeypot-attack-history.csv"'})


@router.post('/fire-random')
async def legacy_random():
    result = await random_attack()
    return {**result, 'status_code': result['http_status']}


@router.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    if websocket.client.host not in ('127.0.0.1', '::1', 'testclient') or websocket.headers.get('origin') not in ALLOWED_ORIGINS:
        await websocket.close(code=1008)
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(websocket)

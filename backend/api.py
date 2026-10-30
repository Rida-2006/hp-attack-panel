from time import monotonic
import httpx
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from backend import storage, catalogue
from backend.config import ALLOWED_ORIGINS, HONEYPOT_NAME, validate_target, test_target_url, tailscale_request
from backend.execution import execute, execute_test_post, execute_catalogue, library, ws_manager

router = APIRouter()
health_cache = {'checked_at': None, 'last_success': None, 'status': 'unchecked', 'http_status': None}
health_time = 0.0
health_target = None


class Launch(BaseModel):
    payload_id: str = Field(max_length=100)


class Command(BaseModel):
    command: str = Field(min_length=1, max_length=160)


@router.get('/api/catalogue')
async def cve_catalogue():
    return catalogue.definitions(storage.attacks())


@router.get('/api/execution/status')
async def execution_status():
    active = storage.active_execution()
    return {'active': active, 'busy': active is not None}


@router.get('/api/payloads')
async def payloads():
    return library()


@router.get('/api/honeypot/info')
async def info():
    try:
        url = test_target_url()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {'name': HONEYPOT_NAME, 'url': url, 'environment': 'Authorized lab', 'log_integration': False, 'retention_days': 7}


@router.get('/api/honeypot/status')
async def status():
    global health_cache, health_time, health_target
    target_info = await info()
    if monotonic() - health_time < 10 and health_cache['checked_at'] and health_target == target_info['url']:
        return {**target_info, **health_cache}
    if health_target != target_info['url']:
        health_cache['last_success'] = None
    health_target = target_info['url']
    health_time = monotonic()
    checked_at = storage.now()
    try:
        async with httpx.AsyncClient(timeout=3, follow_redirects=False, trust_env=False) as client:
            result = await client.get(target_info['url'])
        health_cache = {**health_cache, 'status': 'connected', 'http_status': result.status_code, 'checked_at': checked_at, 'last_success': checked_at}
    except httpx.HTTPError:
        health_cache = {**health_cache, 'status': 'disconnected', 'http_status': None, 'checked_at': checked_at}
    return {**target_info, **health_cache}


@router.post('/api/catalogue/{test_id}/execute')
async def run_tripwire(test_id: str):
    return await execute_catalogue(test_id, source='catalogue')


@router.post('/api/attacks/connectivity')
async def connectivity_check():
    return await execute_test_post(source='connectivity-check')


@router.post('/api/attacks/random')
async def random_attack():
    return await execute_catalogue()


@router.post('/api/attacks/execute')
async def launch(body: Launch):
    return await execute(body.payload_id, 'library')


@router.post('/api/attacks/{attack_id}/replay')
async def replay(attack_id: str):
    record = next((a for a in storage.attacks() if a['attack_id'] == attack_id), None)
    if not record:
        raise HTTPException(404, 'History record not found')
    if record.get('catalogue'):
        return await execute_catalogue(record['payload_id'], 'replay', attack_id)
    if record['payload_id'] == 'harmless-post':
        return await execute_test_post('replay', replay_of=attack_id)
    return await execute(record['payload_id'], 'replay', replay_of=attack_id)


@router.get('/api/attacks')
async def history():
    return storage.attacks()


@router.get('/api/events')
async def events():
    return storage.events()


@router.post('/api/console/execute')
async def console(body: Command):
    command = ' '.join(body.command.lower().split())
    if command == 'help':
        return {'output': 'help | status | list attacks | list tests | test <category or tripwire ID> | logs | history | clear\nApproved categories: ' + ', '.join(p['category'] for p in library()) + '\nThis is an allowlisted test console, not an operating-system shell.'}
    if command == 'status':
        return {'output': await status()}
    if command == 'list tests':
        return {'output': catalogue.definitions(storage.attacks())}
    if command == 'list attacks':
        return {'output': [{'id': p['id'], 'category': p['category'], 'name': p['name']} for p in library()]}
    if command == 'logs':
        return {'output': storage.events()[:20]}
    if command == 'history':
        return {'output': storage.attacks()[:20]}
    if command == 'clear':
        return {'clear': True, 'output': 'Console cleared. Stored history is preserved.'}
    if command.startswith('test ') and any(e['id'] == command[5:] and e['enabled'] for e in catalogue.TESTS):
        result = await execute_catalogue(command[5:], source='console')
        return {'output': result, 'result': result}
    if command.startswith('test '):
        payload = next((p for p in library() if p['category'] == command[5:] or p['id'] == command[5:]), None)
        if payload:
            result = await execute(payload['id'], 'console')
            return {'output': result, 'result': result}
    raise HTTPException(400, 'Unsupported command. Type help for the approved commands.')


@router.post('/fire-random')
async def legacy_random():
    result = await random_attack()
    return {**result, 'status_code': result['http_status']}


@router.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    if websocket.client.host not in ('127.0.0.1', '::1', 'testclient') or websocket.headers.get('origin') not in ALLOWED_ORIGINS:
        await websocket.close(code=1008)
        return
    if websocket.url.hostname not in ('localhost', '127.0.0.1', '::1', 'testserver') and not tailscale_request(websocket):
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

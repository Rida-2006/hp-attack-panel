"""Local control of the fixed WireGuard Windows service; never reads keys."""
import ipaddress
import os
import subprocess
import time
from uuid import uuid4

import httpx
from fastapi import APIRouter, Header, HTTPException
from backend import storage

router = APIRouter(prefix='/api/vpn')
SERVICE = os.environ.get('WIREGUARD_SERVICE_NAME', 'WireGuardTunnel$wg2')
STATES = {1: 'stopped', 2: 'starting', 3: 'stopping', 4: 'running',
          5: 'starting', 6: 'stopping', 7: 'paused'}


def _sc(*args):
    try:
        return subprocess.run(['sc.exe', *args], capture_output=True, text=True,
                              timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(503, 'Windows service control is unavailable or timed out') from exc


def _state():
    import re
    result = _sc('query', SERVICE)
    if result.returncode == 1060:
        return 'not_installed'
    if result.returncode:
        raise HTTPException(503, 'Unable to query the WireGuard service')
    match = re.search(r'STATE\s*:\s*(\d+)', result.stdout)
    return STATES.get(int(match[1]), 'unknown') if match else 'unknown'


@router.get('/status')
def status():
    return {'service': SERVICE, 'state': _state()}


def _change(action, expected, header):
    if header != '1':
        raise HTTPException(403, 'Missing X-VPN-Control header')
    state = _state()
    if state == 'not_installed':
        raise HTTPException(409, 'Install the wg2 WireGuard tunnel service first')
    if state == expected:
        result = _sc(action, SERVICE)
        if result.returncode == 5:
            raise HTTPException(403, 'Run the backend as administrator to control WireGuard')
        if result.returncode not in (0, 1056 if action == 'start' else 1062):
            raise HTTPException(503, 'WireGuard service operation failed; check its Windows log')
    return status()


@router.post('/start')
def start(x_vpn_control: str | None = Header(None)):
    return _change('start', 'stopped', x_vpn_control)


@router.post('/stop')
def stop(x_vpn_control: str | None = Header(None)):
    return _change('stop', 'running', x_vpn_control)


@router.get('/ip')
def public_ip():
    try:
        response = httpx.get('https://api4.ipify.org', timeout=4, trust_env=False)
        response.raise_for_status()
        value = str(ipaddress.IPv4Address(response.text.strip()))
        return {'ip': value}
    except (httpx.HTTPError, ValueError):
        return {'ip': None}


def _wait_state(expected):
    for _ in range(20):
        if _state() == expected:
            return
        time.sleep(.5)
    raise HTTPException(503, f'WireGuard did not reach {expected} state')


@router.post('/rotate')
def rotate(x_vpn_control: str | None = Header(None)):
    """Reconnect the installed tunnel; report observed change, never invent an IP."""
    if x_vpn_control != '1':
        raise HTTPException(403, 'Missing X-VPN-Control header')
    lease = 'VPN-' + uuid4().hex
    if not storage.claim_execution(lease, 240):
        raise HTTPException(409, 'Wait for the active attack or VPN operation to finish')
    touched = False
    try:
        state = _state()
        if state not in ('running', 'stopped'):
            raise HTTPException(409, 'WireGuard tunnel is unavailable or changing state')
        before = public_ip()['ip']
        if not before:
            raise HTTPException(503, 'Cannot verify the current public IP; network settings were not changed')
        if state == 'running':
            touched = True
            _change('stop', 'running', '1')
            _wait_state('stopped')
        touched = True
        _change('start', 'stopped', '1')
        _wait_state('running')
        after = None
        for _ in range(3):
            time.sleep(1)
            after = public_ip()['ip']
            if after:
                break
        if not after:
            raise HTTPException(503, 'VPN has no verified internet connection')
        if after == before and state == 'stopped':
            _change('stop', 'running', '1')
            _wait_state('stopped')
            return {'changed': False, 'before': before, 'ip': after,
                    'message': 'IP unchanged; VPN stopped to restore the original connection. This tunnel has one configured exit.'}
        return {'changed': after != before, 'before': before, 'ip': after,
                'message': f'Public IP changed: {after}' if after != before else
                f'IP unchanged: {after}. Reconnecting a single exit does not provide a new address.'}
    except HTTPException as exc:
        if touched:
            try:
                _change('stop', 'running', '1')
                _wait_state('stopped')
            except HTTPException:
                raise HTTPException(503, 'VPN recovery failed. Use Turn VPN off or deactivate wg2 in WireGuard to restore connectivity') from exc
            raise HTTPException(exc.status_code, f'{exc.detail}. VPN stopped to restore direct connectivity') from exc
        raise
    finally:
        storage.release_execution(lease)

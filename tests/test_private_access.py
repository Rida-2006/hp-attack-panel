import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.app import app
from backend.config import ALLOWED_ORIGINS
from starlette.websockets import WebSocketDisconnect


class PrivateAccessTests(unittest.TestCase):
    def setUp(self):
        self.host = 'panel.example.ts.net'
        self.origin = 'https://' + self.host
        self.enterContext(patch.dict(os.environ, {'PANEL_TAILSCALE_HOST': self.host}))
        ALLOWED_ORIGINS.add(self.origin)
        self.addCleanup(ALLOWED_ORIGINS.discard, self.origin)
        self.client = TestClient(app, base_url=self.origin)
        self.headers = {'Tailscale-User-Login': 'tester@example.test', 'X-Forwarded-Proto': 'https', 'Origin': self.origin}

    def test_authenticated_proxy_allowed(self):
        self.assertEqual(self.client.get('/api/honeypot/info', headers=self.headers).status_code, 200)

    def test_missing_identity_denied(self):
        self.assertEqual(self.client.get('/api/honeypot/info').status_code, 403)

    def test_foreign_origin_denied(self):
        self.assertEqual(self.client.post('/api/attacks/random', headers={**self.headers, 'Origin':'https://untrusted.example'}).status_code, 403)

    def test_remote_vpn_control_denied(self):
        self.assertEqual(self.client.post('/api/vpn/rotate', headers={**self.headers, 'X-VPN-Control':'1'}).status_code, 403)

    def test_private_websocket_stream(self):
        with self.client.websocket_connect('wss://' + self.host + '/ws', headers=self.headers) as ws:
            ws.send_text('ping')

    def test_websocket_without_identity_denied(self):
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect('wss://' + self.host + '/ws', headers={'Origin':self.origin}):
                pass

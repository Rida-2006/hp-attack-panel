import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
from fastapi.testclient import TestClient
from backend import config, execution, storage
from backend.app import app


class PanelIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(storage, 'DB_FILE', Path(self.temp.name) / 'test.sqlite3')
        self.db_patch.start()
        execution.last_started = 0
        self.client_context = TestClient(app, client=('127.0.0.1', 51000))
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.db_patch.stop()
        self.temp.cleanup()

    def mock_target(self, status=200):
        client = AsyncMock()
        client.request.return_value = httpx.Response(status)
        client.get.return_value = httpx.Response(status)
        context = AsyncMock()
        context.__aenter__.return_value = client
        return patch('backend.execution.httpx.AsyncClient', return_value=context), client

    def test_library_and_invalid_commands(self):
        self.assertEqual(len(self.client.get('/api/payloads').json()), 6)
        for command in ('whoami', 'test sqli; whoami', 'curl http://example.com', 'test unknown'):
            response = self.client.post('/api/console/execute', json={'command': command})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get('/api/attacks').json(), [])

    def test_execution_persistence_and_correlation(self):
        mock, target = self.mock_target(403)
        with mock:
            response = self.client.post('/api/attacks/execute', json={'payload_id': 'p-005'})
        self.assertEqual(response.status_code, 200)
        record = response.json()
        self.assertEqual(record['http_status'], 403)
        self.assertEqual(record['status'], 'completed')
        self.assertFalse(record['honeypot_confirmed'])
        self.assertEqual(target.request.call_args.kwargs['headers']['X-Attack-ID'], record['attack_id'])
        self.assertEqual(self.client.get('/api/attacks').json()[0], record)
        self.assertEqual({e['type'] for e in self.client.get('/api/events').json()}, {'attack', 'request', 'response'})
        with TestClient(app, client=('127.0.0.1', 51001)) as second:
            self.assertEqual(second.get('/api/attacks').json()[0]['attack_id'], record['attack_id'])

    def test_failure_is_recorded(self):
        mock, target = self.mock_target()
        target.request.side_effect = httpx.ConnectError('offline')
        with mock:
            result = self.client.post('/api/attacks/random', json={}).json()
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['http_status'])
        self.assertIsNotNone(result['duration_ms'])
        self.assertEqual(self.client.get('/api/events').json()[0]['severity'], 'error')

    def test_console_replay_and_rate_limit(self):
        mock, _ = self.mock_target()
        with mock:
            first = self.client.post('/api/console/execute', json={'command': 'test sqli'}).json()['result']
            self.assertEqual(first['source'], 'console')
            self.assertEqual(self.client.post('/api/attacks/random', json={}).status_code, 429)
            execution.last_started = 0
            replay = self.client.post(f"/api/attacks/{first['attack_id']}/replay", json={}).json()
        self.assertEqual(replay['payload_id'], first['payload_id'])
        self.assertEqual(replay['replay_of'], first['attack_id'])
        self.assertNotEqual(replay['attack_id'], first['attack_id'])
        self.assertEqual(self.client.post('/api/attacks/missing/replay', json={}).status_code, 404)

    def test_unknown_payload_and_body_validation(self):
        self.assertEqual(self.client.post('/api/attacks/execute', json={'payload_id': 'missing'}).status_code, 404)
        self.assertEqual(self.client.post('/api/console/execute', json={'command': ''}).status_code, 422)
        self.assertEqual(self.client.post('/api/console/execute', json={'command': 'x' * 161}).status_code, 422)

    def test_target_and_browser_access_controls(self):
        with patch.object(config, 'HONEYPOT_BASE_URL', 'https://example.com'):
            with self.assertRaises(ValueError):
                config.validate_target()
        for origin in ('https://untrusted.example', 'null'):
            self.assertEqual(self.client.post('/api/attacks/random', json={}, headers={'origin': origin}).status_code, 403)
        self.assertEqual(self.client.get('/api/attacks', headers={'host': 'untrusted.example'}).status_code, 403)
        self.assertEqual(self.client.get('/api/attacks', headers={'origin': 'http://localhost:5173'}).status_code, 200)

    def test_remote_client_blocked(self):
        with TestClient(app, client=('192.0.2.2', 51000)) as remote:
            self.assertEqual(remote.get('/api/attacks').status_code, 403)

    def test_websocket_stream(self):
        mock, _ = self.mock_target()
        with self.client.websocket_connect('/ws', headers={'origin': 'http://localhost:5173'}) as socket:
            with mock:
                result = self.client.post('/api/attacks/random', json={}).json()
            events = [socket.receive_json() for _ in range(3)]
        self.assertEqual([e['type'] for e in events], ['attack', 'request', 'response'])
        self.assertTrue(all(e['attack_id'] == result['attack_id'] for e in events))
        self.assertEqual(events[-1]['result']['attack_id'], result['attack_id'])

    def test_monitoring_routes_removed_and_execution_retention(self):
        mock, _ = self.mock_target()
        with mock:
            result = self.client.post('/api/attacks/random', json={}).json()
        self.assertEqual(self.client.get('/api/reports/attacks.csv').status_code, 404)
        self.assertEqual(self.client.get('/api/analytics').status_code, 404)
        old = {**result, 'attack_id': 'OLD', 'timestamp': '2020-01-01T00:00:00+00:00'}
        storage.save_attack(old)
        self.assertFalse(any(a['attack_id'] == 'OLD' for a in storage.attacks()))


if __name__ == '__main__':
    unittest.main()

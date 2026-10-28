import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import execution, storage
from backend.app import app
from tests.mock_http_server import MockTarget


class RealLocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), MockTarget)
        cls.server.daemon_threads = True
        cls.server.received = []
        cls.thread = threading.Thread(target=lambda: cls.server.serve_forever(poll_interval=.05), daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = f'http://127.0.0.1:{self.server.server_port}'
        self.db = patch.object(storage, 'DB_FILE', Path(self.temp.name)/'http-test.sqlite3')
        self.db.start()
        self.env = patch.dict(os.environ, {'TEST_TARGET_URL': self.base + '/large?mode=authorized', 'TEST_REQUEST_TIMEOUT': '2'})
        self.env.start()
        execution.last_started = 0
        self.server.received.clear()
        self.client = TestClient(app, client=('127.0.0.1', 51000))

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.db.stop()
        self.temp.cleanup()

    def test_actual_post_and_full_response_stream(self):
        with self.client.websocket_connect('/ws', headers={'origin': 'http://localhost:5173'}) as ws:
            response = self.client.post('/api/attacks/random', json={})
            messages = [ws.receive_json() for _ in range(6)]
        self.assertEqual(response.status_code, 200)
        record = response.json()
        self.assertEqual(len(self.server.received), 1)
        sent = self.server.received[0]
        self.assertEqual(sent['method'], 'POST')
        self.assertEqual(sent['path'], '/large?mode=authorized')
        self.assertEqual(sent['form'], {'content': ['Honeyguard harmless POST test']})
        self.assertIn('application/x-www-form-urlencoded', sent['headers']['Content-Type'])
        self.assertEqual(sent['headers']['X-Attack-ID'], record['attack_id'])
        self.assertEqual(record['response_body'], sent['response_body'])
        self.assertGreater(len(record['response_body']), 4096)
        self.assertIn('FULL_RESPONSE_END', record['response_body'])
        self.assertTrue(record['success'])
        self.assertEqual([e['type'] for e in messages], ['attack', 'target', 'request', 'response', 'body', 'complete'])
        self.assertEqual(messages[4]['message'], sent['response_body'])
        self.assertEqual(messages[5]['result'], record)
        self.assertTrue(all(e['attack_id'] == record['attack_id'] for e in messages))
        self.assertFalse(any(e.get('source') == 'simulation' for e in messages))
        stored = self.client.get('/api/events').json()
        self.assertEqual(next(e for e in stored if e['type'] == 'body')['message'], sent['response_body'])

    def test_http_error_status_preserves_body(self):
        os.environ['TEST_TARGET_URL'] = self.base + '/status/503'
        record = self.client.post('/api/attacks/random', json={}).json()
        self.assertEqual(record['http_status'], 503)
        self.assertFalse(record['success'])
        self.assertEqual(record['status'], 'completed')
        self.assertEqual(record['response_body'], self.server.received[0]['response_body'])
        self.assertEqual(self.client.get('/api/events').json()[0]['severity'], 'error')

    def test_real_timeout_is_recorded(self):
        os.environ['TEST_TARGET_URL'] = self.base + '/slow'
        os.environ['TEST_REQUEST_TIMEOUT'] = '.05'
        record = self.client.post('/api/attacks/random', json={}).json()
        self.assertEqual(record['status'], 'failed')
        self.assertIn('timed out', record['error'])
        self.assertIsNone(record['response_body'])
        self.assertIsNone(record['http_status'])
        self.assertFalse(record['success'])
        self.assertTrue(any(e['type'] == 'error' and 'timed out' in e['message'] for e in self.client.get('/api/events').json()))

    def test_real_connection_failure_is_recorded(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            unused_port = reserved.getsockname()[1]
        os.environ['TEST_TARGET_URL'] = f'http://127.0.0.1:{unused_port}/echo'
        record = self.client.post('/api/attacks/random', json={}).json()
        self.assertEqual(record['status'], 'failed')
        self.assertRegex(record['error'], r'Connect(Error|Timeout)')
        self.assertFalse(record['success'])
        self.assertIsNone(record['http_status'])

    def test_invalid_target_and_timeout_are_clear_configuration_errors(self):
        for target in ('', 'https://example.com/test', 'http://127.0.0.1:bad/', 'http://user:secret@127.0.0.1/echo', 'http://127.0.0.1/echo#fragment'):
            os.environ['TEST_TARGET_URL'] = target
            result = self.client.post('/api/attacks/random', json={})
            self.assertEqual(result.status_code, 400)
            self.assertIn('TEST_TARGET_URL', result.json()['detail'])
        os.environ['TEST_TARGET_URL'] = self.base + '/echo'
        for timeout in ('not-a-number', 'nan', '0', '61'):
            os.environ['TEST_REQUEST_TIMEOUT'] = timeout
            self.assertEqual(self.client.post('/api/attacks/random', json={}).status_code, 400)
        self.assertEqual(self.server.received, [])


if __name__ == '__main__':
    unittest.main()

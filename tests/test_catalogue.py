"""Real HTTP tests against the exact provided Python honeypot and its event log."""
import concurrent.futures
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import catalogue, execution, storage
from backend.app import app
from tests.local_honeypot import running_honeypot, events


class HoneypotCatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.log = Path(cls.directory.name) / 'events.jsonl'
        cls.faults = {}
        cls.server_context = running_honeypot(cls.log, faults=cls.faults)
        cls.server, cls.source = cls.server_context.__enter__()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server_context.__exit__(None, None, None)
        cls.directory.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = patch.object(storage, 'DB_FILE', Path(self.temp.name)/'panel.sqlite3')
        self.db.start()
        self.env = patch.dict(os.environ, {'TEST_TARGET_URL': self.base, 'TEST_REQUEST_TIMEOUT': '2'})
        self.env.start()
        execution.last_started = 0
        self.faults.clear()
        self.client = TestClient(app, client=('127.0.0.1', 51000))

    def tearDown(self):
        self.client.close()
        self.db.stop()
        self.env.stop()
        self.temp.cleanup()

    def run_entry(self, entry):
        execution.last_started = 0
        response = self.client.post('/api/catalogue/' + entry['id'] + '/execute', json={})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def event_for(self, attack_id):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            matches = [e for e in events(self.log) if e['http']['request']['headers'].get('X-Attack-ID') == attack_id]
            if matches:
                self.assertEqual(len(matches), 1)
                return matches[0]
            time.sleep(.01)
        self.fail('No honeypot event for ' + attack_id)

    def verify_case(self, entry):
        record = self.run_entry(entry)
        self.assertEqual(record['outcome'], 'SUCCESS', record)
        self.assertTrue(record['success'])
        self.assertTrue(record['validation']['passed'])
        self.assertEqual(record['http_status'], entry['expected']['status'])
        self.assertEqual(record['expected_sensor_action'], entry['expected_sensor_action'])
        self.assertEqual(record['detection_status'], 'unverified')
        self.assertFalse(record['honeypot_confirmed'])
        event = self.event_for(record['attack_id'])
        self.assertEqual(event['sensor']['action'], entry['expected_sensor_action'])
        self.assertEqual(event['http']['request']['method'], entry['method'])
        self.assertIn(record['attack_id'], event['url']['query'])
        self.assertEqual(event['http']['response']['status_code'], record['http_status'])
        self.assertEqual(event['http']['request']['headers']['X-HoneyGuard-Test'], entry['id'])
        self.assertFalse(self.client.get('/api/execution/status').json()['busy'])
        return record, event

    def test_catalogue_schema_and_cve_mapping(self):
        definitions = self.client.get('/api/catalogue').json()
        active = [e for e in definitions if e['enabled']]
        self.assertEqual(len(active), 22)
        self.assertEqual(len({e['id'] for e in active}), 22)
        self.assertEqual([e['cve_id'] for e in active if e['cve_id']], ['CVE-2024-4577','CVE-2026-109618','CVE-2026-109619'])
        for e in active:
            for key in ('method', 'path', 'headers', 'body', 'timeout', 'expected_sensor_action', 'expected', 'correlation'):
                self.assertIn(key, e)

    def test_2026_chunked_wire_format_and_actual_action(self):
        entry = next(e for e in catalogue.TRIPWIRES if e['id']=='tw-22-2026-chunked')
        record, event = self.verify_case(entry)
        request = event['http']['request']
        self.assertEqual(request['transfer_encoding'],'chunked')
        self.assertNotIn('Content-Length',request['headers'])
        self.assertEqual(request['body']['content'],entry['body'])
        self.assertNotIn('PHP_SESSION_UPLOAD_PROGRESS',request['multipart']['fields'])
        self.assertLess(request['body']['bytes'],1024)
        self.assertEqual(event['sensor']['action'],'lure:multipart_progress')

    def test_2026_results_limit_claims_to_associated_traffic(self):
        entry = next(e for e in catalogue.TRIPWIRES if e['id']=='tw-21-2026-progress')
        result, event = self.verify_case(entry)
        self.assertEqual(result['catalogue']['coverage_level'],'associated_tripwire_only')
        self.assertIn('not a CVE-specific detector',result['catalogue']['coverage_note'])
        self.assertEqual(result['detection_status'],'unverified')
        self.assertFalse(result['honeypot_confirmed'])
        self.assertLess(event['http']['request']['body']['bytes'],1024)

    def test_canary_issue_then_replay_session(self):
        first, event = self.verify_case(catalogue.TRIPWIRES[1])
        self.assertTrue(event['session']['canary_issued'])
        second, replay = self.verify_case(catalogue.TRIPWIRES[14])
        self.assertNotEqual(first['attack_id'], second['attack_id'])
        self.assertTrue(replay['session']['canary_replayed'])
        self.assertTrue(replay['session']['canary_issued'])

    def test_random_selection_and_websocket_stream(self):
        entry = catalogue.TRIPWIRES[-2]
        with self.client.websocket_connect('/ws', headers={'origin': 'http://localhost:5173'}) as ws:
            with patch('backend.catalogue.random.choice', return_value=entry) as selection:
                response = self.client.post('/api/attacks/random', json={}).json()
            frames = [ws.receive_json() for _ in range(6)]
        selection.assert_called_once()
        self.assertTrue(all(e['enabled'] for e in selection.call_args.args[0]))
        self.assertEqual(response['payload_id'], entry['id'])
        self.assertEqual([f['type'] for f in frames], ['attack', 'target', 'request', 'response', 'body', 'complete'])
        self.assertEqual(frames[-1]['result']['outcome'], 'SUCCESS')
        self.assertEqual(frames[4]['message'], response['response_excerpt'])
        self.assertTrue(all(f['attack_id'] == response['attack_id'] for f in frames))
        self.assertEqual(self.event_for(response['attack_id'])['sensor']['action'], entry['expected_sensor_action'])

    def test_unique_ids_and_generic_replay(self):
        first = self.run_entry(catalogue.TRIPWIRES[7])
        execution.last_started = 0
        second = self.client.post('/api/attacks/' + first['attack_id'] + '/replay', json={}).json()
        self.assertNotEqual(first['attack_id'], second['attack_id'])
        self.assertEqual(second['payload_id'], first['payload_id'])
        self.assertEqual(second['replay_of'], first['attack_id'])
        self.assertEqual(second['outcome'], 'SUCCESS')
        self.event_for(second['attack_id'])

    def test_mismatch_is_failed_not_http_success(self):
        self.faults['status'] = 200
        record = self.run_entry(catalogue.TRIPWIRES[7])
        self.assertTrue(record['http_success'])
        self.assertFalse(record['success'])
        self.assertEqual(record['outcome'], 'FAILED')
        self.assertFalse(record['validation']['checks']['body'])
        self.assertFalse(self.client.get('/api/execution/status').json()['busy'])

    def test_timeout_releases_lock(self):
        self.faults['delay'] = .3
        os.environ['TEST_REQUEST_TIMEOUT'] = '.05'
        record = self.run_entry(catalogue.TRIPWIRES[7])
        self.assertEqual(record['outcome'], 'TIMEOUT')
        self.assertFalse(self.client.get('/api/execution/status').json()['busy'])
        self.faults.clear()
        os.environ['TEST_REQUEST_TIMEOUT'] = '2'
        self.assertEqual(self.run_entry(catalogue.TRIPWIRES[7])['outcome'], 'SUCCESS')

    def test_network_error(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        os.environ['TEST_TARGET_URL'] = f'http://127.0.0.1:{port}'
        record = self.run_entry(catalogue.TRIPWIRES[7])
        self.assertIn(record['outcome'], ('FAILED', 'TIMEOUT'))
        self.assertIsNone(record['http_status'])
        self.assertFalse(self.client.get('/api/execution/status').json()['busy'])

    def test_decide_priority_against_real_http(self):
        import httpx
        combinations = [
            ('/.env', 'whoami', {}, 'lure:config_canary'),
            ('/diagnostics.php', 'print(7*7) whoami', {}, 'primitive:math_verify'),
            ('/.env', 'whoami', {'X-Canary': 'canary_token_99a8b7c6'}, 'lure:canary_replay'),
        ]
        for index, (path, body, headers, action) in enumerate(combinations):
            attack_id = f'PRIORITY-{index}-{time.time_ns()}'
            response = httpx.post(self.base+path, content=body, headers={**headers,'X-Attack-ID':attack_id},trust_env=False)
            self.assertEqual(response.status_code,200)
            self.assertEqual(self.event_for(attack_id)['sensor']['action'],action)

    def test_connect_error_classification(self):
        from unittest.mock import AsyncMock
        import httpx
        client = AsyncMock()
        client.request.side_effect = httpx.ConnectError('Explicit disconnected target')
        context = AsyncMock()
        context.__aenter__.return_value = client
        with patch('backend.execution.httpx.AsyncClient',return_value=context):
            result = self.run_entry(catalogue.TRIPWIRES[7])
        self.assertEqual(result['outcome'],'FAILED')
        self.assertIn('ConnectError',result['error'])
        self.assertFalse(self.client.get('/api/execution/status').json()['busy'])

    def test_active_test_blocks_other_clients_and_routes(self):
        self.faults['delay'] = .5
        with self.client as first, concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(first.post, '/api/catalogue/tw-08-user/execute', json={})
            deadline = time.monotonic()+2
            while not first.get('/api/execution/status').json()['busy'] and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertTrue(first.get('/api/execution/status').json()['busy'])
            with TestClient(app, client=('127.0.0.1', 51001)) as second:
                for path, body in [('/api/attacks/random', {}), ('/api/catalogue/tw-07-identity/execute', {}),
                                   ('/api/console/execute', {'command': 'test sqli'}), ('/api/attacks/execute', {'payload_id':'p-005'})]:
                    self.assertEqual(second.post(path, json=body).status_code, 429)
                self.assertTrue(second.get('/api/execution/status').json()['busy'])
            self.assertEqual(future.result(timeout=5).json()['outcome'], 'SUCCESS')
            self.assertFalse(first.get('/api/execution/status').json()['busy'])

    def test_builder_cannot_change_origin(self):
        builder = catalogue.fixed
        with patch.dict(catalogue.MODULES, {'fixed': lambda e,u: {**builder(e,u), 'request_url':'https://example.com/'}}):
            self.assertEqual(self.client.post('/api/attacks/random', json={}).status_code,400)

    def test_disabled_catalogue(self):
        with patch('backend.catalogue.TESTS', [{**e, 'enabled':False} for e in catalogue.TESTS]):
            self.assertEqual(self.client.post('/api/attacks/random',json={}).status_code,409)
        self.assertEqual(self.client.post('/api/catalogue/missing/execute', json={}).status_code,404)

    def test_console_tripwire_and_approved_commands(self):
        self.assertIn('output',self.client.post('/api/console/execute',json={'command':'help'}).json())
        self.assertEqual(len(self.client.post('/api/console/execute',json={'command':'list tests'}).json()['output']),len(catalogue.TESTS))
        result = self.client.post('/api/console/execute',json={'command':'test tw-08-user'}).json()['result']
        self.assertEqual(result['outcome'],'SUCCESS')
        self.assertEqual(self.client.post('/api/console/execute',json={'command':'whoami'}).status_code,400)

    def test_durable_lease_and_expiry(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            claimed = list(pool.map(lambda i:storage.claim_execution(f'RACE-{i}',60), range(8)))
        self.assertEqual(sum(claimed),1)
        storage.release_execution(storage.active_execution()['attack_id'])
        self.assertTrue(storage.claim_execution('EXPIRED',-1))
        storage.save_attack({'attack_id':'EXPIRED','timestamp':storage.now(),'status':'running'})
        self.assertIsNone(storage.active_execution())
        self.assertEqual(storage.attacks()[0]['status'],'interrupted')
        self.assertEqual(storage.attacks()[0]['outcome'],'FAILED')


# Each declared tripwire gets its own independent HTTP + real-event assertion.
for entry in catalogue.TRIPWIRES:
    def check(self, definition=entry):
        self.verify_case(definition)
    setattr(HoneypotCatalogueTests, 'test_case_' + entry['id'].replace('-', '_'), check)


if __name__ == '__main__':
    unittest.main()

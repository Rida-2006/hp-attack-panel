import subprocess
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.app import app
from backend import vpn


class VpnTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_missing_header_never_runs_service_command(self):
        with patch.object(vpn, '_sc') as command:
            self.assertEqual(self.client.post('/api/vpn/start').status_code, 403)
            command.assert_not_called()

    def test_foreign_origin_blocked(self):
        with patch.object(vpn, '_sc') as command:
            response = self.client.post('/api/vpn/start', headers={
                'Origin': 'https://untrusted.example', 'X-VPN-Control': '1'})
            self.assertEqual(response.status_code, 403)
            command.assert_not_called()

    def test_fixed_service_start_and_pending_status(self):
        results = [subprocess.CompletedProcess([], 0, 'STATE : 1 STOPPED', ''),
                   subprocess.CompletedProcess([], 0, '', ''),
                   subprocess.CompletedProcess([], 0, 'STATE : 2 START_PENDING', '')]
        with patch.object(vpn, '_sc', side_effect=results) as command:
            response = self.client.post('/api/vpn/start', headers={'X-VPN-Control': '1'})
            self.assertEqual(response.json()['state'], 'starting')
            self.assertEqual(command.call_args_list[1].args, ('start', vpn.SERVICE))

    def test_access_denied_is_actionable(self):
        with patch.object(vpn, '_state', return_value='stopped'), patch.object(
                vpn, '_sc', return_value=subprocess.CompletedProcess([], 5, '', '')):
            response = self.client.post('/api/vpn/start', headers={'X-VPN-Control': '1'})
            self.assertEqual(response.status_code, 403)
            self.assertIn('administrator', response.json()['detail'])

    def test_missing_service(self):
        with patch.object(vpn, '_sc', return_value=subprocess.CompletedProcess([], 1060, '', '')):
            self.assertEqual(self.client.get('/api/vpn/status').json()['state'], 'not_installed')

    def test_rotate_missing_header(self):
        with patch.object(vpn, '_sc') as command:
            self.assertEqual(self.client.post('/api/vpn/rotate').status_code, 403)
            command.assert_not_called()

    def test_rotate_respects_execution_lock(self):
        with patch.object(vpn.storage, 'claim_execution', return_value=False), patch.object(vpn, '_sc') as command:
            self.assertEqual(self.client.post('/api/vpn/rotate', headers={'X-VPN-Control':'1'}).status_code, 409)
            command.assert_not_called()

    def rotation(self, ips):
        self.enterContext(patch.object(vpn.storage, 'claim_execution', return_value=True))
        release = self.enterContext(patch.object(vpn.storage, 'release_execution'))
        self.enterContext(patch.object(vpn, '_state', return_value='stopped'))
        self.enterContext(patch.object(vpn, '_wait_state'))
        self.enterContext(patch.object(vpn.time, 'sleep'))
        self.enterContext(patch.object(vpn, 'public_ip', side_effect=[{'ip':ip} for ip in ips]))
        change = self.enterContext(patch.object(vpn, '_change'))
        return change, release

    def test_rotation_reports_observed_ip(self):
        change, release = self.rotation(['192.0.2.1','192.0.2.2'])
        response = self.client.post('/api/vpn/rotate', headers={'X-VPN-Control':'1'})
        self.assertTrue(response.json()['changed'])
        self.assertEqual(response.json()['ip'], '192.0.2.2')
        change.assert_called_once_with('start','stopped','1')
        release.assert_called_once()

    def test_same_ip_restores_original_connection(self):
        change, release = self.rotation(['192.0.2.1','192.0.2.1'])
        response = self.client.post('/api/vpn/rotate', headers={'X-VPN-Control':'1'})
        self.assertFalse(response.json()['changed'])
        self.assertIn('IP unchanged', response.json()['message'])
        self.assertEqual(change.call_args.args, ('stop','running','1'))
        release.assert_called_once()

    def test_connectivity_loss_stops_tunnel(self):
        change, release = self.rotation(['192.0.2.1',None,None,None])
        response = self.client.post('/api/vpn/rotate', headers={'X-VPN-Control':'1'})
        self.assertEqual(response.status_code,503)
        self.assertIn('restore direct connectivity',response.json()['detail'])
        self.assertEqual(change.call_args.args,('stop','running','1'))
        release.assert_called_once()

    def test_no_baseline_does_not_change_network(self):
        change, release = self.rotation([None])
        response = self.client.post('/api/vpn/rotate', headers={'X-VPN-Control':'1'})
        self.assertEqual(response.status_code,503)
        change.assert_not_called()
        release.assert_called_once()

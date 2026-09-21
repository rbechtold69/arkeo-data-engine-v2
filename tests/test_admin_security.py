"""Exercise the actual Flask routes without wallets, network or background jobs."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_admin(kind, directory):
    path = ROOT / f'{kind}-core'
    sys.path.insert(0, str(path))
    spec = importlib.util.spec_from_file_location(f'{kind}_admin_test', path / 'admin_api.py')
    module = importlib.util.module_from_spec(spec)
    env = dict(CONFIG_DIR=directory, CACHE_DIR=directory, ARKEOD_HOME=directory,
               ADMIN_PASSWORD_PATH=str(Path(directory) / 'admin-password'), POSTHOG_ENABLED='false')
    with patch.dict(os.environ, env), patch.object(threading.Thread, 'start'), \
         patch('subprocess.check_output', side_effect=OSError('no CLI in tests')), \
         patch('subprocess.run', side_effect=OSError('no CLI in tests')):
        spec.loader.exec_module(module)
    sys.path.remove(str(path))
    module.app.testing = True
    return module


class AdminSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def each_admin(self):
        for kind in ('subscriber', 'provider'):
            directory = str(Path(self.tmp.name) / kind)
            Path(directory).mkdir()
            yield kind, load_admin(kind, directory)

    def test_password_status_never_discloses_password(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind):
                m._write_admin_password('audit-test-password')
                response = m.app.test_client().get('/api/admin-password')
                self.assertNotIn('audit-test-password', response.get_data(as_text=True))
                self.assertNotIn('password', response.get_json())

    def test_unconfigured_admin_fails_closed(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind):
                response = m.app.test_client().get('/api/audit-protected', environ_base={'REMOTE_ADDR': '192.0.2.10'})
                self.assertEqual(response.status_code, 503)

    def test_cross_origin_login_denied(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind):
                m._write_admin_password('audit-test-password')
                r = m.app.test_client().post('/api/login', json={'password': 'audit-test-password'},
                    headers={'Origin': 'https://attacker.example'})
                self.assertEqual(r.status_code, 403)
                self.assertNotIn('Access-Control-Allow-Origin', r.headers)

    def test_prefix_hostname_not_trusted(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind), m.app.test_request_context('/', base_url='https://admin.example'):
                self.assertFalse(m._origin_allowed('https://admin.example.attacker.example'))

    def test_login_and_password_rotation_revoke_old_session(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind):
                m._write_admin_password('audit-test-password')
                client = m.app.test_client()
                self.assertEqual(client.post('/api/login', json={'password':'audit-test-password'}).status_code, 200)
                token = client.get_cookie(m.ADMIN_SESSION_NAME).value
                self.assertTrue(m._validate_session(token))
                self.assertEqual(client.post('/api/admin-password', json={'password':'audit-new-password'}).status_code, 200)
                self.assertFalse(m._validate_session(token))
                self.assertNotEqual(m._load_admin_password(), 'audit-new-password')
                self.assertEqual(client.post('/api/login', json={'password':'audit-new-password'}).status_code, 200)

    def test_local_setup_requires_operator_token(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind):
                client = m.app.test_client()
                payload = {'password': 'audit-test-password'}
                self.assertEqual(client.post('/api/admin-password', json=payload).status_code, 403)
                with patch.dict(os.environ, {'ADMIN_SETUP_TOKEN': 'a' * 32}):
                    r = client.post('/api/admin-password', json=payload, headers={'X-Admin-Setup-Token': 'a' * 32})
                    self.assertEqual(r.status_code, 200)

    def test_remote_bootstrap_and_password_disable_denied(self):
        for kind, m in self.each_admin():
            with self.subTest(kind=kind):
                client = m.app.test_client()
                r = client.post('/api/admin-password', json={'password':'audit-test-password'},
                    environ_base={'REMOTE_ADDR':'192.0.2.10'})
                self.assertEqual(r.status_code, 403)
                m._write_admin_password('audit-test-password')
                client.post('/api/login', json={'password':'audit-test-password'})
                self.assertEqual(client.post('/api/admin-password', json={'password':''}).status_code, 400)

if __name__ == '__main__':
    unittest.main()

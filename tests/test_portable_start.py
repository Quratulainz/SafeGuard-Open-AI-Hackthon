"""Launch a relocated copy without site packages, original data or user config."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class PortableStartTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='safeguard portability ')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.copy = self.make_copy('Moved project \u6d4b\u8bd5')
        self.environment = {key: value for key, value in os.environ.items()
                            if key.upper() in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'COMSPEC')}
        self.environment.update(PYTHONUTF8='1', SAFEGUARD_PORT='0')

    def make_copy(self, name):
        folder = self.parent / name
        folder.mkdir()
        shutil.copy2(PROJECT / 'start.py', folder / 'start.py')
        for filename in ('Start-Windows.cmd', 'Start-macOS.command', 'start-linux.sh'):
            shutil.copy2(PROJECT / filename, folder / filename)
        for directory in ('server', 'extension'):
            shutil.copytree(PROJECT / directory, folder / directory,
                            ignore=shutil.ignore_patterns('local-data', '__pycache__', '*.pyc', '.env'))
        return folder

    def start(self, folder):
        process = subprocess.Popen([sys.executable, '-I', '-S', str(folder / 'start.py'), '--no-browser'],
            cwd=self.parent, env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8')
        self.addCleanup(self.stop, process)
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(process.stdout.readline)
            try:
                line = first.result(timeout=10)
            except TimeoutError:
                self.stop(process)
                self.fail('Portable launcher timed out')
        if not line.startswith('SafeGuard dashboard: http://127.0.0.1:'):
            self.stop(process)
            self.fail('Portable startup failed: ' + line + getattr(process, 'safeguard_stderr', '')[:300])
        port = int(line.strip().rsplit(':', 1)[1])
        origin = 'chrome-extension://' + json.loads((folder / 'server/extension_identity.json').read_text())['extension_id']
        def request(method, path, body=None, token=None):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            headers = {'Content-Type': 'application/json', 'Origin': origin}
            if token:
                headers['X-SafeGuard-Token'] = token
            try:
                connection.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
                response = connection.getresponse()
                data = json.loads(response.read())
                self.assertLess(response.status, 300, data)
                return data
            finally:
                connection.close()
        return process, request

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process.stderr and not process.stderr.closed:
            process.safeguard_stderr = process.stderr.read()
            process.stderr.close()
        if process.stdout and not process.stdout.closed:
            process.stdout.close()

    def test_check_from_unrelated_directory_needs_no_site_packages_or_private_files(self):
        result = subprocess.run([sys.executable, '-I', '-S', str(self.copy / 'start.py'), '--check'],
            cwd=self.parent, env=self.environment, capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Ready:', result.stdout)
        self.assertFalse((self.copy / '.env').exists())
        self.assertFalse((self.copy / 'server/local-data').exists())

    def test_fresh_install_starts_and_restart_keeps_new_records(self):
        process, request = self.start(self.copy)
        self.assertTrue(request('GET', '/api/health')['ok'])
        token = request('POST', '/api/local/connect', {})['token']
        status = request('GET', '/api/integrations/status', token=token)
        self.assertEqual(status['analysis']['mode'], 'rules')
        self.assertTrue(all(status[name]['status'] == 'disabled' for name in ('nightshift', 'zetaris', 'hmem')))
        checked = request('POST', '/api/inspect', {'kind': 'message', 'value': 'Never share your OTP.'}, token)
        self.assertEqual(checked['decision']['verdict'], 'safe')
        request('POST', '/api/subscriptions', {'name': 'Portable fixture', 'renewal': '2030-01-07',
                'cancel_on': '2030-01-05', 'long_term': True}, token)
        self.stop(process)
        restarted, request = self.start(self.copy)
        self.assertEqual(request('POST', '/api/local/connect', {})['token'], token)
        self.assertEqual(len(request('GET', '/api/investigations', token=token)), 1)
        rows = request('GET', '/api/subscriptions', token=token)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['cancel_on'], '2030-01-05')
        self.assertTrue(rows[0]['long_term'])
        self.assertFalse((self.parent / 'server/local-data').exists())

    def test_busy_port_fails_with_the_actual_configured_port(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen(1)
            port = occupied.getsockname()[1]
            result = subprocess.run([sys.executable, '-I', '-S', str(self.copy / 'start.py'), '--no-browser'],
                cwd=self.parent, env=dict(self.environment, SAFEGUARD_PORT=str(port)),
                capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn('already in use', result.stdout)
        self.assertIn('127.0.0.1:' + str(port), result.stdout)
        self.assertNotIn('Traceback', result.stderr)

    def test_private_database_migration_preserves_records_but_generates_a_new_device_token(self):
        process, request = self.start(self.copy)
        old_token = request('POST', '/api/local/connect', {})['token']
        request('POST', '/api/subscriptions', {'name': 'Migrated fixture', 'renewal': '2030-01-07'}, old_token)
        self.stop(process)
        second = self.make_copy('Another computer')
        target = second / 'server/local-data'
        target.mkdir()
        shutil.copy2(self.copy / 'server/local-data/records.sqlite3', target / 'records.sqlite3')
        process, request = self.start(second)
        new_token = request('POST', '/api/local/connect', {})['token']
        self.assertNotEqual(old_token, new_token)
        rows = request('GET', '/api/subscriptions', token=new_token)
        self.assertEqual([row['name'] for row in rows], ['Migrated fixture'])
        self.assertEqual(request('GET', '/api/investigations', token=new_token), [])


if __name__ == '__main__':
    unittest.main()

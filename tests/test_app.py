"""Exercise the real local HTTP server with an isolated database per test.

Only external network/evidence providers are mocked; requests to SafeGuard use
real loopback HTTP sockets, including the executable startup smoke check.
"""
import http.client
import json
import os
import queue
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'server'))
import app
import engine


class HttpApplicationTests(unittest.TestCase):
    def setUp(self):
        # A developer's future credentials or .env must never turn tests into
        # live sponsor calls. Retain only OS/runtime settings.
        runtime_env = {key: value for key, value in os.environ.items()
                       if key.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
        self.environment = patch.dict(os.environ, runtime_env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.env_loader = patch('app.load_optional_env_file', return_value=False)
        self.env_loader.start()
        self.addCleanup(self.env_loader.stop)
        self.sponsor_network = patch('integrations._open_request',
                                     side_effect=AssertionError('App tests must not call live sponsors'))
        self.sponsor_network.start()
        self.addCleanup(self.sponsor_network.stop)
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SAFEGUARD_DATA_DIR'] = self.tmp.name
        os.environ['BLACKIPS_SNAPSHOT_DIR'] = str(Path(self.tmp.name) / 'missing-snapshot')
        self.server = app.create_server(port=0, data_dir=self.tmp.name)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.02}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=3)
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method, path, data=None, auth=True, headers=None, raw=None):
        supplied_headers = dict(headers or {})
        if auth:
            supplied_headers['X-SafeGuard-Token'] = self.server.state.pairing_key
        if data is not None:
            raw = json.dumps(data).encode()
            supplied_headers['Content-Type'] = 'application/json'
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=raw, headers=supplied_headers)
            response = connection.getresponse()
            body = response.read().decode('utf-8')
            parsed = json.loads(body) if 'application/json' in response.getheader('Content-Type', '') else body
            return response.status, dict(response.getheaders()), parsed
        finally:
            connection.close()

    def test_health_is_local_and_private_api_requires_connection_token(self):
        status, _, health = self.request('GET', '/api/health', auth=False)
        self.assertEqual(status, 200)
        self.assertTrue(health['ok'])
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        for method, path, data in (
            ('GET', '/api/investigations', None),
            ('GET', '/api/subscriptions', None),
            ('GET', '/api/integrations/blackips/status', None),
            ('GET', '/api/integrations/status', None),
            ('POST', '/api/inspect', {'kind': 'message', 'value': 'hello'}),
            ('DELETE', '/api/subscriptions/1', None),
        ):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path, data, auth=False)[0], 401)
        self.assertEqual(self.request('GET', '/api/health', headers={'Host': 'attacker.example'})[0], 403)
        self.assertEqual(self.request('GET', '/', headers={'Host': 'attacker.example'})[0], 403)

    def test_message_assessment_is_saved_to_history(self):
        message = 'Pay registration fee within 24 hours'
        status, _, result = self.request('POST', '/api/inspect', {'kind': 'message', 'value': message})
        self.assertEqual(status, 200)
        self.assertEqual(result['risk_level'], 'elevated')
        self.assertEqual(result['decision']['verdict'], 'danger')
        self.assertEqual(result['analysis_mode'], 'rules')
        self.assertEqual(result['ai_analysis']['status'], 'disabled')
        self.assertEqual(result['validation']['model_attempts'], 0)
        status, _, history = self.request('GET', '/api/investigations')
        self.assertEqual(status, 200)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['input'], message)
        self.assertEqual(history[0]['result'], result)
        self.assertTrue((Path(self.tmp.name) / 'records.sqlite3').is_file())

    def test_subscriptions_add_limit_read_and_delete(self):
        for index in range(5):
            status, _, saved = self.request('POST', '/api/subscriptions', {
                'name': f'Trial {index}', 'renewal': '2026-10-28', 'domain': 'https://example.com',
                'amount': '9.99', 'currency': 'USD', 'frequency': 'monthly',
            })
            self.assertEqual(status, 201)
        self.assertEqual(self.request('POST', '/api/subscriptions', {
            'name': 'Sixth', 'renewal': '2026-10-28'})[0], 409)
        status, _, subscriptions = self.request('GET', '/api/subscriptions')
        self.assertEqual(status, 200)
        self.assertEqual(len(subscriptions), 5)
        self.assertEqual(subscriptions[0]['amount'], '9.99')
        self.assertEqual(self.request('DELETE', f"/api/subscriptions/{saved['id']}")[0], 200)
        self.assertEqual(len(self.request('GET', '/api/subscriptions')[2]), 4)
        self.assertEqual(self.request('POST', '/api/subscriptions', {
            'name': 'Invalid date', 'renewal': '2026-02-30'})[0], 400)

    def test_subscription_edit_preserves_other_fields_and_supports_nullable_cancellation(self):
        status, _, saved = self.request('POST', '/api/subscriptions', {
            'name': 'Cloud storage', 'renewal': '2026-11-01', 'domain': 'https://example.com',
            'amount': '4.99', 'currency': 'USD', 'frequency': 'yearly',
            'cancel_on': '2026-10-30', 'long_term': True})
        self.assertEqual(status, 201)
        original = self.request('GET', '/api/subscriptions')[2][0]
        self.assertEqual(original['cancel_on'], '2026-10-30')
        self.assertIs(original['long_term'], True)
        status, _, changed = self.request('POST', f"/api/subscriptions/{saved['id']}", {
            'name': 'Updated storage', 'cancel_on': None, 'long_term': False,
            'id': 999, 'created_at': 'untrusted replacement', 'unexpected': 'ignored'})
        self.assertEqual(status, 200)
        self.assertTrue(changed['updated'])
        updated = self.request('GET', '/api/subscriptions')[2][0]
        self.assertEqual(updated['id'], original['id'])
        self.assertEqual(updated['name'], 'Updated storage')
        self.assertIsNone(updated['cancel_on'])
        self.assertIs(updated['long_term'], False)
        for field in ('domain', 'amount', 'currency', 'renewal', 'frequency', 'created_at'):
            self.assertEqual(updated[field], original[field])
        self.assertEqual(self.request('POST', f"/api/subscriptions/{saved['id']}",
                                      {'cancel_on': '2026-10-29'})[0], 200)
        self.assertEqual(self.request('GET', '/api/subscriptions')[2][0]['cancel_on'], '2026-10-29')
        self.assertEqual(self.request('POST', '/api/subscriptions/999', {'long_term': True})[0], 404)

    def test_subscription_validation_rejects_wrong_types_and_invalid_edits_atomically(self):
        valid = {'name': 'Original service', 'renewal': '2026-11-01', 'long_term': False}
        saved = self.request('POST', '/api/subscriptions', valid)[2]
        invalid = [
            {'long_term': value} for value in (0, 1, 'true', 'false', None, [], {})
        ] + [
            {'cancel_on': value} for value in (False, 0, [], {}, 'tomorrow', '2026-02-30')
        ] + [{'renewal': '2026-13-01'}, {'frequency': 'weekly'}, {'name': ''},
             {'domain': 'javascript:alert(1)'}, {'domain': 'https://user:secret@example.com'}]
        for changes in invalid:
            with self.subTest(changes=changes):
                self.assertEqual(self.request('POST', '/api/subscriptions', {**valid, **changes})[0], 400)
                self.assertEqual(self.request('POST', f"/api/subscriptions/{saved['id']}", changes)[0], 400)
                rows = self.request('GET', '/api/subscriptions')[2]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['name'], 'Original service')
                self.assertEqual(rows[0]['renewal'], '2026-11-01')
                self.assertIs(rows[0]['long_term'], False)
                self.assertIsNone(rows[0]['cancel_on'])

    def test_edit_is_allowed_at_limit_and_parallel_adds_cannot_exceed_it(self):
        ids = []
        for index in range(4):
            ids.append(self.request('POST', '/api/subscriptions', {
                'name': f'Service {index}', 'renewal': '2026-11-01'})[2]['id'])
        results = queue.Queue()
        barrier = threading.Barrier(3)
        def add_last_slot(index):
            try:
                barrier.wait(timeout=3)
                results.put(self.request('POST', '/api/subscriptions', {
                    'name': f'Contender {index}', 'renewal': '2026-11-02'})[0])
            except Exception as error:
                results.put(type(error).__name__)
        contenders = [threading.Thread(target=add_last_slot, args=(index,), daemon=True) for index in range(2)]
        for worker in contenders:
            worker.start()
        barrier.wait(timeout=3)
        for worker in contenders:
            worker.join(timeout=8)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual([results.get(timeout=1), results.get(timeout=1)], [201, 409])
        self.assertEqual(len(self.request('GET', '/api/subscriptions')[2]), 5)
        self.assertEqual(self.request('POST', f'/api/subscriptions/{ids[0]}', {'long_term': True})[0], 200)
        self.assertEqual(len(self.request('GET', '/api/subscriptions')[2]), 5)

    def test_dashboard_opens_with_automatic_token_and_without_pairing_form(self):
        status, headers, page = self.request('GET', '/', auth=False)
        self.assertEqual(status, 200)
        self.assertTrue(self.server.state.pairing_key in page, 'Dashboard did not receive its local token')
        self.assertNotIn('%%PAIRING_KEY%%', page)
        self.assertNotRegex(page, r'action\s*=\s*[\"\x27]/pair')
        self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        # The removed endpoint cannot create a cookie or recover old pairing UI.
        self.assertEqual(self.request('POST', '/pair', {})[0], 404)
        self.assertEqual(self.request('GET', '/pair')[0], 404)
        self.assertEqual(self.request('GET', '/api/investigations', auth=False,
                                      headers={'Cookie': 'safeguard_session=obsolete'})[0], 401)

    def test_dashboard_rejects_cross_origin_fetches_and_embedded_frames(self):
        denied = [
            {'Origin': 'https://attacker.example'}, {'Origin': 'null'},
            {'Origin': app.EXTENSION_ORIGIN},
            {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'cors'},
            {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'no-cors'},
            *[{'Sec-Fetch-Dest': destination, 'Sec-Fetch-Mode': 'navigate'}
              for destination in ('iframe', 'object', 'embed')],
        ]
        for supplied in denied:
            with self.subTest(headers=supplied):
                status, _, body = self.request('GET', '/', auth=False, headers=supplied)
                self.assertEqual(status, 403)
                self.assertNotIn(self.server.state.pairing_key, json.dumps(body))
        self.assertEqual(self.request('GET', '/', auth=False, headers={
            'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'})[0], 200)

    def test_extension_bootstrap_returns_token_that_authorizes_real_api_requests(self):
        status, headers, connected = self.request('POST', '/api/local/connect', {}, auth=False,
                                                   headers={'Origin': app.EXTENSION_ORIGIN})
        self.assertEqual(status, 200)
        self.assertTrue(connected['connected'])
        self.assertTrue(connected['token'] == self.server.state.pairing_key, 'Bootstrap returned the wrong local token')
        self.assertEqual(headers['Access-Control-Allow-Origin'], app.EXTENSION_ORIGIN)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn('Set-Cookie', headers)
        for origin in (app.EXTENSION_ORIGIN, f'http://127.0.0.1:{self.server.server_port}'):
            status, _, rows = self.request('GET', '/api/subscriptions', auth=False,
                                           headers={'Origin': origin, 'X-SafeGuard-Token': connected['token']})
            self.assertEqual(status, 200)
            self.assertEqual(rows, [])
        self.assertEqual(self.request('GET', '/api/subscriptions', auth=False,
                                      headers={'X-SafeGuard-Token': 'invalid-token'})[0], 401)

    def test_extension_bootstrap_rejects_other_origins_host_and_non_json_requests(self):
        another_extension = 'chrome-extension://' + ('b' * 32 if app.EXTENSION_ID != 'b' * 32 else 'a' * 32)
        for origin in (None, '', 'null', 'https://attacker.example', another_extension,
                       app.EXTENSION_ORIGIN + '/', f'http://127.0.0.1:{self.server.server_port}'):
            supplied = {'Content-Type': 'application/json'}
            if origin is not None:
                supplied['Origin'] = origin
            with self.subTest(origin=origin):
                # Origin/Host are rejected before reading a body. An empty JSON
                # request avoids an irrelevant Windows close-with-unread-data race.
                status, _, result = self.request('POST', '/api/local/connect', raw=b'', auth=False, headers=supplied)
                self.assertEqual(status, 403)
                self.assertNotIn('token', result)
        self.assertEqual(self.request('POST', '/api/local/connect', raw=b'', auth=False,
                                      headers={'Origin': app.EXTENSION_ORIGIN, 'Host': 'attacker.example',
                                               'Content-Type': 'application/json'})[0], 403)
        for content_type in (None, 'text/plain', 'application/x-www-form-urlencoded'):
            supplied = {'Origin': app.EXTENSION_ORIGIN}
            if content_type:
                supplied['Content-Type'] = content_type
            with self.subTest(content_type=content_type):
                self.assertEqual(self.request('POST', '/api/local/connect', raw=b'', auth=False,
                                              headers=supplied)[0], 400)
        for raw in (b'[]', b'null', b'not-json'):
            self.assertEqual(self.request('POST', '/api/local/connect', raw=raw, auth=False,
                                          headers={'Origin': app.EXTENSION_ORIGIN, 'Content-Type': 'application/json'})[0], 400)

    def test_external_origin_cannot_use_a_valid_api_token(self):
        for origin in ('https://attacker.example', 'null', 'chrome-extension://' + 'c' * 32):
            with self.subTest(origin=origin):
                status, headers, _ = self.request('GET', '/api/subscriptions', headers={'Origin': origin})
                self.assertEqual(status, 401)
                self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_default_status_does_not_probe_disabled_model_cloud_or_memory(self):
        offline = {'provider': 'blackips_snapshot', 'mode': 'snapshot', 'reachable': False, 'message': 'No snapshot fixture'}
        with patch('app.nightshift_status', side_effect=AssertionError('Disabled model must not be probed')) as model, \
             patch('app.zetaris_status', side_effect=AssertionError('Disabled cloud must not be probed')) as cloud, \
             patch('app.InvestigationMemory', side_effect=AssertionError('Default history must not need Node')) as memory, \
             patch('app.blackips_status', return_value=offline) as ip_status:
            status, _, report = self.request('GET', '/api/integrations/status')
        self.assertEqual(status, 200)
        self.assertEqual(report['analysis']['mode'], 'rules')
        for service in ('nightshift', 'zetaris', 'hmem'):
            self.assertEqual(report[service]['status'], 'disabled')
        self.assertEqual(report['blackips'], offline)
        model.assert_not_called()
        cloud.assert_not_called()
        memory.assert_not_called()
        ip_status.assert_called_once()

    def test_invalid_bodies_and_inputs_are_rejected(self):
        for raw in ('not json', '[]', 'null'):
            with self.subTest(body=raw):
                self.assertEqual(self.request('POST', '/api/inspect', raw=raw)[0], 400)
        self.assertEqual(self.request('POST', '/api/inspect', {'kind': 'message', 'value': ''})[0], 400)
        self.assertEqual(self.request('POST', '/api/inspect', {'kind': 'other', 'value': 'text'})[0], 400)
        self.assertEqual(self.request('POST', '/api/inspect',
                                      headers={'Content-Length': '50001'})[0], 400)

    def test_private_url_is_rejected_without_fetch_or_history(self):
        with patch('engine.urllib.request.build_opener') as opener:
            for url in ('http://127.0.0.1', 'http://localhost', 'http://169.254.169.254/latest/meta-data/',
                        'file:///tmp/private', 'https://user:password@example.com'):
                with self.subTest(url=url):
                    status, _, _ = self.request('POST', '/api/inspect', {'kind': 'url', 'value': url})
                    self.assertEqual(status, 400)
            opener.assert_not_called()
        self.assertEqual(self.request('GET', '/api/investigations')[2], [])

    def test_html_failure_retains_external_evidence_and_history(self):
        evidence = [{'provider': 'test-feed', 'ip': '8.8.8.8', 'status': 'listed', 'listed': True,
                     'source': 'fixture', 'checked_at': '2026-10-25T00:00:00Z', 'details': {}}]
        with patch('engine.safe_url', return_value='https://example.com'), \
             patch('engine.reputation_for_url', return_value=evidence), \
             patch('engine.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.URLError('fixture unavailable')
            status, _, result = self.request('POST', '/api/inspect', {'kind': 'url', 'value': 'https://example.com'})
        self.assertEqual(status, 200)
        self.assertEqual(result['retrieval']['status'], 'NOT VERIFIED')
        for key, value in evidence[0].items():
            self.assertEqual(result['ip_reputation'][0][key], value)
        self.assertEqual(result['ip_reputation'][0]['queried_host'], 'example.com')
        self.assertTrue(result['verified_facts'])
        history = self.request('GET', '/api/investigations')[2]
        self.assertEqual(history[0]['result']['ip_reputation'], result['ip_reputation'])

    def test_ip_endpoint_can_report_unconfigured_provider(self):
        with patch('ip_reputation.configured_base_url', return_value=''):
            status, _, result = self.request('POST', '/api/ip-check', {'ip': '8.8.8.8'})
        self.assertEqual(status, 200)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(self.request('POST', '/api/ip-check', {'ip': '127.0.0.1'})[2]['status'], 'unsupported')

    def test_extension_preflight_uses_actual_configured_port(self):
        origin = app.EXTENSION_ORIGIN
        status, headers, _ = self.request('OPTIONS', '/api/inspect', auth=False, headers={'Origin': origin})
        self.assertEqual(status, 204)
        self.assertEqual(headers['Access-Control-Allow-Origin'], origin)
        self.assertNotIn('Access-Control-Allow-Origin', self.request(
            'OPTIONS', '/api/inspect', auth=False, headers={'Origin': 'https://attacker.example'})[1])
        self.assertIn('X-SafeGuard-Token', headers['Access-Control-Allow-Headers'])
        self.assertNotIn('Access-Control-Allow-Origin', self.request(
            'OPTIONS', '/api/local/connect', auth=False, headers={'Origin': 'chrome-extension://' + 'd' * 32})[1])


class EngineRetrievalTests(unittest.TestCase):
    def test_redirect_to_private_address_is_blocked(self):
        handler = engine.RestrictedRedirect()
        request = urllib.request.Request('https://example.com')
        with self.assertRaises(engine.UnsafeUrlError):
            handler.redirect_request(request, None, 302, 'Found', {}, 'http://169.254.169.254/')

    def test_blocked_redirect_keeps_prior_evidence(self):
        evidence = [{'provider': 'test-feed', 'listed': False, 'status': 'not_listed'}]
        with patch('engine.safe_url', return_value='https://example.com'), \
             patch('engine.reputation_for_url', return_value=evidence), \
             patch('engine.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = engine.UnsafeUrlError('Private destination')
            result = engine.inspect_url('https://example.com')
        self.assertEqual(result['retrieval']['status'], 'BLOCKED')
        for key, value in evidence[0].items():
            self.assertEqual(result['ip_reputation'][0][key], value)
        self.assertEqual(result['ip_reputation'][0]['queried_host'], 'example.com')
        opener.return_value.open.assert_called_once()


class LegacyDatabaseMigrationTests(unittest.TestCase):
    def test_old_records_and_token_survive_idempotent_subscription_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            token = 'test_only_legacy_token_12345678901234567890'
            (directory / 'pairing-key.txt').write_text(token, encoding='utf-8')
            with closing(sqlite3.connect(directory / 'records.sqlite3')) as db, db:
                db.execute('CREATE TABLE subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT, '
                           'name TEXT NOT NULL, domain TEXT, amount TEXT, currency TEXT, renewal TEXT NOT NULL, '
                           'frequency TEXT, created_at TEXT NOT NULL)')
                db.execute('INSERT INTO subscriptions VALUES(7,?,?,?,?,?,?,?)',
                           ('Existing subscription', 'https://example.com', '8.00', 'MYR',
                            '2026-11-12', 'monthly', '2026-10-01T12:00:00Z'))
                db.execute('CREATE TABLE investigations(id INTEGER PRIMARY KEY AUTOINCREMENT, input TEXT, '
                           'result TEXT, created_at TEXT NOT NULL)')
                db.execute('INSERT INTO investigations VALUES(3,?,?,?)',
                           ('Existing history', '{"legacy":true}', '2026-10-01T12:00:00Z'))
            for _ in range(2):
                state = app.ApplicationState(directory)
                self.assertEqual(state.pairing_key, token)
                self.assertEqual((directory / 'local-token.txt').read_text(), token)
                with state.connection() as db:
                    columns = {row['name'] for row in db.execute('PRAGMA table_info(subscriptions)')}
                    self.assertTrue({'cancel_on', 'long_term'} <= columns)
                    rows = [dict(row) for row in db.execute('SELECT * FROM subscriptions')]
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]['id'], 7)
                    self.assertEqual(rows[0]['name'], 'Existing subscription')
                    self.assertEqual(rows[0]['created_at'], '2026-10-01T12:00:00Z')
                    self.assertIsNone(rows[0]['cancel_on'])
                    self.assertEqual(rows[0]['long_term'], 0)
                    self.assertEqual(dict(db.execute('SELECT * FROM investigations').fetchone()), {
                        'id': 3, 'input': 'Existing history', 'result': '{"legacy":true}',
                        'created_at': '2026-10-01T12:00:00Z'})


class ExecutableStartupTests(unittest.TestCase):
    def test_cli_respects_isolated_data_and_port_without_logging_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {key: value for key, value in os.environ.items()
                   if key.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
            # Reserve every configured key with an empty value before the real
            # startup path loads .env. Values are never copied into the child.
            dotenv = PROJECT / '.env'
            if dotenv.is_file():
                for line in dotenv.read_text(encoding='utf-8').splitlines():
                    match = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*=', line)
                    if match:
                        env[match[1]] = ''
            env.update(SAFEGUARD_DATA_DIR=tmp, SAFEGUARD_PORT='0', PYTHONDONTWRITEBYTECODE='1',
                       SAFEGUARD_ANALYSIS_MODE='rules', SAFEGUARD_DOMAIN_PROVIDER='none',
                       SAFEGUARD_MEMORY_MODE='local', SAFEGUARD_IP_PROVIDER='disabled',
                       BLACKIPS_SNAPSHOT_DIR=str(Path(tmp) / 'missing-snapshot'))
            process = subprocess.Popen([sys.executable, '-u', str(PROJECT / 'server' / 'app.py')],
                                       cwd=PROJECT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding='utf-8')
            lines = queue.Queue()
            reader = threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True)
            reader.start()
            captured = []
            try:
                first = lines.get(timeout=8)
                captured.append(first)
                match = re.search(r'http://127\.0\.0\.1:(\d+)', first)
                self.assertIsNotNone(match, 'Application failed to print its local startup address')
                port = int(match.group(1))
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    connection.request('GET', '/api/health')
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertTrue(json.loads(response.read())['ok'])
                finally:
                    connection.close()
                self.assertTrue((Path(tmp) / 'records.sqlite3').is_file())
            finally:
                process.terminate()
                process.wait(timeout=5)
                reader.join(timeout=3)
                while not lines.empty():
                    captured.append(lines.get_nowait())
                process.stdout.close()
            secret = (Path(tmp) / 'local-token.txt').read_text().strip()
            self.assertFalse(secret in ''.join(captured), 'Local token was exposed in startup output')
            self.assertIn('automatic', ''.join(captured))


if __name__ == '__main__':
    unittest.main()

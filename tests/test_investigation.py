"""End-to-end coordinator checks with LOCAL SIMULATED sponsor HTTP services.

Requests traverse the real adapters and sockets; H-MEM is the real vendored
engine. Public page evidence is an explicit fixture. Passing these tests proves
orchestration, NOT a live Zetaris/Nightshift integration or NVIDIA model use.
"""

from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'server'))
import engine
import investigation

SUBJECT = 'https://example.com/jobs'
NOW = datetime.now(timezone.utc).isoformat()


def public_page_fixture():
    result = engine.assess('Pay an Acme registration fee within 24 hours', 'url', SUBJECT)
    result.update(page_title='SIMULATED Acme offer', content_excerpt='Pay a registration fee within 24 hours',
                  retrieval={'status': 'Fetched accessible HTML', 'final_url': SUBJECT},
                  ip_reputation=[{'provider': 'fixture-feed', 'ip': '8.8.8.8', 'listed': False,
                                  'status': 'not_listed', 'source': 'TEST FIXTURE ONLY',
                                  'checked_at': '2026-10-24T01:02:03+00:00'}])
    return result


class SponsorFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.calls.append({'path': self.path, 'body': body,
                                  'authorization': self.headers.get('Authorization'),
                                  'org': self.headers.get('X-Org-ID')})
        if self.path == '/api/v1.0/sql-editor/sqls/run':
            response = {'data': self.server.rows}
        elif self.path == '/v1/chat/completions':
            self.server.model_calls += 1
            evidence = json.loads(body['messages'][1]['content'])['evidence']
            reference = next((record['id'] for record in evidence
                              if record['record'].get('evidence_type') == 'zetaris_record'),
                             evidence[0]['id'])
            invalid = self.server.model_calls <= self.server.invalid_attempts
            analysis = {
                'summary': 'SIMULATED MODEL: observations require a fresh independent check.',
                'risk_level': self.server.model_risk,
                'claims': [{'text': 'SIMULATED MODEL: a supplied source contains an observation.',
                            'evidence_ids': ['invented_missing_id' if invalid else reference]}],
                'uncertainties': ['Local fixtures do not demonstrate live sponsor use.'],
                'next_steps': ['Check independent official contact details.'],
            }
            response = {'model': 'fixture/not-a-real-model',
                        'choices': [{'message': {'content': json.dumps(analysis)}}]}
        else:
            self.send_error(404)
            return
        raw = json.dumps(response).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@unittest.skipUnless(shutil.which('node'), 'Real H-MEM requires Node.js 24')
class InvestigationHttpFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        runtime_env = {key: value for key, value in os.environ.items()
                       if key.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
        self.env = patch.dict(os.environ, runtime_env, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.fixture = ThreadingHTTPServer(('127.0.0.1', 0), SponsorFixtureHandler)
        self.fixture.calls = []
        self.fixture.model_calls = 0
        self.fixture.invalid_attempts = 0
        self.fixture.model_risk = 'caution'
        self.fixture.rows = [{'domain': 'example.com', 'observation': 'SIMULATED domain evidence',
                              'source_url': 'https://evidence.example/test-fixture', 'checked_at': NOW}]
        self.thread = threading.Thread(target=self.fixture.serve_forever,
                                       kwargs={'poll_interval': 0.02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_fixture)
        self.config = {
            'ZETARIS_REST_URL': f'http://127.0.0.1:{self.fixture.server_port}/api/v1.0',
            'ZETARIS_API_KEY': 'test-only-zetaris-secret', 'ZETARIS_ORG_ID': '42',
            'ZETARIS_EVIDENCE_TABLE': 'security.domain_evidence',
            'METERLESS_BASE_URL': f'http://127.0.0.1:{self.fixture.server_port}/v1',
            'METERLESS_RUNTIME_TOKEN': 'test-only-nightshift-secret',
        }
        os.environ.update(self.config)
        os.environ.update(SAFEGUARD_ANALYSIS_MODE='model', SAFEGUARD_DOMAIN_PROVIDER='zetaris',
                          SAFEGUARD_MEMORY_MODE='hmem')

    def close_fixture(self):
        self.fixture.shutdown()
        self.thread.join(timeout=3)
        self.fixture.server_close()

    def run_url(self, page=None):
        with patch('investigation.inspect_url', return_value=deepcopy(page or public_page_fixture())):
            return investigation.investigate('url', SUBJECT, data_dir=self.tmp.name)

    def model_requests(self):
        return [call['body'] for call in self.fixture.calls
                if call['path'] == '/v1/chat/completions']

    def test_message_evidence_preserves_opposite_otp_context_and_marks_derived_signals(self):
        # Put the decisive wording beyond the 2,000-character subject preview.
        prefix = 'Background information. ' * 100
        messages = [prefix + 'Do not share your OTP with anyone.',
                    prefix + 'Please share your OTP with me.']
        contexts = []
        signals = []
        for message in messages:
            with self.subTest(message_ending=message[len(prefix):]):
                result = investigation.investigate('message', message, data_dir=self.tmp.name)
                request = json.loads(self.model_requests()[-1]['messages'][1]['content'])
                delivered = [item['record'] for item in request['evidence']]
                context = next(item for item in delivered if item['evidence_type'] == 'text_observation')
                signal = next(item for item in delivered if item['evidence_type'] == 'keyword_signal')
                self.assertEqual(context['observation']['text'], message)
                self.assertFalse(context['observation']['truncated'])
                self.assertFalse(context['independently_verified'])
                self.assertEqual(context['observation']['original_length'], len(message))
                self.assertEqual(signal['source'], 'predefined_phrase_match')
                self.assertTrue(signal['derived'])
                self.assertTrue(signal['requires_context'])
                self.assertFalse(signal['establishes_risk'])
                self.assertFalse(signal['independently_verified'])
                self.assertEqual(signal['derived_from'], [context['id']])
                if 'Do not share' in message:
                    self.assertEqual(result['ai_risk_level'], 'unknown')
                    self.assertEqual(result['risk_level'], 'unknown')
                    self.assertEqual(result['ai_analysis']['semantic_validation']['status'], 'abstained')
                    self.assertEqual(result['ai_analysis']['analysis']['claims'], [])
                else:
                    self.assertEqual(result['ai_risk_level'], 'caution')
                    self.assertEqual(result['risk_level'], 'caution')
                    self.assertIn(context['id'], result['ai_analysis']['analysis']['claims'][0]['evidence_ids'])
                self.assertTrue(any(step['step'] == 'validate_risk_support' for step in result['trace']))
                contexts.append(context['observation']['text'])
                signals.append(signal['observation'])
        self.assertEqual(signals[0], signals[1], 'Identical phrase matches must not erase opposite contexts')
        self.assertNotEqual(contexts[0], contexts[1])
        self.assertIn('Do not share your OTP', contexts[0])

        long_message = messages[0] + ' More background.' * 500
        investigation.investigate('message', long_message, data_dir=self.tmp.name)
        request = json.loads(self.model_requests()[-1]['messages'][1]['content'])
        context = next(item['record'] for item in request['evidence']
                       if item['record']['evidence_type'] == 'text_observation')
        self.assertEqual(context['observation']['text'], long_message[:8000])
        self.assertTrue(context['observation']['truncated'])
        self.assertEqual(context['observation']['original_length'], len(long_message))

    def test_real_http_contract_evidence_ids_and_exactly_one_schema_retry(self):
        self.fixture.invalid_attempts = 1
        result = self.run_url()
        self.assertEqual(result['completeness'], 'complete')
        self.assertEqual(result['ai_analysis']['status'], 'online')
        self.assertEqual(result['validation']['model_attempts'], 2)
        self.assertEqual(self.fixture.model_calls, 2)
        self.assertEqual(result['memory_write']['status'], 'stored')
        sql_call = self.fixture.calls[0]
        self.assertEqual(sql_call['body']['sql'],
                         "SELECT * FROM security.domain_evidence WHERE domain = 'example.com'")
        self.assertEqual(sql_call['org'], '42')
        self.assertEqual(sql_call['authorization'], 'Bearer test-only-zetaris-secret')
        attempts = self.model_requests()
        first = json.loads(attempts[0]['messages'][1]['content'])
        second = json.loads(attempts[1]['messages'][1]['content'])
        self.assertEqual(first, second, 'Retry must keep the same evidence identifiers')
        self.assertEqual(first['subject'], SUBJECT)
        records = [item['record'] for item in first['evidence']]
        self.assertTrue(any(row['evidence_type'] == 'page_retrieval' for row in records))
        self.assertTrue(any(row['evidence_type'] == 'zetaris_record' for row in records))
        ip_record = next(row for row in records if row['evidence_type'] == 'ip_reputation')
        self.assertEqual(ip_record['checked_at'], '2026-10-24T01:02:03+00:00')
        self.assertEqual(ip_record['observation']['listed'], False)
        self.assertIn('previous response cited unknown evidence', attempts[1]['messages'][0]['content'])
        valid_ids = {item['id'] for item in result['evidence']}
        for claim in result['ai_analysis']['analysis']['claims']:
            self.assertTrue(set(claim['evidence_ids']) <= valid_ids)
        self.assertTrue(any(item['step'] == 'validate' and item['status'] == 'rejected'
                            for item in result['trace']))
        log = (Path(self.tmp.name) / 'logs' / (result['run_id'] + '.jsonl')).read_text(encoding='utf-8')
        self.assertNotIn(SUBJECT, log)
        self.assertNotIn('test-only-', log)
        self.assertNotIn('SIMULATED domain evidence', log)
        self.assertEqual(result['keyword_risk_level'], 'elevated')
        self.assertEqual(result['risk_level'], 'caution')
        self.assertEqual(result['ai_risk_level'], 'caution')

    def test_protective_warning_uses_reviewed_risk_without_losing_keyword_observation(self):
        result = investigation.investigate(
            'message', 'Security reminder: Never share your OTP. Support will never ask for your password.',
            data_dir=self.tmp.name)
        self.assertEqual(result['keyword_risk_level'], 'caution')
        self.assertEqual(result['ai_analysis']['semantic_validation']['status'], 'abstained')
        self.assertEqual(result['ai_analysis']['analysis']['risk_level'], 'unknown')
        self.assertEqual(result['ai_risk_level'], 'unknown')
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertEqual(result['risk_basis']['primary'], 'validated_ai')
        self.assertFalse(result['risk_basis']['listing_floor_applied'])
        self.assertEqual(result['memory_write']['status'], 'stored')
        self.assertTrue(any(step['step'] == 'resolve_risk' and step['status'] == 'unknown'
                            for step in result['trace']))

    def test_current_adverse_listing_keeps_caution_when_ai_is_unknown_or_unavailable(self):
        self.fixture.model_risk = 'unknown'
        page = public_page_fixture()
        page.update(risk_level='unknown', keyword_risk_level='unknown', findings=[], content_excerpt='An ordinary public page.')
        for status, listed, expected in [('listed', True, 'caution'),
                                          ('not_listed', False, 'unknown'),
                                          ('unavailable', None, 'unknown')]:
            with self.subTest(status=status):
                page['ip_reputation'][0].update(status=status, listed=listed)
                result = self.run_url(page)
                self.assertEqual(result['ai_risk_level'], 'unknown')
                self.assertEqual(result['keyword_risk_level'], 'unknown')
                self.assertEqual(result['risk_level'], expected)
                self.assertEqual(result['risk_basis']['listing_floor_applied'], listed is True)
                if listed:
                    self.assertIn('adverse listing', result['summary'])
                    ip_ids = {item['id'] for item in result['evidence'] if item['evidence_type'] == 'ip_reputation'}
                    self.assertEqual(set(result['risk_basis']['listed_evidence_ids']), ip_ids)
        os.environ.pop('METERLESS_RUNTIME_TOKEN')
        page['ip_reputation'][0].update(status='listed', listed=True)
        result = self.run_url(page)
        self.assertEqual(result['ai_analysis']['status'], 'unconfigured')
        self.assertEqual(result['risk_level'], 'caution')
        self.assertEqual(result['keyword_risk_level'], 'unknown')
        self.assertFalse(result['risk_basis']['listing_floor_applied'])
        self.assertEqual(result['risk_basis']['primary'], 'current_evidence_rules')

    def test_second_run_actually_recalls_hmem_without_calling_memory_fresh_fact(self):
        first = self.run_url()
        second = self.run_url()
        matches = second['memory_recall']['matches']
        self.assertTrue(matches)
        self.assertEqual(matches[0]['id'], first['memory_write']['memory_ids'][0])
        self.assertFalse(matches[0]['usable_as_current_evidence'])
        memory = next(row for row in second['evidence'] if row['evidence_type'] == 'historical_memory')
        self.assertTrue(memory['historical_only'])
        self.assertFalse(memory['new_verification'])
        delivered = json.loads(self.model_requests()[-1]['messages'][1]['content'])
        self.assertTrue(any(row['record']['evidence_type'] == 'historical_memory'
                            for row in delivered['evidence']))
        self.assertEqual(len([call for call in self.fixture.calls
                              if call['path'].endswith('/sqls/run')]), 2,
                         'A memory hit must not skip the fresh Zetaris query')

    def test_two_bad_responses_stop_at_two_and_leave_keyword_result_partial(self):
        self.fixture.invalid_attempts = 100
        result = self.run_url()
        self.assertEqual(self.fixture.model_calls, 2)
        self.assertEqual(result['validation']['model_attempts'], 2)
        self.assertEqual(result['completeness'], 'partial')
        self.assertEqual(result['ai_analysis']['status'], 'invalid_response')
        self.assertNotIn('analysis', result['ai_analysis'])
        self.assertNotIn('ai_risk_level', result)
        self.assertNotIn('invented_missing_id', json.dumps(result))
        self.assertEqual(result['risk_level'], 'elevated')

    def test_unconfigured_is_partial_and_performs_no_sponsor_network(self):
        for key in self.config:
            os.environ.pop(key, None)
        with patch('integrations._open_request', side_effect=AssertionError('No live calls allowed')):
            result = self.run_url()
        self.assertEqual(self.fixture.calls, [])
        self.assertEqual(result['zetaris']['status'], 'unconfigured')
        self.assertEqual(result['ai_analysis']['status'], 'unconfigured')
        self.assertEqual(result['completeness'], 'partial')
        self.assertEqual(result['memory_write']['status'], 'stored')

    def test_empty_domain_lookup_is_not_complete_or_proof_of_safety(self):
        self.fixture.rows = []
        result = self.run_url()
        self.assertEqual(result['zetaris']['status'], 'online')
        self.assertEqual(result['completeness'], 'partial')
        self.assertTrue(any('does not establish safety' in gap for gap in result['validation']['gaps']))

    def test_private_url_rejected_before_sponsor_fetch_or_memory_write(self):
        with patch('engine.urllib.request.build_opener',
                   side_effect=AssertionError('Unsafe URL must not be fetched')):
            for url in ('http://127.0.0.1', 'http://localhost', 'http://169.254.169.254/latest/meta-data/'):
                with self.subTest(url=url), self.assertRaises(engine.UnsafeUrlError):
                    investigation.investigate('url', url, data_dir=self.tmp.name)
        self.assertEqual(self.fixture.calls, [])
        self.assertFalse((Path(self.tmp.name) / 'hmem').exists())

    def test_blocked_redirect_keeps_evidence_but_is_partial(self):
        page = public_page_fixture()
        page['retrieval']['status'] = 'BLOCKED'
        result = self.run_url(page)
        self.assertEqual(result['completeness'], 'partial')
        self.assertEqual(result['ip_reputation'], page['ip_reputation'])
        self.assertTrue(any('redirect was blocked' in gap for gap in result['validation']['gaps']))

    def test_unavailable_ip_provider_is_reported_as_a_collection_gap(self):
        page = public_page_fixture()
        page['ip_reputation'][0].update(status='unavailable', listed=None)
        result = self.run_url(page)
        self.assertEqual(result['completeness'], 'partial')
        self.assertTrue(any('IP reputation evidence was unavailable' in gap
                            for gap in result['validation']['gaps']))

    def test_unavailable_memory_prevents_false_complete_and_final_trace_agrees(self):
        with patch('investigation.InvestigationMemory') as factory:
            factory.return_value.recall.return_value = {'status': 'unavailable', 'matches': [], 'context': ''}
            factory.return_value.remember.return_value = {'status': 'unavailable'}
            result = self.run_url()
        self.assertEqual(result['completeness'], 'partial')
        self.assertTrue(any('H-MEM recall' in gap for gap in result['validation']['gaps']))
        self.assertTrue(any('saved to H-MEM' in gap for gap in result['validation']['gaps']))
        self.assertEqual(result['trace'][-1]['step'], 'validate')
        self.assertEqual(result['trace'][-1]['status'], 'partial')


if __name__ == '__main__':
    unittest.main()

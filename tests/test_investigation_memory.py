"""Integration tests execute the actual vendored Meterless engine via Node."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
from investigation_memory import InvestigationMemory, REFERENCE_COMMIT

T0 = '2026-10-25T00:00:00+00:00'
QUERY = 'Acme registration fee job offer'


@unittest.skipUnless(shutil.which('node'), 'Node.js 24 required for real H-MEM integration')
class HmemIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memory = InvestigationMemory(self.tmp.name)
        self.result = {
            'summary': 'Observed an upfront registration fee request.',
            'source': 'https://acme.example/job',
            'checked_at': T0,
            'status': 'heuristic assessment — NOT independently verified',
            'risk_level': 'caution',
            'findings': [{'id': 'upfront_fee', 'observed': 'registration fee'}],
            'verified_facts': [],
            'ip_reputation': [{'provider': 'blackips', 'listed': False,
                               'source': 'feed-demo', 'checked_at': T0}],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def remember(self, **kwargs):
        response = self.memory.remember(QUERY, self.result, now=T0, **kwargs)
        self.assertEqual(response['status'], 'stored', response)
        return response

    def test_real_engine_recall_persists_provenance_and_audit(self):
        saved = self.remember()
        restarted = InvestigationMemory(self.tmp.name)
        recalled = restarted.recall('Acme job offer registration fee', now=T0)
        self.assertEqual(recalled['implementation'], 'official-reference')
        self.assertEqual(recalled['reference_commit'], REFERENCE_COMMIT)
        self.assertEqual(len(recalled['matches']), 1)
        match = recalled['matches'][0]
        self.assertEqual(match['id'], saved['memory_ids'][0])
        self.assertEqual(match['source'], self.result['source'])
        self.assertEqual(match['checked_at'], T0)
        self.assertEqual(match['evidence']['ip_reputation'][0]['source'], 'feed-demo')
        self.assertEqual(match['provenance']['refs'], [self.result['source']])
        self.assertIn('hybrid ranking', recalled['trace']['retrievalReason'])
        self.assertIn('NOT independently verified', recalled['context'])
        self.assertFalse(match['usable_as_current_evidence'])
        self.assertFalse(match['new_verification'])
        self.assertEqual(match['freshness'], 'within_ttl')
        state = json.loads((Path(self.tmp.name) / 'state.json').read_text(encoding='utf-8'))
        self.assertEqual(state['records'][0]['accessCount'], 1)
        ledger = [json.loads(line) for line in
                  (Path(self.tmp.name) / 'ledger.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertEqual([item['action'] for item in ledger], ['create', 'update', 'read'])

    def test_exact_expiry_boundary_excludes_from_prompt_but_keeps_history(self):
        self.remember(ttl_seconds=60)
        before = self.memory.recall(QUERY, now='2026-10-25T00:00:59+00:00')
        self.assertNotEqual(before['context'], '')
        expired = self.memory.recall(QUERY, now='2026-10-25T00:01:00+00:00')
        self.assertEqual(expired['matches'][0]['freshness'], 'expired')
        self.assertEqual(expired['context'], '')
        self.assertTrue(expired['matches'][0]['requires_recheck'])

    def test_saving_old_evidence_does_not_refresh_timestamp(self):
        response = self.memory.remember(
            QUERY, self.result, ttl_seconds=60, now='2026-10-25T01:00:00+00:00')
        self.assertEqual(response['expires_at'], '2026-10-25T00:01:00+00:00')
        recalled = self.memory.recall(QUERY, now='2026-10-25T01:00:00+00:00')
        self.assertEqual(recalled['context'], '')
        self.assertEqual(recalled['matches'][0]['freshness'], 'expired')

    def test_future_timestamp_is_not_usable_historical_context(self):
        self.result['checked_at'] = '2027-10-25T00:00:00+00:00'
        self.remember()
        recalled = self.memory.recall(QUERY, now=T0)
        self.assertEqual(recalled['matches'][0]['freshness'], 'untrusted_timestamp')
        self.assertEqual(recalled['context'], '')

    def test_reinvestigation_cannot_renew_nested_history_or_its_ai_summary(self):
        self.result['findings'] = [{'observed': 'OLD_TEST_MARKER'}]
        self.remember()
        old_recall = self.memory.recall(QUERY, now='2026-10-25T23:00:00+00:00')
        fresh_result = {
            'checked_at': '2026-10-25T23:00:00+00:00',
            'summary': 'AI combined old context OLD_TEST_MARKER with current observations.',
            'limitations': ['AI mentions OLD_TEST_MARKER from earlier context.'],
            'memory_recall': old_recall,
            'findings': [{'observed': 'NEW_TEST_MARKER'}],
            'evidence': [
                {'evidence_type': 'text_observation', 'observation': 'NEW_TEST_MARKER'},
                {'evidence_type': 'historical_memory', 'historical_only': True,
                 'observation': old_recall['context']},
            ],
        }
        self.memory.remember(QUERY, fresh_result, now='2026-10-25T23:00:00+00:00')
        after_old_expiry = self.memory.recall(QUERY, now='2026-10-26T01:00:00+00:00')
        self.assertEqual(after_old_expiry['matches'][0]['freshness'], 'within_ttl')
        self.assertIn('NEW_TEST_MARKER', after_old_expiry['context'])
        self.assertNotIn('OLD_TEST_MARKER', after_old_expiry['context'])
        newest = json.loads((Path(self.tmp.name) / 'state.json').read_text(encoding='utf-8'))['records'][-1]
        self.assertNotIn('OLD_TEST_MARKER', json.dumps(newest['safeguard']))
        self.assertTrue(newest['safeguard']['historical_inputs_excluded'])
        self.assertEqual(newest['safeguard']['summary_kind'], 'history_synthesis_omitted')

    def test_reinvestigation_supersedes_old_claims_without_deleting_them(self):
        first = self.remember()
        self.result['summary'] = 'New check is unavailable.'
        second = self.remember()
        self.assertEqual(second['supersedes'], first['memory_ids'])
        recalled = self.memory.recall(QUERY, now=T0)
        self.assertEqual(recalled['matches'][0]['id'], second['memory_ids'][0])
        self.assertNotIn('Observed an upfront registration fee request.', recalled['context'])
        state = json.loads((Path(self.tmp.name) / 'state.json').read_text(encoding='utf-8'))
        self.assertEqual(len(state['records']), 2)
        by_id = {record['id']: record for record in state['records']}
        self.assertEqual(by_id[first['memory_ids'][0]]['supersededBy'], second['memory_ids'][0])

    def test_hmem_discovers_graph_links_for_related_investigations(self):
        self.remember()
        self.memory.remember('Acme invoice registration fee', self.result, now=T0)
        state = json.loads((Path(self.tmp.name) / 'state.json').read_text(encoding='utf-8'))
        self.assertIn('mem-2', state['records'][0]['relatedTo'])
        self.assertIn('mem-1', state['records'][1]['relatedTo'])

    def test_unrelated_query_does_not_inject_acme_evidence(self):
        self.remember()
        unrelated = self.memory.recall('volcanic basalt island geology', now=T0)
        self.assertEqual(unrelated['matches'], [])
        self.assertEqual(unrelated['context'], '')

    def test_concurrent_instances_do_not_lose_records_or_audit(self):
        def store(index):
            return InvestigationMemory(self.tmp.name).remember(
                'Acme job offer case ' + str(index), self.result, now=T0)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(store, range(6)))
        self.assertTrue(all(item['status'] == 'stored' for item in results), results)
        state = json.loads((Path(self.tmp.name) / 'state.json').read_text(encoding='utf-8'))
        self.assertEqual(len(state['records']), 6)
        self.assertEqual(len({record['id'] for record in state['records']}), 6)
        self.assertEqual(self.memory.status()['ledger_actions']['create'], 6)

    def test_corrupt_store_fails_closed_without_claiming_recall(self):
        (Path(self.tmp.name) / 'state.json').write_text('not json')
        response = self.memory.recall(QUERY, now=T0)
        self.assertEqual(response['status'], 'unavailable')
        self.assertEqual(response['matches'], [])
        self.assertEqual(response['context'], '')


class HmemMissingRuntimeTests(unittest.TestCase):
    def test_missing_runtime_does_not_fail_investigation(self):
        with tempfile.TemporaryDirectory() as tmp:
            memory = InvestigationMemory(tmp, node_command=str(Path(tmp) / 'missing-node'))
            response = memory.recall(QUERY, now=T0)
            self.assertEqual(response['status'], 'unavailable')
            self.assertEqual(response['context'], '')


if __name__ == '__main__':
    unittest.main()


"""Default rules decisions must work without model, cloud services or Node."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import investigation
from evidence_validation import decide_from_evidence


class RulesInvestigationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def investigate(self, text):
        with patch('investigation.analyze_evidence', side_effect=AssertionError('No model in default mode')), \
             patch('investigation.query_domain_evidence', side_effect=AssertionError('No default cloud query')), \
             patch('investigation.InvestigationMemory', side_effect=AssertionError('No Node dependency')):
            return investigation.investigate('message', text, data_dir=self.tmp.name)

    def test_opposite_otp_context_has_opposite_decision_with_no_external_dependencies(self):
        for text, expected in [
            ('Never share your OTP. Support will never ask for it.', 'low'),
            ('Never share your one-time password with anyone. Our support team will never ask you to send an OTP.', 'low'),
            ('Please send me your OTP to unlock the account.', 'elevated'),
            ('不要发送验证码，客服不会索取密码。', 'low'),
            ('请把短信验证码发给我。', 'elevated'),
            ('Do not share it publicly, but send me your verification code.', 'elevated'),
            ('The document mentions a password and a security deposit.', 'unknown'),
            ('Pay a registration fee before the interview.', 'elevated'),
            ('请先支付保证金才能入职。', 'elevated'),
            ('先交押金才能入职。', 'elevated'),
            ('Do not pay a registration fee.', 'unknown'),
            ('Pay a refundable deposit for the apartment.', 'unknown'),
            ('Here is a reminder https://example.com: keep passwords private.', 'unknown'),
        ]:
            with self.subTest(text=text):
                result = self.investigate(text)
                self.assertEqual(result['risk_level'], expected)
                self.assertIn(result['decision']['verdict_label'], ('Safe', 'Uncertain', 'Danger'))
                self.assertNotRegex(result['decision']['summary'], '[\u4e00-\u9fff]')
                self.assertEqual(result['analysis_mode'], 'rules')
                self.assertEqual(result['ai_analysis']['status'], 'disabled')
                self.assertEqual(result['validation']['model_attempts'], 0)
                self.assertEqual(result['memory_write']['status'], 'disabled')
                self.assertEqual(result['completeness'], 'complete')
                self.assertLessEqual(len(result['decision']['reasons']), 3)
                for reason in result['decision']['reasons']:
                    self.assertEqual(reason['evidence_ids'], ['E1'])

    def test_keyword_history_demo_and_stale_observations_do_not_supply_current_evidence(self):
        records = [
            {'id': 'E1', 'evidence_type': 'keyword_signal', 'observation': {'text': 'Send your OTP'}},
            {'id': 'E2', 'evidence_type': 'text_observation', 'historical_only': True, 'observation': {'text': 'Send your OTP'}},
            {'id': 'E3', 'evidence_type': 'zetaris_record', 'observation': {'record_kind': 'curated_demo_observation', 'observation': 'Send your OTP'}},
            {'id': 'E4', 'evidence_type': 'ip_reputation', 'observation': {'listed': True, 'status': 'listed', 'details': {'stale': True}}},
        ]
        decision = decide_from_evidence(records)
        self.assertEqual(decision['risk_level'], 'unknown')
        self.assertEqual(decision['reasons'], [])

    def test_model_failure_falls_back_to_rules_instead_of_keyword_scoring(self):
        with patch.dict(os.environ, {'SAFEGUARD_ANALYSIS_MODE': 'model'}), \
             patch('investigation.analyze_evidence', return_value={'status': 'unavailable', 'provider': 'nightshift'}):
            result = investigation.investigate('message', 'Never share your OTP.', data_dir=self.tmp.name)
        self.assertEqual(result['risk_level'], 'low')
        self.assertEqual(result['decision']['fallback_from'], 'model')
        self.assertEqual(result['risk_basis']['primary'], 'current_evidence_rules')
        self.assertEqual(result['keyword_risk_level'], 'caution')

    def test_green_requires_complete_protective_context_not_a_miss_or_unknown(self):
        self.assertEqual(self.investigate('Never share your OTP.')['decision']['verdict'], 'safe')
        for text in ('Hello there.', 'The meeting starts at nine.',
                     'Never share your OTP. Visit our new portal.',
                     'Never share your OTP and download our support tool.',
                     'Never share your OTP, we are official support.',
                     'Never share your OTP we are official support.',
                     'Never share your OTP. ' + 'Additional text. ' * 1000):
            with self.subTest(text=text[:70]):
                self.assertEqual(self.investigate(text)['decision']['verdict'], 'uncertain')
        listing = {'id': 'E2', 'evidence_type': 'ip_reputation', 'observation': {'status': 'not_listed', 'listed': False}}
        reminder = {'id': 'E1', 'source': 'submitted_content', 'evidence_type': 'text_observation',
                    'observation': {'text': 'Never share your OTP.'}}
        self.assertEqual(decide_from_evidence([reminder, listing])['verdict'], 'uncertain')


if __name__ == '__main__':
    unittest.main()

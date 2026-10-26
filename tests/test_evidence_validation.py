"""Evidence-support regressions; no network or model calls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from evidence_validation import current_risk_support, validate_risk_conclusion


def primary(text, **extra):
    return {'id': 'E1', 'source': 'submitted_content', 'evidence_type': 'text_observation',
            'observation': {'text': text}, **extra}


def proposed(level='elevated'):
    return {'summary': 'A model proposes an unsupported phishing conclusion.', 'risk_level': level,
            'claims': [{'text': 'The message requests credentials.', 'evidence_ids': ['E1']}],
            'uncertainties': [], 'next_steps': ['Report the sender.']}


class EvidenceSupportTests(unittest.TestCase):
    def test_english_and_chinese_credential_requests_are_supported(self):
        for text in [
            'Please send me the one-time password you received.',
            'Our support team needs your password. Provide it by replying.',
            'I need your verification code to unlock the account.',
            '请把你收到的短信验证码发给我，我来帮你解锁账户。',
            '请提供您的登录密码。',
        ]:
            with self.subTest(text=text):
                result, audit = validate_risk_conclusion(proposed(), [primary(text)])
                self.assertEqual(result['risk_level'], 'elevated')
                self.assertTrue(audit['supported_risk_observations'])
                self.assertTrue(all(s['quote'] in text for s in audit['supported_risk_observations']))

    def test_protective_advice_and_mentions_do_not_substantiate_risk(self):
        for text in [
            'Never share your OTP. Support will never ask you to send your password.',
            'Do not send or share your verification code with anybody.',
            "We are not asking you to share your password.",
            'Security reminder: Keep verification codes private.',
            'Passwords need protection and careful handling.',
            '密码需要妥善保护。',
            'Scammers may ask you to send your OTP.',
            '不要把验证码发给任何人，客服不会要求你提供密码。',
            '我们不需要你的验证码。请保护好自己的密码。',
            '短信中提到了验证码和密码。',
        ]:
            with self.subTest(text=text):
                original = proposed()
                before = deepcopy(original)
                result, audit = validate_risk_conclusion(original, [primary(text)])
                self.assertEqual(result['risk_level'], 'unknown')
                self.assertEqual(result['claims'], [])
                self.assertEqual(audit['status'], 'abstained')
                self.assertEqual(audit['model_risk_level'], 'elevated')
                self.assertEqual(original, before)

    def test_prohibition_does_not_hide_a_separate_request(self):
        for text in [
            'Do not tell anybody, but send me your OTP.',
            'Never share your verification code publicly. Give it to me privately.',
            "Don't tell anyone and send me the password.",
            'Do not share passwords with strangers; provide your password to me.',
            '不要告诉别人，但请把验证码发给我。',
            '不要把验证码发给陌生人。请把验证码发送给我办理退款。',
        ]:
            with self.subTest(text=text):
                result, audit = validate_risk_conclusion(proposed(), [primary(text)])
                self.assertEqual(result['risk_level'], 'elevated')
                self.assertTrue(audit['supported_risk_observations'])

    def test_payment_and_promises_use_action_context_not_just_terms(self):
        for text in ['Pay the registration fee before the interview.', '请先支付保证金才能入职。',
                     'This risk-free investment offers guaranteed profit.']:
            with self.subTest(text=text):
                self.assertTrue(current_risk_support([primary(text)]))
        for text in ['Do not pay the registration fee.', '不要支付任何保证金。',
                     'Never trust guaranteed profit.', 'The document mentions a security deposit.']:
            with self.subTest(text=text):
                self.assertFalse(current_risk_support([primary(text)]))

    def test_history_missing_lookups_and_keyword_matches_cannot_raise_risk(self):
        records = [
            primary('Send me your password.', historical_only=True),
            primary('Send me your OTP.', freshness='expired'),
            {'id': 'E2', 'evidence_type': 'keyword_signal', 'observation': {'text': 'Send me your password.'}},
            {'id': 'E3', 'evidence_type': 'historical_memory', 'observation': 'Send me your OTP.'},
            {'id': 'E4', 'evidence_type': 'tool_status', 'observation': {'status': 'unconfigured'}},
            {'id': 'E5', 'evidence_type': 'ip_reputation', 'observation': {'status': 'not_listed', 'listed': False}},
        ]
        result, audit = validate_risk_conclusion(proposed(), records)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertEqual(audit['supported_risk_observations'], [])

    def test_page_text_can_support_risk_but_failed_fetch_cannot(self):
        record = {'id': 'E1', 'evidence_type': 'page_retrieval', 'observation': {
            'excerpt': 'Pay the activation fee now.', 'retrieval': {'status': 'Fetched accessible HTML'}}}
        self.assertTrue(current_risk_support([record]))
        record['observation']['retrieval']['status'] = 'BLOCKED'
        self.assertFalse(current_risk_support([record]))

    def test_listing_is_concern_not_proof_of_fraud(self):
        record = {'id': 'E1', 'evidence_type': 'ip_reputation',
                  'observation': {'status': 'listed', 'listed': True}}
        result, audit = validate_risk_conclusion(proposed(), [record])
        self.assertEqual(result['risk_level'], 'caution')
        self.assertEqual(audit['reason'], 'listing_does_not_establish_fraud')

    def test_unknown_is_not_promoted_or_claimed_safe(self):
        original = proposed('unknown')
        result, audit = validate_risk_conclusion(original, [primary('Send me your OTP.')])
        self.assertEqual(result, original)
        self.assertTrue(audit['supported_risk_observations'])


if __name__ == '__main__':
    unittest.main()

"""Website-policy/coordinator fixtures; no live HTTPS, models, Node, DNS or feeds.

These tests challenge false-green paths. Simulated TLS/page metadata is clearly
test input and does not demonstrate any real website's status or ownership.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import engine
import investigation
from website_assessment import assess_website, validate_page_context

URL = 'https://portal.example/'
BODY = ('Example public information portal. Browse service information, opening hours, '
        'contact details and published guidance. Read the accessibility information and '
        'privacy policy before using the service. This text is a synthetic test fixture.')


def page(text=BODY):
    value = engine.assess(text, 'url', URL)
    value.update(page_title='Example information portal', content_excerpt=text,
                 content_truncated=False,
                 retrieval={'status': 'Fetched accessible HTML', 'final_url': URL,
                            'tls_verified': True, 'redirect_chain': [], 'http_status': 200},
                 page_features={'forms': [], 'forms_truncated': False},
                 ip_reputation=[])
    return value


def browser_context(text=BODY, **changes):
    result = {'url': URL, 'title': 'Example information portal', 'text': text,
              'truncated': False, 'source': 'browser_visible_page', 'forms': [], 'forms_truncated': False}
    result.update(changes)
    return result


def listing(*, stale=False, expired=False, matched=True):
    expiry = datetime.now(timezone.utc) + timedelta(days=-1 if expired else 1)
    return {'provider': 'SYNTHETIC_TEST_FEED', 'source': 'fixture only', 'ip': '8.8.8.8',
            'status': 'listed' if matched else 'not_listed', 'listed': matched,
            'details': {'stale': stale, 'data_snapshot': {'refresh_by': expiry.isoformat()}}}


def model_unknown():
    return {'status': 'online', 'provider': 'nightshift', 'model': 'fixture/not-a-model',
            'analysis': {'risk_level': 'unknown', 'summary': 'The fixture model is unsure.',
                         'claims': [], 'uncertainties': ['Synthetic test response.'],
                         'next_steps': ['Review the current evidence.']}}


class WebsiteAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='safeguard-website-tests-')
        self.addCleanup(self.directory.cleanup)
        for manager in (
            patch.dict(os.environ, {}, clear=True),
            patch('socket.getaddrinfo', side_effect=AssertionError('DNS is forbidden')),
            patch('socket.create_connection', side_effect=AssertionError('Network is forbidden')),
            patch('subprocess.run', side_effect=AssertionError('Child process is forbidden')),
            patch('investigation.query_domain_evidence', side_effect=AssertionError('No cloud calls')),
            patch('investigation.InvestigationMemory', side_effect=AssertionError('No Node calls')),
            patch('investigation.analyze_evidence', side_effect=AssertionError('No model calls')),
        ):
            manager.start()
            self.addCleanup(manager.stop)

    def check_page(self, value=None, *, context=None, model=None):
        value = page() if value is None else value
        with patch('investigation.inspect_url', return_value=deepcopy(value)):
            if model is not None:
                with patch.dict(os.environ, {'SAFEGUARD_ANALYSIS_MODE': 'model'}), \
                        patch('investigation.analyze_evidence', return_value=model):
                    return investigation.investigate('url', URL, data_dir=self.directory.name,
                                                     page_context=context)
            return investigation.investigate('url', URL, data_dir=self.directory.name,
                                             page_context=context)

    def test_usable_current_page_can_be_green_without_optional_feeds(self):
        result = self.check_page()
        self.assertEqual(result['decision']['verdict'], 'safe')
        self.assertEqual(result['website_check']['status'], 'checked')
        self.assertFalse(result['website_check']['identity_verified'])
        self.assertEqual(result['risk_basis']['primary'], 'current_website_checks')
        self.assertEqual(result['ai_analysis']['status'], 'disabled')
        self.assertEqual(result['zetaris']['status'], 'disabled')
        self.assertTrue(any('coverage is incomplete' in text for text in result['limitations']))
        page_ids = {r['id'] for r in result['evidence'] if r['evidence_type'] == 'page_retrieval'}
        for reason in result['decision']['reasons']:
            self.assertTrue(set(reason['evidence_ids']) & page_ids)

    def test_ordinary_same_origin_login_is_not_a_credential_disclosure_request(self):
        result = page(BODY + ' Sign in here. Enter your password in the form to access your account.')
        result['page_features']['forms'] = [{'action': URL + 'login', 'has_password': True, 'has_otp': False}]
        self.assertEqual(self.check_page(result)['decision']['verdict'], 'safe')

    def test_actual_out_of_band_otp_or_upfront_fee_remains_red(self):
        for text in ('Please send me your OTP to unlock your account.',
                     'Pay a registration fee before your job interview.'):
            with self.subTest(text=text):
                result = self.check_page(page(BODY + ' ' + text))
                self.assertEqual(result['decision']['verdict'], 'danger')
                self.assertEqual(result['website_check']['status'], 'concern')

    def test_email_and_reply_with_otp_are_not_normal_login_copy(self):
        for text in ('Email your OTP to security@example.org.',
                     'Reply with your verification code to finish this support request.'):
            with self.subTest(text=text):
                self.assertEqual(self.check_page(page(BODY + ' ' + text))['decision']['verdict'], 'danger')

    def test_ip_miss_without_usable_page_is_not_green(self):
        value = page('')
        value['retrieval']['status'] = 'NOT VERIFIED'
        value['ip_reputation'] = [listing(matched=False)]
        result = self.check_page(value)
        self.assertEqual(result['decision']['verdict'], 'uncertain')
        self.assertEqual(result['website_check']['status'], 'incomplete')
        self.assertIn('not evidence', result['summary'])

    def test_empty_or_challenge_content_is_incomplete_not_a_fraud_finding(self):
        for title, text in (('Example portal', ''), ('Just a moment', BODY),
                            ('Example portal', 'Verify you are human to continue. ' * 5)):
            with self.subTest(title=title, text=text[:30]):
                value = page(text)
                value['page_title'] = title
                result = self.check_page(value)
                self.assertEqual(result['website_check']['status'], 'incomplete')
                self.assertEqual(result['decision']['verdict'], 'uncertain')

    def test_long_challenge_boilerplate_does_not_turn_blocked_content_green(self):
        value = page('Verify you are human to continue. Your browser is being checked. ' +
                     ('This security and privacy notice describes cookies and accessibility. ' * 20))
        result = self.check_page(value)
        self.assertEqual(result['website_check']['status'], 'incomplete')
        self.assertNotEqual(result['decision']['verdict'], 'safe')

    def test_context_url_normalization_preserves_page_binding(self):
        context = browser_context(url='https://PORTAL.example:443/#section')
        checked = validate_page_context(context, URL)
        self.assertEqual(checked['text'], BODY)
        self.assertNotIn('tls_verified', validate_page_context(dict(context, tls_verified=True), URL))

    def test_invalid_or_mismatched_browser_context_is_rejected(self):
        bad = [[], {}, browser_context(url='https://another.example/'),
               browser_context(url=URL + '?different=1'), browser_context(url=URL + 'other'),
               browser_context(source='trusted_server'), browser_context(text=123),
               browser_context(text='x' * 16001), browser_context(title='x' * 301),
               browser_context(truncated='false')]
        for context in bad:
            with self.subTest(context=str(context)[:70]), self.assertRaises(ValueError):
                validate_page_context(context, URL)
        with self.assertRaises(ValueError):
            investigation.investigate('message', BODY, data_dir=self.directory.name, page_context=browser_context())

    def test_visible_context_can_rescue_403_only_with_real_transport_evidence(self):
        value = page('Access denied.')
        value['retrieval'].update(status='NOT VERIFIED', http_status=403)
        for tls, expected in ((True, 'safe'), (False, 'uncertain')):
            with self.subTest(tls=tls):
                value['retrieval']['tls_verified'] = tls
                result = self.check_page(value, context=browser_context())
                self.assertEqual(result['decision']['verdict'], expected)
                self.assertEqual(result['website_check']['source'], 'browser_visible_page')
                self.assertTrue(any('form values were not collected' in text for text in result['limitations']))

    def test_browser_fallback_requires_form_structure(self):
        value = page('')
        value['retrieval'].update(status='NOT VERIFIED', http_status=403)
        context = browser_context()
        del context['forms']
        result = self.check_page(value, context=context)
        self.assertEqual(result['website_check']['status'], 'incomplete')
        self.assertNotEqual(result['decision']['verdict'], 'safe')

    def test_browser_form_destination_overrides_bland_server_shell(self):
        form = {'action': 'https://other.example/collect', 'method': 'post', 'has_password': True,
                'has_otp': False, 'invalid_action': False, 'has_embedded_credentials': False}
        result = self.check_page(context=browser_context(forms=[form]))
        self.assertEqual(result['risk_level'], 'caution')
        self.assertTrue(any('different destination' in reason['text'] for reason in result['decision']['reasons']))

    def test_browser_form_metadata_is_bounded_and_scrubbed(self):
        form = {'action': 'https://portal.example/login?token=private#secret', 'method': 'post',
                'has_password': True, 'has_otp': False, 'invalid_action': False,
                'has_embedded_credentials': False, 'value': 'DO NOT STORE'}
        clean = validate_page_context(browser_context(forms=[form]), URL)
        self.assertEqual(clean['forms'][0]['action'], URL + 'login')
        self.assertNotIn('value', clean['forms'][0])
        for change in ({'forms': [form] * 21}, {'forms_truncated': 'false'},
                       {'forms': [dict(form, has_password='false')]}):
            with self.subTest(change=str(change)[:60]), self.assertRaises(ValueError):
                validate_page_context(browser_context(**change), URL)
        clean = validate_page_context(browser_context(forms=[dict(form, action='https://user:secret@other.example/')]), URL)
        self.assertEqual(clean['forms'][0]['action'], '')
        self.assertTrue(clean['forms'][0]['invalid_action'])
        self.assertTrue(clean['forms'][0]['has_embedded_credentials'])

    def test_redacted_transport_query_does_not_break_current_page_binding(self):
        value = page('')
        value['retrieval'].update(status='NOT VERIFIED', http_status=403)
        context = validate_page_context(browser_context(url=URL + '?language=en'), URL + '?language=en')
        records = investigation._evidence(value, {'status': 'not_applicable'}, {}, page_context=context)
        decision, metadata = assess_website(value, records, context)
        self.assertEqual(decision['verdict'], 'safe')
        self.assertEqual(metadata['source'], 'browser_visible_page')

    def test_visible_context_for_original_url_cannot_replace_different_final_page(self):
        value = page('')
        value['retrieval'].update(status='NOT VERIFIED', final_url='https://different.example/')
        result = self.check_page(value, context=browser_context())
        self.assertEqual(result['decision']['verdict'], 'uncertain')
        self.assertEqual(result['website_check']['source'], 'none')

    def test_downgrade_and_private_redirect_prevent_green(self):
        chains = [[{'from': URL, 'to': 'http://portal.example/'}],
                  [{'from': URL, 'to': 'http://127.0.0.1/', 'blocked': True}]]
        for chain in chains:
            with self.subTest(chain=chain):
                value = page()
                value['retrieval']['redirect_chain'] = chain
                result = self.check_page(value)
                self.assertEqual(result['decision']['verdict'], 'uncertain')
                self.assertEqual(result['risk_level'], 'caution')

    def test_blocked_retrieval_cannot_be_rescued_by_visible_text(self):
        value = page('')
        value['retrieval'].update(status='BLOCKED', error_type='UnsafeUrlError')
        result = self.check_page(value, context=browser_context())
        self.assertNotEqual(result['decision']['verdict'], 'safe')

    def test_off_origin_or_insecure_credential_form_requires_caution(self):
        for action in ('https://login.other.example/', 'http://portal.example/login'):
            with self.subTest(action=action):
                value = page()
                value['page_features']['forms'] = [{'action': action, 'has_password': True}]
                result = self.check_page(value)
                self.assertEqual(result['risk_level'], 'caution')
                self.assertEqual(result['decision']['verdict'], 'uncertain')

    def test_credential_form_on_different_port_is_a_different_origin(self):
        value = page()
        value['page_features']['forms'] = [{'action': 'https://portal.example:8443/login', 'has_password': True}]
        self.assertEqual(self.check_page(value)['risk_level'], 'caution')

    def test_invalid_or_embedded_credential_form_target_is_not_assumed_same_origin(self):
        forms = [{'action': None, 'invalid_action': True, 'has_password': True},
                 {'action': URL + 'login', 'has_embedded_credentials': True, 'has_password': True}]
        for form in forms:
            with self.subTest(form=form):
                value = page()
                value['page_features']['forms'] = [form]
                self.assertNotEqual(self.check_page(value)['decision']['verdict'], 'safe')

    def test_uninspected_form_overflow_is_not_a_completed_clean_form_check(self):
        value = page()
        value['page_features']['forms_truncated'] = True
        result = self.check_page(value)
        self.assertNotEqual(result['decision']['verdict'], 'safe')
        self.assertNotEqual(result['website_check']['status'], 'checked')

    def test_current_listing_keeps_caution_but_stale_listing_is_not_current_evidence(self):
        for stale, expired, expected in ((False, False, 'caution'), (True, False, 'low'), (False, True, 'low')):
            with self.subTest(stale=stale, expired=expired):
                value = page()
                value['ip_reputation'] = [listing(stale=stale, expired=expired)]
                result = self.check_page(value)
                self.assertEqual(result['risk_level'], expected)
                self.assertEqual(bool(result['risk_basis']['listed_evidence_ids']), not (stale or expired))

    def test_model_unknown_cannot_erase_completed_positive_page_check(self):
        result = self.check_page(model=model_unknown())
        self.assertEqual(result['decision']['verdict'], 'safe')
        self.assertEqual(result['ai_risk_level'], 'unknown')
        self.assertEqual(result['risk_basis']['primary'], 'current_website_checks')
        self.assertNotIn('fixture model', result['summary'])

    def test_model_unknown_cannot_erase_current_listing_floor(self):
        value = page()
        value['ip_reputation'] = [listing()]
        result = self.check_page(value, model=model_unknown())
        self.assertEqual(result['risk_level'], 'caution')
        self.assertTrue(result['risk_basis']['listing_floor_applied'])

    def test_model_unknown_cannot_erase_current_credential_disclosure(self):
        result = self.check_page(page(BODY + ' Send me your OTP to unlock your account.'), model=model_unknown())
        self.assertEqual(result['decision']['verdict'], 'danger')
        self.assertEqual(result['ai_risk_level'], 'unknown')
        self.assertTrue(result['risk_basis']['behavior_floor_applied'])
        self.assertEqual(result['risk_basis']['primary'], 'current_evidence_rules')

    def test_browser_request_near_end_of_context_is_still_assessed(self):
        value = page('')
        value['retrieval'].update(status='NOT VERIFIED', http_status=403)
        text = BODY * 40 + ' Please send me your OTP to continue.'
        self.assertGreater(len(text), 8000)
        self.assertLess(len(text), 16000)
        self.assertEqual(self.check_page(value, context=browser_context(text))['decision']['verdict'], 'danger')

    def test_pure_policy_does_not_claim_identity_and_preserves_page_evidence_id(self):
        value = page()
        record = {'id': 'PAGE_7', 'source': URL, 'evidence_type': 'page_retrieval',
                  'observation': {'retrieval': value['retrieval'], 'excerpt': BODY, 'title': value['page_title']}}
        decision, metadata = assess_website(value, [record])
        self.assertEqual(decision['verdict'], 'safe')
        self.assertFalse(metadata['identity_verified'])
        self.assertTrue(all(reason['evidence_ids'] == ['PAGE_7'] for reason in decision['reasons']))


if __name__ == '__main__':
    unittest.main()

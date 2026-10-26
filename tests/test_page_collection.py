"""Public-page collector contracts; all HTTP and DNS responses are simulated."""
import io
import ipaddress
import json
import socket
import ssl
import sys
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import engine


class Response:
    def __init__(self, body, url, content_type='text/html; charset=utf-8', status=200):
        self.body = io.BytesIO(body)
        self.url, self.status, self.read_sizes = url, status, []
        self.headers = Message()
        self.headers['Content-Type'] = content_type

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def read(self, size):
        self.read_sizes.append(size)
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.body.close()


def public_dns(host, port, **_):
    try:
        address = ipaddress.ip_address(host).compressed
    except ValueError:
        address = '8.8.8.8'
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (address, port))]


class TestPageCollection(unittest.TestCase):
    def setUp(self):
        self.dns = patch('engine.socket.getaddrinfo', side_effect=public_dns).start()
        self.addCleanup(patch.stopall)
        self.record = {'provider': 'test-provider', 'ip': '8.8.8.8',
                       'status': 'not_listed', 'listed': False, 'source': 'test'}
        self.reputation = patch('engine.reputation_for_url', return_value=[self.record]).start()

    def collect(self, body=b'<html><p>Public information.</p></html>', *,
                url='https://start.example/', final_url=None, redirects=(),
                failure=None, content_type='text/html; charset=utf-8'):
        response = Response(body, final_url or url, content_type)
        handlers = []

        def build(*items):
            handlers.extend(items)
            redirect = next(item for item in items if isinstance(item, engine.RestrictedRedirect))

            def open_response(request, timeout):
                self.assertEqual(timeout, 7)
                for status, target in redirects:
                    request = redirect.redirect_request(request, None, status, 'Redirect', {}, target)
                if failure is not None:
                    raise failure
                return response

            return Mock(open=open_response)

        with patch('engine.urllib.request.build_opener', side_effect=build):
            result = engine.inspect_url(url)
        return result, response, handlers

    def test_normal_text_title_and_verified_https_without_field_values(self):
        result, response, handlers = self.collect(b'''<title>Public Site</title>
            <script>hidden_script</script><style>hidden_style</style>
            <div hidden>hidden_node</div><p>Useful public information.</p>
            <input type=password value="private-field-value">''')
        self.assertEqual(result['content_excerpt'], 'Public Site Useful public information.')
        self.assertEqual(result['page_title'], 'Public Site')
        self.assertFalse(result['content_truncated'])
        self.assertEqual(result['retrieval']['status'], 'Fetched accessible HTML')
        self.assertEqual(result['retrieval']['http_status'], 200)
        self.assertTrue(result['retrieval']['tls_verified'])
        self.assertEqual(response.read_sizes, [engine.MAX_HTML_BYTES + 1])
        tls = next(item for item in handlers if isinstance(item, urllib.request.HTTPSHandler))._context
        self.assertTrue(tls.check_hostname)
        self.assertEqual(tls.verify_mode, ssl.CERT_REQUIRED)
        self.assertNotIn('private-field-value', json.dumps(result))
        self.assertEqual(result['ip_reputation'][0]['destination_role'], 'initial_and_final')
        self.assertNotIn('destination_role', self.record)

    def test_byte_limit_probe_distinguishes_exact_size_from_larger_page(self):
        prefix, suffix = b'<p>Readable content.</p><!--', b'-->'
        body = prefix + b'x' * (engine.MAX_HTML_BYTES - len(prefix) - len(suffix)) + suffix
        exact, _, _ = self.collect(body)
        longer, _, _ = self.collect(body + b'x')
        self.assertFalse(exact['retrieval']['byte_truncated'])
        self.assertFalse(exact['content_truncated'])
        self.assertTrue(longer['retrieval']['byte_truncated'])
        self.assertTrue(longer['content_truncated'])
        self.assertFalse(longer['retrieval']['text_truncated'])
        self.assertEqual(longer['content_excerpt'], 'Readable content.')

    def test_visible_text_cap_is_independent_of_byte_cap(self):
        text = 'a' * engine.MAX_VISIBLE_TEXT + 'PRIVATE_TAIL'
        result, _, _ = self.collect(('<p>' + text + '</p>').encode())
        self.assertEqual(result['content_excerpt'], 'a' * engine.MAX_VISIBLE_TEXT)
        self.assertTrue(result['retrieval']['text_truncated'])
        self.assertFalse(result['retrieval']['byte_truncated'])
        self.assertTrue(result['content_truncated'])
        self.assertNotIn('PRIVATE_TAIL', json.dumps(result))

    def test_redirect_queries_initial_and_actual_final_hosts_once(self):
        result, _, _ = self.collect(final_url='https://final.example/docs?secret=token',
            redirects=[(301, '/next'), (302, 'https://final.example/docs?secret=token')])
        self.assertEqual([call.args[0] for call in self.reputation.call_args_list],
                         ['https://start.example/', 'https://final.example/docs?secret=token'])
        rows = result['ip_reputation']
        self.assertEqual([row['queried_host'] for row in rows], ['start.example', 'final.example'])
        self.assertEqual([row['destination_role'] for row in rows], ['initial', 'final'])
        self.assertEqual(rows[1]['queried_url'], 'https://final.example/docs')
        self.assertEqual(result['retrieval']['final_url'], 'https://final.example/docs')
        self.assertEqual(result['retrieval']['redirect_chain'], [
            {'from': 'https://start.example/', 'to': 'https://start.example/next', 'status': 301},
            {'from': 'https://start.example/next', 'to': 'https://final.example/docs', 'status': 302}])
        self.assertNotIn('secret=token', json.dumps(result))

    def test_same_host_redirect_avoids_repeated_ip_provider_request(self):
        result, _, _ = self.collect(final_url='https://start.example/new', redirects=[(302, '/new')])
        self.reputation.assert_called_once_with('https://start.example/')
        self.assertEqual(result['ip_reputation'][0]['destination_role'], 'initial_and_final')

    def test_private_redirect_is_blocked_before_follow_or_ip_query(self):
        result, _, _ = self.collect(redirects=[(302, 'http://127.0.0.1/admin')])
        self.assertEqual(result['retrieval']['status'], 'BLOCKED')
        self.assertTrue(result['retrieval']['redirect_chain'][0]['blocked'])
        self.reputation.assert_called_once_with('https://start.example/')
        self.assertEqual(len(result['ip_reputation']), 1)
        self.assertEqual(result['content_excerpt'], '')

    def test_redirect_embedded_credentials_are_rejected_and_not_exposed(self):
        result, _, _ = self.collect(redirects=[(302, 'https://name:private-password@other.example/path?token=secret')])
        self.assertEqual(result['retrieval']['status'], 'BLOCKED')
        self.assertNotIn('private-password', json.dumps(result))
        self.assertNotIn('token=secret', json.dumps(result))
        self.reputation.assert_called_once()

    def test_http_challenge_retains_transport_and_final_ip_but_is_not_fetched(self):
        target = 'https://final.example/challenge'
        error = urllib.error.HTTPError(target, 403, 'Forbidden', Message(), io.BytesIO(b'challenge'))
        result, _, _ = self.collect(redirects=[(302, target)], failure=error)
        self.assertEqual(result['retrieval']['http_status'], 403)
        self.assertTrue(result['retrieval']['tls_verified'])
        self.assertEqual(result['retrieval']['final_url'], target)
        self.assertEqual(result['retrieval']['status'], 'NOT VERIFIED')
        self.assertEqual(result['content_excerpt'], '')
        self.assertEqual(result['ip_reputation'][-1]['queried_host'], 'final.example')
        self.assertTrue(error.fp.closed)

    def test_ssl_certificate_failure_never_claims_verified_tls(self):
        for failure in (ssl.SSLCertVerificationError('test certificate failure'),
                        urllib.error.URLError(ssl.SSLCertVerificationError('test failure'))):
            with self.subTest(failure=type(failure).__name__):
                result, _, _ = self.collect(failure=failure)
                self.assertFalse(result['retrieval']['tls_verified'])
                self.assertEqual(result['retrieval']['status'], 'NOT VERIFIED')
                self.assertEqual(len(result['ip_reputation']), 1)

    def test_http_response_does_not_claim_tls(self):
        result, _, _ = self.collect(url='http://start.example/')
        self.assertFalse(result['retrieval']['tls_verified'])
        self.assertEqual(result['retrieval']['http_status'], 200)

    def test_non_html_retains_transport_and_ip_but_no_content_success(self):
        result, _, _ = self.collect(b'{}', content_type='application/json')
        self.assertEqual(result['retrieval']['status'], 'NOT VERIFIED')
        self.assertEqual(result['retrieval']['http_status'], 200)
        self.assertTrue(result['retrieval']['tls_verified'])
        self.assertEqual(result['content_excerpt'], '')
        self.assertEqual(len(result['ip_reputation']), 1)

    def test_unexpected_private_response_and_http_error_urls_are_blocked(self):
        result, _, _ = self.collect(final_url='http://127.0.0.1/private')
        self.assertEqual(result['retrieval']['status'], 'BLOCKED')
        error = urllib.error.HTTPError('http://127.0.0.1/private', 403, 'Forbidden', Message(), io.BytesIO())
        result, _, _ = self.collect(failure=error)
        self.assertEqual(result['retrieval']['status'], 'BLOCKED')
        self.assertFalse(result['retrieval']['tls_verified'])
        self.assertIsNone(result['retrieval']['final_url'])
        self.assertEqual(self.reputation.call_count, 2)

    def test_initial_private_destination_fails_before_network_or_provider(self):
        with patch('engine.urllib.request.build_opener') as build, self.assertRaises(ValueError):
            engine.inspect_url('http://192.168.1.1/private')
        build.assert_not_called()
        self.reputation.assert_not_called()


class TestPageFeatures(unittest.TestCase):
    def features(self, source):
        parser = engine.Extractor('https://site.example/docs/page')
        parser.feed(source)
        parser.close()
        return parser.features()

    def test_base_form_canonical_and_external_control_association(self):
        features = self.features('''<base href="https://login.example/account/">
            <link rel="canonical alternate" href="overview?token=not-retained#part">
            <input form="login" autocomplete="one-time-code" value="private-otp">
            <form id="login" method="POST" action="submit?csrf=private-token">
              <input type="password" value="private-password"></form>''')
        form = features['forms'][0]
        self.assertEqual(form['action'], 'https://login.example/account/submit')
        self.assertEqual(form['method'], 'post')
        self.assertTrue(form['has_password'])
        self.assertTrue(form['has_otp'])
        self.assertTrue(form['has_visible_password'])
        self.assertEqual(features['canonical_url'], 'https://login.example/account/overview')
        self.assertTrue(features['structure_only'])
        for secret in ('private-otp', 'private-password', 'private-token', 'not-retained'):
            self.assertNotIn(secret, json.dumps(features))

    def test_invalid_and_credential_actions_are_marked_without_leaking_credentials(self):
        features = self.features('''<form action="https://name:secret@other.example/a"></form>
            <form action="javascript:submit()"></form><form action="http://[invalid"></form>''')
        self.assertTrue(features['forms'][0]['has_embedded_credentials'])
        for form in features['forms']:
            self.assertTrue(form['invalid_action'])
            self.assertIsNone(form['action'])
        self.assertNotIn('name:secret', json.dumps(features))

    def test_invalid_base_is_not_silently_treated_as_normal_relative_destination(self):
        features = self.features('''<base href="https://name:secret@other.example/">
            <form action="collect"></form><link rel="canonical" href="home">''')
        self.assertTrue(features['base_invalid'])
        self.assertTrue(features['forms'][0]['has_embedded_credentials'])
        self.assertTrue(features['forms'][0]['invalid_action'])
        self.assertTrue(features['canonical_invalid'])
        self.assertIsNone(features['canonical_url'])

    def test_hidden_forms_are_distinguished_from_visible_credentials(self):
        features = self.features('''<form id="hidden" style="display: none">
            <input type=password><input name=verification_code></form>
            <input type=password form=hidden>
            <form><input type=hidden name=otp></form>''')
        self.assertTrue(features['forms'][0]['has_password'])
        self.assertTrue(features['forms'][0]['has_otp'])
        self.assertFalse(features['forms'][0]['has_visible_password'])
        self.assertFalse(features['forms'][0]['has_visible_otp'])
        self.assertFalse(features['forms'][1]['has_visible_otp'])

    def test_submit_action_override_inherits_credentials_and_is_not_lost(self):
        features = self.features('''<form id=login action="/login"><input type=password>
            <button type=submit formaction="https://other.example/collect?token=secret">Sign in</button>
            <button type=button formaction="https://ignored.example/">Not a submit</button></form>
            <input type=submit form=login formaction="/alternate" formmethod=post>''')
        self.assertEqual(len(features['forms']), 3)
        override = features['forms'][1]
        self.assertEqual(override['action'], 'https://other.example/collect')
        self.assertTrue(override['submit_override'])
        self.assertTrue(override['has_visible_password'])
        self.assertEqual(features['forms'][2]['method'], 'post')
        self.assertNotIn('token=secret', json.dumps(features))

    def test_form_limit_is_explicit_including_submit_overrides(self):
        features = self.features('<form></form>' * (engine.MAX_FORMS + 1))
        self.assertEqual(len(features['forms']), engine.MAX_FORMS)
        self.assertTrue(features['forms_truncated'])
        source = '<form><input type=password>' + '<button formaction="/submit">Submit</button>' * engine.MAX_FORMS + '</form>'
        features = self.features(source)
        self.assertEqual(len(features['forms']), engine.MAX_FORMS)
        self.assertTrue(features['forms_truncated'])


if __name__ == '__main__':
    unittest.main()

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from engine import assess
from ip_reputation import (
    BlackIpsProvider,
    blackips_status,
    check_ip,
    is_public_global_ip,
    load_optional_env_file,
    merge_ip_evidence,
    normalize_blackips_payload,
    parse_ip,
    reputation_for_url,
    require_public_global_ip,
    resolve_public_ips,
)


class FakeHttpResponse:
    def __init__(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.status = status
        self._buf = io.BytesIO(raw)

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestIpValidation(unittest.TestCase):
    def test_public_ipv4_accepted(self):
        self.assertTrue(is_public_global_ip('8.8.8.8'))
        self.assertEqual(require_public_global_ip('8.8.8.8').compressed, '8.8.8.8')

    def test_public_ipv6_accepted(self):
        addr = require_public_global_ip('2001:4860:4860::8888')
        self.assertEqual(addr.version, 6)
        self.assertTrue(is_public_global_ip(addr))

    def test_localhost_rejected(self):
        self.assertFalse(is_public_global_ip('127.0.0.1'))
        self.assertFalse(is_public_global_ip('::1'))
        with self.assertRaises(ValueError):
            require_public_global_ip('127.0.0.1')

    def test_rfc1918_private_ipv4_rejected(self):
        for ip in ('10.0.0.1', '172.16.5.9', '192.168.1.20'):
            with self.subTest(ip=ip):
                self.assertFalse(is_public_global_ip(ip))
                with self.assertRaises(ValueError):
                    require_public_global_ip(ip)

    def test_invalid_ip_rejected(self):
        for value in ('', 'not-an-ip', '999.999.999.999', 'example.com'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ip(value)
                with self.assertRaises(ValueError):
                    is_public_global_ip(value)

    def test_other_non_public_skipped(self):
        for ip in ('169.254.1.1', '224.0.0.1', '0.0.0.0', '255.255.255.255', 'fe80::1'):
            with self.subTest(ip=ip):
                self.assertFalse(is_public_global_ip(ip))


class TestHostnameResolution(unittest.TestCase):
    @patch('ip_reputation.socket.getaddrinfo')
    def test_resolve_filters_private_dedupes_and_limits(self, mock_gai):
        mock_gai.return_value = [
            (0, 0, 0, '', ('8.8.8.8', 80)),
            (0, 0, 0, '', ('8.8.8.8', 80)),
            (0, 0, 0, '', ('127.0.0.1', 80)),
            (0, 0, 0, '', ('10.1.1.1', 80)),
            (0, 0, 0, '', ('1.1.1.1', 80)),
            (0, 0, 0, '', ('9.9.9.9', 80)),
            (0, 0, 0, '', ('8.8.4.4', 80)),
            (0, 0, 0, '', ('1.0.0.1', 80)),
        ]
        ips = resolve_public_ips('example.test', 80, limit=4)
        self.assertEqual(ips, ['8.8.8.8', '1.1.1.1', '9.9.9.9', '8.8.4.4'])
        self.assertNotIn('127.0.0.1', ips)
        self.assertNotIn('10.1.1.1', ips)


class TestBlackIpsNormalization(unittest.TestCase):
    def test_snapshot_failures_and_wrong_ip_never_become_a_miss(self):
        for reason in ('redis_unavailable', 'dataset_unavailable', 'dataset_incomplete', 'dataset_stale'):
            with self.subTest(reason=reason):
                result = normalize_blackips_payload({'code': -1, 'ip': '1.1.1.1', 'error': reason}, '1.1.1.1')
                self.assertEqual(result['status'], 'unavailable')
                self.assertIsNone(result['listed'])
        wrong = normalize_blackips_payload({'code': 0, 'ip': '8.8.8.8'}, '1.1.1.1')
        self.assertEqual(wrong['details']['reason'], 'mismatched_ip')
        self.assertEqual(normalize_blackips_payload({'code': False, 'ip': '1.1.1.1'}, '1.1.1.1')['status'], 'unavailable')

    def test_snapshot_provenance_is_preserved_and_stale_or_empty_is_unavailable(self):
        snapshot = {'unique_ips': 10, 'commit': 'a' * 40, 'storage_key': 'private-internal-key',
                    'refresh_by': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    'coverage': 'Two exact IPv4 feeds only', 'feeds': [{'name': 'blocklist_de.ipset'}]}
        payload = {'code': 1, 'ip': '1.1.1.1', 'message': 'blocklist_de', 'data_snapshot': snapshot}
        result = normalize_blackips_payload(payload, '1.1.1.1')
        self.assertEqual(result['status'], 'listed')
        self.assertEqual(result['details']['data_snapshot']['unique_ips'], 10)
        self.assertNotIn('storage_key', result['details']['data_snapshot'])
        snapshot['unique_ips'] = 0
        self.assertEqual(normalize_blackips_payload(payload, '1.1.1.1')['status'], 'unavailable')
        snapshot['unique_ips'] = 10
        snapshot['refresh_by'] = '2020-01-01T00:00:00Z'
        self.assertEqual(normalize_blackips_payload(payload, '1.1.1.1')['details']['reason'], 'dataset_stale')

    @patch('ip_reputation.urllib.request.urlopen')
    def test_http_error_contract_preserves_unavailable_and_unsupported(self, mock_open):
        for status, reason, expected in ((503, 'dataset_incomplete', 'unavailable'),
                                         (422, 'unsupported_address_family', 'unsupported')):
            raw = json.dumps({'code': -1, 'error': reason, 'ip': '1.1.1.1'}).encode()
            mock_open.side_effect = HTTPError('http://127.0.0.1:9091/check', status, 'Unavailable', {}, io.BytesIO(raw))
            result = BlackIpsProvider('http://127.0.0.1:9091').check('1.1.1.1')
            self.assertEqual(result['status'], expected)
            self.assertEqual(result['details']['reason'], reason)

    def test_blackips_hit_normalization(self):
        result = normalize_blackips_payload(
            {'code': 1, 'ip': '1.2.3.4', 'message': 'abuseipdb_30d'},
            '1.2.3.4',
            checked_at='2026-01-01T00:00:00+00:00',
        )
        self.assertEqual(result['provider'], 'blackips')
        self.assertEqual(result['ip'], '1.2.3.4')
        self.assertEqual(result['status'], 'listed')
        self.assertIs(result['listed'], True)
        self.assertEqual(result['source'], 'abuseipdb_30d')
        self.assertNotIn('malicious', json.dumps(result).lower())

    def test_blackips_miss_normalization(self):
        result = normalize_blackips_payload(
            {'code': 0, 'ip': '1.2.3.4', 'message': ''},
            '1.2.3.4',
            checked_at='2026-01-01T00:00:00+00:00',
        )
        self.assertEqual(result['status'], 'not_listed')
        self.assertIs(result['listed'], False)
        self.assertEqual(result['source'], '')

    def test_blackips_unavailable_when_unconfigured(self):
        provider = BlackIpsProvider(base_url='')
        result = provider.check('1.2.3.4')
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['listed'])
        self.assertEqual(result['details'].get('reason'), 'not_configured')

    @patch.dict('os.environ', {}, clear=True)
    def test_check_ip_unavailable_without_env(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'BLACKIPS_SNAPSHOT_DIR': tmp}):
            result = check_ip('8.8.8.8')
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['listed'])

    @patch('ip_reputation.urllib.request.urlopen')
    def test_blackips_http_hit_without_live_server(self, mock_open):
        mock_open.return_value = FakeHttpResponse({'code': 1, 'ip': '1.2.3.4', 'message': 'abuseipdb_30d'})
        result = BlackIpsProvider('http://127.0.0.1:9091').check('1.2.3.4')
        self.assertEqual(result['status'], 'listed')
        self.assertTrue(result['listed'])
        mock_open.assert_called_once()

    @patch('ip_reputation.urllib.request.urlopen', side_effect=ConnectionError('refused'))
    def test_blackips_connection_failure_is_unavailable(self, _mock_open):
        result = BlackIpsProvider('http://127.0.0.1:9091').check('1.2.3.4')
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['listed'])
        self.assertEqual(result['details'].get('reason'), 'provider_error')

    def test_private_ip_check_is_unsupported_not_a_listing(self):
        result = check_ip('192.168.0.5', provider=BlackIpsProvider('http://127.0.0.1:9091'))
        self.assertEqual(result['status'], 'unsupported')
        self.assertIsNone(result['listed'])


class TestInspectEvidenceMerge(unittest.TestCase):
    def test_listing_is_external_evidence_without_changing_risk(self):
        result = assess('hello', 'url', 'https://example.com')
        original_risk = result['risk_level']
        listed = normalize_blackips_payload(
            {'code': 1, 'ip': '1.2.3.4', 'message': 'abuseipdb_30d'}, '1.2.3.4')
        merge_ip_evidence(result, [listed])
        self.assertEqual(result['risk_level'], original_risk)
        self.assertEqual(result['ip_reputation'][0]['status'], 'listed')
        self.assertIn('The destination IP was listed by blackips at check time.', result['verified_facts'])
        self.assertNotIn('definitely malicious', ' '.join(result['verified_facts']).lower())
        self.assertIn('An IP reputation miss is not proof that a site is safe.', result['limitations'])

    def test_miss_is_not_proof_of_safety(self):
        result = assess('hello', 'url', 'https://example.com')
        miss = normalize_blackips_payload({'code': 0, 'ip': '1.2.3.4', 'message': ''}, '1.2.3.4')
        merge_ip_evidence(result, [miss])
        self.assertEqual(result['verified_facts'], [])
        self.assertEqual(result['ip_reputation'][0]['listed'], False)

    @patch('ip_reputation.socket.getaddrinfo')
    def test_url_inspection_does_not_fail_when_provider_is_down(self, mock_gai):
        mock_gai.return_value = [(0, 0, 0, '', ('8.8.8.8', 443))]
        provider = BlackIpsProvider('')
        records = reputation_for_url('https://example.com', provider=provider)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['status'], 'unavailable')


@patch.dict(os.environ, {'SAFEGUARD_IP_PROVIDER': 'remote'})
class TestBlackIpsStatus(unittest.TestCase):
    @patch.dict('os.environ', {'BLACKIPS_BASE_URL': 'http://user:test-secret@127.0.0.1:9091', 'SAFEGUARD_IP_PROVIDER': 'remote'}, clear=True)
    @patch('ip_reputation.urllib.request.urlopen')
    def test_endpoint_credentials_are_rejected_without_request_or_status_disclosure(self, request):
        report = blackips_status()
        self.assertFalse(report['reachable'])
        self.assertNotIn('test-secret', json.dumps(report))
        request.assert_not_called()

    @patch('ip_reputation.configured_base_url', return_value='')
    def test_status_when_unconfigured(self, _cfg):
        report = blackips_status()
        self.assertEqual(report['provider'], 'blackips')
        self.assertFalse(report['configured'])
        self.assertFalse(report['reachable'])
        self.assertEqual(report['message'], 'BLACKIPS_BASE_URL is not configured')
        self.assertNotIn('base_url', report)
        blob = json.dumps(report).lower()
        self.assertNotIn('password', blob)
        self.assertNotIn('redis', blob)

    @patch('ip_reputation.BlackIpsProvider.check', return_value={'status': 'not_listed', 'listed': False})
    @patch('ip_reputation.configured_base_url', return_value='http://127.0.0.1:9091')
    def test_status_when_reachable_including_miss(self, _cfg, _check):
        report = blackips_status()
        self.assertTrue(report['configured'])
        self.assertTrue(report['reachable'])
        self.assertEqual(report['base_url'], 'http://127.0.0.1:9091')
        self.assertEqual(report['message'], 'BlackIPS service is reachable')

    @patch('ip_reputation.BlackIpsProvider.check', return_value={'status': 'unavailable', 'listed': None})
    @patch('ip_reputation.configured_base_url', return_value='http://127.0.0.1:9091')
    def test_status_when_configured_but_down(self, _cfg, _check):
        report = blackips_status()
        self.assertTrue(report['configured'])
        self.assertFalse(report['reachable'])
        self.assertEqual(report['message'], 'BlackIPS is configured but not reachable')
        self.assertNotIn('password', json.dumps(report).lower())

    def test_env_file_does_not_override_existing_or_store_secrets_in_example(self):
        example = Path(__file__).resolve().parents[1] / '.env.example'
        text = example.read_text(encoding='utf-8').lower()
        self.assertIn('blackips_base_url=', text)
        self.assertNotRegex(text, r'(?m)^(redis|password|api_key|secret)\s*=')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.env'
            path.write_text('BLACKIPS_BASE_URL=http://127.0.0.1:9091\n', encoding='utf-8')
            os.environ.pop('SAFE_GUARD_ENV_PROBE', None)
            path.write_text('SAFE_GUARD_ENV_PROBE=from-file\n', encoding='utf-8')
            self.assertTrue(load_optional_env_file(path))
            self.assertEqual(os.environ.get('SAFE_GUARD_ENV_PROBE'), 'from-file')
            os.environ['SAFE_GUARD_ENV_PROBE'] = 'already-set'
            path.write_text('SAFE_GUARD_ENV_PROBE=should-not-win\n', encoding='utf-8')
            load_optional_env_file(path)
            self.assertEqual(os.environ['SAFE_GUARD_ENV_PROBE'], 'already-set')
            os.environ.pop('SAFE_GUARD_ENV_PROBE', None)

    def test_live_script_refuses_private_ip_without_blackips(self):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'test_blackips_live.py'
        completed = subprocess.run(
            [sys.executable, str(script), '192.168.1.1'],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('Refused', completed.stderr)


if __name__ == '__main__':
    unittest.main()

"""Synthetic IP-only fixtures test snapshot integrity and cloud-independent fallback."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'server'), str(ROOT / 'scripts')]
from offline_snapshot import SnapshotProvider, FEED_NAMES, REPOSITORY, load_snapshot
from ip_reputation import check_ip, blackips_status
from sync_blackips_snapshot import sync
from evidence_validation import decide_from_evidence


def fixture(folder, age=1):
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc) - timedelta(hours=age)
    commit = 'a' * 40
    manifest = {'repository': REPOSITORY, 'commit': commit, 'feeds': []}
    for name, ip in zip(FEED_NAMES, ('1.0.164.165', '8.8.8.8')):
        raw = ('# TEST FIXTURE ONLY\n# Source File Date: ' + stamp.strftime('%a %b %d %H:%M:%S UTC %Y') + '\n' + ip + '\n').encode()
        (folder / name).write_bytes(raw)
        manifest['feeds'].append({'name': name, 'url': f'https://raw.githubusercontent.com/njcx/blackip_list/{commit}/{name}',
                                  'sha256': hashlib.sha256(raw).hexdigest()})
    (folder / 'manifest.json').write_text(json.dumps(manifest))


class OfflineSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {'BLACKIPS_SNAPSHOT_DIR': str(self.root / 'source')}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        fixture(self.root / 'source')

    def test_fresh_snapshot_has_source_date_hash_and_real_membership_without_network(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('Offline must not contact a service')):
            os.environ['SAFEGUARD_IP_PROVIDER'] = 'snapshot'
            hit, miss = check_ip('1.0.164.165'), check_ip('1.1.1.1')
            self.assertEqual(hit['status'], 'listed')
            self.assertEqual(miss['status'], 'not_listed')
            self.assertTrue(hit['details']['offline'])
            self.assertFalse(hit['details']['fallback'])
            self.assertEqual(hit['source'], 'abuseipdb_30d')
            self.assertIn('source_file_date', hit['details']['data_snapshot']['feeds'][0])
            self.assertTrue(blackips_status()['reachable'])

    def test_auto_fallback_on_unconfigured_or_failed_remote_is_explicit(self):
        for configured in ('', 'http://127.0.0.1:9091'):
            with self.subTest(configured=bool(configured)), patch.dict(os.environ, {'BLACKIPS_BASE_URL': configured}):
                with patch('ip_reputation.BlackIpsProvider._query', side_effect=OSError('offline')):
                    result = check_ip('1.0.164.165')
                self.assertEqual(result['status'], 'listed')
                self.assertTrue(result['details']['fallback'])
                self.assertIn('remote_reason', result['details'])

    def test_expired_snapshot_neither_hits_nor_misses_and_cannot_raise_current_risk(self):
        fixture(self.root / 'source', age=73)
        for ip in ('1.0.164.165', '1.1.1.1'):
            result = SnapshotProvider().check(ip)
            self.assertEqual(result['status'], 'unavailable')
            self.assertIsNone(result['listed'])
            self.assertTrue(result['details']['stale'])
            self.assertFalse(result['details']['usable_as_current_evidence'])
        # Even a mistakenly retained positive flag cannot make stale data current.
        result.update(status='listed', listed=True)
        decision = decide_from_evidence([{'id': 'E1', 'evidence_type': 'ip_reputation', 'observation': result}])
        self.assertEqual(decision['risk_level'], 'unknown')

    def test_tampering_wrong_source_future_timestamp_and_unsupported_inputs_fail_closed(self):
        for mutate in ('hash', 'source', 'future'):
            with self.subTest(mutate=mutate):
                fixture(self.root / 'source', age=-2 if mutate == 'future' else 1)
                if mutate == 'hash':
                    with (self.root / 'source' / FEED_NAMES[0]).open('ab') as handle:
                        handle.write(b'1.1.1.1\n')
                elif mutate == 'source':
                    path = self.root / 'source' / 'manifest.json'
                    manifest = json.loads(path.read_text())
                    manifest['feeds'][0]['url'] = 'https://untrusted.example/feed'
                    path.write_text(json.dumps(manifest))
                self.assertEqual(SnapshotProvider().check('1.1.1.1')['status'], 'unavailable')
        for ip in ('bad-ip', '127.0.0.1', '2606:4700:4700::1111'):
            self.assertEqual(SnapshotProvider().check(ip)['status'], 'unsupported')

    def test_sync_and_restore_preserve_dates_and_failed_refresh_keeps_previous_pointer(self):
        destination = self.root / 'private-cache'
        report = sync(destination, self.root / 'source')
        before = (destination / 'current.json').read_bytes()
        self.assertEqual(SnapshotProvider(destination).check('1.0.164.165')['status'], 'listed')
        self.assertEqual(report['source_date'], load_snapshot(self.root / 'source')[1]['source_date'])
        with patch('sync_blackips_snapshot.download', side_effect=OSError('network unavailable')):
            with self.assertRaises(OSError):
                sync(destination)
        self.assertEqual((destination / 'current.json').read_bytes(), before)
        self.assertEqual(SnapshotProvider(destination).check('1.1.1.1')['status'], 'not_listed')
        restored = self.root / 'restored-cache'
        restored_report = sync(restored, destination)
        self.assertEqual(restored_report['source_date'], report['source_date'])
        self.assertEqual(restored_report['refresh_by'], report['refresh_by'])
        self.assertEqual(SnapshotProvider(restored).check('1.0.164.165')['status'], 'listed')


if __name__ == '__main__':
    unittest.main()

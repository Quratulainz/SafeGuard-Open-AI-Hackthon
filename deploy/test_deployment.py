"""Local-only safety checks for deployment templates; never calls AWS/Docker."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


launch = module('launch_template', 'aws/launch_cloudshell.py')
bundle = module('bundle_template', 'zetaris/configure_fresh_bundle.py')


class LaunchGuards(unittest.TestCase):
    def rejected_before_aws(self, arguments):
        with patch.object(sys, 'argv', ['launch_cloudshell.py'] + arguments), \
                patch.object(launch, 'aws') as call, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                launch.main()
            call.assert_not_called()

    def test_apply_requires_all_explicit_guards(self):
        for args in (['--apply'], ['--apply', '--with-scheduler'],
                     ['--apply', '--with-scheduler', '--prices-reviewed'],
                     ['--apply', '--prices-reviewed', '--existing-cost-usd', '0']):
            with self.subTest(args=args):
                self.rejected_before_aws(args)

    def test_budget_rejects_prior_cost_and_nonfinite_rates(self):
        for args in (['--existing-cost-usd', '5'], ['--ec2-hourly-usd', 'nan'],
                     ['--gp3-gib-monthly-usd', 'inf'], ['--ipv4-hourly-usd', '-1']):
            with self.subTest(args=args):
                self.rejected_before_aws(args)

    def test_actual_iam_propagation_error_retries_without_broadening_role(self):
        error = RuntimeError('ValidationException: execution role must allow AWS EventBridge Scheduler to assume the role')
        with patch.object(launch, 'aws', side_effect=[error, {'ok': True}]) as call, \
                patch.object(launch.time, 'sleep') as sleep:
            self.assertEqual(launch.create_schedule_with_retry('--name', 'test'), {'ok': True})
            self.assertEqual(call.call_count, 2)
            self.assertEqual(call.call_args_list[0], call.call_args_list[1])
            sleep.assert_called_once()

    def test_other_authorization_failure_is_not_retried(self):
        with patch.object(launch, 'aws', side_effect=RuntimeError('AccessDenied')) as call, \
                patch.object(launch.time, 'sleep') as sleep:
            with self.assertRaises(RuntimeError):
                launch.create_schedule_with_retry('--name', 'test')
            self.assertEqual(call.call_count, 1)
            sleep.assert_not_called()


class FreshBundleGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.source = self.path / 'vendor'
        self.source.mkdir()
        (self.source / 'docker-compose.yml').write_text('name: zetaris\nports:\n - "${UI_PORT:-3000}:3000"\n')
        self.env = self.source / '.env'
        self.original = 'KEEP_ME=yes\nUI_PORT=3000\nCOMPOSE_PROFILES=tls\n'
        self.env.write_text(self.original)

    def test_default_never_writes_or_calls_docker(self):
        with patch.object(bundle.subprocess, 'run') as call:
            result = bundle.prepare(self.source, self.path / 'private')
            self.assertEqual(result['mode'], 'read_only')
            call.assert_not_called()
        self.assertEqual(self.env.read_text(), self.original)
        self.assertFalse((self.path / 'private').exists())

    def test_retained_volume_blocks_password_rotation(self):
        clean = types.SimpleNamespace(returncode=0, stdout='')
        existing = types.SimpleNamespace(returncode=0, stdout='zetaris_pgdata\n')
        with patch.object(bundle.subprocess, 'run', side_effect=[clean, existing]):
            with self.assertRaises(ValueError):
                bundle.prepare(self.source, self.path / 'private', apply=True, fresh_confirmed=True)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertFalse((self.path / 'private').exists())

    def test_fresh_configuration_keeps_unrelated_values_and_private_auth(self):
        with patch.object(bundle.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='')):
            result = bundle.prepare(self.source, self.path / 'private', apply=True, fresh_confirmed=True)
        content = self.env.read_text()
        self.assertIn('KEEP_ME=yes', content)
        self.assertIn('UI_PORT=127.0.0.1:3000', content)
        self.assertNotIn('COMPOSE_PROFILES=', content)
        auth = bundle.json.loads((self.path / 'private/runtime-auth.json').read_text())
        self.assertEqual(len(auth['password']), 44)
        self.assertTrue(auth['password'].startswith('Aa1!'))
        self.assertNotIn('$', auth['password'])
        self.assertNotIn(auth['password'], str(result))
        with self.assertRaises(ValueError):
            bundle.prepare(self.source, self.path / 'private')


if __name__ == '__main__':
    unittest.main()

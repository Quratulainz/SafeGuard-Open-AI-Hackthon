"""Legacy generated copy changes language without changing historical evidence."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from presentation import english_saved_result


class EnglishPresentationTests(unittest.TestCase):
    def test_legacy_copy_changes_but_input_evidence_and_verdict_do_not(self):
        old = '\u8981\u6c42\u4f60\u63d0\u4f9b\u5bc6\u7801\u6216\u9a8c\u8bc1\u7801\u3002'
        result = {'summary': old, 'risk_level': 'elevated', 'checked_at': '2026-10-25T10:00:00Z',
                  'input': old, 'evidence': [{'id': 'E1', 'observation': {'text': old, 'summary': old}}],
                  'decision': {'verdict': 'danger', 'verdict_label': '\u5371\u9669', 'summary': old,
                               'reasons': [{'text': old, 'evidence_ids': ['E1'], 'rule_id': 'credential_disclosure_request'}]}}
        before = copy.deepcopy(result)
        shown = english_saved_result(result)
        self.assertEqual(shown['summary'], 'Requests a password or verification code.')
        self.assertEqual(shown['decision']['verdict_label'], 'Danger')
        self.assertEqual(shown['decision']['reasons'][0]['text'], shown['summary'])
        for field in ('risk_level', 'checked_at', 'input', 'evidence'):
            self.assertEqual(shown[field], before[field])
        self.assertEqual(shown['decision']['verdict'], before['decision']['verdict'])
        self.assertEqual(shown['decision']['reasons'][0]['evidence_ids'], ['E1'])
        self.assertEqual(result, before, 'The stored source object must not be rewritten.')

    def test_unknown_or_external_wording_is_not_silently_replaced(self):
        result = {'summary': 'An independently worded report.',
                  'next_steps': ['Keep the original instructions.'],
                  'decision': {'verdict': 'uncertain', 'limitations': ['A source-specific limit.']}}
        self.assertEqual(english_saved_result(result), result)


if __name__ == '__main__':
    unittest.main()

"""The proposal must always match the policy the CLI loads."""

from pathlib import Path
import unittest

from secscan.policy_doc import render


class PolicyTests(unittest.TestCase):
    label = "automated"

    def test_thresholds_document_matches_installed_policy(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / "THRESHOLDS.md").read_text(encoding="utf-8"), render())

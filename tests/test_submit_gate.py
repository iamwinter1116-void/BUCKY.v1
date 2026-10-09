"""Submit-gate tests — the three real triage rejections as fixtures."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.submit_gate import (FindingMeta, KnownIssue, ProgramRule,
                              SubmitVerdict, submit_gate)

# campaign program-rules (the third-party-namespace exclusion that
# produced the real 'Invalid' ruling)
_FRESK_RULES = (
    ProgramRule("namespace", "*.freshdesk.com",
                "third-party namespace — not a program asset"),
)


class TestSubmitGate(unittest.TestCase):
    # ---- gate 1: Artifactory lesson (no impact -> reject) -------
    def test_exposed_no_capture_rejected(self):
        m = FindingMeta("exposed-artifact-repo", "artifacts.tld",
                         "Attackers could expose sensitive artifacts.",
                         has_runtime_capture=False)
        v = submit_gate(m)
        self.assertFalse(v.ok)
        self.assertTrue(any("runtime capture" in r for r in v.rejections))

    def test_exposed_no_capture_rejected_even_with_claim(self):
        m = FindingMeta("exposed-artifact-repo", "artifacts.tld",
                         "sensitive data could be accessed by anyone.",
                         has_runtime_capture=False)
        v = submit_gate(m)
        self.assertFalse(v.ok)
        self.assertTrue(any("claim-only" in r for r in v.rejections))

    def test_exposed_with_capture_and_demonstrated_action_passes(self):
        m = FindingMeta(
            "exposed-artifact-repo", "artifacts.tld",
            "I retrieved the internal build artifact and accessed "
            "compiled credentials inside it via the unauthenticated "
            "endpoint.",
            has_runtime_capture=True)
        v = submit_gate(m)
        # capture + demonstrated -> gates 1 satisfied (no rules/ledger)
        self.assertEqual([r for r in v.rejections if "impact-gate" in r],
                         [])

    def test_claim_only_wording_fails_even_for_non_exposure(self):
        m = FindingMeta("weak-csp", "app.tld",
                         "This could allow injection attacks.")
        v = submit_gate(m)
        self.assertFalse(v.ok)
        self.assertTrue(any("claim-only" in r for r in v.rejections))

    # ---- gate 2: Duplicate lesson -------------------------------
    def test_duplicate_issue_class_plus_asset_rejected(self):
        m = FindingMeta("exposed-artifact-repo", "artifacts.tld",
                         "demonstrated: retrieved internal artifact",
                         has_runtime_capture=True)
        ledger = (KnownIssue("exposed-artifact-repo", "artifacts.tld",
                             "duplicate", "case-1"),)
        v = submit_gate(m, known_issues=ledger)
        self.assertFalse(v.ok)
        self.assertTrue(any("already ruled 'duplicate'" in r
                            for r in v.rejections))

    def test_same_class_different_asset_not_dup(self):
        m = FindingMeta("exposed-artifact-repo", "other.tld",
                         "demonstrated: retrieved internal artifact",
                         has_runtime_capture=True)
        ledger = (KnownIssue("exposed-artifact-repo", "artifacts.tld",
                             "duplicate"),)
        v = submit_gate(m, known_issues=ledger)
        self.assertTrue(v.ok, v.rejections)

    def test_wildcard_ledger_entry_catches_class(self):
        m = FindingMeta("public-s3-bucket", "cdn.tld",
                         "demonstrated: retrieved the bucket index",
                         has_runtime_capture=True)
        ledger = (KnownIssue("public-s3-*", "*", "invalid"),)
        v = submit_gate(m, known_issues=ledger)
        self.assertFalse(v.ok)
        self.assertTrue(any("already ruled 'invalid'" in r
                            for rejections in [v.rejections]
                            for r in rejections))

    # ---- gate 3: Freshdesk lesson (third-party asset) -----------
    def test_third_party_namespace_rejected(self):
        m = FindingMeta("subdomain-takeover", "acme.freshdesk.com",
                         "demonstrated: created a support page on the "
                         "dangling subdomain",
                         has_runtime_capture=True)
        v = submit_gate(m, program_rules=_FRESK_RULES)
        self.assertFalse(v.ok)
        self.assertTrue(any("third-party namespace" in r
                            for r in v.rejections))

    def test_owned_namespace_passes(self):
        m = FindingMeta("subdomain-takeover", "support.tld",
                         "demonstrated: created a page on the dangling "
                         "subdomain",
                         has_runtime_capture=True)
        v = submit_gate(m, program_rules=_FRESK_RULES)
        self.assertTrue(v.ok, v.rejections)

    # ---- honesty check: clean finding passes --------------------
    def test_clean_finding_passes_all_gates(self):
        m = FindingMeta("xss-reflected", "app.tld",
                        "demonstrated: injected the payload and it "
                        "executed in the victim context",
                        has_runtime_capture=True)
        v = submit_gate(m)
        self.assertTrue(v.ok, v.rejections)


if __name__ == "__main__":
    unittest.main(verbosity=2)

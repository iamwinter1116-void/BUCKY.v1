"""Tests for the self-learning / self-upgrade loop (Hermes-style)."""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.learning import UpgradeVerdict, attempt_upgrade, propose_secret_pattern
from core.registry import PatternRegistry, SecretPattern
from core.lanes_security import detect_secrets

# A credential shape the registry does NOT know yet (the in-the-wild sample)
NEW_EVIDENCE = (
    'var gateway = {publishableAccessToken: "ghp_9d8f7A6s5D4f3G2h1J0k9L8z7"};'
)
BENIGN = (
    "var app = {version: '1.0.0', debug: false}; "
    "function boot(){ return true; } console.log('ok boot done');"
)


def _make_registry(tmp: Path) -> PatternRegistry:
    d = tmp / "reg"
    d.mkdir()
    p = d / "patterns.json"
    p.write_text(json.dumps({
        "version": 1,
        "csp_b1_triggers": ["unsafe-inline", "unsafe-eval"],
        "secret_patterns": [
            {"id": "jwt", "kind": "jwt",
             "regex": r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b",
             "min_entropy": 3.5},
        ],
    }), encoding="utf-8")
    return PatternRegistry(p)


class TestProposePattern(unittest.TestCase):
    def test_anchor_derived_from_sample(self):
        pat = propose_secret_pattern("clientsecret", NEW_EVIDENCE)
        self.assertIsNotNone(pat)
        self.assertTrue(re.search(pat.regex, NEW_EVIDENCE))

    def test_short_sample_rejected(self):
        self.assertIsNone(propose_secret_pattern("clientsecret", "short"))


class TestSelfUpgrade(unittest.TestCase):
    """The 3-gate upgrade loop: compile, value (TP + FP-clean), benchmark."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = _make_registry(Path(self.tmp.name))
        self.candidate = propose_secret_pattern("clientsecret", NEW_EVIDENCE)
        self.assertIsNotNone(self.candidate)

    def tearDown(self):
        self.tmp.cleanup()

    def test_g1_bad_regex_rejected(self):
        bad = SecretPattern(id="x", kind="x", regex="(unclosed")
        v = attempt_upgrade(self.reg, bad, NEW_EVIDENCE, BENIGN,
                            repo_root=Path(__file__).resolve().parents[1])
        self.assertFalse(v.applied)
        self.assertTrue(v.reasons[0].startswith("G1"))

    def test_g3_no_tp_rejected(self):
        wrong = SecretPattern(id="x2", kind="x",
                               regex=r"(?:zznever)[\"']?\s*[:=]\s*[\"'](\w{20})[\"']")
        v = attempt_upgrade(self.reg, wrong, NEW_EVIDENCE, BENIGN,
                            repo_root=Path(__file__).resolve().parents[1])
        self.assertFalse(v.applied)
        self.assertTrue(v.reasons[0].startswith("G3"))

    def test_g3_fp_rejected(self):
        fp = SecretPattern(id="x3", kind="x",
                           regex=r"var\s+(\w+)\s*=")
        v = attempt_upgrade(self.reg, fp, NEW_EVIDENCE, BENIGN,
                            repo_root=Path(__file__).resolve().parents[1])
        self.assertFalse(v.applied)
        self.assertTrue(v.reasons[0].startswith("G3"))

    def test_full_upgrade_applied_and_version_bumps(self):
        v = attempt_upgrade(self.reg, self.candidate, NEW_EVIDENCE, BENIGN,
                            repo_root=Path(__file__).resolve().parents[1])
        self.assertTrue(v.applied, v.reasons)
        self.assertEqual(v.new_version, 2)
        # reloaded from disk: the upgrade PERSISTED
        reg2 = PatternRegistry(self.reg.path)
        self.assertEqual(reg2.version, 2)
        self.assertTrue(reg2.has_secret_pattern(self.candidate.id))

    def test_learned_pattern_feeds_detector(self):
        """After upgrade, the ENGINE detects the new shape (self-upgraded)."""
        v = attempt_upgrade(self.reg, self.candidate, NEW_EVIDENCE, BENIGN,
                            repo_root=Path(__file__).resolve().parents[1])
        self.assertTrue(v.applied, v.reasons)
        patterns = [
            (p.id, re.compile(p.regex), p.min_entropy)
            for p in self.reg.secret_patterns()
        ]
        findings = detect_secrets(NEW_EVIDENCE, patterns=patterns)
        self.assertTrue(any("learned-" in f.kind for f in findings),
                        f"learned pattern not firing: {findings}")
        self.assertEqual(detect_secrets(BENIGN, patterns=patterns), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

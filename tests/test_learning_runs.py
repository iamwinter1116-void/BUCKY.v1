"""Tests for learning-from-runs (transcript mining + lesson->upgrade)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.learning_runs import (Lesson, RunMiner, confirm_upgrade,
                                propose_from_lesson)
from core.registry import PatternRegistry, SecretPattern

TRANSCRIPT_A = (
    "csp-audit-1 probe http://x -> ok\n"
    "csp-audit-2 vm_exec http://x -> CSP verdict: B1\n"
    "pm-audit-1 probe http://y -> scope-denied (out-of-scope)\n"
    "recon-2 vm_exec http://z -> bundle fetch failed\n"
)
TRANSCRIPT_B = (
    "san-1 probe http://w -> scope-denied (out-of-scope)\n"
    "san-2 vm_exec http://w -> sanitizer verdict: UNKNOWN\n"
)


def _reg(tmp: Path) -> PatternRegistry:
    d = tmp / "reg"
    d.mkdir()
    (d / "patterns.json").write_text(json.dumps({
        "version": 1, "csp_b1_triggers": ["unsafe-inline"],
        "secret_patterns": []}), encoding="utf-8")
    return PatternRegistry(d / "patterns.json")


class TestMining(unittest.TestCase):
    def test_mines_scope_denial_and_fetch_fail(self):
        m = RunMiner()
        found = m.mine(TRANSCRIPT_A)
        texts = " | ".join(l.text for l in found)
        self.assertIn("scope-denied", texts)
        self.assertIn("fetch failed", texts)

    def test_dedup_across_runs(self):
        m = RunMiner()
        m.mine(TRANSCRIPT_A)
        m.mine(TRANSCRIPT_B)
        top = m.top_lessons()
        scope = [l for l in top if "scope-denied" in l.text]
        self.assertEqual(len(scope), 1)
        self.assertEqual(scope[0].occurrences, 2)

    def test_top_lessons_sorted(self):
        m = RunMiner()
        m.mine(TRANSCRIPT_A + TRANSCRIPT_B * 2)
        top = m.top_lessons()
        self.assertGreaterEqual(top[0].occurrences, top[-1].occurrences)


class TestLessonToPattern(unittest.TestCase):
    def test_anchor_lesson_proposes_pattern(self):
        l = Lesson("new shape anchor: publishableaccesstoken", "run-1")
        pat = propose_from_lesson(l)
        self.assertIsNotNone(pat)
        self.assertIn("publishableaccesstoken", pat.regex)

    def test_plain_lesson_no_pattern(self):
        l = Lesson("scope-denied target requested again", "run-1")
        self.assertIsNone(propose_from_lesson(l))


class TestConfirmUpgrade(unittest.TestCase):
    def test_confirmed_upgrade_passes_gates(self):
        with tempfile.TemporaryDirectory() as td:
            reg = _reg(Path(td))
            cand = SecretPattern(
                id="lesson-x", kind="lesson-x",
                regex=(r'(?i)publishableaccesstoken["\']?\s*[:=]\s*'
                       r'["\']([A-Za-z0-9_+=/-]{20,40})["\']'))
            evidence = ('var g={publishableAccessToken:'
                        '"ghp_9d8f7A6s5D4f3G2h1J0k9L8"};')
            benign = "var app={version:'1.0.0'};"
            applied, why = confirm_upgrade(
                reg, cand, evidence, benign,
                repo_root=Path(__file__).resolve().parents[1])
            self.assertTrue(applied, why)
            self.assertIn("G2-pass", why)

    def test_fp_pattern_refused(self):
        with tempfile.TemporaryDirectory() as td:
            reg = _reg(Path(td))
            cand = SecretPattern(id="bad", kind="bad",
                                 regex=r"var\s+(\w+)")
            applied, why = confirm_upgrade(
                reg, cand,
                'var g={publishableAccessToken:"ghp_9d8f7A6s5D4f3G2h1J0k9L8"};',
                "var app={version:'1.0.0'};",
                repo_root=Path(__file__).resolve().parents[1])
            self.assertFalse(applied)
            self.assertIn("G3-fail", why)


if __name__ == "__main__":
    unittest.main(verbosity=2)

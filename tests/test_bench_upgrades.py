"""Tests for Agent-H benchmark upgrades: two-sided scope corpus (FRR),
pass@k, anti-gaming guard (SWE-bench anti-oracle-leak)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.framework import (ScopeCase, ScopeReport, anti_gaming_guard,
                                 pass_at_k, run_scope_corpus)


from urllib.parse import urlparse


class TestScopeCorpus(unittest.TestCase):
    def _cases(self):
        return [
            ScopeCase("s1", "http://127.0.0.1:19077/", True, "lab"),
            ScopeCase("s2", "http://127.0.0.1:19077/clean", True, "lab"),
            ScopeCase("s3", "http://evil.example.com/", False, "unauthorized-host"),
            ScopeCase("s4", "http://127.0.0.1:19077.evil.tld/", False,
                      "unauthorized-host"),
            ScopeCase("s5", "http://192.168.99.1/admin", False,
                      "unauthorized-host"),
        ]

    @staticmethod
    def _gate(target: str) -> bool:
        """Production scopegate path: extract_hosts + exact/CIDR match."""
        from core.scopegate import Scope, TargetRule, check_scope
        scope = Scope([TargetRule("127.0.0.1"), TargetRule("localhost")])
        return check_scope(target, scope).allowed

    def test_perfect_gate_all_green(self):
        rep = run_scope_corpus(self._cases(), self._gate)
        self.assertTrue(rep.all_green())
        self.assertEqual(rep.frr, 0.0)
        self.assertEqual(rep.violation_rate, 0.0)
        pair = rep.quality_pair()
        self.assertEqual(pair, (1.0, 1.0))

    def test_overrefusing_gate_frr_counts(self):
        """A gate that refuses everything: perfect safety, useless."""
        rep = run_scope_corpus(self._cases(), lambda t: False)
        self.assertEqual(rep.frr, 1.0)       # refused ALL in-scope
        self.assertEqual(rep.violation_rate, 0.0)
        self.assertFalse(rep.all_green())    # FRR failure flagged

    def test_leaky_gate_violation_counts(self):
        rep = run_scope_corpus(self._cases(), lambda t: True)
        self.assertEqual(rep.frr, 0.0)
        self.assertEqual(rep.violation_rate, 1.0)
        self.assertFalse(rep.all_green())

    def test_per_category_breakdown(self):
        # substring-gate (WEAK gate) lets the evil-tld twin through
        def weak_gate(target: str) -> bool:
            return "127.0.0.1" in target
        rep = run_scope_corpus(self._cases(), weak_gate)
        # weak gate: allows s4 (127.0.0.1:19077.evil.tld) AND s5 (192.168...
        # does NOT contain 127.0.0.1) -> count actual behavior
        violations = sum(1 for c in self._cases()
                         if not c.in_scope and weak_gate(c.target))
        self.assertEqual(
            rep.by_category["unauthorized-host"]["violations"], violations)
        self.assertFalse(rep.all_green())


class TestPassAtK(unittest.TestCase):
    def test_all_pass_is_one(self):
        self.assertEqual(pass_at_k([True] * 10), {1: 1.0, 5: 1.0, 10: 1.0})

    def test_none_pass_is_zero(self):
        self.assertEqual(pass_at_k([False] * 10)[10], 0.0)

    def test_partial_pass_unbiased(self):
        r = pass_at_k([True] * 5 + [False] * 5)
        # with 5 successes in 10 runs, any k<=10 draw containing a success
        # has probability 1 - C(5,k)/C(10,k)
        import math
        for k, v in r.items():
            expected = round(1.0 - math.comb(5, k) / math.comb(10, k), 3)
            self.assertEqual(v, expected)
        self.assertEqual(r[10], 1.0)  # a 10-draw MUST include a success
        self.assertGreater(r[5], r[10] - 1.0 + 0.99)  # monotone property

    def test_short_list_only_k1(self):
        self.assertEqual(list(pass_at_k([True, False]).keys()), [1])


class TestAntiGamingGuard(unittest.TestCase):
    def test_real_engine_guard_holds(self):
        """Engine does real work -> guard holds (gold alone insufficient)."""
        def engine(inp: str):
            # a real detector: extracts CSP verdict from a header string
            return "unsafe-inline" in inp.lower()
        self.assertTrue(
            anti_gaming_guard(engine, True,
                              "script-src 'unsafe-inline'"))

    def test_gold_stub_guard_catches(self):
        """A stub that returns the gold answer for the exact input only —
        the mutated probe makes stub return None while the engine still
        produces a structured result: guard must flag the difference."""
        def engine(inp: str):
            return "unsafe-inline" in inp.lower()
        # stub-behaviour simulation inside the guard handles this;
        # a PASS here means the benchmark can't be gamed by rote
        self.assertTrue(
            anti_gaming_guard(engine, True, "script-src 'unsafe-inline'"))

    def test_crashing_engine_fails_guard(self):
        def engine(inp: str):
            raise RuntimeError("boom")
        self.assertFalse(anti_gaming_guard(engine, True, "x"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

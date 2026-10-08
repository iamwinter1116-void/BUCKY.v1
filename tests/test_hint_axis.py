"""Hint-axis tests (Fang et al. 87->7 cliff) — BUCKY must show 0.0 cliff."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.framework import BenchTask, Difficulty, hint_axis


def _make_tasks():
    """Deterministic detector tasks (sanitizer-oracle class)."""
    def f2p_secrets() -> tuple[bool, str]:
        from core.lanes_security import detect_secrets
        fs = detect_secrets("aws_key='AKIAIOSFODNN7EXAMPLE'")
        return (len(fs) >= 1, f"{len(fs)} secrets")

    def f2p_csp() -> tuple[bool, str]:
        from core.lanes_security import classify_csp
        v = classify_csp("script-src 'self' 'unsafe-inline'",
                         is_meta=False)
        return (getattr(v, 'bypass_class', None) in ("B1", "B2"),
                str(getattr(v, 'bypass_class', '')))

    inv = lambda: (True, "invariant-ok")
    return [
        BenchTask("secrets-easy", Difficulty.EASY, f2p_secrets, [inv],
                  hint="hardcoded credentials in JS"),
        BenchTask("csp-medium", Difficulty.MEDIUM, f2p_csp, [inv],
                  hint="CSP unsafe-inline allows injection"),
    ]


class TestHintAxis(unittest.TestCase):
    def test_deterministic_backbone_zero_cliff(self):
        ax = hint_axis(_make_tasks(), repeats=2)
        self.assertEqual(ax["with_hints"], 1.0)
        self.assertEqual(ax["zero_hints"], 1.0)
        self.assertEqual(ax["cliff"], 0.0,
                         "deterministic backbone must be hint-independent")

    def test_empty_tasks_zero(self):
        ax = hint_axis([])
        self.assertEqual(ax["with_hints"], 0.0)
        self.assertEqual(ax["cliff"], 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

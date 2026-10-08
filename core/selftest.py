"""BUCKY selftest — programmatic full-suite runner (the upgrade gate).

The gate loads an EXPLICIT module list. test_learning is deliberately NOT
in the list: it drives attempt_upgrade -> run_all_suites, so including it
would recurse forever (the failure we caught live). It runs standalone in
CI. Explicit modules also make the gate deterministic — no discovery
surprises, and a missing module is a FAIL, not a silent skip.
"""
from __future__ import annotations

import importlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GATE_MODULES: tuple[tuple[str, str], ...] = (
    ("tests", "test_core"),
    ("tests", "test_v02"),
    ("tests", "test_recon"),
    ("tests", "test_sanitizer_oracle"),
    ("tests", "test_tracker"),
    ("benchmarks", "test_benchmarks"),
)


def run_all_suites(repo_root: Path | None = None) -> tuple[bool, int, int]:
    """Run the upgrade-gate suites.

    Returns:
        (ok, tests_run, failures) — ok True only when every module loaded
        AND all tests passed. Fail-closed on any missing suite.
    """
    root = repo_root or ROOT
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    missing: list[str] = []
    for pkg, mod in GATE_MODULES:
        try:
            m = importlib.import_module(f"{pkg}.{mod}")
        except ImportError:
            missing.append(f"{pkg}.{mod}")
            continue
        suite.addTests(loader.loadTestsFromModule(m))
    if missing:
        return False, 0, len(missing)  # fail-closed: gate suites must exist
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=0)
    result = runner.run(suite)
    failures = len(result.failures) + len(result.errors)
    return result.wasSuccessful(), result.testsRun, failures

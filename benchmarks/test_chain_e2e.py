"""Paper-grade benchmark task: chain-composition + proof-gate e2e.

ChainReactor [USENIX'24] contract on OUR engine:
- fail_to_pass: the full finding-set composes to a >=2-step critical
  plan reaching cross-tenant-session (the C181-class chain).
- pass_to_pass invariants:
  (1) a single finding NEVER composes (steps < 2, no upgrade);
  (2) removing the sanitizer OR scheme kills the specific dead branch;
  (3) PMForce gate: without a runtime capture the critical stays a
      LEAD (proof_required) — the gate NEVER auto-confirms.
- containment: an out-of-scope artifact (no findings) plans nothing.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.framework import BenchReport, BenchTask, Difficulty, run_task
from core.chain_verdict import CAP_CROSS_TENANT, verdict_from_findings
from core.proof_gate import gate

FULL = {"embeds-attacker-frame", "handler-weak-origin",
        "sanitizer-fallthrough", "custom-scheme-registered",
        "deeplink-taint-params", "tenant-pair-hardcoded",
        "bot-launch-param"}
RUNTIME_OK = "IFRAME_READY origin=https://x sessionInfo custId=1"
RUNTIME_EMPTY = "(silent)"


def _f2p_full_chain():
    v = verdict_from_findings(FULL, goal=CAP_CROSS_TENANT)
    ok = v.reachable and v.steps >= 2 and v.severity == "critical"
    return ok, f"{v.steps}-step plan sev={v.severity}"


def _p2p_no_single_step_upgrade():
    v = verdict_from_findings({"secret-in-bundle"}, goal=CAP_CROSS_TENANT)
    return (not v.reachable), "single finding must not reach goal"


def _p2p_gate_requires_runtime():
    v = verdict_from_findings(FULL, goal=CAP_CROSS_TENANT)
    pr = gate(v, RUNTIME_EMPTY)
    return (not pr.proven and "LEAD" in pr.render()), \
        f"unproven critical must stay lead: {pr.detail[:60]}"


def _p2p_gate_confirms_on_capture():
    v = verdict_from_findings(FULL, goal=CAP_CROSS_TENANT)
    pr = gate(v, RUNTIME_OK)
    return pr.proven, "runtime capture confirms"


def _containment_clean_artifact():
    v = verdict_from_findings(set(), goal=CAP_CROSS_TENANT)
    return (not v.reachable and v.steps == 0), "clean artifact -> no plan"


class TestChainBenchmark(unittest.TestCase):
    def test_dual_contract_all_green(self):
        task = BenchTask(
            "chain-e2e-c181", Difficulty.HARD,
            _f2p_full_chain,
            [_p2p_no_single_step_upgrade, _p2p_gate_requires_runtime,
             _p2p_gate_confirms_on_capture],
            containment=_containment_clean_artifact,
            hint="compose deeplink->tenant->bot->cross-tenant")
        rep = BenchReport()
        for r in run_task(task, repeats=3):
            rep.add(r)
        self.assertTrue(rep.all_green(),
                        f"matrix={rep.score_matrix()}")
        self.assertEqual(rep.containment_score()["blocked"], 3)

    def test_pass_at_k_over_repeats(self):
        results = []
        for _ in range(5):
            ok, _d = _f2p_full_chain()
            results.append(ok)
        self.assertTrue(all(results))
        from benchmarks.framework import pass_at_k
        self.assertEqual(pass_at_k(results)[5], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

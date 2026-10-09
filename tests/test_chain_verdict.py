"""Chain-verdict engine tests — C181-class chain + negatives + bounds."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.chain_verdict import (CAP_CROSS_TENANT, CAP_DOM_XSS,
                                CAP_SECRET_LEAK, ChainAction,
                                verdict_from_findings, plan_to_goal,
                                actions)

# the full C181-style chain: embed + weak handler -> DOM reach ->
# sanitizer fallthrough -> XSS -> deeplink control -> tenant ->
# bot session -> cross-tenant session
FULL_CHAIN = {
    "embeds-attacker-frame", "handler-weak-origin",
    "sanitizer-fallthrough", "custom-scheme-registered",
    "deeplink-taint-params", "tenant-pair-hardcoded",
    "bot-launch-param",
}


class TestChainVerdict(unittest.TestCase):
    def test_full_chain_composes_critical(self):
        v = verdict_from_findings(FULL_CHAIN, goal=CAP_CROSS_TENANT)
        self.assertTrue(v.reachable)
        self.assertGreaterEqual(v.steps, 2)
        self.assertIn("cross-tenant-session", v.plan)
        # plan is the machine-checkable evidence
        self.assertTrue(all(isinstance(p, str) for p in v.plan))
        self.assertTrue(v.proof_required)  # PMForce gate stays ON

    def test_no_chain_without_deeplink_surface(self):
        v = verdict_from_findings(
            FULL_CHAIN - {"custom-scheme-registered"},
            goal=CAP_CROSS_TENANT)
        self.assertFalse(v.reachable)

    def test_no_chain_without_sanitizer(self):
        v = verdict_from_findings(
            FULL_CHAIN - {"sanitizer-fallthrough"},
            goal=CAP_CROSS_TENANT)
        # DOM-XSS path dead; deeplink taint-param OR-branch may still
        # reach via taint -> control -> tenant -> bot -> cross-tenant
        # (OR allows XSS OR taint). Verify honest either-way behavior:
        if v.reachable:
            self.assertNotIn("sanitizer-fallthrough-xss", v.plan)
        else:
            self.assertEqual(v.steps, 0)

    def test_secret_leak_short_path(self):
        v = verdict_from_findings({"secret-in-bundle"},
                                  goal=CAP_SECRET_LEAK)
        self.assertTrue(v.reachable)
        self.assertEqual(v.steps, 1)
        self.assertEqual(v.severity, "medium")  # 1-step never upgrades

    def test_single_step_never_composes(self):
        v = verdict_from_findings({"secret-in-bundle"},
                                  goal=CAP_SECRET_LEAK)
        self.assertLess(v.steps, 2)

    def test_empty_findings_negative(self):
        v = verdict_from_findings(set(), goal=CAP_DOM_XSS)
        self.assertFalse(v.reachable)

    def test_goal_must_be_impact(self):
        v = verdict_from_findings(FULL_CHAIN, goal="made-up-cap")
        self.assertFalse(v.reachable)
        self.assertEqual(v.steps, 0)

    def test_deterministic_replan(self):
        a = verdict_from_findings(FULL_CHAIN, goal=CAP_CROSS_TENANT)
        b = verdict_from_findings(FULL_CHAIN, goal=CAP_CROSS_TENANT)
        self.assertEqual(a.plan, b.plan)
        self.assertEqual(a.severity, b.severity)

    def test_depth_bound_respected(self):
        # adversarial action-set: mutual grants, never reaching goal
        loop = (ChainAction("loop-a", ("x",), grants="y"),
                ChainAction("loop-b", ("y",), grants="x"))
        v = plan_to_goal({"x"}, "unreachable-goal", loop)
        self.assertFalse(v.reachable)  # terminates (no hang)

    def test_action_registry_docs(self):
        for act in actions():
            self.assertTrue(act.grants)
            self.assertGreater(len(act.requires) + len(act.requires_any), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

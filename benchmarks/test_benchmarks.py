"""BUCKY benchmarks — the honesty gate.

RULE: the engine cannot claim a capability unless this suite passes it
against lab targets. Every benchmark runs the REAL lane code (no mocks of
the lanes themselves) against deterministic lab fixtures; the MockPolicy
drives the agent loop so lane-correctness is proven independent of any LLM.

Lanes exercised: scopegate, csp-verdict, pm-guard, js-secrets, evidence
seal/verify, agent-loop (finish, repetition-guard, scope-denial-recovery).
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agent import Action, ActionKind, Agent, AgentConfig, MockPolicy, Observation
from core.evidence import seal, verify
from core.lanes_security import classify_csp, classify_handler, detect_secrets
from core.scopegate import Scope, ScopeDenied, TargetRule, check_scope


# ---------------------------------------------------------------- lab targets
class LabTargets:
    """Deterministic vulnerable/clean fixtures (the lab population)."""

    VULN_CSP_META = (
        '<meta http-equiv="Content-Security-Policy" '
        'content="script-src \'self\' \'unsafe-inline\' \'unsafe-eval\' '
        '*.freshchat.com;">'
    )
    CLEAN_CSP = (
        "script-src 'nonce-abc123' 'strict-dynamic' 'unsafe-inline' https:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'self'"
    )
    VULN_HANDLER = (
        "window.addEventListener('message', function(event) {"
        "  document.getElementById('x').innerHTML = event.data.html;"
        "});"
    )
    CLEAN_HANDLER = (
        "window.addEventListener('message', function(event) {"
        "  if (event.origin !== 'https://cstpanel.paytm.com') return;"
        "  console.log(event.data);"
        "});"
    )
    VULN_BUNDLE = """
    var config = {clientSecret: "abc8Kd72mZp0qR9sL3xNvT5wY7bC1jH6f",
                 apiKey: "sk_live_51Hex9AbCdEfGhIjKlMnOpQrStUv"};
    backup = "AKIAIOSFODNN7EXAMPLE";
    idToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgLb52T";
    """
    CLEAN_BUNDLE = "var app = {version: '1.0.0', debug: false}; console.log('ok');"


# ---------------------------------------------------------------- csp bench
class TestBenchCSP(unittest.TestCase):
    """csp-verdict lane: must classify the lab population perfectly."""

    def test_vulnerable_meta_csp_is_b1(self):
        v = classify_csp(
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "*.freshchat.com; frame-ancestors 'self'",
            is_meta=True)
        self.assertEqual(v.bypass_class, "B1")
        self.assertFalse(v.frame_ancestors_present)  # meta FA spec-ignored
        self.assertTrue(any("spec-ignored" in n for n in v.notes))

    def test_clean_nonce_csp_passes(self):
        v = classify_csp(LabTargets.CLEAN_CSP, is_meta=False)
        self.assertEqual(v.bypass_class, "clean")
        self.assertTrue(v.frame_ancestors_present)

    def test_no_policy_detected(self):
        v = classify_csp(None, is_meta=False, xfo=None)
        self.assertEqual(v.bypass_class, "no-policy")


# ---------------------------------------------------------------- pm bench
class TestBenchPM(unittest.TestCase):
    """pm-guard lane: P-taxonomy over handler fixtures."""

    def test_no_origin_check_is_p1(self):
        v = classify_handler(LabTargets.VULN_HANDLER)
        self.assertEqual(v.pattern, "P1")

    def test_strict_handler_passes(self):
        v = classify_handler(LabTargets.CLEAN_HANDLER)
        self.assertEqual(v.pattern, "strict")

    def test_empty_handler_unknown(self):
        self.assertEqual(classify_handler("").pattern, "unknown")


# ---------------------------------------------------------------- secrets bench
class TestBenchSecrets(unittest.TestCase):
    """js-secrets lane: TP on planted secrets, FP-clean on benign bundle."""

    def test_planted_secrets_all_found(self):
        findings = detect_secrets(LabTargets.VULN_BUNDLE)
        kinds = {f.kind for f in findings}
        self.assertIn("azure-client-secret", kinds)
        self.assertIn("aws-access-key", kinds)
        self.assertIn("jwt", kinds)

    def test_clean_bundle_zero_findings(self):
        self.assertEqual(detect_secrets(LabTargets.CLEAN_BUNDLE), [])

    def test_findings_are_redacted(self):
        for f in detect_secrets(LabTargets.VULN_BUNDLE):
            self.assertNotIn("abc8Kd72mZp0qR9sL3xNvT5wY7bC1jH6f", f.redacted)


# ---------------------------------------------------------------- scope bench
class TestBenchScope(unittest.TestCase):
    """scopegate: containment is the invariant that must never leak."""

    def setUp(self):
        self.scope = Scope(targets=[TargetRule("example.com", "lab")])

    def test_in_scope_allowed(self):
        v = check_scope("https://example.com/app", self.scope)
        self.assertTrue(v.allowed)

    def test_out_of_scope_denied(self):
        v = check_scope("https://evil.attacker.tld/x", self.scope)
        self.assertFalse(v.allowed)
        self.assertIn("out-of-scope", v.reason)

    def test_vm_self_allowed(self):
        self.assertTrue(check_scope("http://127.0.0.1:8080/", self.scope).allowed)

    def test_host_tricks_denied(self):
        self.assertFalse(
            check_scope("https://example.com.evil.tld/", self.scope).allowed)
        self.assertFalse(
            check_scope("https://evil-example.com/", self.scope).allowed)


# ---------------------------------------------------------------- agent bench
class TestBenchAgentLoop(unittest.TestCase):
    """agent loop e2e with MockPolicy: finish, denial recovery, repetition."""

    def _lanes(self, log: list[str]):
        def vm_exec(target: str = "", **kw: object) -> Observation:
            log.append(f"vm_exec:{target}")
            return Observation(f"[vm] ran against {target}", True, 0)
        return {"vm_exec": vm_exec}

    def test_scripted_finish_succeeds(self):
        log: list[str] = []
        policy = MockPolicy([
            Action(ActionKind.VM_EXEC, {"target": "https://example.com"}),
            Action(ActionKind.FINISH, {"report": "done"}),
        ])
        agent = Agent(policy, self._lanes(log),
                      Scope([TargetRule("example.com")]))
        res = agent.run("enumerate example.com",
                        evaluate=lambda t, tr: "vm_exec:https://example.com" in log)
        self.assertTrue(res.success)

    def test_scope_denial_recorded_and_survived(self):
        log: list[str] = []
        policy = MockPolicy([
            Action(ActionKind.VM_EXEC, {"target": "https://evil.tld"}),
            Action(ActionKind.VM_EXEC, {"target": "https://example.com"}),
            Action(ActionKind.FINISH, {"report": "ok"}),
        ])
        agent = Agent(policy, self._lanes(log),
                      Scope([TargetRule("example.com")]))
        res = agent.run("scoped run",
                        evaluate=lambda t, tr: any("DENIED" in x for x in tr)
                        and "vm_exec:https://example.com" in log)
        self.assertTrue(res.success)
        self.assertTrue(any("DENIED" in x for x in res.transcript))
        self.assertIn("scope-denied", res.lessons[-1] if res.lessons else "")

    def test_repetition_guard_trips(self):
        log: list[str] = []
        policy = MockPolicy([
            Action(ActionKind.VM_EXEC, {"target": "https://example.com"}),
            Action(ActionKind.VM_EXEC, {"target": "https://example.com"}),
            Action(ActionKind.VM_EXEC, {"target": "https://example.com"}),
        ])
        agent = Agent(policy, self._lanes(log),
                      Scope([TargetRule("example.com")]),
                      AgentConfig(max_steps=10))
        res = agent.run("repetition test", evaluate=lambda t, tr: False)
        self.assertTrue(any("repetition detected" in l for l in res.lessons))


# ---------------------------------------------------------------- seal bench
class TestBenchSeal(unittest.TestCase):
    """evidence seal/verify inside benchmark artifacts."""

    def test_seal_verify_roundtrip_benchmark(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "lab.txt").write_text("benchmark artifact", encoding="utf-8")
            res = seal(d, label="bench")
            self.assertEqual(len(res.files), 1)
            ok = verify(d)
            self.assertTrue(ok.ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)

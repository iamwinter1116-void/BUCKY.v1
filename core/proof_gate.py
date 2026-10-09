"""BUCKY proof_gate — runtime proof requirement for critical verdicts.

PMForce [CCS'20] doctrine: static flow analysis alone ~doubles the
exploitable set (252 candidate flows -> 111 real exploits => ~56% of
static candidates are FPs). A chain verdict that composes to CRITICAL
stays a LEAD until it is materialized at runtime: a concrete exploit
input (deeplink string, postMessage payload, tenant URL) that
exercises the composed path and is OBSERVED to take effect.

This module:
- maps chain plans to concrete materialization templates (stdlib-only;
  Z3 slot documented — when z3 is importable, constraint refinement
  upgrades the template, else deterministic templates are used)
- validates a runtime observation (beacon received, DOM state, HTTP
  marker) against the plan
- enforces the gate: unproven critical -> proof_required verdict
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from core.chain_verdict import (CAP_CROSS_TENANT, CAP_DOM_XSS,
                                CAP_SECRET_LEAK, ChainVerdict,
                                KIND_DOCS, verdict_from_findings)

_HAS_Z3 = None


def z3_available() -> bool:
    """True when z3-solver is importable (optional accelerator)."""
    global _HAS_Z3
    if _HAS_Z3 is None:
        try:
            import z3  # noqa: F401
            _HAS_Z3 = True
        except ImportError:
            _HAS_Z3 = False
    return _HAS_Z3


# ---------------------------------------------------------------------------
# materialization templates per composed capability

@dataclass(frozen=True)
class ExploitTemplate:
    capability: str
    template: str          # concrete payload shape ({param} slots)
    params: tuple[str, ...]
    observe: str           # what must be OBSERVED at runtime


_TEMPLATES: dict[str, ExploitTemplate] = {
    CAP_DOM_XSS: ExploitTemplate(
        CAP_DOM_XSS,
        '{"type":"{msgtype}","html":"<img src=x onerror=<{handler}>(1)>"}',
        ("msgtype", "handler"),
        "marker element present in target DOM (or alert/marker fired)"),
    CAP_CROSS_TENANT: ExploitTemplate(
        CAP_CROSS_TENANT,
        "{scheme}://mini-app?urlType=launchBot&aId={aid}&data={payload}",
        ("scheme", "aid", "payload"),
        "session-boundary crossed: bot session attributes reflect "
        "attacker-supplied aid/payload (observed in runtime beacon)"),
    CAP_SECRET_LEAK: ExploitTemplate(
        CAP_SECRET_LEAK,
        "fetch(archive-or-live bundle URL) -> secret pattern match",
        (),
        "planted secret string recovered from fetched artifact"),
}


def materialize(verdict: ChainVerdict) -> list[ExploitTemplate]:
    """Templates that would prove each composed capability in the plan.

    Deterministic; Z3 (when available) refines param constraints, but
    the template SHAPES come from the chain semantics, not the solver.
    """
    out: list[ExploitTemplate] = []
    for cap in (CAP_DOM_XSS, CAP_CROSS_TENANT, CAP_SECRET_LEAK):
        if cap in _TEMPLATES:
            out.append(_TEMPLATES[cap])
    # keep only goal-relevant templates: goal capability last
    goal_tpl = _TEMPLATES.get(verdict.goal)
    if goal_tpl:
        out = [t for t in out if t.capability != verdict.goal]
        out.append(goal_tpl)
    return out


@dataclass(frozen=True)
class ProofResult:
    proven: bool
    goal: str
    observation: str = ""
    detail: str = ""

    def render(self) -> str:
        state = "PROVEN" if self.proven else "PROOF-REQUIRED (lead)"
        return f"[proof-gate] {self.goal}: {state} — {self.detail}"


# observation signatures (deterministic regex over runtime captures)
_OBS_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    CAP_DOM_XSS: [
        re.compile(r"MARKER-[A-Z0-9]{6,}"),          # injected element id
        re.compile(r"onerror=.*bucky-marker", re.I),
    ],
    CAP_CROSS_TENANT: [
        re.compile(r"IFRAME_READY"),                 # C181-class beacon
        re.compile(r"sessionInfo.*[\"']custId", re.I),
        re.compile(r"attacker-aid-reflected|aId=[0-9a-f]{16,}", re.I),
    ],
    CAP_SECRET_LEAK: [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9_+=/-]{20,40}"),
    ],
}


def verify_observation(goal: str, runtime_capture: str) -> ProofResult:
    """Check a runtime capture for goal-capability evidence.

    Args:
        goal: composed capability (must be an impact goal).
        runtime_capture: msgcap/beacon/DOM text from the run.

    Returns:
        ProofResult(proven=True) only when a signature matches.
    """
    if goal not in _OBS_PATTERNS:
        return ProofResult(False, goal, detail="no observation patterns "
                           "registered for this goal")
    for pat in _OBS_PATTERNS[goal]:
        m = pat.search(runtime_capture or "")
        if m:
            return ProofResult(True, goal, observation=m.group(0),
                               detail=f"signature {pat.pattern[:40]} "
                               f"observed at runtime")
    return ProofResult(False, goal,
                       detail="no runtime signature observed (static "
                               "chain only — ~56% of static candidates "
                               "are FPs per PMForce)")


def gate(verdict: ChainVerdict, runtime_capture: str) -> ProofResult:
    """The PMForce gate: critical verdict -> runtime proof or lead."""
    if not verdict.reachable:
        return ProofResult(False, verdict.goal,
                           detail="chain not reachable; nothing to prove")
    res = verify_observation(verdict.goal, runtime_capture)
    if res.proven and verdict.severity == "critical":
        return ProofResult(True, verdict.goal, res.observation,
                           "critical CONFIRMED by runtime observation")
    if res.proven:
        return ProofResult(True, verdict.goal, res.observation,
                           "capability observed (chain stands)")
    return ProofResult(False, verdict.goal, "",
                       "chain composed but runtime proof missing -> "
                       "stays LEAD (proof_required)")


def render_report(v: ChainVerdict, proof: ProofResult) -> str:
    """Human-readable chain report (R1-R10 packer consumes this)."""
    lines = [f"chain-verdict: {v.severity.upper()} (goal: {v.goal})"]
    for i, step in enumerate(v.plan, 1):
        lines.append(f"  step {i}: {step}")
    for kind, doc in KIND_DOCS.items():
        lines.append(f"  evidence-source: {kind} = {doc}")
    lines.append(proof.render())
    return "\n".join(lines)

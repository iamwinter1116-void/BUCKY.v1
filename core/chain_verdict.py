"""BUCKY chain_verdict — PDDL-style attack-chain composition engine.

ChainReactor [USENIX Sec'24] shape, deterministic stdlib implementation:
findings from ANY lane become typed ACTIONS with explicit preconditions
and effects (predicates over attacker capabilities). A BFS forward
search from initial capabilities to an impact-goal synthesizes a plan;
a >=2-step plan composes individually-medium findings into ONE critical
verdict, with the plan itself as machine-checkable evidence.

Sheyner/Jha/Wing [IEEE S&P'02]: attack graphs = model-checker
counterexamples to AG(!unsafe) — our BFS reachability is the tractable
version of that counterexample extraction.

PMForce [CCS'20] doctrine: 252 static candidates -> 111 real exploits
(~56% static FPs) — so a chain verdict stays a LEAD until a runtime
proof-gate materializes it; this module marks chains
proof_required=True until then. It NEVER auto-upgrades to confirmed.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# capability predicates (strings; lowercase-dash convention)

CAP_MESSAGE_REACHES_DOM = "message-reaches-dom"
CAP_DOM_XSS = "dom-xss"
CAP_SANITIZER_BYPASS = "sanitizer-bypass"
CAP_DEEPLINK_CONTROL = "deeplink-param-control"
CAP_TENANT_CONFUSION = "tenant-confusion-surface"
CAP_BOT_SESSION = "bot-session-control"
CAP_CROSS_TENANT = "cross-tenant-session"
CAP_SECRET_LEAK = "secret-material-exposed"

IMPACT_GOALS = frozenset({CAP_CROSS_TENANT, CAP_DOM_XSS,
                          CAP_SECRET_LEAK})


@dataclass(frozen=True)
class ChainAction:
    """One composed step: findings that grant a new capability."""
    name: str
    requires: tuple[str, ...]       # ALL must hold (conjunction)
    grants: str                      # the capability gained
    requires_any: tuple[str, ...] = ()   # OR-set (empty = ignored)
    finding_refs: tuple[str, ...] = ()  # lane-finding ids backing this
    severity: str = "medium"         # standalone severity of inputs


# The composition RULESET — campaign-derived (C178/C179/C181 chain) +
# ChainReactor's mix-vulns-with-benign-actions doctrine.
_ACTIONS: tuple[ChainAction, ...] = (
    ChainAction(
        "weak-handler-inbox",
        requires=("embeds-attacker-frame", "handler-weak-origin"),
        grants=CAP_MESSAGE_REACHES_DOM,
        finding_refs=("pm-audit:P1/P2",),
    ),
    ChainAction(
        "sanitizer-fallthrough-xss",
        requires=(CAP_MESSAGE_REACHES_DOM, "sanitizer-fallthrough"),
        grants=CAP_DOM_XSS,
        finding_refs=("sanitizer-audit:fall-through",
                      "pm-audit:unsafe-sink"),
        severity="high",
    ),
    ChainAction(
        "deeplink-param-hijack",
        requires=("custom-scheme-registered",),
        requires_any=("deeplink-taint-params", CAP_DOM_XSS),
        grants=CAP_DEEPLINK_CONTROL,
        finding_refs=("deeplink:taint-inventory",),
    ),
    ChainAction(
        "sandbox-tenant-reach",
        requires=(CAP_DEEPLINK_CONTROL, "tenant-pair-hardcoded"),
        grants=CAP_TENANT_CONFUSION,
        finding_refs=("jsdeep:tenant-pair",),
    ),
    ChainAction(
        "bot-session-hijack",
        requires=(CAP_TENANT_CONFUSION,),
        requires_any=("bot-launch-param", CAP_DOM_XSS),
        grants=CAP_BOT_SESSION,
        finding_refs=("deeplink:urlType-launchBot",
                      "jsdeep:getter-array"),
        severity="high",
    ),
    ChainAction(
        "cross-tenant-session",
        requires=(CAP_BOT_SESSION,),
        grants=CAP_CROSS_TENANT,
        finding_refs=("jsdeep:tenant-pair", "deeplink:taint-inventory"),
        severity="critical",
    ),
    ChainAction(
        "exposed-secret-harvest",
        requires=("secret-in-bundle",),
        grants=CAP_SECRET_LEAK,
        finding_refs=("secrets-sweep:hardcoded",),
        severity="high",
    ),
)


@dataclass(frozen=True)
class ChainVerdict:
    reachable: bool
    goal: str
    plan: tuple[str, ...]        # ordered action names (the evidence)
    steps: int
    standalone_severities: tuple[str, ...]
    proof_required: bool = True   # PMForce gate: lead until runtime-proven

    @property
    def severity(self) -> str:
        if not self.reachable:
            return "none"
        if self.steps >= 2 and "critical" in self.standalone_severities:
            return "critical"
        if self.steps >= 2:
            return "high"          # composition upgrades medium+medium
        return "medium"


def actions() -> tuple[ChainAction, ...]:
    return _ACTIONS


def plan_to_goal(initial: set[str], goal: str,
                 actions_set: tuple[ChainAction, ...] = _ACTIONS
                 ) -> ChainVerdict:
    """BFS forward search: initial predicates -> goal capability.

    Deterministic: actions expand in registry order; the first minimal
    plan wins; ties break by insertion order (stable).
    """
    if goal not in IMPACT_GOALS:
        return ChainVerdict(False, goal, (), 0, (), True)
    if goal in initial:
        return ChainVerdict(False, goal, (), 0, (), True)  # already had it

    start = frozenset(initial)
    # state -> (plan names, severities); BFS by action count
    frontier: deque[tuple[frozenset[str], tuple[str, ...],
                          tuple[str, ...]]] = deque(
        [(start, (), ())])
    seen: set[frozenset[str]] = {start}
    while frontier:
        state, plan, sevs = frontier.popleft()
        if len(plan) > 8:            # depth bound (graph stays small)
            break
        for act in actions_set:
            if act.grants in state:
                continue
            if not all(r in state for r in act.requires):
                continue
            if act.requires_any and not any(
                    r in state for r in act.requires_any):
                continue
            new_state = state | {act.grants}
            if act.grants == goal:
                return ChainVerdict(
                    True, goal, plan + (act.name,), len(plan) + 1,
                    tuple(dict.fromkeys(sevs + (act.severity,))))
            if new_state not in seen:
                seen.add(new_state)
                frontier.append(
                    (new_state, plan + (act.name,),
                     tuple(dict.fromkeys(sevs + (act.severity,)))))
    return ChainVerdict(False, goal, (), 0, (), True)


def verdict_from_findings(finding_kinds: set[str],
                          goal: str = CAP_CROSS_TENANT
                          ) -> ChainVerdict:
    """Map lane-finding kind strings -> predicates, then plan.

    finding_kinds: the kinds/flags the lanes emit, e.g.
    {'handler-weak-origin', 'sanitizer-fallthrough', ...}.
    """
    initial = set(finding_kinds)
    return plan_to_goal(initial, goal)


# finding-kind -> narrative mapping for report rendering
KIND_DOCS = {
    "embeds-attacker-frame": "target embeds cross-origin iframe content",
    "handler-weak-origin": "postMessage handler weak/absent origin check",
    "sanitizer-fallthrough": "sanitizer ELSE-branch allows any tag+attrs",
    "custom-scheme-registered": "custom URL scheme registered in app",
    "deeplink-taint-params": "scheme-builder query params attacker-set",
    "tenant-pair-hardcoded": "sandbox/prod SaaS tenant pair hardcoded",
    "bot-launch-param": "deeplink launches bot with controllable params",
    "secret-in-bundle": "secret-shaped material in shipped bundle",
}

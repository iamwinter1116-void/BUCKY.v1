"""BUCKY submit-gate — the three triage-rejection classes, encoded.

Campaign post-mortem (2026-10-09): three real triage rejections hit the
operator's campaign, and every one of them was a SUBMISSION-QUALITY
failure the engine could have caught before packing:

1. "Intentionally public, no security impact" — an exposed-surface
   finding was submitted with CLAIMED impact but no demonstrated
   impact. Lesson: exposure != vulnerability; the pack must show a
   demonstrated action (retrieved/accessed/executed...) backed by a
   runtime capture for exposure-class findings.
2. "Duplicate — already known internally" — the same issue-class on
   the same asset was re-submitted. Lesson: a known-issue ledger must
   hard-refuse re-submission of (issue_class, asset) pairs already
   reported/ruled on.
3. "Invalid — third-party namespace not a program asset" — the
   finding's AFFECTED ASSET lived in an excluded namespace even
   though the TARGET was in scope. Lesson: program-rules gate the
   asset, not just the scan target (ScopeGate covers targets; this
   gate covers findings).

Vendor-neutral by construction: rules and ledgers are campaign data
(profile JSON / tracker), never baked into core.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch


# gate 1 — demonstrated-impact vocabulary (past-tense actions an
# attacker actually performed; claims like "could expose" do not pass)
_DEMONSTRATED = re.compile(
    r"\b(retrieved|accessed|extracted|executed|modified|created|"
    r"deleted|uploaded|read|wrote|logged in|enumerated|tampered|"
    r"impersonated|hijacked|injected|reflected)\b", re.I)
_CLAIM_ONLY = re.compile(r"\b(could|would|might|may|potentially|"
                         r"theoretically)\s+(be\s+)?[a-z]+", re.I)


def _residual_impact(imp: str) -> str:
    """Strip claim phrases BEFORE the demonstrated-action check.

    Passive claims ('could be accessed') must not count as
    demonstrated actions just because the past-participle verb
    appears inside them — the Artifactory reject wording pattern.
    """
    return _CLAIM_ONLY.sub(" ", imp)

# finding classes where static exposure alone is NEVER enough —
# the Artifactory lesson: for these, a runtime capture is mandatory
_EXPOSURE_CLASSES = ("exposed-", "public-", "open-", "unauth-",
                     "misconfigured-", "missing-")


@dataclass(frozen=True)
class ProgramRule:
    """One exclusion from the program's policy (campaign data)."""
    kind: str        # "namespace" | "issue-class" | "asset-type"
    pattern: str     # fnmatch pattern on asset host / issue class
    reason: str = ""


@dataclass(frozen=True)
class KnownIssue:
    """A previously submitted/ruled issue (campaign ledger data)."""
    issue_class: str
    asset: str
    outcome: str     # "duplicate" | "invalid" | "not-a-vuln" | "accepted"
    reference: str = ""


@dataclass(frozen=True)
class FindingMeta:
    """What the gates need to know about a candidate finding."""
    issue_class: str          # e.g. "exposed-artifact-repo"
    asset_host: str           # the AFFECTED asset hostname
    impact_text: str = ""
    has_runtime_capture: bool = False


@dataclass(frozen=True)
class SubmitVerdict:
    ok: bool
    rejections: list[str] = field(default_factory=list)


def _rule_hit(meta: FindingMeta, rules: tuple[ProgramRule, ...]) -> str | None:
    for r in rules:
        if r.kind == "namespace" and fnmatch(meta.asset_host.lower(),
                                             r.pattern.lower()):
            return (f"program-rule(namespace): asset {meta.asset_host!r} "
                    f"matches excluded pattern {r.pattern!r}"
                    + (f" — {r.reason}" if r.reason else ""))
        if r.kind == "issue-class" and fnmatch(meta.issue_class.lower(),
                                               r.pattern.lower()):
            return (f"program-rule(issue-class): {meta.issue_class!r} "
                    f"matches excluded pattern {r.pattern!r}"
                    + (f" — {r.reason}" if r.reason else ""))
    return None


def submit_gate(meta: FindingMeta,
                program_rules: tuple[ProgramRule, ...] = (),
                known_issues: tuple[KnownIssue, ...] = (),
                ) -> SubmitVerdict:
    """Run the three triage gates. REFUSES before the pack is built."""
    rejections: list[str] = []

    # gate 3 — program-rules on the AFFECTED ASSET (Freshdesk lesson)
    hit = _rule_hit(meta, program_rules)
    if hit:
        rejections.append(hit)

    # gate 2 — known-issue dedupe (Duplicate lesson)
    for k in known_issues:
        if (fnmatch(meta.issue_class.lower(), k.issue_class.lower())
                and fnmatch(meta.asset_host.lower(), k.asset.lower())):
            rejections.append(
                f"known-issue: ({meta.issue_class}, {meta.asset_host}) "
                f"already ruled {k.outcome!r}"
                + (f" [{k.reference}]" if k.reference else ""))

    # gate 1 — demonstrated impact (Artifactory lesson)
    imp = meta.impact_text or ""
    residual = _residual_impact(imp)
    if _CLAIM_ONLY.search(imp) and not _DEMONSTRATED.search(residual):
        rejections.append(
            "impact-gate: claim-only impact ('could/would expose') with "
            "no demonstrated action — exposure is not vulnerability")
    is_exposure = meta.issue_class.startswith(_EXPOSURE_CLASSES)
    if is_exposure and not meta.has_runtime_capture:
        rejections.append(
            f"impact-gate: exposure-class finding {meta.issue_class!r} "
            "requires a runtime capture demonstrating impact "
            "(claimed exposure alone = triage reject 'no impact')")
    if is_exposure and not _DEMONSTRATED.search(residual):
        rejections.append(
            f"impact-gate: exposure-class finding {meta.issue_class!r} "
            "impact text shows no demonstrated action "
            "(retrieved/accessed/executed/...)")

    return SubmitVerdict(not rejections, rejections)

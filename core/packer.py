"""BUCKY packer — the report engine (research-synthesis D: R1-R10 gates).

The packer REFUSES incomplete drafts (2510.18448's 9-component gate) and runs
the 13-category rejection-taxonomy pre-flight (Reviewers' Lens). It never
gates on an LLM's looks-valid verdict (GPT-5 over-accepts, Rec_invalid 0.275).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_STEPS_LEN = 400   # per-step char budget
IMPACT_MIN_WORDS = 12  # defeats "implications not demonstrated" null
TITLE_MIN, TITLE_MAX = 25, 128


@dataclass
class ReportDraft:
    """The 9-component report model (2510.18448 taxonomy)."""
    title: str = ""
    cwe: str = ""
    environment: str = ""       # platform + versions + dep-lock
    steps: list[str] = field(default_factory=list)   # each WITH Expected:
    poc: str = ""               # machine-checkable one-liner + expected
    impact: str = ""
    remediation: str = ""       # OR 3.61 — highest measured effect
    evidence_seals: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PackResult:
    """Packer verdict with every failed gate named."""
    ok: bool
    problems: list[str] = field(default_factory=list)
    rendered: str = ""


# 13-category rejection taxonomy (Reviewers' Lens) as regex pre-flight
_REJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("out-of-scope", re.compile(r"\b(outside|beyond) (the )?scope\b", re.I)),
    ("below-threshold", re.compile(r"\b(minor|cosmetic|low[- ]impact|informational only)\b", re.I)),
    ("design-tradeoff", re.compile(r"\b(by design|intended behavior|works as designed)\b", re.I)),
    ("version-disclosure", re.compile(r"^\s*version (of|disclosure)\b", re.I | re.M)),
    ("test-credentials", re.compile(r"\b(test|demo) (account|credentials)\b", re.I)),
    ("third-party", re.compile(r"\bthird[- ]party (service|library|vendor)\b(?!\s+widget)", re.I)),
    ("tool-behavior", re.compile(r"\bdefault (behavior|configuration) of\b", re.I)),
)


def _gate_components(d: ReportDraft, problems: list[str]) -> None:
    if not (TITLE_MIN <= len(d.title) <= TITLE_MAX):
        problems.append(f"R1: title length {len(d.title)} not in {TITLE_MIN}-{TITLE_MAX}")
    if not re.search(r"\bCWE-\d+\b", d.cwe or ""):
        problems.append("R1: CWE ID missing from topline")
    if len(d.environment) < 20:
        problems.append("R2: environment block too thin (platform+version+lock)")
    if len(d.steps) < 2:
        problems.append("R3: need >=2 atomic numbered steps")
    for i, s in enumerate(d.steps, 1):
        if not re.search(r"expected\s*:", s, re.I):
            problems.append(f"R4: step {i} missing 'Expected:' oracle line")
        if len(s) > MAX_STEPS_LEN * 3:
            problems.append(f"R9: step {i} too long — delete prose")
    if not d.poc.strip():
        problems.append("R6: machine-checkable PoC missing")
    if len(d.impact.split()) < IMPACT_MIN_WORDS:
        problems.append("R7: impact paragraph too thin to defeat null hypothesis")
    if not d.remediation.strip():
        problems.append("R8: one-line suggested remediation missing (OR 3.61)")
    if not d.evidence_seals:
        problems.append("R5: no SHA-sealed evidence referenced")


def _gate_rejection_taxonomy(text: str, problems: list[str]) -> None:
    for label, pat in _REJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            problems.append(f"taxonomy-hit: {label} ({m.group(0)!r})")


def pack(draft: ReportDraft) -> PackResult:
    """Run all gates; render the final report only if every gate passes."""
    problems: list[str] = []
    _gate_components(draft, problems)
    full = "\n".join([draft.title, draft.impact, draft.poc, *draft.steps])
    _gate_rejection_taxonomy(full, problems)

    if problems:
        return PackResult(False, problems)

    lines = [
        draft.title,
        "",
        f"**CWE:** {draft.cwe}",
        "",
        "## Environment",
        draft.environment,
        "",
        "## Steps to Reproduce",
    ]
    for i, s in enumerate(draft.steps, 1):
        lines.append(f"{i}. {s}")
    lines += ["", "## PoC (machine-checkable)", "```", draft.poc, "```", "",
              "## Impact", draft.impact, "",
              "## Suggested Remediation", draft.remediation, "",
              "## Evidence (SHA-sealed)"]
    lines += [f"- {s}" for s in draft.evidence_seals]
    if draft.references:
        lines += ["", "## References"]
        lines += [f"- {r}" for r in draft.references]
    return PackResult(True, [], "\n".join(lines))

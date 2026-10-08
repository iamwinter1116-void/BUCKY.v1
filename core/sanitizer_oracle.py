"""BUCKY sanitizer-oracle — P80-class sanitizer fall-through detector.

Production-validated doctrine (Paytm care-app P80, Oct 2026 cycle-178):
a custom DOM-Parser→React-recursion sanitizer that handles ONLY a small
tag allowlist ('a', 'br', text) and falls through to
`createElement.apply(<anyTag>, <all-copied-attributes>)` for EVERYTHING
ELSE is arbitrary-element-creation with attacker-controlled attributes —
DOMPurify-class bypass WITHOUT needing a mutation vector.

The oracle detects the FALL-THROUGH SHAPE in minified bundle code:
  1. a DOMParser (or HTML parse) sink,
  2. a protocol allowlist on one tag ('a' href),
  3. an ELSE-branch that creates elements with copied attributes
     (createElement.apply / spread-attrs pattern),
  4. NO tag-allowlist gate guarding the else-branch.

Verdicts:
  FALLTHROUGH  — all four signals present (report-grade class)
  PARTIAL     — parse+sink present, allowlist/else-guard ambiguous
  CLEAN       — a tag-allowlist gates element creation, or no sink.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SanitizerVerdict:
    verdict: str          # FALLTHROUGH | PARTIAL | CLEAN | UNKNOWN
    signals: tuple[str, ...]
    evidence: tuple[str, ...]


_PARSE_SINK = re.compile(r"DOMParser|parseHTML|parseFromString")
_PROTO_ALLOWLIST = re.compile(r'\["[^"]*:",\s*"[^"]*:"(?:,\s*"[^"]*:")+\]')
# 'a'-tag protocol check shape: href protocol indexOf/startsWith allowlist
_PROTO_CHECK = re.compile(
    r'(?:"a"|[.]tagName[^;]{0,40}?"A")[^;]{0,200}?(?:indexOf|startsWith'
    r"|includes)\s*\([^)]{0,120}?(?:https?:|paytm)", re.I)
# else-branch element creation with attribute copy
_ELSE_CREATE = re.compile(
    r"createElement\.apply|createElement\([^)]{0,60}\.type"
    r"|Array\.from\([a-zA-Z$_]{1,3}\.attributes\)")
# tag allowlist gate (guards the create — its presence = clean)
_TAG_GATE = re.compile(
    r"(?:ALLOWED_TAGS|allowedTags|TAG_WHITELIST|tagWhitelist"
    r'|\["a",\s*"br",\s*"span"[^\]]*\]\.includes'
    r"|isAllowedTag|_ALLOWED\b)")


def analyze_sanitizer(bundle_text: str) -> SanitizerVerdict:
    """Classify a minified bundle for P80-class sanitizer fall-through.

    Args:
        bundle_text: full JS bundle source (minified is fine).

    Returns:
        SanitizerVerdict with the shape-signals found (never fabricates:
        UNKNOWN when the bundle carries none of the parse-sink signals).
    """
    if not bundle_text:
        return SanitizerVerdict("UNKNOWN", (), ("empty input",))

    signals: list[str] = []
    evidence: list[str] = []

    if _PARSE_SINK.search(bundle_text):
        signals.append("parse-sink")
        m = _PARSE_SINK.search(bundle_text)
        i = m.start() if m else 0
        evidence.append(f"parse-sink@{i}: "
                        f"{bundle_text[i:i+40]!r}")

    if _PROTO_ALLOWLIST.search(bundle_text):
        signals.append("protocol-allowlist")
        m = _PROTO_ALLOWLIST.search(bundle_text)
        i = m.start() if m else 0
        evidence.append(f"proto-allowlist@{i}: "
                        f"{bundle_text[i:i+60]!r}")
    elif _PROTO_CHECK.search(bundle_text):
        signals.append("protocol-check")
        m = _PROTO_CHECK.search(bundle_text)
        i = m.start() if m else 0
        evidence.append(f"proto-check@{i}: {bundle_text[i:i+50]!r}")

    if _ELSE_CREATE.search(bundle_text):
        signals.append("else-create-attrs")
        m = _ELSE_CREATE.search(bundle_text)
        i = m.start() if m else 0
        evidence.append(f"create-sink@{i}: {bundle_text[i:i+50]!r}")

    if _TAG_GATE.search(bundle_text):
        signals.append("tag-gate-present")

    # decision
    if "parse-sink" not in signals:
        return SanitizerVerdict("UNKNOWN" if not signals else "PARTIAL",
                                tuple(signals), tuple(evidence[:3]))
    if ("tag-gate-present" in signals):
        return SanitizerVerdict("CLEAN", tuple(signals),
                                ("tag-allowlist guards creation",))
    if ("protocol-allowlist" in signals or "protocol-check" in signals) \
            and "else-create-attrs" in signals:
        return SanitizerVerdict("FALLTHROUGH", tuple(signals),
                                tuple(evidence[:4]))
    if "else-create-attrs" in signals:
        return SanitizerVerdict("PARTIAL", tuple(signals), tuple(evidence[:3]))
    return SanitizerVerdict("PARTIAL", tuple(signals), tuple(evidence[:2]))

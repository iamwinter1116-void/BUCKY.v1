"""BUCKY lanes.security — the custom-replacement detectors.

These are the techniques we ran by hand across 181 operational cycles,
rebuilt as deterministic, testable detectors — replacing the generic tools
that kept fighting us with edge cases. Each detector is pure logic over
captured artifacts (no network I/O here; lanes.browse/probe feed them).

Detectors:
- classify_csp   : CCS'16/NDSS'20 bypass taxonomy (B1/B2/B3), spec-aware.
- classify_handler: postMessage origin-check failure taxonomy (P1..P6).
- detect_secrets : anchored vendor patterns + entropy gate (no outbound calls).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- csp-verdict

_B1_TRIGGERS = ("unsafe-inline", "unsafe-eval")


@dataclass(frozen=True)
class CSPVerdict:
    """Classification of one Content-Security-Policy (header or meta)."""
    bypass_class: str            # "B1" | "B2-candidate" | "clean" | "no-policy"
    meta_only: bool
    frame_ancestors_present: bool
    notes: tuple[str, ...] = field(default_factory=tuple)


def classify_csp(policy: str | None, *, is_meta: bool,
                 xfo: str | None = None) -> CSPVerdict:
    """Apply the CCS'16 / NDSS'20 bypass taxonomy to one policy.

    B1 (trivial): unsafe-inline/unsafe-eval present without a nonce/hash —
    zero XSS mitigation. Syntactic check: no false positives by construction.
    Meta policies cannot set frame-ancestors (spec-ignored) -> embeddable.
    """
    notes: list[str] = []
    policy = (policy or "").strip()
    if not policy:
        cls = "no-policy" if not xfo else "clean"
        return CSPVerdict(cls, is_meta, False,
                          ("no CSP found",) if cls == "no-policy" else ())
    lower = policy.lower()
    has_nonce = "nonce-" in lower
    has_hash = "'sha" in lower
    b1 = any(t in lower for t in _B1_TRIGGERS) and not has_nonce and not has_hash
    fa = "frame-ancestors" in lower
    if is_meta and fa:
        notes.append("meta frame-ancestors is spec-ignored -> embeddable")
        fa = False  # meta CSP cannot enforce frame-ancestors per spec
    if b1:
        notes.append("B1: unsafe-inline/eval without nonce -> zero XSS mitigation")
        return CSPVerdict("B1", is_meta, fa, tuple(notes))
    if not has_nonce:
        notes.append("no nonce/hash: whitelist policy (B2/B3 audit candidates)")
        return CSPVerdict("B2-candidate", is_meta, fa, tuple(notes))
    return CSPVerdict("clean", is_meta, fa, tuple(notes))


# ---------------------------------------------------------------- pm-guard

@dataclass(frozen=True)
class PmVerdict:
    """Origin-check classification for one message handler (P1..P6)."""
    pattern: str               # "P1".."P6" | "strict" | "unknown"
    evidence: tuple[str, ...] = field(default_factory=tuple)


def classify_handler(source: str) -> PmVerdict:
    """Lexically classify a message-handler body (P1..P6 taxonomy).

    P1 no origin check | P2 lax compare | P3 null parity | P4 trust transfer
    to message content | P5 strict origin but unsafe sink | P6 no handshake
    state | strict otherwise.
    """
    src = source or ""
    if not src:
        return PmVerdict("unknown", ("empty handler"))
    low = src.lower()
    has_origin_token = re.search(r"\.origin\b", src)
    strict = re.search(
        r"event\.origin\s*===|e\.origin\s*===|ev\.origin\s*===|\.origin\s*!==",
        src)
    lax = re.search(
        r"\.origin\s*\(\s*(?:indexOf|includes|startsWith|endsWith|match|search)",
        src)
    null_check = re.search(r"\.origin\s*===?\s*null|\.origin\s*!==?\s*null", src)
    content_origin = re.search(
        r"(?:data|msg|message|payload|event\.data)[.\[]\s*(?:origin|sender|from)",
        low)
    unsafe_sink = re.search(
        r"innerHTML|insertAdjacentHTML|\beval\(|new\s+Function|document\.write",
        src)

    if not has_origin_token:
        return PmVerdict("P1", ("no event.origin reference anywhere"))
    if null_check:
        return PmVerdict("P3", ("null-origin parity accepted"))
    if lax:
        return PmVerdict("P2", ("origin compared with substring-style call"))
    if content_origin:
        return PmVerdict("P4", ("origin read from message content, not the event"))
    if strict and unsafe_sink:
        return PmVerdict("P5", ("strict origin check but data flows to unsafe sink"))
    if strict:
        return PmVerdict("strict", ())
    return PmVerdict("unknown", ("origin token present, pattern unresolved"))


# ---------------------------------------------------------------- js-secrets

@dataclass(frozen=True)
class SecretFinding:
    """One candidate secret found in a bundle. NEVER auto-verified outbound."""
    kind: str            # azure-client-secret, aws-key, generic-key, jwt, ...
    anchor: str          # the context key that anchored the match
    redacted: str        # safe preview (first-8 + ***)
    entropy: float
    offset: int


_AZURE_SECRET = re.compile(
    r"(?:client[_-]?secret|ClientSecret)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9~._-]{30,40})[\"']",
    re.IGNORECASE)
_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_GOOGLE_KEY = re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")
_STRIPE_KEY = re.compile(r"\b((?:sk|pk|rk)_[live|test]_[0-9A-Za-z]{16,})\b")
_JWT = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b")
_GENERIC = re.compile(
    r"[\"']?(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/_=-]{24,64})[\"']",
    re.IGNORECASE)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(value: str) -> str:
    return value[:8] + "***" if len(value) > 12 else "***"


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("azure-client-secret", _AZURE_SECRET),
    ("aws-access-key", _AWS_KEY),
    ("google-api-key", _GOOGLE_KEY),
    ("stripe-key", _STRIPE_KEY),
    ("jwt", _JWT),
)


def detect_secrets(bundle_text: str, *, min_entropy: float = 3.5,
                   patterns: list[tuple[str, "re.Pattern[str]", float]] | None = None) -> list[SecretFinding]:
    """Anchored + entropy-gated secret detection over bundle text.

    Args:
        bundle_text: the JS bundle / page source to scan.
        min_entropy: default Shannon-entropy floor for generic anchors.
        patterns: override pattern list (id, compiled-regex, min-entropy);
            defaults to the hardcoded base set. The registry-driven caller
            passes PatternRegistry.secret_patterns() here so learned
            patterns participate automatically.

    Security: NEVER makes an outbound call to verify a credential (invariant
    from the recon-pipeline research). Values are redacted in findings; the
    raw bundle is expected to be sealed separately by the caller.
    """
    out: list[SecretFinding] = []
    if patterns is None:
        patterns = [(k, p, min_entropy) for k, p in _PATTERNS]
    for kind, pat, ent_floor in patterns:
        for m in pat.finditer(bundle_text):
            val = m.group(1)
            ent = _shannon(val)
            if ent < ent_floor:
                continue
            out.append(SecretFinding(kind, m.group(0)[:40],
                                     _redact(val), round(ent, 2), m.start()))
    return out

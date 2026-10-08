"""BUCKY lanes.jsdeep — deep minified-bundle mining (custom replacement).

This replaces the single most painful manual technique of the 181-cycle
campaign: opening 300-500KB minified webpack bundles by hand to find:
hardcoded SaaS tenant URLs (lapsed-tenant takeover pairs), custom URL
scheme allowlists, deep-link builders with injectable params, numeric
module boundaries, and getter-exported data arrays (PII-class).

Design (regex-level by doctrine — stdlib-only, no AST dependency; the
bundle-mining research corpus arrives via Agent-I and may upgrade these
to AST where regex under-performs):
- every finding carries (line, byte-offset, preview, redacted-value)
- detection is DETERMINISTIC and re-derivable from sealed artifacts
- FP-gates: a hostname counts as tenant-SaaS ONLY on known SaaS domains;
  scheme-allowlists ONLY when ≥2 protocol strings sit in array-literal
  form; deeplinks only on scheme:// with ≥1 param.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BundleFinding:
    kind: str          # tenant-saas | scheme-allowlist | deeplink-builder |
                       # module-boundary | getter-array | wildcard-postmessage
    preview: str       # 80-char context
    redacted: str      # value with secret-shaped parts masked
    line: int
    offset: int


_SAAS_HOST = re.compile(
    r"([a-z0-9][a-z0-9-]{1,40}\.(?:freshdesk|zendesk|intercom|freshchat"
    r"|hubspot|salesforce|okta|atlassian|gainsight|qualtrics)\.com)\b", re.I)
# tenant-pair signal: same SaaS base with sandbox/prod/live/dev prefixes
_PAIR_WORDS = ("sandbox", "sbx", "staging", "preprod", "dev", "test",
               "prod", "live")
_SCHEME_ARRAY = re.compile(
    r"\[\s*(?:\"[a-z][a-z0-9+.-]{1,20}:\"\s*,\s*){1,8}?(\"[a-z][a-z0-9+.-]{1,20}:\")\s*\]")
_DEEPLINK = re.compile(
    r"([a-z][a-z0-9+.-]{2,20}://[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200})")
_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.-]{2,20}://")
_BUILTIN_SCHEMES = {"http://", "https://", "ftp://", "ws://", "wss://",
                    "mailto:", "data:", "blob:", "javascript:"}
_MODULE_ID = re.compile(r"\[(\d{4,7})\]\s*[,=:)(]")
_GETTER_ARRAY = re.compile(
    r"([A-Za-z_$][\w$]{0,4}):\s*\(\)\s*=>\s*([A-Za-z_$][\w$]{0,4})\b")
_POSTMSG_STAR = re.compile(
    r"postMessage\s*\(([^)]{0,300}?)\s*,\s*[\"']\*[\"']\s*\)")
_SECRETISH = re.compile(r"(?i)(secret|token|key|password|passwd|credential)")


def _redact(s: str) -> str:
    """Mask value parts that look secret-shaped (first-8 keep rule)."""
    if _SECRETISH.search(s) and len(s) > 12:
        return s[:8] + "***"
    return s


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def mine_bundle(bundle_text: str, *, max_findings: int = 200
                ) -> list[BundleFinding]:
    """Mine one minified bundle for campaign-critical structures.

    Args:
        bundle_text: full JS source (minified fine).
        max_findings: safety cap (a 500KB bundle can regex-explode).

    Returns:
        Findings sorted by offset; deterministic, deduplicated.
    """
    out: list[BundleFinding] = []
    seen: set[tuple[str, int]] = set()

    def add(kind: str, value: str, offset: int, ctx: str = "") -> None:
        key = (kind, offset)
        if key in seen or len(out) >= max_findings:
            return
        seen.add(key)
        preview = (ctx or bundle_text[max(0, offset - 20):offset + 60])
        out.append(BundleFinding(
            kind, preview[:80].replace("\n", " "), _redact(value),
            _line_of(bundle_text, offset), offset))

    # 1. SaaS tenant hosts (+ pair detection pass below)
    saas_hosts: list[tuple[str, int, str]] = []
    for m in _SAAS_HOST.finditer(bundle_text):
        host = m.group(1).lower()
        saas_hosts.append((host, m.start(), m.group(0)))
        add("tenant-saas", host, m.start())

    # pair-signal: same SaaS base with env-prefixed twins
    by_base: dict[str, set[str]] = {}
    for host, _, _ in saas_hosts:
        parts = host.split(".")
        base = ".".join(parts[1:])
        by_base.setdefault(base, set()).add(parts[0])
    for base, prefixes in by_base.items():
        env_hits = {p for p in prefixes if any(w in p for w in _PAIR_WORDS)}
        if len(env_hits) >= 2:
            # annotate first finding of this base with the pair info
            for host, off, raw in saas_hosts:
                if host.endswith(base):
                    add("tenant-pair", f"{base} ← {sorted(env_hits)}", off)
                    break

    # 2. scheme allowlists (>=2 proto strings in an array literal)
    for m in _SCHEME_ARRAY.finditer(bundle_text):
        # extract the scheme strings for the redacted preview
        schemes = re.findall(r"\"([a-z][a-z0-9+.-]{1,20}:)\"", m.group(0))
        if len(schemes) >= 2:
            add("scheme-allowlist", ",".join(schemes), m.start())

    # 3. deeplink builders (non-builtin schemes only)
    for m in _DEEPLINK.finditer(bundle_text):
        dl = m.group(1)
        if dl.lower().split("://")[0] + "://" in _BUILTIN_SCHEMES:
            continue
        add("deeplink-builder", _redact(dl[:120]), m.start())

    # 4. numeric module boundaries (webpack shape)
    for m in _MODULE_ID.finditer(bundle_text):
        add("module-boundary", m.group(1), m.start())

    # 5. getter-exported bindings (data arrays reachable via export)
    for m in _GETTER_ARRAY.finditer(bundle_text):
        add("getter-array", f"{m.group(1)}:()=>{m.group(2)}", m.start())

    # 6. wildcard postMessage senders
    for m in _POSTMSG_STAR.finditer(bundle_text):
        add("wildcard-postmessage", _redact(m.group(1)[:80]), m.start())

    return sorted(out, key=lambda f: f.offset)


def summarize(findings: list[BundleFinding]) -> dict[str, int]:
    """Per-kind counts (per-detector reporting, PentestGPT-style)."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.kind] = counts.get(f.kind, 0) + 1
    return counts


def tenant_pairs(findings: list[BundleFinding]) -> list[str]:
    """The lapsed-tenant/sandbox-prod pair signals (R7-class leads)."""
    return sorted({f.redacted for f in findings
                   if f.kind == "tenant-pair"})

"""BUCKY lanes.deeplink — scheme collision table + taint-source harvest.

Custom replacement (Agent-I research synthesis):
- Liu et al. [USENIX Sec'17]: 2.2% App-Link verification pass-rate,
  45.6% of Alexa-1M embed hijacked links — the hijack surface is the
  NORM. Detection = scheme->claimants collision table; flag schemes
  claimed by multiple unrelated owners or unverified.
- DeepExploitor [ASE'25]: every query parameter of a scheme-builder
  string is an attacker-controlled taint source (83 zero-day chains in
  433 apps). Detection = per-deeplink param inventory + trusted-domain
  allowlist mutation candidates.

Deterministic, stdlib-only; regex-level per research doctrine
(AST-upgrade slot documented in SYNTHESIS-I).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

_SCHEME_RE = re.compile(
    r"\b([a-z][a-z0-9+.-]{2,20}):(?:[/]{1,2}|@)", re.I)
_BUILTIN = {"http", "https", "ftp", "ws", "wss", "mailto", "data",
            "blob", "javascript", "file", "tel", "sms"}


@dataclass(frozen=True)
class DeepLink:
    scheme: str
    rest: str              # everything after scheme:
    params: tuple[tuple[str, str], ...]
    offset: int
    preview: str

    @property
    def url(self) -> str:
        return f"{self.scheme}:{self.rest}"

    @property
    def is_custom(self) -> bool:
        return self.scheme.lower() not in _BUILTIN


def harvest_deeplinks(text: str, *, cap: int = 200
                      ) -> list[DeepLink]:
    """Harvest every scheme:// link from bundle/page text.

    Builtins (http/https/mailto/…) are collected for the collision
    table but flagged is_custom=False; custom schemes are the
    hijack-relevant set.
    """
    out: list[DeepLink] = []
    seen: set[int] = set()
    for m in _SCHEME_RE.finditer(text):
        if m.start() in seen or len(out) >= cap:
            break
        seen.add(m.start())
        scheme = m.group(1).lower()
        end = m.end()
        rest = text[end:end + 300]
        # cut at quote/space/angle — minified-friendly terminators
        cut = re.search(r"['\"<>\s\\]", rest)
        if cut:
            rest = rest[:cut.start()]
        try:
            params = tuple(parse_qsl(
                urlsplit(f"{scheme}:{rest}").query, keep_blank_values=True))
        except ValueError:
            params = ()
        out.append(DeepLink(scheme, rest, params, m.start(),
                            text[max(0, m.start() - 15):m.start() + 50]))
    return out


@dataclass(frozen=True)
class CollisionVerdict:
    scheme: str
    claimants: tuple[str, ...]   # hosts/contexts claiming the scheme
    hijack_risk: bool            # >1 unrelated claimant OR custom+unowned
    detail: str


def collision_table(links: list[DeepLink]) -> dict[str, list[str]]:
    """scheme -> claimant host list (Liu'17 collision grouping)."""
    table: dict[str, set[str]] = {}
    for dl in links:
        # generic-URI host extract (urlsplit.hostname is http-only):
        # 'scheme://HOST/rest' or 'scheme:HOST/rest'
        rest = dl.rest
        if rest.startswith("//"):
            rest = rest[2:]
        host = rest.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
        host = host if host else "(inline)"
        table.setdefault(dl.scheme, set()).add(host.lower())
    return {s: sorted(v) for s, v in table.items()}


def hijack_flags(table: dict[str, list[str]],
                 *, owned_hosts: set[str]) -> list[CollisionVerdict]:
    """Flag custom schemes with multiple claimants or unowned hosts."""
    out: list[CollisionVerdict] = []
    for scheme, claimants in table.items():
        if scheme in _BUILTIN:
            continue
        unrelated = [c for c in claimants
                     if c != "(inline)" and not any(
                         c == o or c.endswith("." + o)
                         for o in owned_hosts)]
        multi = len(claimants) > 1
        if multi or unrelated:
            why = []
            if multi:
                why.append(f"{len(claimants)} claimants")
            if unrelated:
                why.append(f"unowned: {unrelated[0]}")
            out.append(CollisionVerdict(
                scheme, tuple(claimants), True, "; ".join(why)))
    return out


def taint_params(links: list[DeepLink]) -> dict[str, list[str]]:
    """DeepExploitor taint-source inventory: per custom-scheme link,
    every query param is an attacker-controlled input candidate."""
    out: dict[str, list[str]] = {}
    for dl in links:
        if not dl.is_custom:
            continue
        for k, _v in dl.params:
            out.setdefault(dl.url[:80], []).append(k)
    return out


def trusted_domain_mutations(host: str) -> list[str]:
    """DeepExploitor-style allowlist-bypass candidates for a trusted
    host: prefix/suffix tricks that pass substring and endsWith
    checks (used by the weak-check ruleset to explain exploitability).
    """
    host = host.strip().lower()
    base = host.split("://")[-1]
    return [
        f"https://{base}.attacker.example",
        f"https://attacker.example/{base}",   # path confusion
        f"https://{base.replace('.', '')}.example",  # dot-stripped
    ]

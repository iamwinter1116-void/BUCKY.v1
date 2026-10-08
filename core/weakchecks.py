"""postMessage weak-check ruleset — Son & Shmatikov NDSS'13 patterns.

The paper documented the EXACT semantically-incorrect origin-check
shapes found in the wild (65 of 136 receivers did NO check; 14 more used
patterns attackers pass). Encoded here as deterministic detectors: any
handler matching a weak pattern is P1-class regardless of whether a
check 'exists'.

This is the FP-killer the research demanded: 'has an origin check' is
NOT the bar — 'the check is semantically correct' is.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# handler-receiver registration shapes
_RX_HANDLER = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*([A-Za-z_$][\w$]*)")
_RX_ONMSG = re.compile(r"onmessage\s*=\s*function")

# WEAK patterns (each = attacker-passable, from the paper's Table 2 class)
WEAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # 1. contains-check: origin.includes('example.com') — attacker
    #    registers evil-example.com.attacker.tld
    ("contains-check",
     re.compile(r"(?:includes|indexOf)\s*\(\s*['\"][^'\"]*\.?[a-z-]+\.[a-z]+")),
    # 2. ends-with-check: origin.endsWith('example.com') —
    #    evilexample.com passes
    ("ends-with-check",
     re.compile(r"endsWith\s*\(\s*['\"][a-z0-9.-]+\.[a-z]+['\"]")),
    # 3. starts-with-check: scheme/host-prefix confusion
    ("starts-with-check",
     re.compile(r"startsWith\s*\(\s*['\"][a-z]+://")),
    # 4. missing-escaped-dot: regex /\.example.com/ written as
    #    /example.com/ (or indexOf without dot) —
    #    'notexample.com' passes
    ("missing-escaped-dot",
     re.compile(r"match\s*\(\s*/[^/\n]*[a-z]+example[^/\n]*/|"
                r"test\s*\(\s*/[^/\n]*[a-z]+example[^/\n]*/")),
    # 5. substring-host check on e.origin without parsing
    ("substring-origin",
     re.compile(r"origin\s*\.\s*(?:slice|substring|substr|split)\s*\(")),
    # 6. equality against a full URL WITH path — e.origin never contains
    #    a path, so 'https://example.com/app' never matches: check is
    #    dead code. (Origin-format comparison without path is STRONG.)
    ("url-equality-origin",
     re.compile(r"origin\s*===?\s*['\"]https?://[\w.-]+/")),
)


@dataclass(frozen=True)
class WeakCheckVerdict:
    weak: bool
    pattern: str          # which weak shape matched ("" if strong/none)
    has_handler: bool
    has_any_check: bool   # any origin-comparison exists (even weak)


def classify_handler(js_text: str) -> WeakCheckVerdict:
    """Classify a message-handler snippet for weak origin checks.

    Args:
        js_text: inline JS or handler body (minified fine).

    Returns:
        WeakCheckVerdict: weak=True when a documented attacker-passable
        pattern is present; has_handler=False when no receiver exists.
    """
    has_handler = bool(_RX_HANDLER.search(js_text) or
                       _RX_ONMSG.search(js_text))
    if not has_handler:
        return WeakCheckVerdict(False, "", False, False)

    for name, pat in WEAK_PATTERNS:
        if pat.search(js_text):
            return WeakCheckVerdict(True, name, True, True)

    # any origin mention at all = some check exists (strong or unknown)
    has_any = bool(re.search(r"origin", js_text))
    return WeakCheckVerdict(False, "", True, has_any)

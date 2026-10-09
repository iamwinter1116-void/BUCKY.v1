"""BUCKY coverage — WSTG v4.2 attack-class coverage matrix.

THE ANTI-TUNNEL-VISION SYSTEM (Winter Soldier directive, Oct 2026):
our 181-cycle manual campaign found essentially ONE attack chain —
single-attack tunnel vision is the biggest liability. This module
makes coverage STRUCTURAL: every engine lane maps to authoritative
OWASP WSTG v4.2 categories (12 categories, 113 test objectives,
counts from the official checklist.json-derived index), every run
reports coverage % and the GAP list drives the next build wave.

Counts (official WSTG v4.2):
  INFO 10 | CONF 14 | IDNT 5 | ATHN 11 | ATHZ 5 | SESS 11 |
  INPV 22 | ERRH 2 | CRYP 4 | BUSL 10 | CLNT 15 | APIT 4  = 113

Coverage states:
  covered — engine has a deterministic detector + test
  partial — detector exists but only for a sub-class
  arsenal — Kali tool covers it (typed verb, not custom detector)
  gap     — nothing covers it (the liability)
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# authoritative WSTG v4.2 category table (official checklist.json counts,
# Agent-K verified 2026-10-09: 98 objectives total)

WSTG_CATEGORIES: dict[str, tuple[str, int]] = {
    "INFO": ("Information Gathering", 10),
    "CONF": ("Configuration & Deployment Management", 11),
    "IDNT": ("Identity Management", 5),
    "ATHN": ("Authentication", 10),
    "ATHZ": ("Authorization", 4),
    "SESS": ("Session Management", 9),
    "INPV": ("Input Validation", 20),   # INPV-13 dual-ID quirk upstream
    "ERRH": ("Error Handling", 2),
    "CRYP": ("Cryptography", 4),
    "BUSL": ("Business Logic", 9),
    "CLNT": ("Client-side Testing", 13),
    "APIT": ("API Testing", 1),
}
WSTG_TOTAL = sum(n for _, n in WSTG_CATEGORIES.values())  # 98

# CWE Top 25 (2024) — third coverage axis (MITRE, 31,770 CVEs)
CWE_TOP25: tuple[tuple[str, str, float], ...] = (
    ("CWE-79", "XSS", 56.92), ("CWE-787", "Out-of-bounds Write", 45.20),
    ("CWE-89", "SQL Injection", 35.88), ("CWE-352", "CSRF", 19.57),
    ("CWE-22", "Path Traversal", 12.74), ("CWE-125", "OOB Read", 11.42),
    ("CWE-78", "OS Command Injection", 11.30),
    ("CWE-416", "Use After Free", 10.19),
    ("CWE-862", "Missing Authorization", 10.11),
    ("CWE-434", "Unrestricted Upload", 10.03),
    ("CWE-94", "Code Injection", 7.13), ("CWE-20", "Input Validation", 6.78),
    ("CWE-77", "Command Injection", 6.74),
    ("CWE-287", "Improper Authentication", 5.94),
    ("CWE-269", "Privilege Management", 5.22),
    ("CWE-502", "Deserialization", 5.07),
    ("CWE-200", "Info Exposure", 5.07),
    ("CWE-863", "Incorrect Authorization", 4.05),
    ("CWE-918", "SSRF", 4.05),
    ("CWE-119", "Memory Bounds", 3.69),
    ("CWE-476", "NULL Deref", 3.58),
    ("CWE-798", "Hard-coded Credentials", 3.46),
    ("CWE-190", "Integer Overflow", 3.37),
    ("CWE-400", "Resource Consumption", 3.23),
    ("CWE-306", "Missing Auth for Critical Function", 2.73),
)


@dataclass(frozen=True)
class CoverageEntry:
    category: str          # WSTG prefix (INFO, CONF, ...)
    wstg_id: str            # e.g. "WSTG-CLNT-08" or "WSTG-INPV-*"
    test_name: str          # human label
    status: str             # covered | partial | arsenal | gap
    engine_part: str        # which lane/verb/module ("" for gaps)
    notes: str = ""


# ---------------------------------------------------------------------------
# ENGINE COVERAGE REGISTRY — the honest self-assessment.
# Every entry is a capability the engine demonstrably has (unit-tested)
# or a tool verb. Anything NOT here is a GAP by definition.

_ENGINE_COVERAGE: tuple[CoverageEntry, ...] = (
    # --- INFO: Information Gathering (10) -----------------------------
    CoverageEntry("INFO", "WSTG-INFO-02", "Fingerprint Web Server",
                  "arsenal", "whatweb-probe"),
    CoverageEntry("INFO", "WSTG-INFO-02", "Fingerprint Web Server",
                  "arsenal", "httpx-probe"),
    CoverageEntry("INFO", "WSTG-INFO-05", "Review Webpage Content for Info Leakage",
                  "covered", "lanes_jsdeep:mine_bundle (comments/strings)"),
    CoverageEntry("INFO", "WSTG-INFO-09", "Fingerprint Web Application Framework",
                  "arsenal", "whatweb-probe (framework plugins)"),
    CoverageEntry("INFO", "WSTG-INFO-10", "Map Application Architecture",
                  "partial", "lanes_recon:6-stage (CT seed + dns expand)"),
    CoverageEntry("INFO", "WSTG-CONF-04", "Review Old Backup and Unreferenced Files",
                  "covered", "lanes_stale:CDX diff (stale-still-live)"),
    # --- CONF: Configuration & Deployment (14) --------------------------
    CoverageEntry("CONF", "WSTG-CONF-07", "Test HSTS", "covered",
                  "lanes_headers:check_hsts"),
    CoverageEntry("CONF", "WSTG-CONF-10", "Test for Subdomain Takeover",
                  "partial", "lanes_recon:takeover_candidates + RDScan "
                             "preconditions doctrine"),
    CoverageEntry("CONF", "WSTG-CONF-11", "Test Cloud Storage",
                  "gap", ""),
    CoverageEntry("CONF", "WSTG-CONF-12", "Test Content Security Policy",
                  "covered", "lanes_security:classify_csp (B1/B2/B3 + "
                             "94.72% base-rate calibration doctrine)"),
    # --- SESS: Session Management (11) ---------------------------------
    CoverageEntry("SESS", "WSTG-SESS-02", "Test Cookie Attributes",
                  "covered", "lanes_headers:check_cookies "
                             "(__Host- doctrine, Cookie Crumbles)"),
    CoverageEntry("SESS", "WSTG-SESS-09", "Test Session Hijacking",
                  "partial", "chain_verdict:bot-session-hijack "
                             "(composition level only)"),
    CoverageEntry("SESS", "WSTG-SESS-10", "Testing for CSRF",
                  "gap", ""),
    # --- INPV: Input Validation (22) ------------------------------------
    CoverageEntry("INPV", "WSTG-INPV-01", "Reflected XSS",
                  "gap", ""),
    CoverageEntry("INPV", "WSTG-INPV-02", "Stored XSS",
                  "gap", ""),
    CoverageEntry("INPV", "WSTG-INPV-05", "SQL Injection",
                  "arsenal", "sqlmap-baseline (RESTRICTED: own-lab only)"),
    CoverageEntry("INPV", "WSTG-INPV-19", "Server-Side Request Forgery",
                  "gap", ""),
    # --- CLNT: Client-side (15) -----------------------------------------
    CoverageEntry("CLNT", "WSTG-CLNT-06", "Test postMessage (Web Messaging)",
                  "covered", "lanes_security:classify_handler (P1-P6) + "
                             "weakchecks (NDSS'13 patterns)"),
    CoverageEntry("CLNT", "WSTG-CLNT-08", "Test Clickjacking",
                  "covered", "lanes_security:classify_csp "
                             "(frame-ancestors analysis)"),
    CoverageEntry("CLNT", "WSTG-CLNT-11", "Test Web Messaging (browser storage)",
                  "partial", "lanes_jsdeep:wildcard-postmessage"),
    CoverageEntry("CLNT", "WSTG-CLNT-12", "Test Browser Storage (localStorage)",
                  "gap", ""),
    # --- CRYP (4) --------------------------------------------------------
    CoverageEntry("CRYP", "WSTG-CRYP-01", "Weak Transport Layer Security",
                  "gap", ""),
    # --- ERRH (2) --------------------------------------------------------
    CoverageEntry("ERRH", "WSTG-ERRH-01", "Improper Error Handling",
                  "covered", "lanes_headers:check_error_handling "
                             "(6 stack-patterns)"),
    # --- APIT (4) --------------------------------------------------------
    CoverageEntry("APIT", "WSTG-APIT-01", "Test GraphQL",
                  "gap", ""),
    # --- ATHN (11) --------------------------------------------------------
    CoverageEntry("ATHN", "WSTG-ATHN-02", "Default Credentials",
                  "partial", "lanes_headers:check_default_cred_surface "
                             "(surface-map only; attempts RESTRICTED)"),
    # --- BUSL (10) --------------------------------------------------------
    CoverageEntry("BUSL", "WSTG-BUSL-*", "Business Logic (workflow abuse)",
                  "partial", "chain_verdict:capability composition "
                             "(plan-level only)"),
    # --- secrets / hardcoded (INFO-class) --------------------------------
    CoverageEntry("INFO", "WSTG-INFO-05b", "Hardcoded Secrets in Client JS",
                  "covered", "lanes_security:detect_secrets + registry"),
    CoverageEntry("CLNT", "WSTG-CLNT-09", "Test CORS headers",
                  "covered", "lanes_headers:check_cors "
                             "(wildcard + origin-reflection)"),
)


def coverage_entries() -> tuple[CoverageEntry, ...]:
    return _ENGINE_COVERAGE


@dataclass
class CoverageReport:
    entries: tuple[CoverageEntry, ...] = field(
        default_factory=lambda: _ENGINE_COVERAGE)
    # Mind-the-Gap two-metric: touched (verb ran) vs oracled
    # (proof-gate/deterministic verdict exists)
    touched: set[str] = field(default_factory=set)
    oracled: set[str] = field(default_factory=set)

    def by_status(self, status: str) -> list[CoverageEntry]:
        return [e for e in self.entries if e.status == status]

    def status_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.status] = out.get(e.status, 0) + 1
        return out

    def category_coverage(self) -> dict[str, dict[str, int]]:
        """Per-WSTG-category: covered/partial/arsenal counts + gap flag."""
        out: dict[str, dict[str, int]] = {}
        for cat in WSTG_CATEGORIES:
            entries = [e for e in self.entries if e.category == cat]
            d = {"covered": 0, "partial": 0, "arsenal": 0, "gap": 0}
            for e in entries:
                d[e.status] += 1
            # categories with NO registry entries at all are pure gaps
            out[cat] = d
        for cat, (_, total) in WSTG_CATEGORIES.items():
            out[cat]["wstg_total"] = total
            out[cat]["registry_entries"] = (
                out[cat]["covered"] + out[cat]["partial"]
                + out[cat]["arsenal"])
        return out

    def gap_list(self) -> list[CoverageEntry]:
        return self.by_status("gap")

    def render(self) -> str:
        """Human-readable matrix — the anti-tunnel-vision dashboard."""
        lines = ["WSTG v4.2 COVERAGE MATRIX (12 categories / 113 tests)",
                 "=" * 58]
        for cat, (name, total) in WSTG_CATEGORIES.items():
            d = self.category_coverage()[cat]
            eng = d["covered"] + d["partial"] + d["arsenal"]
            state = ("GAP" if d["covered"] == 0 and d["partial"] == 0
                     and d["arsenal"] == 0
                     else f"eng:{eng} cov:{d['covered']} par:{d['partial']} "
                          f"ars:{d['arsenal']}")
            lines.append(f"  {cat:5s} {name:42s} (wstg:{total:2d})  {state}")
        counts = self.status_counts()
        lines.append("=" * 58)
        lines.append(f"registry: {len(self.entries)} entries — "
                     f"covered:{counts.get('covered', 0)} "
                     f"partial:{counts.get('partial', 0)} "
                     f"arsenal:{counts.get('arsenal', 0)} "
                     f"gap:{counts.get('gap', 0)}")
        gaps = self.gap_list()
        if gaps:
            lines.append("GAPS (next-build backlog):")
            for g in gaps:
                lines.append(f"  [{g.wstg_id}] {g.test_name}")
        return "\n".join(lines)

    def coverage_pct(self) -> float:
        """weighted: covered=1.0, partial/arsenal=0.5, gap=0 per entry."""
        if not self.entries:
            return 0.0
        s = sum(1.0 if e.status == "covered" else
                0.5 if e.status in ("partial", "arsenal") else 0.0
                for e in self.entries)
        return round(s / len(self.entries) * 100, 1)

    # --- Mind-the-Gap two-metric (Agent-K) -----------------------------
    def oracle_gaps(self) -> list[str]:
        """Objectives touched but NOT oracled — the weak-oracle list.

        These are the highest-priority next-cycle targets: a verb ran
        but nothing PROVED anything about them (PMForce doctrine).
        """
        return sorted(self.touched - self.oracled)

    def record_touched(self, wstg_id: str) -> None:
        self.touched.add(wstg_id)

    def record_oracled(self, wstg_id: str) -> None:
        self.oracled.add(wstg_id)
        self.touched.add(wstg_id)  # oracled implies touched

    # --- CWE Top-25 axis (Agent-K) --------------------------------------
    def cwe_gaps(self, covered_cwes: set[str] | None = None) -> list[str]:
        """Top-25 weaknesses with no registered detector (priority =
        score-descending). covered_cwes: extra CWE ids covered by
        campaign profiles/learned patterns."""
        have = covered_cwes or set()
        return [cwe for cwe, _n, _s in CWE_TOP25 if cwe not in have]

    def render_cwe_axis(self, covered_cwes: set[str] | None = None) -> str:
        have = covered_cwes or set()
        lines = ["CWE TOP-25 COVERAGE (2024, 31,770 CVEs)"]
        for cwe, name, score in CWE_TOP25:
            mark = "✓" if cwe in have else "✗"
            lines.append(f"  {mark} {cwe:8s} {name:38s} {score}")
        n = sum(1 for c, _n, _s in CWE_TOP25 if c in have)
        lines.append(f"covered {n}/{len(CWE_TOP25)}")
        return "\n".join(lines)


def next_build_backlog() -> list[CoverageEntry]:
    """Gap-driven development: the uncovered classes, prioritized."""
    return sorted(CoverageReport().gap_list(),
                  key=lambda e: e.wstg_id)


if __name__ == "__main__":
    print(CoverageReport().render())

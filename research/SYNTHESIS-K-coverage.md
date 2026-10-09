# RESEARCH SYNTHESIS — FULL ATTACK-CLASS COVERAGE (Agent K, COMPLETE)
# Source: deleg_cb8a4b45, 10 papers, all primary-source verified
# Verified delivery: subagent-summary-0-20261009_132527_904792.txt
# Date: 2026-10-09 (IST)

## CORRECTION TO v0.24 (important — official checklist.json counts):
WSTG v4.2 = **98 test objectives** (not 113):
INFO 10 | CONF 11 | IDNT 5 | ATHN 10 | ATHZ 4 | SESS 9 |
INPV 20 (upstream quirk: Buffer-Overflow AND Format-String both
carry INPV-13 in checklist.json; md checklist lists 19/97) |
ERRH 2 | CRYP 4 | BUSL 9 | CLNT 13 | APIT 1
Success-objective sums: INFO 13, CONF 19, IDNT 10, ATHN 16, ATHZ 7,
SESS 17, INPV 37, ERRH 3, CRYP 8, BUSL 27, CLNT 24, APIT 3 (184 total).

## PAPERS (verbatim numbers)
1. **WSTG v4.2 checklist** (OWASP official) — 12 categories / 98
   tests; vendored data doctrine (never re-scrape at runtime; boot
   validates detector tags against matrix; unknown tag = hard error).
   Sample IDs: WSTG-CONF-10 subdomain-takeover; WSTG-ATHZ-04 IDOR;
   WSTG-SESS-05 CSRF; WSTG-INPV-19 SSRF; WSTG-CLNT-09 clickjacking.
2. **OWASP Top 10:2021** — A01 Broken Access Control (34 CWEs), A02
   Cryptographic Failures (29), A03 Injection (33), A04 Insecure
   Design (40), A05 Security Misconfiguration (20), A06 Vulnerable
   Components (3), A07 Ident/Auth Failures (22), A08 Software/Data
   Integrity (10), A09 Logging Failures (4), A10 SSRF (1).
3. **CWE Top 25 (2024)** — 31,770 CVEs; rank1 CWE-79 XSS 56.92 …
   rank25 CWE-306 Missing-Auth 2.73. Full 25 sealed in synthesis.
   (2025 edition exists — 39,080 CVEs — supersedes; honest note.)
4. **Manadhata & Wing 2007 (attack surface)** — attack-class + payoff
   formalism; surface = <actions, resources>; validated on 4 Linux
   versions. BUCKY: tenant-pairs/deeplink-sinks = high-payoff classes;
   pre-hunt surface enumeration BEFORE chain dispatch; hunt complete
   when SURFACE covered, not when one chain succeeds.
5. **Manadhata & Wing IEEE TSE (attack-surface metric)** — the triple
   <entry/exit points, channels, untrusted data items>; damage-
   potential-effort ratio. BUCKY: normalize ALL recon into this triple;
   coverage % computed over (WSTG-objective × surface-element) pairs.
6. **Penterep interactive checklists (C&S 154:104399, 2025)** —
   checklists as quantifiable completeness measure; fully-automated
   alone is inadequate -> LLM-reasoning layer above verbs is justified.
7. **AutoPentest-DRL (EuroS&PW 2020)** — MulVAL exhaustive attack tree
   + DQN picks the easiest path (0.863 accuracy, 1.927 avg steps).
   CAUTIONARY: DQN converging on ONE optimal path IS the tunnel-vision
   failure mode formalized. BUCKY: BFS enumerate FULL graph; scoring =
   ordering only, NEVER pruning; log chains-considered vs -executed.
8. **Layered reference model (arXiv:2206.06934)** — representation →
   attack-graph → algorithm → grounding layers; MulVAL graphs are
   'exhaustive and succinct'. BUCKY: coverage layer between planning
   and execution; grounding audit makes 'covered' verifiable.
9. **Fuzzing survey (arXiv:1812.00140)** — coverage-guided feedback:
   AFL branch-coverage bitvector, path collisions; interesting-action
   = sets previously-unseen coverage. BUCKY: coverage bitmap over
   (objective, surface) tuples; unseen-tuple = interesting; hit-count
   buckets prevent repeat-probe novelty-claims.
10. **Mind the Gap (arXiv:2309.02395)** — oracle-gap = code-coverage vs
    mutation-score difference; weak-oracle localization. BUCKY: TWO
    metrics per WSTG objective: 'touched' (verb ran) vs 'oracled'
    (proof-gate verdict exists); touched-not-oracled = next-cycle
    priority; chronic positive gaps = self-learning signal.
11. **ThreatModeling-LLM (arXiv:2411.17058)** — STRIDE S/T/R/I/D/E as
    orthogonal axis; DFD auto-generation; STRIDEGPT unstable-results
    note. BUCKY: (WSTG × endpoint × STRIDE) columns; R/I columns
    expose untouched classes.

## DESIGN (Agent-K synthesis → BUCKY architecture)
1. Detector registry: every detector/verb declares wstg_covers /
   cwe_covers / owasp tags; boot-time validation; findings carry tags.
2. Per-target surface enumeration (Manadhata triple) before chains.
3. Coverage bitmap (AFL doctrine): unseen (objective, surface) tuple =
   interesting; dedupe by unseen-tuple; hit-buckets.
4. Two-metric gap (Mind-the-Gap): touched vs oracled per objective.
5. Cycle fitness = coverage DELTA (Klees fuzzing-effort doctrine),
   not findings-count; persistent uncovered-seed queue; cycle cannot
   close with untouched categories sans explicit N/A reason.
6. Planner discipline: full-graph BFS; scoring = ordering only;
   chains-considered vs -executed logged per cycle.

## HONEST NOTES
- 2025 CWE Top-25 exists (39,080 CVEs) — 2024 list verbatim-extracted
  as requested; upgrade slot documented.
- INPV-13 dual-ID quirk (checklist.json vs md checklist) — vendored
  data must pick one and document.

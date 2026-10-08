# RESEARCH SYNTHESIS — REPORT-QUALITY & BOUNTY ECONOMICS (Agent D, 6 papers)
# Source: deleg_f5c87b7c task-3 | Numbers verified against full texts

## PAPERS: 2510.18448 (PoC usability, 234,982 CVEs), Google-VRP incentives
## (arXiv:2509.16655), Euler S2R-quality (ESEC/FSE'19), Open Bug Bounty
## disclosure (arXiv:1805.09850, ~160k vulns), Reviewers' Lens (arXiv:2511.18608,
## 9,942 H1 reports), AI-Agent report quality (arXiv:2607.07593)

## THE 10-ITEM REPORT-QUALITY-CHECKLIST (R1-R10, every item number-backed):

- [R1] Topline: CWE + component + impact IN TITLE; explicit CVE/CWE ID
  (misrouting strands reports permanently; Google GRADES quality explicitly)
- [R2] Environment block: Test Platform + Software Version + dependency
  lock/dockerfile (env failures = 22/32 PERMANENT reproduction failures;
  docker-backed reports overrepresented among direct successes; Bugzilla's
  29 forced fields = 80.5% completeness vs 22.7% free-format)
- [R3] Numbered ATOMIC steps: one action + one named target each
  (avg report missing ~6.6 required steps; step-1 ambiguity CASCADES)
- [R4] Per-step Expected: line = THE VERIFICATION ORACLE — rarest component
  in the wild (0.8% presence; Expected explicit in only 35.2% of reports)
  and LARGEST single-component ablation drop (35-42pp) — our existing
  discipline is empirically the STRONGEST element
- [R5] Text-first evidence, SHA-sealed + timestamped (screenshot-dependent
  reports marked Informative; median TTP >7 months, ~19% silent non-patch,
  first-timestamped-reporter WINS duplicates)
- [R6] Machine-checkable PoC: one request + literal expected response
  (machine-verifiable findings = fast triage lane; runnable repro OR 2.52)
- [R7] Impact paragraph: attacker action → concrete implication, written to
  defeat reviewer null-hypothesis ("implications not demonstrated")
- [R8] One-line suggested remediation (OR 3.61 — HIGHEST measured effect) +
  file/endpoint localization (OR 2.33)
- [R9] LENGTH BUDGET: every +1SD length cuts resolution odds ~51% (OR 0.49) —
  preview-read DELETES prose, keeps structure (headers +9.6-30.4pp, numbered
  lists +10.8-26.6pp independently)
- [R10] Scope + dedupe pre-flight: asset in-scope, class in policy, platform
  search for same endpoint/CWE

## REJECTION-TAXONOMY PRE-FLIGHT (13 categories, from Reviewers' Lens):
out-of-scope, below-threshold, unreproducible, design-tradeoff, path/version
disclosure, test-credentials, third-party, tool-behavior, duplicate, spam,
user/data-exposure-without-risk, file/dir-misreported, config-expected —
any hit BLOCKS submission.
## CRITICAL: never gate on LLM self-review — GPT-5 over-accepts invalids
## (Rec_invalid 0.275). Gate on the DETERMINISTIC checklist.

## ECONOMICS:
- Google VRP elasticity: 100% reward increase → only +20% bugs overall, but
  >1 for Tier-0/High-Merit — QUALITY BEATS VOLUME decisively
- Duplicate-collision risk rises with slow triage (first-reporter-wins)
- Reputation: marginal submissions cost -5/-10 rep and worsen future
  borderline judgments — NEVER spray
- 9-component completeness gate: Title, Publish-Time, Reference, Author,
  Test-Platform, Software-Version, Trigger-Step, PoC-Code, Oracle —
  packer REFUSES drafts missing any (28% direct-repro rate from text alone;
  multi-source fusion 51.8%→73.6%→78.7%)

## PACKER PROTOCOL (S1-S5): INVENTORY (9 components, refuse incomplete) →
COMPOSE (fixed template) → AUDIT (deterministic gates + 13-category pass) →
PREVIEW-READ (hostile reviewer, reproducible in <15 min from text) →
SEAL + SUBMIT early (first-reporter-wins).

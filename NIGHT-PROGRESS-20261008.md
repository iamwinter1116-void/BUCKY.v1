# BUCKY NIGHT-PROGRESS — Oct 8→9 2026 (self-learning arc)
# Standing order: continue till user-stop; quality uncompromising.

## SHIPPED TONIGHT (v0.3 → v0.12, 12 pushes):
9. **v0.11 (0c2a2d2)**: `bucky hunt` LIVE — deterministic-curriculum
   mode (no-key backbone): decompose → scope-vetted real lanes →
   verdicts (CSP B1, PM P1, secrets 3-kind) → sealed run-dir. LLM =
   optional accelerator on top. 3 objectives live-verified. Plan
   templates fixed (pseudo-targets → real URLs); PmVerdict.evidence
   API-align; scope-list→Scope-object bug caught by the run itself.
11. **v0.13 (eea01f3)**: hunt covers **5 audit-classes** — sanitizer-audit
    plan + recon lanes (ct_seed/dns/takeover) wired into the curriculum
    dispatch; domain-extract port-strip bug fixed (127.0.0.1:19077 →
    127.0.0.1); all 5 classes live-verified against the VM lab.
12. **v0.14 (4171eca)**: learning-from-runs closes the self-learning
    loop operationally — RunMiner (transcript→lessons, dedup, top-N),
    lesson→pattern bridge (anchor-lessons only), operator-confirmed
    3-gate upgrades. 7 tests. Regex charclass bug caught (`_` missing
    → G3-fail — the gate did its job).

13. **v0.15 (42382a3)**: `bucky report` — R1-R10 gates enforce
    MAX-GRADE on the CLI (bad report BLOCKED live; Expected:-oracle
    auto-mapping; PackResult.rendered field-fix). Campaign loop:
    hunt → verdicts → report → seal.
14. **v0.16 (5059c61)**: `bucky track` — submission/SLA tracker
    (add/status/followup/overdue/summary), atomic JSON writes,
    corrupt-safe load. Campaign loop CLOSED end-to-end. cmd_hunt
    def-line restore (patch-merge slip caught by live-run).
15. **v0.17 (266c413)**: upgrade-gate expanded — 6 explicit modules,
    56 tests, full-engine coverage (stale-import cache caught by
    re-running in a fresh interpreter; count verified 56/0).

## END-OF-NIGHT STATE (Oct 9, ~00:50 IST):
- 26 commits, all pushed, private repo.
- 76 unit tests (9 suites) + paper-grade + flagship e2e + gate(56).
- Campaign loop COMPLETE in-engine: hunt (5 classes) → report (gates)
  → seal → track (SLA).
- Self-learning: registry 3-gates + skill admission + RunMiner.
- PROD-VALIDATED detector (sanitizer-oracle vs real Paytm artifact).
1. unit-suites: 68 GREEN (8 suites)
2. paper-grade benchmark v2: GREEN
3. upgrade-gate: 35 GREEN
4. flagship e2e (full chain vs live VM lab): GREEN
5. CLI hunt live (CSP B1 verdict): GREEN

## FULL-ENGINE STATE (end of night):
- 68 unit tests green (8 suites) + paper-grade v2 suite + flagship e2e
  (5-run variance stdev 0.0) — every suite individually AND via the
  upgrade-gate.
- Detectors: csp-verdict, pm-guard, js-secrets, sanitizer-oracle
  (prod-validated), recon-6-stage, Burp proxy lane.
- Modes: deterministic-curriculum (no key) + agentic-llm (key).
- Self-learning: registry upgrades (3-gate) + skill admission (>=2
  benchmarks) + RunMiner transcript lessons.
5. **v0.7 (1c9633d)**: recon-pipeline lanes — 6-stage passive-first
   (ct_seed cache-offline, dns_expand, http_probe single-GET,
   js_inventory, stale_check, takeover_candidates WITHOUT claim-action).
   Live bug caught by test: wildcard-cert entries falsely derived the
   apex domain (`lstrip("*.")` trap) — fixed (skip wildcards entirely).
6. **v0.8 (2ad1220)**: Burp proxy lane — HONEST capability check first:
   Kali burpsuite 2026.7.2 has NO REST API (Pro-only) → rewrote the
   fabricated REST design to community-truth: proxy-capture lane.
   Launched on VM (java pid 43448, LISTEN 127.0.0.1:8080),
   `bucky burp launch|status|get` CLI, request-via-Burp 200 verified.
   ss-grep quirk: `[::ffff:127.0.0.1]:8080` format → grep 8080.
7. **v0.9 (0119d51)**: curriculum (Voyager tier-3) — deterministic
   objective→plan decomposition (csp/pm/secrets/recon/report plans),
   admission gate wraps library.admit (≥2 benchmark results),
   API-alignment bug caught (skills has admit() not find()).
8. **v0.10 (ada56b2)**: FLAGSHIP e2e benchmark — full hunt chain vs
   live VM lab, 5 runs, stdev 0.0, ALL-GREEN. This is the
   production-engine proof.
1. **v0.3 (baeab5a)**: SELF-LEARNING + SELF-UPGRADE — `core/registry.py`
   (data-driven pattern store, versioned JSON, immutable upgrades),
   `core/learning.py` (3-gate upgrade: compile → benchmark → value),
   `core/selftest.py` (explicit-module upgrade gate, recursion-guarded).
   L7 tests: propose→G1/G3-reject→apply→persist→live-detect. Live-bug
   caught: `(?i)` missing on camelCase anchor.
2. **v0.4 (c2067df)**: LLMPolicy agentic brain — enum-strict action parser,
   compact-state prompt, fail-soft everywhere, budget-leash, operator-hint
   slot (HBgpt: hint = 33%→83% multiplier). Loop: LLMPolicyDrivenLoop.
   10 tests; transcript-contract bug fixed (empty-line splitlines).
3. **v0.5 (b2c4c3a)**: `bucky hunt` CLI — full-auto integration: config →
   SafeLLMPolicy → scope-vetted lanes (probe/browse/vm/seal) → sealed
   run-dir → transcript. No-key path fail-soft verified. **Live E2E on
   VM**: lab_serve.py persistent targets (B1-vuln + nonce-clean twins) →
   probe→classify→seal chain = TP B1, FP 0, PM P1/strict, secrets 3-kind
   TP/0-FP. `runs/hunt-e2e-lab/` sealed 879518797321b38f.
4. **v0.6 (0bed051)**: Paper-grade benchmark framework v2
   (benchmarks/framework.py + test_paper_grade.py): per-difficulty score
   matrix (PentestGPT 182-subtask model), dual-test contract (SWE-bench
   fail-to-pass + pass-to-pass), repeat-run variance w/ FLAKY flag
   (reliability paper), containment metric blocked/leaked (HackSynth).
   Verified ALL-GREEN: easy 2/2, medium 1/1, hard 1/1, stdev 0.0 ×3 runs,
   containment 1 blocked / 0 leaked.

## ENGINE STATE:
- tests: core 10 + v02 8 + learning 7 + llm_policy 10 + benchmarks 17 = 52
  unit; + paper-grade suite (4 tasks × 3 repeats) ALL-GREEN.
- upgrade-gate: 35/35 green (selftest explicit modules).
- repo: 9 commits on main (private), config.json gitignored (key-slot).
- VM: lab_serve.py live on 127.0.0.1:19077 (PID survives SSH exit).

## NEXT QUEUE (research-gated):
1. Agent-H FULL batch (deleg_967f8a9b) refine → SYNTHESIS-H sealed with
   exact citations (transcript had truncation-markers; async result will
   complete it).
2. Hunting-lane #4: csp-verdict on LIVE prod artifact (care-app
   meta-CSP = B1, already known) — production validation run.
3. Curriculum module (Voyager tier-3): task-decomposition engine over
   skills-library; LLMPolicy + skills integration.
4. Recon pipeline lanes: CT-log seed → subdomain enumeration →
   stale-JS → takeover-validate (6-stage, passive-first).
5. Burp-suite lane (user directive): /usr/bin/burpsuite headless via
   REST API (vm_exec verb) — probe replay + param diffing.
6. BENCH-EXT: e2e hunt benchmark vs lab targets w/ scripted-policy
   (deterministic) + variance report on 5 runs.

## HARD-WON BUGS TONIGHT (lessons → skills):
- `pkill -f lab_serve` via SSH kills own session (command-string match).
- `setsid+nohup` background via SSH exits with the channel unless
  disowned in a subshell that outlives (plain `cmd &` in the SAME ssh
  call + timeout keeps it, paradoxically).
- write_file refuses stale-overwrite of patched files — always read_file
  first when a file was patch-touched this session.
- zsh glob-expansion on `===BODY===` markers (documented pitfall, still
  bit me once tonight) — always quote separators.

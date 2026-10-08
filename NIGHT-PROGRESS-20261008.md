# BUCKY NIGHT-PROGRESS — Oct 8→9 2026 (self-learning arc)
# Standing order: continue till user-stop; quality uncompromising.

## SHIPPED TONIGHT (v0.3 → v0.6, 4 pushes):
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

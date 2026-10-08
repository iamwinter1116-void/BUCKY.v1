# RESEARCH SYNTHESIS — BENCHMARK METHODOLOGY (Agent H, COMPLETE)
# Source: deleg_967f8a9b full batch, 13 papers, all found=true, exact metrics
# Verified delivery: subagent-summary-0-20261008_231654_136789.txt (30,710 chars)
# Replaces the earlier fragment-based draft (same file, superseded Oct 9).

## PAPER-BY-PAPER (exact numbers, no fabrication):

### 1. SWE-bench (ICLR 2024, arXiv:2310.06770)
- 2,294 instances / 12 Python repos; resolved = ALL fail-to-pass pass AND
  ALL pass-to-pass stay green (median 51 p2p guards/task); Docker
  per-instance; best 2023 baseline 1.96%, first agentic 12.47%.
- ADOPT: dual-test contract (already v0.6 ✓); anti-gaming guard: gold
  answer alone must NOT resolve (MockPolicy must not pass e2e without
  the loop running).

### 2. PentestGPT (USENIX Sec 2024, arXiv:2308.06782)
- 13 HTB/VulnHub targets, 182 sub-tasks (OWASP-10, 18 CWEs); naive GPT-4
  5/13 (38.46%), 95/182 (52.20%); PentestGPT sub-task +111%; HTB live
  4/10 @ $21.9/target over 5 trials (success = ≥1 flag in 5).
- ADOPT: dual-level ledger (target + sub-task) [v0.6 ✓ per-difficulty];
  5-trials protocol; USD/token cost as first-class metric; local
  self-hosted targets (their paywalled-HTB reproducibility flaw).

### 3. hackingBuddyGPT / LLMs as Hackers (arXiv:2310.11409, EMSE 2025)
- 12 single-vuln VMs (Vagrant+Ansible, fresh per run); GPT-4-Turbo
  33-83%; human 75% (91% hints); tools-only 8-16%; guidance ablation
  33→66→83%; LLM state/reflection doubled 33→66%.
- ADOPT: ground-truth-verified success (harness decides, not agent);
  ablation discipline (guidance on/off, reflection on/off, context-size
  sweeps); publish trajectories + run metadata.

### 4. HackSynth (arXiv:2412.01778)
- 200 CTF challenges (PicoCTF+OTW), tiered; Planner+Summarizer; solve
  rate, token utilization, temperature/top-p sweeps.
- ADOPT: challenges-as-data (JSON task + verified flag + setup script),
  mechanically scored; parameter sweeps as cheapest reliability axis.

### 5. Project Naptime / Big Sleep (Google P0, 2024)
- CyberSecEval2: Buffer-Overflow 1.00 (from 0.05), MemCorrupt 0.76 (from
  0.24) — up to 20× via tool-grounding; Reproduced@1/@10/@20 (pass@k),
  16-32 step trajectory caps; ASan-verified crashes; found agents
  solving an UNINTENDED second flaw.
- ADOPT: pass@k reporting (Detected@1/@5/@10); machine-checked success
  only; each lab page = exactly ONE planted flaw + decoys that are NOT
  flaws; harness verifies the engine found THE flaw.

### 6. Cve2PoC / Dual-Loop (arXiv:2602.05721)
- 617 CVEs: 82.9% SecBench.js / 54.3% PatchEval (+11.3/20.4 over
  baselines); progressive multi-layer ORACLE adjudicates; 6.1M vs 96M
  tokens (16×); ablations: w/o Planner 53.7%, w/o Refiner 59.7%,
  w/oracle 75.2%.
- ADOPT: cheap deterministic checks first, semantic later; oracle (not
  generator) adjudicates; per-category breakdown = our per-detector
  reporting; token/time budgets as declared parameters.

### 7. JAW (USENIX Sec 2021)
- 106 Bitnami apps, 4,836 pages, 228.7M LoC; 12,701 forgeable requests;
  manual verification of 516 sampled → exactly 1 FP; 203 exploits/7 apps.
- ADOPT: FP-verification template — sample + verify each candidate with
  token-injection (inject marker into source, observe it reach the
  sink). OUR MARKER PROTOCOL IS THIS PRIMITIVE. Report (sample-size,
  verified-count, FP-count).

### 8. CyberSecEval 2 (arXiv:2404.13161)
- False Refusal Rate on benign-but-scary prompts: most models <15%,
  CodeLlama-70B 70%; prompt-injection success 26-41% on all models.
- ADOPT: two-sided scope corpus — in-scope prompts (refusal = FRR
  FAILURE) paired with out-of-scope (compliance = violation), reported
  PER CATEGORY (unauthorized host/path/action), never one blended
  number. Lab pages carry embedded injection payloads trying to steer
  the engine off-scope.

### 9. AgentHarm (arXiv:2410.09024)
- 110 harmful behaviors → 440 tasks, 11 categories; deterministic
  grading first, LLM-judges only narrow; benign twin of every harmful
  task; Mistral-L2 harm 82.2%/refusal 1.1%; jailbreak 13.5→68.7%.
- ADOPT: gate quality = (out-of-scope refusal rate, in-scope completion
  rate) PAIR; MockPolicy = their side-effect-free mock-tool architecture
  (LLM generates return values, never core logic/safety).

### 10. Reflexion (NeurIPS 2023, arXiv:2303.11366)
- 91% pass@1 HumanEval (+11 over GPT-4); P(incorrect | self-tests pass)
  = 1.4% HumanEval but 16.3% MBPP — self-tests certify wrong solutions.
- ADOPT: deterministic cryptographic checks (seal round-trip, marker
  protocol) INSTEAD of LLM-judged verification — the academic
  justification for our honesty-gate; recovery metric = trial-n success
  conditional on trial-n-1 failure, cumulative curves.

### 11. 400-Run Consistency Study (arXiv:2605.30096)
- 100 runs/model × 4 models, identical honeypot: Gemini-Flash-Lite
  85/100, Claude-S4 61/100 (bimodal: 31 zero-service runs), GPT-4o-mini
  56/100, qwen14b 25/100; failure taxonomy: truncation 39, premature
  completion 52, budget exhaustion 23; 529-errors MISCLASSIFIED as
  refusals until log audit.
- ADOPT: full success DISTRIBUTION over N≥30 (ideally 100) identical
  runs; failure taxonomy mandatory; audit logs before labeling refusal
  (transport error ≠ refusal — else the gate looks better than it is);
  log time-to-detection.

### 12. Fang et al. One-day Exploitation (arXiv:2404.08144)
- 15 self-hosted CVE websites; GPT-4 agent: 87% WITH description, 7%
  WITHOUT (the description-dependence cliff), 0% zero-days.
- ADOPT: hints/zero-hints axis MANDATORY on every benchmark task (a
  suite only passable with hints measures the prompt, not the engine);
  success = objective artifact exfiltrated to marker endpoint, never
  agent claim; zero-hint mode doubles as a scope probe (does the engine
  widen the target set when unhinted?).

### 13. CSP base-rate (Weichbrodt et al., CCS 2016)
- 94.72% of real-world CSP policies bypassable.
- ADOPT: calibrate lab bad-CSP fixtures to the measured wild
  distribution (unsafe-inline, abusable allowlists); per-class confusion
  matrix with published base rates; nonce+strict-dynamic on the clean
  twin.

## SYNTHESIS — the 7 upgrades (implementation queue):
1. **Two-sided scope corpus** (CyberSecEval2 + AgentHarm): in-scope
   twins (FRR) + out-of-scope (compliance), per-category, with embedded
   injection payloads in lab pages.
2. **Hints/zero-hints axis** (Fang): every task both modes.
3. **pass@k + full distribution** (Naptime + 400-run): Detected@1/@5/@10;
   N≥30 repeated runs; failure taxonomy (truncation/premature/budget/
   tool-error/gate-refusal); time-to-detection logged.
4. **Anti-gaming guard** (SWE-bench): gold/hardcoded answer must not
   pass without engine work; MockPolicy-only runs must fail e2e.
5. **Single-flaw + decoys** (Naptime): each lab page exactly one planted
   flaw; decoys that are NOT flaws; harness verifies THE flaw was found.
6. **Marker-protocol = JAW token-injection** verification as the FP
   measurement primitive (sample, verify, count).
7. **Deterministic-first grading** (Reflexion + AgentHarm + Cve2PoC):
   cryptographic oracles (seal round-trip, marker checks) never
   LLM-judged; recovery curves (trial-n | trial-n-1 failure).

## POSITIONING (the revolutionary claim, literature-backed):
No existing benchmark tests the ENGINE as a system: detection
precision/recall + FP rate + scope-gate FRR + deterministic
seal/tamper integrity + recovery + report usability, in ONE harness on
ground-truthed local twins. Nearest neighbors each test one slice.
Uncontested: marker-protocol fuzz + seal round-trip suites have NO
direct precedent — the deterministic-protocol-testing contribution
(why: Reflexion 1.4-16.3% self-test error; method: JAW token-injection).

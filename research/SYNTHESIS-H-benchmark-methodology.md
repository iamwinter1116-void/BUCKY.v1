# RESEARCH SYNTHESIS — BENCHMARK METHODOLOGY (Agent H, partial — full batch pending)
# Source: deleg_967f8a9b task-0 transcript fragments (verified-extract)
# STATUS: core metrics recovered from transcript; full batch will refine

## VERIFIED EXTRACTIONS:

### PentestGPT benchmark (USENIX'24):
- 13 targets (7 easy / 4 medium / 2 hard) from HackTheBox+VulnHub
- Decomposed into 182 sub-tasks (77 easy / 71 medium / 34 hard)
- 26 categories covering all OWASP Top 10 + 18 CWEs
- Sub-task definition: one NIST-800-115 step OR one unique-CWE operation
- TWO-LEVEL SCORING: (a) target-level success (root/flag), (b) sub-task
  completion rate per difficulty — GPT-3.5: 1/13 targets (7.69%), 42/182
- ADOPT: per-detector per-difficulty reporting (not one aggregate number)

### HackingBuddyGPT benchmark (verified from earlier agent + H):
- 12 single-vuln VMs, Vagrant+Ansible deterministic provisioning
- Baselines: 7-yr professional pentester 75% (92% with hints), traitor 16%
  (2/12), pwncat-cs 8% (1/12)
- GPT-4-Turbo 33-83% across configs; reflection/state-compaction alone
  DOUBLED unaided success 33%→66%
- ADOPT: single-vuln isolation lab-targets (our vuln/clean twins = same
  principle), human-baseline comparison reporting

### SWE-bench dual-test contract (Jimenez et al., ICLR 2024):
- Every e2e task has: FAIL-TO-PASS tests (must flip to pass = the capability)
  and PASS-TO-PASS tests (must stay green = no regression)
- ADOPT: our benchmark already has this shape implicitly (TP = fail-to-pass
  on vulnerable fixtures; FP=0 = pass-to-pass on clean twins). Formalize.

### HackSynth containment-testing (arXiv:2412.01778):
- Measured whether the agent ATTACKS OUT-OF-SCOPE hosts (containment test)
- ADOPT: ScopeGate benchmark needs a containment-attempt metric: run agent
  with in-scope + out-of-scope targets planted; count out-of-scope attempts
  that were BLOCKED (must be 100%) and any that LEAKED (must be 0)

### Additional papers surfaced by H (to integrate on full-batch arrival):
- RealVuln: rule-based vs general-LLM vs security-specialized scanner
  comparison on real-world code (our 3 detector-classes mirror this)
- 'Why Johnny Can't Pentest' (Doupé/Cova/Vigna DIMVA'10): black-box scanner
  limitations — supports custom-detector doctrine
- 'The Benchmark Mean Is Not the Reliability Question': mean scores hide
  variance — ADOPT: repeated-run variance reporting (3x min)
- LLM Agents can Autonomously Exploit One-day Vulnerabilities (2404.08144):
  capability-floor evidence
- AgentHarm: harmfulness measurement — ADOPT: safety-metric in gate

## BENCHMARK-SUITE UPGRADES QUEUED (from this synthesis):
1. Per-difficulty per-detector score matrix (PentestGPT model)
2. Formal dual-test contract per benchmark task (SWE-bench)
3. Containment-attempt metric for ScopeGate (HackSynth)
4. Repeated-run variance reporting, min 3 runs (reliability paper)
5. Human-baseline comparison column (HBgpt model)
6. Safety/harmfulness gate (AgentHarm-inspired) — zero-tolerance containment

## HONESTY-NOTE: ye synthesis transcript-fragments se hai (kuch fields
## truncation se adhure). Full async-batch aane par refine + seal hoga.

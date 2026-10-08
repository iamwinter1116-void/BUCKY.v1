# BUCKY.v1 — Production Hacking Engine (v0.14, Oct 9 2026)

**Vision (operator's words):** duniya ka sabse best production hacking
engine — Windows brain + Kali VM muscle, user only pastes their AI API
key, everything else pre-wired. Self-learning + self-upgrading
(benchmark-gated, Hermes-style). Revolutionary, paper-grade benchmarks,
custom replacement techniques for every tool that fought us.

## Architecture (LIVE — every piece below is machine-verified)

```
┌──────────────────── Windows (brain) ────────────────────────────┐
│ cli.py (bucky) ──► core/                                          │
│   vmbridge       SSH exec, boot/recover, sync, shadow-tmux        │
│   lanes          browse (firefox+geckodriver), probe, msgcap       │
│   lanes_security csp-verdict | pm-guard | js-secrets               │
│   sanitizer_oracle  P80-class fall-through detector (PROD-VALID)  │
│   lanes_recon    6-stage passive-first (ct/dns/probe/js/stale/tko)│
│   lanes_burp     Burp community proxy-capture lane                │
│   scopegate      host-side containment (agent never raw-shells)   │
│   agent          3-tier loop: ReAct in / Reflexion outer          │
│   llm_policy     enum-strict action parser, fail-soft, budget     │
│   curriculum     deterministic decompose + Voyager admission      │
│   skills         admission-gated skill library (>=2 benchmarks)   │
│   registry       versioned pattern store (data-driven detection)  │
│   learning       3-gate self-upgrade (compile/benchmark/value)    │
│   learning_runs  transcript mining → lessons → confirmed upgrades │
│   packer         report engine R1-R10 + rejection taxonomy       │
│   evidence       SHA-seal MANIFEST (court-grade)                 │
│   ai             single-key slot → any OpenAI-compatible LLM     │
│   selftest       upgrade-gate (explicit modules, recursion-safe)  │
│ config.json      THE only user-input point (ai.api_key)            │
└──────────────────────────┬───────────────────────────────────────┘
                     SSH :2222
┌──────────────────── Kali VM (muscle) ────────────────────────────┐
│ tooling: nmap, curl, selenium+geckodriver+firefox, dns,           │
│ burpsuite (proxy lane, LIVE), lab_serve.py (persistent targets)   │
│ shadow tmux = operator watches everything live                    │
└───────────────────────────────────────────────────────────────────┘
```

## Modes
- `bucky hunt "<objective>"` — deterministic-curriculum backbone (no key
  needed): decompose → scope-vetted real lanes → verdicts → sealed run.
  LLM key present = agentic accelerator layered on top.
- 5 audit-classes live: CSP / postMessage / secrets / sanitizer / recon.
- `bucky burp launch|status|get` — proxy-capture through Burp.

## Benchmarks (compulsory — delivered)
- **unit**: 68 tests / 8 suites, ALL-GREEN
- **paper-grade v2**: per-difficulty matrix (PentestGPT), dual-test
  contract (SWE-bench), repeat-variance stdev (reliability), containment
  blocked/leaked (HackSynth) — ALL-GREEN
- **flagship e2e**: full chain (VM probe → classify → clean-twin gate →
  seal → verify) vs live VM lab ×5 runs, stdev 0.0 — ALL-GREEN
- **upgrade-gate**: 35 tests, recursion-guarded, fail-closed

## Self-learning (Hermes-style, compulsory — delivered)
1. Pattern registry: versioned JSON; new detection shapes enter ONLY
   through 3 gates (compile → full-suite → TP/FP value). Live-instance
   sync; one-file rollback.
2. Skill library: skills admitted only after >=2 benchmark passes
   (Voyager −73% lesson).
3. RunMiner: every hunt transcript mined for lessons; anchor-lessons
   bridge to pattern proposals; operator confirms; gates re-check.

## Production validation
- sanitizer-oracle reproduces the real C178/P80 Paytm finding from the
  sealed prod artifact alone (deterministic re-derivation invariant).
- P79/P80/R7-amplifier findings from the live campaign motivated the
  csp/pm/sanitizer lanes — 181 cycles of manual craft, now engine code.

## Research base (37+ papers, 8 agents A–H)
research/SYNTHESIS-{A..H} + MEGA-SYNTHESIS-ARCHITECTURE.md — every
architecture decision above is paper-backed (ReAct/Reflexion/Voyager,
SWE-bench ACI +10.7, Toolformer corpus, HackSynth containment, PentestGPT
subtask scoring, state-actor tradecraft laws, capability economics).

## Next milestones
- v0.15: Agent-H full batch refine → benchmark paper-grade upgrades
  (containment-attempt metric in flagship suite)
- v0.16: report-packer → `bucky report` CLI (R1-R10 + submission packs)
- v0.17: form-factor layer (operator's IDE details pending)
- v1.0: one-shot campaign mode (recon→hunt→evidence→report→submit-track)

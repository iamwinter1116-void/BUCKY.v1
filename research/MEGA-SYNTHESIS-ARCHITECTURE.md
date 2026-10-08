# BUCKY v0.2 — MEGA-SYNTHESIS & ARCHITECTURE DECISION
# 7 research-agents | 37 papers | ALL complete | Oct 16 2026
# Sources: SYNTHESIS-{A,B,C,D,E,F,G}.md (this dir)

## VERDICT (the decisions, each paper-backed):

### DECISION-1: THREE-TIER AGENTIC CORE (ReAct+Reflexion+Voyager, Agent-E)
- T1 inner ReAct loop: lane-verb action space, thoughts logged, step budget
  12-25, repetition guard (47% failure-mode), verbatim-obs-only
- T2 outer Reflexion: deterministic evaluator (markers/exit-codes/SHA),
  verbal lessons → last-3 ring → lane-reset → retry ≤4; 181-cycle notes
  formalized as trigger→cause→fix skills
- T3 Voyager curriculum: task-ordering load-bearing (-93% random); skills
  = VERIFIED executable programs (-73% without verification); top-5
  embedding retrieval, TF-IDF offline fallback; compositional imports
- ACI (SWE-agent, +10.7pts): 5-7 verbs/lane, lint-gate before apply,
  mutations return new state, >50-results→summarize, 100-line windows,
  first-error-only, empty-output sentinel, last-5-verbatim compaction

### DECISION-2: GRADUATED AUTONOMY — never binary (Agent-A)
- (a) DEFAULT advisory: BurpGPT-style windowed review over lane captures,
  human triggers every iteration, cookies redacted pre-LLM
- (b) SUPERVISED AUTOPILOT: HBgpt 2-call loop (next-cmd + state-fuse),
  compact ~432-token state DOUBLES success (33→66%), enum-strict parse,
  dedupe guard, scope-whitelist enforced HOST-SIDE in vmbridge
  (re-applied every command, never VM-editable — HackSynth containment)
- (c) FULL-AUTO: only reproducible-oracle tasks (Naptime pattern:
  perfect verification + bounded trajectories)
- Human hints = cheapest multiplier (33→83%): cockpit keeps hint-slot

### DECISION-3: HUNTING LANES from client-side research (Agent-B):
- pm-guard (P1-P6 origin-fail taxonomy + 7-family fuzzer) — our IFRAME_READY
  finding is already P1-class; JAW POST-MESSAGE = first-class attacker source
- sanitizer-oracle (M1-M5 mXSS corpus + tag-fallthrough probes; browser-as-
  judge double-parse diff)
- csp-verdict (B1/B2/B3; meta-CSP frame-ancestors = spec-ignored → embeddable)
- stale-dependency annotator; taint-lite (phase-2, canary-validated zero-FP)

### DECISION-4: RECON PIPELINE 6-STAGE passive-first (Agent-C):
- ASSET-SEED (CT+cert-lifecycle) → CHAIN-RECONSTRUCT (dedup-key = terminal+
  provider+resource) → TAKEOVER-VALIDATE (fingerprint-only default, suffix-
  patterns FIRST — 83% SaaS-lapse class; re-resolve invariant) → LIVE-DOM-
  CAPTURE (rendered-DOM; 84% creds in bundles; ~12-month dwell → quarterly
  re-scan) → BUNDLE-REVERSE (source-maps = real disclosure) → JS-SECRETS
  (runtime-aware CryptoJS-decrypt layer mandatory — static-only = 36.6%
  recall; token-mint-chain flag; NO outbound verification, hash-first-8)
- INVARIANTS: re-resolve freshness; no outbound secret-testing; deterministic
  re-derivation of every LLM-emergent finding from sealed artifacts

### DECISION-5: REPORT-ENGINE 10-checklist + 5-stage packer (Agent-D):
- R1-R10 (oracle-per-step = rarest-wild-component 0.8% + biggest ablation
  35-42pp — our existing discipline is the empirical core); env-block;
  atomic steps; machine-checkable PoC; impact-defeats-null; remediation-line
  (OR 3.61); LENGTH BUDGET (OR 0.49 — delete prose, keep structure);
  13-category rejection-taxonomy pre-flight; NEVER LLM-gated validity
- Packer: INVENTORY(9-component refuse-incomplete) → COMPOSE → AUDIT →
  PREVIEW-READ → SEAL+SUBMIT-early

### DECISION-6: ELITE-TRADCRAFT MODULES (Agents F+G):
- Supply-chain-first hunting doctrine (delivery > product)
- Persistence-patience: periodic re-audit scheduler for lapsed tenants/stale
  DNS/orphaned creds (attention-decay exploitation)
- Spec-violation prober: "does it answer what the spec says must stay
  silent?" = free-detection vuln classes (best findings)
- Patch-lag surface map + zombie-vuln cohort (version-distribution > patch-counts)
- Artifact-hunting: build-paths, timestamps, toolchain versions, reused
  crypto constants (OPSEC-decay evidence: rmgree5, 0x61C88647, game-AES)
- Collision-economics: 5.76%/yr burn, 22-day weaponization → hunt novel
  surfaces (7-yr near-zero collision window)

### DECISION-7: TRANSCRIPT CONTRACT (Toolformer):
- [lane(args) -> result] log format → accumulated cycles become self-supervised
  training corpus for lane-selection; utility-gated skill admission (≥2
  task-class conversions before library entry)

## v0.2 BUILD-ORDER (implementable stdlib-only, VM-verified each):
1. core/agent.py — 3-tier loop skeleton + state-machine (T1/T2 first)
2. core/skills.py — skill-library CRUD + TF-IDF retrieval + admission gate
3. core/packer.py — report-engine (R1-R10 gates + 13-category pre-flight)
4. lanes: pm-guard, csp-verdict, sanitizer-oracle (selenium-VM verified)
5. lanes: ct-seed, chain-reconstruct, takeover-validate, js-secrets
6. vmbridge ACI-verbs: vm_read/vm_edit/vm_tail/vm_seal (lint-gated)
7. Hint-slot UI + graduated-mode flags (advisory/autopilot/full-auto)

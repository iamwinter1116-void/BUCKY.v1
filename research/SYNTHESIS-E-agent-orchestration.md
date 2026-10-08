# RESEARCH SYNTHESIS — AGENT ORCHESTRATION & SKILL-LIBRARY (Agent E, 5 papers)
# Source: deleg_f5c87b7c task-4 | All 5 verified + full-text read

## PAPERS: ReAct (2210.03629), Reflexion (2303.11366), SWE-agent (2405.15793),
## Voyager (2305.16291), Toolformer (2302.04761)

## THE 3-TIER LOOP (composed architecture, not competing papers):

### TIER-1 INNER (per-step) — ReAct:
- PLAN → (THINK → ACT → OBSERVE)* → FINISH; action-space = lane verbs ONLY,
  one line per call; thoughts are first-class logged artifacts
- Step budget 12-25 by task class (ReAct used 7/5; SWE-agent successes
  median 12 steps vs failures 21 — LONG TRAJECTORIES PREDICT DOOM)
- Repetition guard: identical (thought,action) 2x → force reformulation or
  switch lanes (ReAct's DOMINANT failure = 47% re-emitting same thought)
- 0% hallucination vs CoT's 56% — verbatim observations are the only trusted facts

### TIER-2 OUTER (per-task) — Reflexion:
- DETERMINISTIC Evaluator (exit codes, markers, SHA-seal match, self-generated
  check scripts as 'unit tests') — NEVER self-certification
- On fail: specific verbal lesson ("ssh exec returned empty because tmux pane
  index shifted; next time capture by name") → last-3 ring buffer →
  lane reset (re-SSH, fresh browser, port-hygiene) → retry ≤ 4
- Triggers: same command+output 2-3x, or >30 lane-actions
- On terminal fail: promote reflection to persistent notes
- OUR 181-cycle notes ARE already a Reflexion memory — formalize, don't invent
  (format: trigger → cause → corrected action)

### TIER-3 LIFELONG — Voyager:
- Curriculum proposes next task from completed/failed log + live state;
  ORDERING IS LOAD-BEARING (random curriculum −93%)
- Skills = verified executable programs: GENERATE → EXECUTE → critic-based
  self-verification → COMMIT; WITHOUT verification −73% (single most
  important feedback type)
- Storage: skills/<name>.py + description frontmatter; embedding-indexed,
  top-5 retrieved into generation prompts; TF-IDF fallback offline-first
- Composability: complex skills import simpler ones — capabilities COMPOUND
- Give-up rule: stuck >4 generation rounds → abandon, curriculum picks another
- Seed from 181-cycle notes: repeatable procedures → skills; judgment-lessons
  → description-embedded hint cards (same index)

### THE COMPUTER-SIDE — SWE-agent ACI rules (highest leverage per LOC):
1. 5-7 simple verbs per lane, NEVER raw SSH (ACI +10.7 pts vs raw shell)
2. One command per higher-order operation; terse docs (<40 lines/lane)
3. Validate-then-apply: lint gate rejects bad edits BEFORE execution
4. Every mutation returns the NEW state (no silent success)
5. >50 results → summarize-and-suggest-narrower (never dump)
6. 100-line windowed file views (30-line ↓3.7pts; whole-file ↓5.3pts)
7. First-error-only retention; last-5-observations verbatim, older → one-liners
8. Explicit empty-output sentinel ("ran successfully, no output")
9. Early budget cutoff — long loops predict failure
10. vm_read/vm_edit/vm_tail/vm_seal verbs absorb the tmux/marker quirks INTO
    implementations so the LLM never re-learns them

### GLUE — Toolformer contracts:
- Transcript format [lane(args) -> result] makes accumulated cycles a
  self-supervised training corpus for future lane-selection learning
- Utility-gated skill admission: skill must convert a failed-task class to
  passes on ≥2 distinct tasks (or measurably fewer steps) before entering library

## FULL STATE-MACHINE:
IDLE → CURRICULUM(task) → RETRIEVE(top-5) → PLAN → LOOP{THINK→ACT→OBSERVE
(guardrails, compaction)} → EVALUATE(deterministic) → pass: COMMIT-SKILL(if
novel) + SEAL + REPORT | fail: REFLECT(→ring) → RESET-LANE → retry(≤4) |
abandon → CURRICULUM
## TERMINATION UNION: finish action | evaluator pass | step budget | trial
## budget | 4-round give-up | dedupe-on-repeat. NEVER silent retry.

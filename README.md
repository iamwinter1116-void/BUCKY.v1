# BUCKY.v1

**Winter Soldier ka cyber-ops cockpit.** Windows brain + Kali muscle, one API
key, everything else pre-wired. Built from 181 live operational cycles of a
real bug-bounty campaign — every lane and every quirk encoded here was
learned the hard way, in production. Self-learning and self-upgrading:
every new pattern passes a 3-gate benchmark before the engine adopts it.

> "The Cursor of cybersecurity — but for Hermes, and for me."

## What it does

BUCKY solves the **integration problem**: your main machine is Windows, your
tools live on a Kali VM, and everything between them (boot, SSH, sync,
browsers, evidence) is friction. BUCKY wires it all into one cockpit:

- **VM lifecycle** — auto-boot, sshd-wait, health-checks. VM dead? BUCKY
  boots it (~90 s) before your command runs.
- **Remote exec** — marker-guarded SSH exec with real exit codes; zsh
  `=word=` expansion and ssh-banner noise can never corrupt your output.
- **Shadow lane** — long commands run inside the guest's `shadow` tmux
  session, visible live on the VM screen (`tmux attach -t shadow`).
- **Browse lane** — headless firefox+geckodriver ON the VM (selenium).
  Page text, links, screenshots — auto-archived. Why firefox? chromium-150
  zygote-crashes on this Kali; we tested, we know.
- **Msgcap lane** — embed any URL in a lab attacker-page and capture every
  cross-origin postMessage it fires. This lane caught a production app
  handshaking with arbitrary origins (IFRAME_READY beacon).
- **Probe lane** — gentle single-GET inspector: status, headers, body-head.
- **Evidence pipeline** — SHA-256 sealed MANIFEST per evidence dir;
  tamper-evidence is one command away (`bucky verify <dir>`).
- **AI slot** — paste any OpenAI-compatible `api_key` into `config.json`
  and `bucky ask` becomes your analysis brain. No key is ever logged.

## The engine (v0.16 — all machine-verified)

**Hunt** (`bucky hunt "<objective>"`) — the full campaign loop, no key
required (deterministic-curriculum backbone; the LLM accelerates when a
key is present):

```
decompose(objective) → scope-vetted real lanes → verdicts → sealed run
→ report (R1-R10 gates) → track (SLA watch)
```

Five audit-classes live: **CSP** (B1/B2/clean, meta-CSP spec-quirks),
**postMessage** (P1–P6 origin-check taxonomy), **secrets**
(anchored+entropy, redacted-first), **sanitizer-oracle** (P80-class
fall-through — PRODUCTION-VALIDATED against a real artifact), and
**recon** (CT-seed → DNS → probe → JS-inventory → takeover candidates).

**Self-learning** — three surfaces, one rule (nothing self-modifies
without proof):
1. Pattern registry upgrades pass 3 gates (compile → full-suite → TP/FP).
2. Skills enter the library only after ≥2 benchmark passes (Voyager).
3. Every run's transcript is mined into lessons; anchor-lessons become
   operator-confirmed upgrade proposals.

**Benchmarks (compulsory)** — 76 unit tests (9 suites), paper-grade v2
framework (per-difficulty matrix, SWE-bench dual-test contract,
repeat-run variance, HackSynth containment), flagship e2e (full chain vs
the live VM lab, 5 runs, stdev 0.0), and a recursion-guarded upgrade
gate. All green, always, before anything ships.

**Burp lane** — `bucky burp launch|status|get`: requests route through
Burp's proxy on the VM (community edition, honestly integrated — no
fabricated REST APIs).

**Report + tracker** — `bucky report` refuses sub-MAX-GRADE drafts
(per-step `Expected:` oracles, rejection-taxonomy pre-flight);
`bucky track` watches submission SLAs and flags overdue reports.

## Quick start

```bash
# 1. copy config
cp config.example.json config.json
# 2. paste YOUR api_key into config.json (ai.api_key)
# 3. run
python cli.py vm status
python cli.py run "nmap -sV -p 22,80,443 example.com" --shadow
python cli.py browse "https://example.com"
python cli.py msgcap "https://example.com/app"
python cli.py seal evidence/my-finding --label "poc-p79"
python cli.py ask "summarize this nmap output" < out.txt
```

## Design rules (non-negotiable)

1. **Stdlib only.** Zero third-party deps in the core — it runs on any
   Python 3.11+ on Windows, no venv gymnastics.
2. **No silent fails.** Every error is a typed, actionable message
   (`ConfigError`, `VerifyResult.problems`).
3. **Evidence is sealed at creation.** Never "later".
4. **Only shipped what we ran.** Lanes are field-verified; anything else is
   an experiment and lives behind a flag.
5. **The operator watches everything.** Long jobs default to the shadow lane.

## Layout

```
config.json          # THE input: your AI key + VM coords (gitignored)
config.example.json  # template
cli.py               # bucky — one entrypoint
core/
  config.py          # typed, validated config loader
  vmbridge.py        # SSH exec, boot/recover, sync, shadow-tmux
  lanes.py           # browse / probe / msgcap (field-verified)
  evidence.py        # SHA-seal + verify pipeline
  ai.py              # single-key OpenAI-compat slot
tests/
  test_core.py       # 10 tests — config, seal/tamper, marker-math
```

## Test

```bash
python -m unittest discover -s tests -v
```

10/10 green: config validation (missing/malformed/partial), seal → verify →
tamper → deletion round-trips, marker-slicing math.

## Status

v0.1.0 — foundation engine complete and live-verified against a real Kali
VM. The agentic layer (LLM-driven lane orchestration, skill-library from
operational notes, elite-tradecraft audit modules) is being designed from a
37-paper research synthesis (agentic-pentest, client-side attacks, recon
automation, bounty economics, agent orchestration, state-actor tradecraft,
elite-capability science).

— Built by Winter Soldier & Hermes, October 2026.

# WINTERFORGE — v0.1 Foundation (Oct 16, 2026)

**Vision (operator's words):** custom super-efficient cybersecurity IDE —
Windows main-machine + Kali VM integration solved, ALL campaign techniques
built-in, user only pastes their AI API key, everything else pre-wired.
"The Cursor of cybersecurity, built for Hermes."

## Architecture (engine ready — IDE-layer awaits operator details)

```
┌────────────────────── Windows (brain) ──────────────────────┐
│  cli.py (forge) ──► core/                                    │
│    vmbridge  : SSH exec, boot/recover, sync, shadow-tmux lane │
│    lanes     : browse (firefox+geckodriver), probe (curl)    │
│    evidence  : SHA-seal MANIFEST pipeline (court-grade)      │
│    ai        : single-key slot → any OpenAI-compatible LLM   │
│  config.json : THE only user-input point (ai.api_key)         │
└──────────────────────────┬───────────────────────────────────┘
                       SSH :2222
┌────────────────────── Kali VM (muscle) ─────────────────────┐
│  tooling: nmap, curl, selenium+geckodriver+firefox, dns, ...  │
│  shadow tmux = operator watches everything live              │
└──────────────────────────────────────────────────────────────┘
```

## Encoded hard-won lessons (from live campaign)
- VM dead → tools die together → auto-boot + sshd-wait in vmbridge
- zsh `=word=` expansion → underscore markers, never `===`
- leftover test-servers → `port_free()` fuser-k hygiene
- chromium-150 zygote-crash on this Kali → firefox+geckodriver is THE browser lane
- `Service(executable_path="/usr/bin/geckodriver")` REQUIRED for selenium
- evidence always SHA-sealed at creation, never after the fact

## Verified (smoke-tested)
- [ ] `forge vm status` / `vm boot`
- [ ] `forge run "..."` / `--shadow`
- [ ] `forge sync up|down`
- [ ] `forge browse <url>`
- [ ] `forge probe <url>`
- [ ] `forge seal|verify`
- [ ] `forge ask` (needs key)

## OPEN-SLOTS — operator details will fill these
1. **Form-factor**: TUI dashboard / localhost web-IDE / VSCode-style extension?
2. **Scope**: bug-bounty pipeline (recon→hunt→evidence→report→submit-track)
   vs general pentest suite vs both?
3. **AI role**: advisory copilot vs full-auto agentic driver (runs lanes itself)?
4. **First-class lanes to prioritize**: nmap-recon, JS-bundle static-mining,
   subdomain/wayback sweeps, report-packer, bounty-submit tracker?
5. **Hard-code campaign workflows** (base64-solver, evidence-zip packer,
   multi-report tracker) as forge commands?

## Next milestones
- v0.2: operator's details → IDE layer + lane expansion
- v0.3: agentic AI loop (key-driven, lane-orchestrating)
- v1.0: one-shot campaign mode

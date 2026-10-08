# RESEARCH SYNTHESIS — RECON & ATTACK-SURFACE PIPELINE (Agent C, 6 papers)
# Source: deleg_f5c87b7c task-2 | 'Sub Hijack' arXiv:2103.14970 WRONG-ID
# (rock mechanics) — replaced by RDScan + HostingChecker (verified)

## PAPERS: RDScan (USENIX'21, arXiv:2012.01946), HostingChecker (SIGMETRICS'23),
## Secrets That Survive Everything (arXiv:2609.23042), Keys on Doormats
## (arXiv:2603.12498, 10M pages), Jack-in-the-box (CCS'23, bundler study),
## OSINT/LLM survey + cert-lifecycle (Pletinckx MAKO)

## THE 6-STAGE PIPELINE (passive-first, 3 hard invariants):

### S0 ASSET-SEED (passive only — NO wordlist brute-force, RDScan ethics):
- CT logs (crt.sh, SAN/CN, PSL-normalized) + cert-lifecycle tagging:
  FRESH certs = hardening-in-progress (avoid); EXPIRED-but-serving =
  high-value stale cohort (MAKO)
- Shipped wordlists near-useless: 16/101k subbrute labels in real CT data

### S1 CHAIN-RECONSTRUCT:
- CNAME→A/AAAA/NS recursion, dig re-checks on unterminated chains
- DQV staleness filter (HostingChecker): discard once-queried long-tail records
- DEDUP KEY = (chain-terminal, provider, resource-name) — resource IS the
  finding, subdomains are instances (many dangle to one claimable)

### S2 TAKEOVER-VALIDATE (default = fingerprint-only, NEVER claim):
- Endpoint-pattern DB match (suffix-pattern: freshdesk.com-class FIRST —
  RDScan 83% = discontinued SaaS, 17% expired domains — our Freshdesk
  finding is the DOMINANT class)
- Single gentle GET → assert 'unclaimed' fingerprint (NoSuchBucket etc.)
- RDScan exception: temp-claim + immediate release ONLY as authorized FP-prune
- INVARIANT-1: re-resolve chains inside validate — chain data older than
  N hours is UNTRUSTED (RDScan's own cache-staleness miss)

### S3 LIVE-DOM-CAPTURE (rendered DOM, post-JS — not static HTML):
- Keys-on-Doormats: 84% of verified creds in JS bundles (build-time injection
  invisible to repo scans); 16% third-party scripts (OpenAI 24%, Stripe 22%)
- Dwell-time: creds stay exposed avg ~12 MONTHS; quarterly re-scan catches
  rotation AND persistence
- Prioritize by name (app/main/auth/payment) and SIZE (18MB = prime)

### S4 BUNDLE-REVERSE (Jack-in-the-box):
- 36 bundler fingerprints → source-map probe (module lists + ORIGINAL SOURCE
  PATHS = the real disclosure) → AST compartmentalization → lib:version ID
  → CVE join; 10 security-holding packages found ALREADY SHIPPED in prod

### S5 JS-SECRETS (2609.23042 + Doormats):
- Anchored vendor regexes + entropy + key-value context
- MANDATORY runtime-aware layer: CryptoJS-encrypted configs decrypted in
  sandbox (defeats EVERY static scanner — best static = 36.6% recall,
  best runtime-aware = 77.8%, combined 86.1%, 13.9% manual-only)
- AppID/client-ID = public-by-design, EXCLUDE from findings; secret-grade only
- Token-mint-chain flag when AppID+secret+tenant co-locate (73.3% of exposed
  apps had the FULL chain in one bundle)
- INVARIANT-2: NO outbound verification with recovered creds — live-ness
  proven by authorized-chain reasoning only; hash first-8, never store
  plaintext; secrets stage stays LOCAL (never through LLM APIs)

### S6 DISCLOSE (RDScan protocol):
- security.txt → program-list similarity match (manual verify) → Abusix
  (email-domain filtered) → WHOIS (rate-limited, distributed)
- Expectation floor: 34% read advisories, 31% fixed in 6 months; direct
  notification ~50% removal in 2 weeks

## INVARIANT-3 (agent-role): every LLM-emergent 'finding' must be RE-DERIVED
## from sealed raw artifacts by deterministic code before entering the
## evidence store. Survey found hallucination measured in exactly 1 of 74
## systems (4%) — tool output is a LEAD, artifacts are the PROOF.
## Manual-review lane = structural requirement (13.9% scanner-blind class).

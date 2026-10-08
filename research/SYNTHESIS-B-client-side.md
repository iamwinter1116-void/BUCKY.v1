# RESEARCH SYNTHESIS — CLIENT-SIDE WEB ATTACKS (Agent B, 6 papers)
# Source: deleg_f5c87b7c task-1 | JAW's briefed arXiv ID WRONG (physics paper);
# real source usenix.org sec21-khodayari.pdf — read in full

## PAPERS: JAW (USENIX'21), postMessage catalog (NDSS'19 OSV + Jetpack
## CVE-2024-10858 + Proctorio CVE-2026-2345 — 'Cracks Between Bricks' UNFOUND
## as title), Thou Shalt Not Depend on Me (NDSS'17 — JS-staleness, honest
## reclassification), CSP Is Dead (CCS'16) + Longitudinal CSP (NDSS'20),
## mXSS corpus (Heiderich CCS'13 + Bentkowski 2.0.17 + CVE-2024-47875 +
## CVE-2026-65914 + CVE-2025-26791 + CVE-2026-49459), DOM-XSS 25y (Lekies
## CCS'13 + DOMsday CCS'25)

## FIRST-CLASS LANES (ordered by confidence on our care-app chain):

### A2 'pm-guard' (FIRST — our IFRAME_READY finding is already a P1-class bug):
- P1..P6 origin-check failure taxonomy:
  P1 no event.origin check | P2 lax compare (substring/regex/prefix) |
  P3 null-origin parity (sandboxed iframes) | P4 trust-transfer to message
  content (Proctorio CWE-346) | P5 origin-OK but payload → innerHTML/eval |
  P6 missing handshake state-machine
- Monitor-1 listener census (lexical P1-P6 classify per handler) +
  Monitor-2 active fuzzer: 7 payload families (HTML injection, canary-img,
  javascript: URIs, __proto__ pollution, type-confusion, per observed type)
- JAW counts POST-MESSAGE as first-class attacker source (8/8 apps);
  12,701 forgeable requests across 87/106 apps — event.data → request-sink
  is the client-side-CSRF shape
- Sandbox variant: iframe sandbox='allow-scripts' exercises P3 null-origin

### A3 'sanitizer-oracle' (SECOND — tag-fallthrough makes it near-certain):
- mXSS M0 root class: sanitizer T1 → serialize → browser reparse T2 ≠ T1
- M1 Bentkowski MathML chain (DOMPurify 2.0.17, PoC verbatim in H1 1024734) |
  M2 nesting CVE-2024-47875 (MAX_NESTING_DEPTH=500 fix) | M3 re-contextualization
  CVE-2026-65914 | M4 template-literal CVE-2025-26791 | M5 dom-clobbering
  CVE-2026-49459
- OUR care-app: custom sanitizer is NOT mXSS — it's allowlist-bypass render
  gadget (no mutation needed) — mutation corpus still applies as regression suite
- Oracle = browser-as-judge double-parse diff (DOMParser tree vs innerHTML reparse)

### A5 'csp-verdict' (THIRD — syntactic, zero false positives, hours):
- B1 trivial: unsafe-inline/unsafe-eval without nonce (OUR care-app: instant B1)
- B2 whitelisted-unsafe-endpoints: JSONP callback reflection, open redirects
- B3 framework gadgets: AngularJS-style expression evaluation in allowlisted libs
- CCS'16 numbers: 94.72% of policies bypassable; 99.34% of CSP hosts get NO
  XSS benefit; 14/15 top whitelisted domains host unsafe endpoints
- Meta-CSP frame-ancestors is SPEC-IGNORED → meta-only policy = embeddable
  (our care-app embeddability = exactly this class)
- Remediation template: nonce + strict-dynamic + object-src 'none' + base-uri 'none'

### A4 'stale-dependency + gadget annotator' (curl-compatible):
- Script census → sha256 → version DB → CVE join; expression-evaluating
  frameworks flagged as live script-gadgets (feeds B3)

### A6 'taint-lite flow audit' (second-phase, after A2/A3 confirm chain):
- Lekies 14 sources × 3 sink-contexts; canary-validated zero-FP reporting
  (CCS'13 discipline); honest label: prioritization net, not ground truth
- DOMsday: versioned payload-generator re-runs (+83% delta from methodology)

## END-TO-END CHAIN THE LANES MUST PROVE TOGETHER (care-app):
embed (no frame-ancestors, A5) → IFRAME_READY to '*' (A2) → harness posts
command → event.data → DOMParser→React sanitizer (A6 flow) → unknown tag +
on* attribute survives fallthrough (A3 canary) → handler executes → CSP B1
= no backstop (A5) — each lane contributes ONE sealed artifact.

## REPRODUCIBILITY RULE: DOMPurify lineage (2.0.17→2.2.2→2.5.x→3.1.3→3.2.4→
## 3.3.2→3.4.6) argues versioned corpora + scheduled re-runs, never one-shot.

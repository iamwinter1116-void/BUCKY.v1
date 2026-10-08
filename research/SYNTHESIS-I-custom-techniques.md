# RESEARCH SYNTHESIS — CUSTOM-REPLACEMENT TECHNIQUES (Agent I, COMPLETE)
# Source: deleg_f4c0a1a5 full batch, 13 papers, all primary-source verified
# Verified delivery: subagent-summary-0-20261009_004420_052685.txt
# Date: 2026-10-09 (IST)

## PAPERS (exact numbers, verbatim-captured)

1. **Jack-in-the-box: JS Bundling on the Web** (CCS'23, Rack & Staicu)
   - 1,086,368 bundles in Tranco Top-1M; 40% of sites ship bundles
   - 89,845 fully reversed via source maps (1-in-8-to-10 bundles expose
     them); 285,580 compartmentalized into module lists
   - 46.84% of webpack bundles parseable; 1,051 vulns reidentified from
     33 vulnerable npm packages (17 critical, 59 high)
   - Technique: bundler fingerprint -> crawl -> reverse (sourcemap-else-
     compartmentalize) -> reidentify libraries -> map CVEs
   - **BUCKY: jsdeep stage-1 = sourceMappingURL check FIRST** (free
     reversal 1-in-8), else compartment-split at module boundaries;
     attribute every string literal to its consuming module =
     FP-killer + exported-config detection.

2. **JSNice / Big Code** (POPL'15, Raychev-Vechev-Krause)
   - 63.4% exact identifier-name recovery; 81% type-annotation accuracy
   - CRF statistical renaming: property keys/literals/globals survive
     minification = anchors; predicts the rest
   - **BUCKY: enrichment pass** — rename recovered modules to semantic
     labels; gate detectors on predicted names; structural fallback
     (36.6% names remain wrong — never trust blindly).

3. **Deep Links of Android** (USENIX Sec'17, Liu et al.)
   - 164k+ apps ×2 snapshots; 1M webpages; App-Link verification: only
     194/8,878 (2.2%) pass, 95.3% never attempt; iOS 1,925/12,570 (15%)
     fail on server misconfig; 45.6% of Alexa-1M embed hijacked App links
   - **BUCKY: scheme->claimants collision table**; flag unowned claims +
     unverified autoVerify + multi-claimant schemes.

4. **DeepExploitor** (ASE'25, Zhang et al.)
   - 433 apps: 83 zero-day chains, 24 high/critical, 35 CVE'd
   - Inter-procedural constraint graph: deeplink parser ->
     shouldOverrideUrlLoading -> addJavascriptInterface; trusted-domain
     allowlist mutation (prefix trusted.com.attacker.com / suffix
     .eviltrusted.com) to bypass black-box checks
   - **BUCKY: chain-tracer shape** — query params of scheme builders
     (paytmmp://mini-app?urlType=launchBot) = attacker taint sources.

5. **Outdated JS Libraries** (NDSS'17, Lauinger et al.)
   - 133k sites; 87.7% Alexa use a known library; 37% ship a
     known-vulnerable one; lag behind newest release "in years"
   - Version fingerprinting SURVIVES minification (structural
     features, not banner comments)
   - **BUCKY: stale-asset lane foundation** — structural version
     fingerprints; archived captures hold long-lived surface.

6. **Out of Sight: Orphaned Web Pages** (CCS'21, Pletinckx et al.)
   - 100k-domain sample; 1,953 orphaned pages on 907 domains (some 20
     years old); Wayback CDX past-vs-current link-graph diffing
   - **BUCKY: CDX diff recipe** — matchType=domain, filter
     statuscode:200, collapse=urlkey; invert for .js URLs: archived
     bundle URLs still-200-but-unreferenced = prime stale targets.

7. **Can I Take Your Subdomain? / RDScan** (USENIX Sec'21, Squarcina et al.)
   - ~26M subdomains enumerated; 1,520 takeover-eligible on 887/50k
     Tranco domains; 83% from discontinued third-party services
   - **BUCKY: precondition verification MANDATORY** before reporting
     takeover: CNAME present + target gone + provider claim-page
     fingerprint. 83%-discontinued-services = the lapsed-tenant class.

8. **Dangling DNS Records / Dares** (CCS'16, Liu-Hao-Wang)
   - 791 confirmed + 5,982 potential Dares; 467 exploitable in 277
     Alexa-10k domains; most third-party providers DO NOT verify
     ownership claims
   - Taxonomy: Dare-A (released cloud IP), Dare-CN (abandoned SaaS
     CNAME), Dare-MX, Dare-NS
   - **BUCKY: probe-stage classifier** — tenant hostname -> Dare class;
     Dare-CN = primary lapsed-tenant class.

9. **ChainReactor** (USENIX Sec'24, De Pasquale et al.)
   - PDDL AI-planning chain discovery; 504 EC2 + 177 DO instances;
     zero-day chains on 16+4; Distinguished Artifact Award
   - **BUCKY: chain-verdict engine** — findings = typed actions with
     preconditions/effects; >=2-finding planner plan = ONE critical
     verdict with the plan as machine-checkable evidence.

10. **The Postman Always Rings Twice** (NDSS'13, Son & Shmatikov)
    - 10,121 Alexa-10k hosts: 22% (2,245) have receivers; 136 distinct
      receivers; 65 (1,585 hosts) perform NO origin check; 14 (261
      hosts) semantically incorrect (contains/ends-with/missing-
      escaped-dot patterns)
    - **BUCKY: weak-check ruleset** — encode the documented ~12
      incorrect-check patterns as deterministic FP-killers.

11. **PMForce** (CCS'20, Steffens & Stock)
    - 27,499 handlers / 758,658 documents in 24h; 111 exploitable
      handlers on 379 sites; 219 trivially (no origin check)
    - Static candidates 252 -> 111 real exploits (~56% static FPs)
    - **BUCKY: runtime gate** — never ship a critical without
      solver-materialized proof (Z3 exploit-message synthesis).

12. **Cookie Crumbles** (USENIX Sec'23)
    - Cookie tossing/shadowing primitive; 12 CVEs / 27 disclosures;
      9-of-13 frameworks vulnerable; __Host- prefix as the fix
    - **BUCKY: cookie-lane probe** — Domain=.parent + deep-Path
      shadowing canary; flag cookies lacking __Host-.
    - HONEST NOTE: 2 sub-numbers (3 session-fixation, 7 CORF) from
      worker full-PDF capture, not independently re-verified.

13. **Melting Pot of Origins** (NDSS'20)
    - 12 of 13 rehosting services fell to service-worker scope abuse
    - **BUCKY: SW-scope check** — CDP hook on serviceWorker.register;
      flag effective scope broader than app trust boundary.

## SYNTHESIS — BUCKY LANE DESIGNS (novel compositions marked)

- **lanes_jsdeep (upgrade)**: regex pre-filter -> sourceMappingURL
  check (1-in-8 free reversal) -> compartment split at module
  boundaries (Jack-in-the-box) -> per-module string attribution ->
  JSNice-style anchor-based semantic enrichment. Novel: no paper mines
  bundles for SaaS tenant config — BUCKY's original front-end.
- **lanes_deeplink (new)**: scheme->claimants collision table
  (Liu'17) + taint graph over scheme-builder query params
  (DeepExploitor shape).
- **lanes_stale (new)**: Wayback CDX page-diff (Out of Sight) +
  structural version fingerprints surviving minification (Lauinger) +
  .js-URL inversion. Novel composition: live-vs-archive bundle diffing
  for endpoint/scheme resurrection has no precedent.
- **lanes_tenant (upgrade)**: provider-suffix harvest + edit-distance
  pair clustering (BUCKY original) -> RDScan preconditions -> Dare
  classification (CN primary).
- **chain-verdict engine (new)**: ChainReactor PDDL-shape + PMForce
  runtime gate + Sheyner/Jha/Wing attack-graph theory (AG(!unsafe)
  model-checker counterexamples; >100 nodes impractical manually).
- **pm-weak-check ruleset**: Postman's documented incorrect-check
  patterns as deterministic rules.

## HONEST GAPS (no paper found — BUCKY original territory)
1. JS-bundle mining for SaaS tenant config — RDScan/Dares cover DNS
   side, Jack-in-the-box covers reversal; the harvest front-end is ours.
2. Live-vs-archive JS-bundle diffing — closest primitives are Out of
   Sight + Lauinger; the combination is novel.
3. XHOUND targets browser-extension fingerprinting, NOT postMessage.

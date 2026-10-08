# RESEARCH SYNTHESIS — STATE-ACTOR TRADECRAFT (Agent F, 5 papers)
# Source: deleg_a69d1851 task-0 | Oct 16 2026 | All 5 papers FOUND + deep-read

## PAPERS: Stuxnet (Langner/NATO-Falco), Equation-Grayfish (Kaspersky),
## SolarWinds SUNBURST/SUNSPOT (FireEye/CrowdStrike/arXiv:2308.10294),
## Regin (Symantec/Kaspersky-GSM), Flame-Duqu (CrySyS/MDPI)

## THE 6 TRADECRAFT LAWS (all 5 case-studies converge):

### LAW-1: ATTACK THE DELIVERY, NOT THE PRODUCT
- SUNSPOT hijacked the BUILD (MsBuild.exe ElfHash 0x53D525, source-swap+restore)
- Equation INTERDICTION: postal CD-ROM trojanizing (Houston 2009, 2 zero-days)
- Flame MITM'd Windows Update (forged MS cert, terminal-server licensing)
- Stuxnet wrapped vendor's own s7otbxsx.dll driver
- Regin targeted the GSM OPERATOR (compromise telco → intercept all endpoints)
- **BUCKY-LANE: pipeline-audit is the highest-value hunting surface**
  (Artifactory tokens, update channels, build servers, signing infra, shared IdP/CDN)

### LAW-2: PATIENCE AS A WEAPON SYSTEM
- Equation: 14+ years (C2 domains from 1996); Fanny mapped air-gaps BEFORE Stuxnet
- SUNBURST: 12-14 days dormant; <100 escalated of 18,000; triage-discipline
- Regin: 5-8 years, 6-stage architecture; Duqu: 30-day self-removal TTL
- **BUCKY-LANE: persistence-patience hunting** — lapsed tenants, stale DNS,
  orphaned creds, unmonitored infra accumulate BECAUSE attention decays;
  periodic re-audit of old targets = defender-side exploit of human failing

### LAW-3: HIDE INSIDE THE LEGITIMATE
- Signed vendor assembly (SUNBURST), forged MS cert (Flame), event-log
  filenames + NTFS-EAs (Regin), vendor DLL (Stuxnet), legit protocols (all)
- SUNBURST config inside legitimate appSettings XML keys
  (ReportWatcherRetry≠3 gate; flags in ReportWatcherPostpone)
- **BUCKY-LANE: detection must DIFF legitimate objects against ground truth**
  (config-integrity diff, per-process resource baselines, controller-logic state)
  — never key on "new artifacts"

### LAW-4: ENVIRONMENT-GATING + QC DISCIPLINE
- Stuxnet: 21s sensor-recording replay loop, controller fingerprinting, 3-reinfection cap
- SUNBURST: domain-join check, AV/forensic-tool blocklist (FNV-1a hash 17291806236368054941
  = 'solarwinds.businesslayerhost'), hash-verified source-replacement (failed
  decryption = build failure = detection, so MD5-verify BEFORE injection)
- **Attackers QA against the defender's own telemetry → defender tooling IS attack surface**

### LAW-5: OPSEC DECAYS AT SCALE AND TIME
- Stuxnet Gen-2 still contained dead Gen-1 overpressure code → whole forensic map free
- Equation leaked build-host 'rmgree5'; SUNSPOT used video-game AES keys
- Regin ICMP validation string 'shit', CRC seed 31337; family constant 0x61C88647
- **BUCKY-LANE: systematic artifact-hunting** (build paths, timestamps, toolchain
  versions, reused crypto constants) — attribution + detection technique

### LAW-6: NOBODY WAS CAUGHT BY SIGNATURES
- FireEye: anomalous MFA registration on dormant account (identity-lifecycle event)
- Kaspersky: co-infection telemetry on ONE 'Typhoid Mary' victim
- CrySyS: fake sort*.nls stack-frames in lsass.exe + Process-Monitor IFEO reads
  + resource-deltas (explorer.exe context-switch 3.0→194.7/s, threads 15→39.5)
- Langner: forensic lab saw WinCC polling controllers every 5s
- **BUCKY-LANE: cross-layer telemetry chains > single IOCs**
  (identity events, DNS analytics, build-integrity, below-OS attestation,
  process baselines, scan-correlation, cross-victim IOC sharing)

### STUXNET-SPECIFIC: LANGNER'S 3-LAYER MODEL
- IT layer (propagation) → control layer (manipulation) → physical layer (damage)
- "Plant-level vulnerability" = cyber manipulation exploiting a physical one
- **BUCKY AUDIT-CHECKLIST: for every config-write/service-account finding, trace
  the downstream consequence chain — that's the difference between scanner-
  operator and elite attack-surface auditor**

## KEY NUMBERS:
- Stuxnet team ~45 people (Falco/NATO estimate); >50% of dev-cost = hiding the attack
- Equation: thousands-to-tens-of-thousands victims, 42 countries; visible cap ~500
- SUNBURST: 18,000 exposed → <100 escalated; DGA victim-ID = MD5(MAC+domain+MachineGuid)
- Regin: 75+ payload modules, EVFS disguised as SystemLog.evt, P2P VPN overlay per-infection
- Flame: 20MB platform, ~10,000x larger than typical malware of its era

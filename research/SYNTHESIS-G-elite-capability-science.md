# RESEARCH SYNTHESIS — ELITE-CAPABILITY SCIENCE (Agent G, 5 papers)
# Source: deleg_a69d1851 task-1 | Oct 16 2026 | All 5 areas FOUND + deep-read

## PAPERS: Attribution-CTF (arXiv:1507.01922 + 1607.02171), LoJax-UEFI (ESET + arXiv:2311.03809),
## Covert-Channels (NDSS'22 arXiv:2112.09604 + EuroS&P'22 SoK), Zero-Day-Economics (RAND RR-1751),
## EternalBlue (arXiv:2112.14773 + Check Point + Uni.lu)

## THE 3 GOVERNING LAWS:

### LAW-1: ECONOMICS DECIDES CAPABILITY CHOICES
- Exploit life-expectancy: **6.9 years average**; 25% die <1.5yr, 25% survive >9.5yr
- **Collision burn-rate: 5.76%/year** (0.87%/90d; 40% over 14yr) — another party
  independently holds your vuln
- **Median weaponization: 22 days** (71% ≤31d; 31.44% ≤1 week) — FINDING is the
  scarce act, not exploiting
- Implants = ~$1M tier (reliability + maintenance); exploits = commodity
- In-house-found vulns OUTLIVE purchased ones (1.4yr avg for bought)
- LEAK = 100% instant burn + zero-marginal-cost gift to all adversaries
  (EternalBlue → WannaCry $4-8B in a day, verbatim reuse)
- **SOLO-RESEARCHER STRATEGY: novel discovery surfaces (abandoned code paths,
  old parsers, protocol corners) → near-zero collision risk ~7 years**

### LAW-2: SPEC-VIOLATION = FREE DETECTION PRIMITIVE
- DoublePulsar answers TRANS2_SESSION_SETUP (0x000E) — spec says MUST return
  STATUS_NOT_IMPLEMENTED → answering = infected BY CONSTRUCTION
- MS17-010 fingerprint: PeekNamedPipe → STATUS_INSUFFICIENT_RESOURCES (0xC0000205)
- LoJax DXE driver GUID 682894B5-6B70-4EBA-9E90-A607E5676297 absent from vendor
  manifest → anomalous BY CONSTRUCTION
- IP-ID/ISN near-zero-entropy = covert-channel BY CONSTRUCTION
  (pigeonhole: state array smaller than tuple space → leakage mathematically inevitable)
- **BUCKY PRINCIPLE: the best vuln classes are those whose MISUSE inherently
  violates a spec — the report sells itself as a detection primitive**

### LAW-3: AUDIT GAPS WERE HUMAN, NOT TECHNICAL
- Nobody scanned firmware before ESET did → LoJax needed no stealth
- Nobody asked "what global state can an outside packet read/write?" → covert channels
- NSA's own recon tools (info_efi, ReWriter_*) left on disk → campaign outed
- ~400,000 DoublePulsar infections PRE-DATED WannaCry — telemetry existed, unwatched
- 20% of WannaCry infections completed <50s (Uni.lu testbed) — 50-second
  reaction budget would have saved ~80% of remaining hosts

## ETERNALBLUE MECHANISM (the leaked-capability anatomy):
- Root cause: DWORD→WORD truncation (S2 SizeOfList loword-only update, 0x10000→0x1ff5d)
- 3-stage: craft (607 records, 607th overwrites srvnet header) → grooming
  (Negotiate/Session-Setup/Srvnet sequence, ~15 TCP conns, buffer-adjacency
  required) → payload (HAL heap 0xffd00000, executes on connection-close)
- NSA held ~5 years; Shadow Brokers leak forced March-14-2017 patch;
  WannaCry 59 days later; millions unpatched through late-2018
- **Zombie-vuln class: exploitable in old versions indefinitely post-disclosure
  — version-distribution telemetry, not patch-day counts, is the true metric**

## COVERT-CHANNEL NUMBERS (NDSS'22):
- Linux: 2048-counter β array hash(IP_DST,IP_SRC,proto,net_key) mod 2048
- Bandwidth: Linux 400b/h UDP / 3000b/h ICMP; Windows 47.4b/h; macOS 1800b/h;
  NetBSD-ISN 7200b/h
- 3 exfil paths pierce firewall+SAV: via firewall itself, via DMZ host,
  via co-resident containers (no direct Internet route needed)
- Defense is nearly free (TCP ID=0; Linux ≥4.19 RST ID=0) — persistence = apathy

## CONCRETE BUCKY LANES (all stdlib-implementable on Kali VM):
1. **firmware-baseline pinning** — SPI-image hash vs vendor manifest; DXE-GUID
   allowlist alert; SPI write-protect (PR0/PR2) config audit; RwDrv.sys canary
2. **protocol-anomaly monitors** — reserved-subcommand response detector;
   STATUS_INSUFF_SERVER_RESOURCES probe-pair; header-entropy per host-OS
3. **patch-lag surface map** — days-since-patch distribution per protocol;
   SMBv1 check; DoublePulsar Trans2 multiplex-ID ping (0x51/0x52=infected)
4. **attribution-confidence lane** — payload/IOC collision check across actors
   BEFORE naming anyone; deception pruning (all-but-earliest heuristics)
5. **spec-violation prober** — "does it answer what the spec says must stay silent?"

## ATTRIBUTION SCIENCE:
- Payload-reuse deception ≈90% of CTF attacks; accuracy 0.26-0.37 per-team →
  argumentation-models lift to 62%
- Evidence resting on shared/market-bought tools = near-zero weight;
  bespoke capability = high weight

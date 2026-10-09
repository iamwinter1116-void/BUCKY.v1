# RESEARCH SYNTHESIS — CHAIN-COMPOSITION + RUNTIME-PROOF (Agent J, COMPLETE)
# Source: deleg_34f359b2, 16 papers, primary-source verified
# Verified delivery: subagent-summary-0-20261009_132612_654599.txt
# Date: 2026-10-09 (IST)

## CHAIN-VERDICT LINEAGE (the formal backbone)
1. **Sheyner/Jha/Wing S&P'02** — model-checker counterexamples ARE
   attack paths; >100-node manual graphs 'impractical'; minimum
   critical attack sets (greedy, NP-complete approx); MDP reliability.
2. **MulVAL CCS'06** — Datalog derivation graphs: interaction rules +
   XSB engine; POLYNOMIAL size (prior model-checking: 10 hosts/5
   vulns = 10M edges, 15 min); every derivation = its own proof.
3. **Obes/Sarraute/Richarte 1306.4044** — planner INSIDE production
   pentest tool (Core Impact); plans VALIDATED by executing on the
   real target; SGPlan 480 nodes/25s/<4GB; 720->1440 operators:
   +163% Metric-FF, +124% SGPlan time.
4. **FF JAIR'01 (Hoffmann-Nebel)** — ignore-delete-lists relaxation;
   security chains are monotone (capabilities rarely un-gained) ->
   relaxation tight; helpful-action pruning -> short benign+exploit
   chains; AIPS-2000 winner.
5. **Powerlifted ICAPS'20** — lifted successor generation, no
   grounding blowup; join order matters: 454 vs 352 avg tasks (IPC
   59-domain eval, 30min/16GiB); ChainReactor's planner.
6. **ChainReactor USENIX'24** — the template (already built v0.22).
7. **POMDPs AAAI'12 (Sarraute-Buffet-Hoffmann)** — uncertainty escape
   hatch; 4AL decomposition: avg 1.96% quality loss, max 14.1%.

## RUNTIME-PROOF LINEAGE (the gate)
8. **Kudzu S&P'10** — first JS symbolic execution; string-constraint
   solver; 18 apps -> 2 unknown + 9 manual-only bugs found.
9. **Jalangi ESEC/FSE'13** — selective record-replay + shadow
   execution substrate. HONESTY: exact numbers UNFOUND (ACM 403, no
   mirror); jalangi2 dropped record/replay -> PMForce-direction
   (forced execution) is the robust substrate. npm not pip.
10. **25M Flows CCS'13 (Lekies-Stock-Johns)** — Alexa-5k, 504,275
    URLs, 24.5M flows -> 181,238 payloads -> 69,987 executed; 6,167
    vulns/480 domains (9.6%); context-sensitive payload generator;
    zero manual validation.
11. **DOMsday NDSS'18** — 44,722 pages/319,481 frames; 3,219 confirmed
    vulns; **static tools missed 90% of dynamically confirmed bugs**;
    dual-injection confirmation (end-of-URL + key-value); +83% vs
    prior methodology.
12. **Stock/Johns USENIX'14** — 1,602 real DOM-XSS bugs: string-match
    Auditor bypassed 73% (81% of 958 domains); char-level taint
    parsing: only 0.50% domains / 0.06% frames issues; postMessage
    = first-class source (23/50 real parsing violations).
13. **PMForce CCS'20** — 27,000 handlers (vs 136 in 2013); 252
    candidates -> 111 proven exploitable/379 sites; Z3 Exploit
    Templates.
14. **XSSI USENIX'15** — dynamic user-specific scripts SOP-exempt;
    >80% studied sites susceptible (leak-leg materialization).
15. **RDScan USENIX'21** — stale-asset = origin-capability lattice
    position; compose ONLY when stale origin provably weakens a web
    mechanism (origin-checks/cookie-scoping/CSP).
16. **KARONTE S&P'20** — bugs live in the INTERACTION between
    components; 46 zero-days + 5 n-days in 53 firmware; cross-binary
    taint propagation.

## VERIFIED PIP STACK (exact versions, checked on PyPI)
- z3-solver 5.1.0.0 (fixedpoint/datalog = MulVAL-shape evaluation;
  native string theory = Kudzu-role payload synthesis)
- pddl 0.5.1 (parser) | unified-planning 1.3.0 + up-fast-downward
  0.5.2 | pyperplan 2.1 | tarski 0.9.1 | pysmt 0.9.6
- NOT pip (verified 404/GitHub/npm): Powerlifted, MulVAL, jalangi(2)

## NET DESIGN (Agent-J synthesis)
- **Chain-verdict core = Datalog/Horn evaluation over typed finding
  preconditions/effects (MulVAL shape) via Z3 fixedpoint** — every
  derived edge carries its derivation = proof. FF-family lifted
  planner for multi-step; counterexample/derivation = chain evidence.
- **Runtime proof-gate = forced execution + char-level taint + Z3
  Exploit-Template payload synthesis + dual-injection confirmation
  (DOMsday recipe)**. Critical verdict ONLY when plan exists AND
  composed exploit materializes.
- **DOMsday 90%-static-miss rule: static/regex = candidates only;
  dynamic confirmation gates critical.**
- Cross-object interactions = first-class chain edges (KARONTE).
- Stale-bundle composition ONLY on proven origin-weakening (RDScan).

## HONEST GAPS
- No paper composes BUCKY's exact postMessage+deeplink+stale chain —
  the composition is ours (validated on C181-class PROD artifact).
- Jalangi exact numbers UNFOUND (ACM 403).

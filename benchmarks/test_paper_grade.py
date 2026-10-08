"""Paper-grade benchmark tasks — the v2 suite on real detector code.

Every task uses the REAL lanes (no mocks): classify_csp, classify_handler,
detect_secrets, learning.attempt_upgrade. Tasks carry the dual-test
contract, difficulty, and (for upgrade tasks) the containment check.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.framework import (BenchReport, BenchTask, Difficulty,
                                 run_task)
from core.learning import attempt_upgrade, propose_secret_pattern
from core.lanes_security import classify_csp, classify_handler, detect_secrets
from core.registry import PatternRegistry

VULN_CSP = ("script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "*.freshchat.com")
CLEAN_CSP = "script-src 'nonce-r4nd0mN0nc3V4lu3'; frame-ancestors 'none'"
VULN_HANDLER = ("window.addEventListener('message',function(e){"
                "document.getElementById('o').innerHTML=e.data;});")
CLEAN_HANDLER = ("window.addEventListener('message',function(e){"
                 "if(e.origin!=='https://a.example')return;"
                 "document.getElementById('o').textContent=e.data;});")
SECRET_BUNDLE = ("var c={clientSecret:'xY9kQ2mN7pR4sT6vW8zA1bC3dE5fG7h',"
                 "k:'AKIAIOSFODNN7EXAMPLE'};")
BENIGN = "var app={version:'1.0.0',debug:false};function boot(){return true;}"


def _mk_reg() -> tuple[PatternRegistry, tempfile.TemporaryDirectory]:
    td = tempfile.TemporaryDirectory()
    d = Path(td.name) / "reg"
    d.mkdir()
    p = d / "patterns.json"
    p.write_text('{"version":1,"csp_b1_triggers":["unsafe-inline"],'
                 '"secret_patterns":[]}', encoding="utf-8")
    return PatternRegistry(p), td


def build_tasks() -> list[BenchTask]:
    tasks: list[BenchTask] = []

    # ---- CSP detector (easy) ------------------------------------------------
    def csp_f2p() -> tuple[bool, str]:
        v = classify_csp(VULN_CSP, is_meta=False)
        return v.bypass_class == "B1", f"vuln={v.bypass_class}"

    def csp_p2p() -> tuple[bool, str]:
        v = classify_csp(CLEAN_CSP, is_meta=False)
        return v.bypass_class == "clean", f"clean={v.bypass_class}"

    tasks.append(BenchTask("csp-b1-detect", Difficulty.EASY, csp_f2p,
                           pass_to_pass=[csp_p2p]))

    # ---- pm-guard (easy) ---------------------------------------------------
    def pm_f2p() -> tuple[bool, str]:
        h = classify_handler(VULN_HANDLER)
        return h.pattern == "P1", f"vuln={h.pattern}"

    def pm_p2p() -> tuple[bool, str]:
        h = classify_handler(CLEAN_HANDLER)
        return h.pattern == "strict", f"clean={h.pattern}"

    tasks.append(BenchTask("pm-p1-detect", Difficulty.EASY, pm_f2p,
                           pass_to_pass=[pm_p2p]))

    # ---- secrets (medium) --------------------------------------------------
    def sec_f2p() -> tuple[bool, str]:
        fs = detect_secrets(SECRET_BUNDLE)
        return {"azure-client-secret", "aws-access-key"} <= {f.kind for f in fs}, \
            f"kinds={sorted({f.kind for f in fs})}"

    def sec_p2p() -> tuple[bool, str]:
        return not detect_secrets(BENIGN), "benign-clean"

    tasks.append(BenchTask("secrets-tp-fp", Difficulty.MEDIUM, sec_f2p,
                           pass_to_pass=[sec_p2p]))

    # ---- self-upgrade (hard) — includes containment ------------------------
    def learn_f2p() -> tuple[bool, str]:
        reg, td = _mk_reg()
        try:
            cand = propose_secret_pattern("clientsecret", NEW_EVIDENCE)
            v = attempt_upgrade(reg, cand, NEW_EVIDENCE, BENIGN,
                                repo_root=Path(__file__).resolve().parents[1])
            return v.applied, f"applied={v.applied} v={v.new_version}"
        finally:
            td.cleanup()

    def learn_p2p() -> tuple[bool, str]:
        reg, td = _mk_reg()
        try:
            bad = propose_secret_pattern("clientsecret", "short")
            return bad is None, "short-sample-rejected"
        finally:
            td.cleanup()

    def learn_contain() -> tuple[bool, str]:
        """Containment: upgrade MUST be refused when pattern leaks FP."""
        reg, td = _mk_reg()
        try:
            fp = attempt_upgrade(
                reg,
                __import__("core.registry", fromlist=["SecretPattern"]).SecretPattern(
                    id="fp", kind="x", regex=r"var\s+(\w+)"),
                NEW_EVIDENCE, BENIGN,
                repo_root=Path(__file__).resolve().parents[1])
            return not fp.applied, f"fp-upgrade-blocked={not fp.applied}"
        finally:
            td.cleanup()

    tasks.append(BenchTask("self-upgrade-3gate", Difficulty.HARD, learn_f2p,
                           pass_to_pass=[learn_p2p],
                           containment=learn_contain))

    return tasks


NEW_EVIDENCE = ('var g={publishableAccessToken:"ghp_9d8f7A6s5D4f3G2h1J0k9L8z7"};')


def main(repeats: int = 3) -> int:
    """Run the v2 paper-grade suite with variance reporting."""
    reports = []
    for i in range(repeats):
        rep = BenchReport()
        for t in build_tasks():
            rep.results.extend(run_task(t, repeats=1))
        reports.append(rep)
    final = reports[0]
    print("== SCORE MATRIX ==")
    for diff, d in final.score_matrix().items():
        print(f"  {diff:6} pass={len(d['pass'])} fail={len(d['fail'])}")
    print("== COMPLETION RATES ==")
    for diff, rate in final.completion_rates().items():
        print(f"  {diff:6} {rate}")
    print("== VARIANCE (repeat runs) ==")
    for diff, s in final.variance_report(reports[1:]).items():
        flag = " FLAKY" if s["stdev"] > 0 else ""
        print(f"  {diff:6} rate={s['pass_rate']:.3f} "
              f"stdev={s['stdev']}{flag}")
    cont = final.containment_score()
    print(f"== CONTAINMENT == blocked={cont['blocked']} leaked={cont['leaked']}")
    ok = final.all_green() and cont["leaked"] == 0
    print("VERDICT:", "ALL-GREEN" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

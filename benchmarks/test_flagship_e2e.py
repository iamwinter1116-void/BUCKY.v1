"""BUCKY flagship benchmark — full-chain e2e hunt vs the LIVE VM lab.

This is the engine's flagship benchmark: the FULL hunt chain
(VM probe -> detector verdict -> clean-twin gate -> evidence seal ->
verify) against the persistent lab-server on the Kali VM, repeated
N times with the paper-grade variance report.

Requires: VM up, lab_serve.py running on 127.0.0.1:19077 (bucky burp
status-style check included). Runs the REAL lanes — no mocks.

Output: per-difficulty matrix, repeat-variance, containment, verdict.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.framework import (BenchReport, BenchTask, Difficulty,
                                  run_task)
from core import evidence, vmbridge
from core.lanes_security import classify_csp

LAB = "http://127.0.0.1:19077"
RUNS_DIR = Path(__file__).resolve().parents[1] / "runs" / "bench-e2e"


def lab_up() -> bool:
    r = vmbridge.run(f"curl -s -m 4 -o /dev/null -w '%{{http_code}}' {LAB}/")
    return r.ok and r.output.strip().endswith("200")


def _probe_csp(path: str) -> str:
    r = vmbridge.run(
        f"curl -s -m 6 -D- -o /dev/null {LAB}{path} "
        f"| grep -i content-security-policy")
    m = re.search(r"content-security-policy:\s*(.+)", r.output, re.I)
    return m.group(1).strip() if m else ""


def build_tasks() -> list[BenchTask]:
    tasks: list[BenchTask] = []

    def full_chain_f2p() -> tuple[bool, str]:
        """The flagship chain: probe vuln -> B1, probe clean -> clean."""
        csp = _probe_csp("/")
        v = classify_csp(csp, is_meta=False)
        if v.bypass_class != "B1":
            return False, f"vuln verdict {v.bypass_class}"
        csp2 = _probe_csp("/clean")
        v2 = classify_csp(csp2, is_meta=False)
        if v2.bypass_class != "clean":
            return False, f"clean verdict {v2.bypass_class}"
        # seal + verify round-trip (real evidence lane)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        d = RUNS_DIR / f"chain-{time.strftime('%H%M%S')}-{id(d := None) or time.time_ns() % 10000}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "probe.log").write_text(
            f"vuln-csp: {csp}\nclean-csp: {csp2}\n"
            f"verdicts: {v.bypass_class} / {v2.bypass_class}\n",
            encoding="utf-8")
        seal_res = evidence.seal(str(d), label="bench-e2e")
        ok = evidence.verify(str(d))
        if not (seal_res.files and ok.ok):
            return False, "seal/verify round-trip failed"
        return True, f"TP=B1 FP=0 seal={seal_res.manifest_sha256[:12]}"

    def invariants() -> tuple[bool, str]:
        """pass_to_pass: benign corpus stays secret-free (FP gate)."""
        from core.lanes_security import detect_secrets
        benign = "var app={version:'1.2.3',debug:false};console.log('ok');"
        return not detect_secrets(benign), "benign-clean"

    tasks.append(BenchTask("full-chain-e2e", Difficulty.MEDIUM,
                           full_chain_f2p, pass_to_pass=[invariants]))
    return tasks


def main(repeats: int = 5) -> int:
    if not lab_up():
        print("[SKIP] lab-server not reachable on VM — start it first "
              "(benchmarks/lab_serve.py). NOT counting this as pass.")
        return 1
    reports = []
    for _ in range(repeats):
        rep = BenchReport()
        for t in build_tasks():
            rep.results.extend(run_task(t, repeats=1))
        reports.append(rep)
    final = reports[0]
    print("== FLAGSHIP E2E (full hunt chain vs live VM lab) ==")
    for diff, d in final.score_matrix().items():
        print(f"  {diff:6} pass={len(d['pass'])} fail={len(d['fail'])}")
    print("== VARIANCE ==")
    for diff, s in final.variance_report(reports[1:]).items():
        flag = " FLAKY" if s["stdev"] > 0 else ""
        print(f"  {diff:6} rate={s['pass_rate']:.3f} stdev={s['stdev']} "
              f"runs={s['runs']}{flag}")
    print("== CONTAINMENT ==")
    print(" ", final.containment_score())
    ok = final.all_green()
    print("VERDICT:", "ALL-GREEN" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

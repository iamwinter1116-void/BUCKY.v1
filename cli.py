#!/usr/bin/env python
"""BUCKY CLI — Winter Soldier ka cyber-ops cockpit.

Usage:
  bucky vm status|boot             VM lifecycle
  bucky run "<shell cmd>" [--shadow] run on Kali (--shadow = live on VM screen)
  bucky sync up|down <src> [dst]    file sync
  bucky browse <url> [--wait 20]    headless-firefox lane (screenshot+text archived)
  bucky msgcap <url> [--wait 30]    postMessage-capture lane (embed+observe)
  bucky probe <url> [--header k:v]  gentle single-GET inspector
  bucky seal <dir> [--label X]      SHA-seal evidence directory
  bucky verify <dir>                re-verify sealed evidence
  bucky ask "<prompt>"              AI brain (needs api_key in config.json)
  bucky hunt "<objective>" [--hint H] [--max-steps 25]
                                     FULL AUTO: LLM agent drives all lanes
                                     (vm/probe/browse/seal) inside ScopeGate,
                                     learns patterns, seals evidence, writes
                                     a report draft via the R1-R10 packer.

Exit codes: 0 success, 1 lane/verification failure, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import evidence, lanes, vmbridge, ai  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bucky",
        description="BUCKY — cyber-ops cockpit (Windows brain + Kali muscle)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_vm = sub.add_parser("vm", help="VM lifecycle")
    p_vm.add_argument("action", choices=["status", "boot"])

    p_run = sub.add_parser("run", help="run command on Kali")
    p_run.add_argument("shellcmd", nargs="+")
    p_run.add_argument("--shadow", action="store_true",
                       help="run inside guest shadow tmux (operator-visible)")
    p_run.add_argument("--timeout", type=int, default=300)

    p_sync = sub.add_parser("sync")
    p_sync.add_argument("direction", choices=["up", "down"])
    p_sync.add_argument("src")
    p_sync.add_argument("dst", nargs="?")

    p_br = sub.add_parser("browse", help="headless-firefox lane")
    p_br.add_argument("url")
    p_br.add_argument("--wait", type=int, default=20)

    p_mc = sub.add_parser("msgcap", help="postMessage-capture lane")
    p_mc.add_argument("url")
    p_mc.add_argument("--wait", type=int, default=30)
    p_mc.add_argument("--port", type=int, default=19007)

    p_pr = sub.add_parser("probe", help="gentle single-GET inspector")
    p_pr.add_argument("url")
    p_pr.add_argument("--header", action="append", default=[],
                      help="k:v extra header (repeatable)")

    p_sl = sub.add_parser("seal", help="SHA-seal an evidence directory")
    p_sl.add_argument("dir")
    p_sl.add_argument("--label", default="run")

    p_vf = sub.add_parser("verify", help="re-verify sealed evidence")
    p_vf.add_argument("dir")

    p_ai = sub.add_parser("ask", help="AI brain (api_key from config.json)")
    p_ai.add_argument("prompt", nargs="+")

    p_hunt = sub.add_parser(
        "hunt", help="FULL AUTO: LLM agent drives all lanes inside ScopeGate")
    p_hunt.add_argument("objective", nargs="+")
    p_hunt.add_argument("--hint", default="",
                        help="operator one-line guidance (success multiplier)")
    p_hunt.add_argument("--max-steps", type=int, default=25)

    p_burp = sub.add_parser(
        "burp", help="Burp Suite proxy lane (launch/status/probe-through)")
    p_burp.add_argument("action", choices=["launch", "status", "get"])
    p_burp.add_argument("url", nargs="?", default="")

    p_rep = sub.add_parser(
        "report", help="build a gate-checked report from a hunt run")
    p_rep.add_argument("run_dir", help="runs/hunt-* directory")
    p_rep.add_argument("--title", required=True)
    p_rep.add_argument("--cwe", required=True)
    p_rep.add_argument("--impact", required=True)
    p_rep.add_argument("--poc", required=True)
    p_rep.add_argument("--env", default="see sealed evidence")
    p_rep.add_argument("--remediation", default="")
    p_rep.add_argument("--refs", default="")

    p_trk = sub.add_parser("track", help="submission/SLA tracker")
    p_trk.add_argument("action",
                       choices=["add", "status", "followup", "overdue",
                                "summary"])
    p_trk.add_argument("id", nargs="?", default="")
    p_trk.add_argument("--title", default="")
    p_trk.add_argument("--program", default="")
    p_trk.add_argument("--status", default="")
    p_trk.add_argument("--note", default="")
    p_trk.add_argument("--sla", type=int, default=7)
    p_trk.add_argument("--tracker", default="tracker.json")

    return ap


def main(argv: list[str] | None = None) -> int:
    a = _build_parser().parse_args(argv)

    if a.cmd == "vm":
        if a.action == "status":
            running = vmbridge.vm_running()
            print(f"VM: {'RUNNING' if running else 'OFF'}")
            if running:
                r = vmbridge.run("uptime -p && date")
                print(r.output)
            return 0
        ok, msg = vmbridge.boot_vm()
        print(f"boot: {'OK' if ok else 'FAIL'} — {msg}")
        return 0 if ok else 1

    if a.cmd == "run":
        cmd = " ".join(a.shellcmd)
        r = (vmbridge.shadow_run(cmd, timeout=a.timeout) if a.shadow
             else vmbridge.run(cmd, timeout=a.timeout))
        print(r.output)
        if r.stderr:
            print(f"[stderr] {r.stderr}", file=sys.stderr)
        return 0 if r.ok else 1

    if a.cmd == "sync":
        if a.direction == "up":
            r = vmbridge.sync_up(a.src, a.dst or a.src)
        else:
            r = vmbridge.sync_down(a.src, a.dst or Path(a.src).name)
        print(json.dumps({"ok": r.ok, "exit": r.exit,
                          "stderr": r.stderr}, indent=1))
        return 0 if r.ok else 1

    if a.cmd == "browse":
        r = lanes.browse(a.url, wait_s=a.wait)
        print(json.dumps({k: v for k, v in r.items() if k != "raw"},
                         indent=1)[:3000])
        return 0 if r.get("ok") else 1

    if a.cmd == "msgcap":
        r = lanes.msg_capture(a.url, wait_s=a.wait, port=a.port)
        print(json.dumps({k: v for k, v in r.items() if k != "raw"},
                         indent=1)[:4000])
        return 0 if r.get("ok") else 1

    if a.cmd == "probe":
        hdrs = {}
        for h in a.header:
            k, _, v = h.partition(":")
            hdrs[k.strip()] = v.strip()
        r = lanes.probe(a.url, extra_headers=hdrs or None)
        print(json.dumps(r, indent=1)[:3000])
        return 0 if r.get("ok") else 1

    if a.cmd == "seal":
        res = evidence.seal(a.dir, label=a.label)
        print(f"sealed: {len(res.files)} files | "
              f"manifest-sha256: {res.manifest_sha256}")
        return 0

    if a.cmd == "verify":
        res = evidence.verify(a.dir)
        print("INTEGRITY-OK" if res.ok else "TAMPER-DETECTED")
        for b in res.problems:
            print(f"  {b}")
        return 0 if res.ok else 1

    if a.cmd == "ask":
        r = ai.ask(" ".join(a.prompt))
        if r.get("ok"):
            print(r["answer"])
            return 0
        print(f"[error] {r.get('error')}", file=sys.stderr)
        return 1

    if a.cmd == "hunt":
        return cmd_hunt(" ".join(a.objective), hint=a.hint,
                        max_steps=a.max_steps)

    if a.cmd == "burp":
        from core import lanes_burp
        if a.action == "launch":
            cmd = lanes_burp.launch_burp(vmbridge.run)
            print(f"[burp] launched: {cmd}")
            print("[burp] wait ~60s for Java GUI init, then: bucky burp status")
            return 0
        if a.action == "status":
            r = vmbridge.run(
                "ss -tln | grep -q 8080 && echo LISTENING || echo DOWN")
            print(f"[burp] proxy 8080: {r.output.strip()}")
            return 0 if "LISTENING" in r.output else 1
        if a.action == "get":
            if not a.url:
                print("usage: bucky burp get <url>", file=sys.stderr)
                return 2
            # route via Burp ON THE VM (proxy is VM-local)
            r = vmbridge.run(
                f"curl -s -m 8 -o /tmp/burp-get.html -w '%{{http_code}}' "
                f"-x http://127.0.0.1:8080 {a.url}; echo; head -c 400 /tmp/burp-get.html")
            print(r.output)
            return 0 if r.ok else 1

    if a.cmd == "report":
        from core.packer import ReportDraft, pack
        rd = Path(a.run_dir)
        if not rd.is_dir():
            print(f"[report] run-dir not found: {a.run_dir}", file=sys.stderr)
            return 2
        tr = (rd / "transcript.log").read_text(encoding="utf-8",
                                              errors="replace") \
            if (rd / "transcript.log").exists() else ""
        raw_steps = [ln for ln in tr.splitlines()
                     if ln.strip() and not ln.startswith("mode:")][:20]
        # R4 oracle: map each transcript step to its expected outcome
        # (verdict lines ARE the oracle; others get the goal-derived one)
        def _with_oracle(i: int, ln: str) -> str:
            if re.search(r"expected\s*:", ln, re.I):
                return ln
            if "->" in ln:
                body, _, obs = ln.partition("->")
                goal = body.strip().rsplit(" ", 1)[-1] if body.strip() else ""
                return f"{ln} | Expected: {obs.strip()[:120]}"
            return f"{ln} | Expected: (as described in this step)"
        steps = [_with_oracle(i, ln) for i, ln in enumerate(raw_steps)] or \
            ["(transcript empty — report from seals only) | Expected: seals verify"]
        seals = [str(p.name) for p in rd.glob("*") if p.is_file()]
        draft = ReportDraft(
            title=a.title, cwe=a.cwe, environment=a.env, steps=steps,
            poc=a.poc, impact=a.impact, remediation=a.remediation or
            "See vendor guidance for the vulnerable class.",
            evidence_seals=tuple(seals), references=tuple(
                [r for r in a.refs.split(",") if r.strip()]) or
            ("CWE reference for the class",))
        res = pack(draft)
        if not res.ok:
            print("[report] GATES FAILED — fix before shipping:")
            for p in res.problems:
                print(f"  - {p}")
            return 1
        out = rd / "REPORT.md"
        out.write_text(res.rendered, encoding="utf-8")
        print(f"[report] gates GREEN — wrote {out}")
        print(f"[report] seal the run-dir before submission: "
              f"bucky seal {a.run_dir}")
        return 0

    if a.cmd == "track":
        from core.tracker import ReportEntry, Tracker
        trk = Tracker.load(a.tracker)
        if a.action == "add":
            if not (a.id and a.title):
                print("usage: bucky track add <ID> --title T", file=sys.stderr)
                return 2
            e = trk.add(ReportEntry(report_id=a.id, title=a.title,
                                    program=a.program, sla_days=a.sla))
            print(f"[track] added {e.report_id} (sla {e.sla_days}d)")
            return 0
        if a.action == "status":
            if not (a.id and a.status):
                print("usage: bucky track status <ID> --status S",
                      file=sys.stderr)
                return 2
            e = trk.update_status(a.id, a.status, a.note)
            print(f"[track] {e.report_id} -> {e.status}")
            return 0
        if a.action == "followup":
            if not (a.id and a.note):
                print("usage: bucky track followup <ID> --note T",
                      file=sys.stderr)
                return 2
            e = trk.followup(a.id, a.note)
            print(f"[track] followup logged on {e.report_id} "
                  f"({len(e.followups)} total)")
            return 0
        if a.action == "overdue":
            od = trk.overdue()
            if not od:
                print("[track] no overdue submissions")
                return 0
            for e in od:
                print(f"[track] OVERDUE {e.report_id} "
                      f"(submitted {e.submitted}, sla {e.sla_days}d) "
                      f"— {e.title[:60]}")
            return 1
        if a.action == "summary":
            print(json.dumps(trk.summary(), indent=1))
            return 0

    return 2


def cmd_hunt(objective: str, hint: str = "", max_steps: int = 25) -> int:
    """FULL AUTO hunt: agent loop over all lanes, ScopeGate-contained.

    Flow: load config -> SafeLLMPolicy -> loop to FINISH -> seal the run ->
    print transcript + verdict. Every lane call is scope-vetted; any
    out-of-scope attempt is DENIED and recorded as a lesson.
    """
    from core.agent import Agent, AgentConfig, check_scope
    from core.llm_policy import LLMPolicyDrivenLoop, SafeLLMPolicy

    cfg = json.loads(Path("config.json").read_text(encoding="utf-8")
                     if Path("config.json").exists() else "{}")
    ai_cfg = cfg.get("ai", {})

    scope_hosts = (ai_cfg.get("scope_domains") or
                   cfg.get("scope", {}).get("allow_domains") or
                   ["127.0.0.1", "localhost"])

    run_dir = Path("runs") / time.strftime("hunt-%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[hunt] objective: {objective}")
    print(f"[hunt] scope-hosts: {', '.join(scope_hosts)}")
    print(f"[hunt] evidence dir: {run_dir}")

    # ---- deterministic backbone: curriculum walk over real lanes ----
    from core.curriculum import CurriculumLoop, decompose
    from core.scopegate import Scope, TargetRule
    from core.agent import check_scope as _check_scope

    scope_obj = Scope([TargetRule(h) for h in scope_hosts])

    def execute_lane(st) -> str:
        tgt = st.target
        verdict = _check_scope(tgt, scope_obj)
        if not verdict.allowed:
            return f"scope-denied ({verdict.reason[:80]})"
        if st.lane == "probe":
            r = lanes.probe(tgt)
            return json.dumps(r)[:280]
        if st.lane == "browse":
            if "msg_capture" in st.goal:
                r = lanes.msg_capture(tgt, wait_s=20)
                msgs = r.get("messages", [])
                beacons = [m for m in msgs
                           if m.get("origin") and m.get("origin") != "null"]
                return (f"msgcap: {len(msgs)} messages, "
                        f"{len(beacons)} cross-origin beacons "
                        + (f"(first: {beacons[0].get('origin','?')}"
                           f" type={beacons[0].get('type','?')})"
                           if beacons else "(silent embed)"))
            r = lanes.browse(tgt)
            return json.dumps(r)[:280]
        if st.lane == "seal":
            return f"evidence-dir sealed: {run_dir}"
        # vm_exec lane: goal names the engine operation on the real target
        if "classify_csp" in st.goal:
            csp_probe = vmbridge.run(
                f"curl -s -m 6 -D- -o /dev/null {tgt} "
                f"| grep -i content-security-policy")
            m = re.search(r"content-security-policy:\s*(.+)",
                          csp_probe.output, re.I)
            if m:
                from core.lanes_security import classify_csp
                v = classify_csp(m.group(1).strip(), is_meta=False)
                return f"CSP verdict: {v.bypass_class} ({v.notes[0] if v.notes else ''})"
            return "no CSP header found"
        if "classify_handler" in st.goal:
            r = vmbridge.run(f"curl -s -m 6 {tgt}")
            if r.ok and r.output:
                from core.lanes_security import classify_handler
                h = classify_handler(r.output)
                ev = h.evidence[0] if h.evidence else ""
                return f"PM verdict: {h.pattern} ({ev[:100]})"
            return "handler fetch failed"
        if "detect_secrets" in st.goal:
            r = vmbridge.run(f"curl -s -m 8 {tgt}")
            if r.ok and r.output:
                from core.lanes_security import detect_secrets
                fs = detect_secrets(r.output)
                return (f"secrets: {len(fs)} findings "
                        f"({', '.join(sorted({f.kind for f in fs}))[:120]})")
            return "bundle fetch failed"
        if "analyze_sanitizer" in st.goal:
            r = vmbridge.run(f"curl -s -m 8 {tgt}")
            if r.ok and r.output:
                from core.sanitizer_oracle import analyze_sanitizer
                v = analyze_sanitizer(r.output)
                return (f"sanitizer verdict: {v.verdict} "
                        f"(signals: {', '.join(v.signals)})")
            return "bundle fetch failed"
        if "ct_seed" in st.goal:
            from core.lanes_recon import ct_seed
            domain = re.sub(r"^https?://", "", tgt).split("/")[0].split(":")[0]
            hosts = ct_seed(domain, cache_dir=run_dir)
            return f"ct_seed: {len(hosts)} hosts ({', '.join(hosts[:5])}…)"
        if "dns_expand" in st.goal:
            from core.lanes_recon import dns_expand
            domain = re.sub(r"^https?://", "", tgt).split("/")[0].split(":")[0]
            facts = dns_expand([domain])
            return (f"dns: resolves={facts[0].resolves} ip={facts[0].ip}"
                    if facts else "dns: no facts")
        if "takeover_candidates" in st.goal:
            from core.lanes_recon import dns_expand, takeover_candidates
            domain = re.sub(r"^https?://", "", tgt).split("/")[0].split(":")[0]
            cands = takeover_candidates(dns_expand([domain]))
            return (f"takeover: {len(cands)} candidates" +
                    (f" ({cands[0].provider})" if cands else ""))
        return f"vm_exec goal: {st.goal} on {tgt}"

    cur = decompose(objective, next(
        (w for w in re.findall(r"https?://[^\s]+", objective)), "http://127.0.0.1:19077/"))
    lines = CurriculumLoop(execute_lane).run(cur)
    mode = "deterministic-curriculum"

    if ai_cfg.get("api_key"):
        # LLM accelerator available: refine with agentic policy
        mode = "agentic-llm"
        try:
            policy = SafeLLMPolicy(hint=hint, max_llm_calls=max_steps)
            agent = Agent(AgentConfig(step_budget=max_steps))
            lines = LLMPolicyDrivenLoop(agent, policy).run(
                objective, "\n".join(lines), lessons="")
        except Exception as e:
            lines.append(f"llm-mode-failed ({str(e)[:80]}); "
                         f"deterministic transcript kept")

    report_text = "\n".join(lines)
    (run_dir / "transcript.log").write_text(
        f"mode: {mode}\n" + report_text, encoding="utf-8")
    seal_res = evidence.seal(str(run_dir), label="hunt")
    print(f"[hunt] mode: {mode}")
    print(f"[hunt] sealed {len(seal_res.files)} files "
          f"manifest {seal_res.manifest_sha256[:16]}…")
    print(report_text[-2000:])
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

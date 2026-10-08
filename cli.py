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

Exit codes: 0 success, 1 lane/verification failure, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import sys
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

    return 2


if __name__ == "__main__":
    sys.exit(main())

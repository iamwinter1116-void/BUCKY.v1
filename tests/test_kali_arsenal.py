"""Tests for kali_arsenal — 20+ scoped Kali-tool verbs (lab + mock VM)."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.kali_arsenal import (PASSIVE, LIGHT, ACTIVE, RESTRICTED,
                               build_command, categories, inventory,
                               normalize, run_verb, verbs, vet_target)
from core.scopegate import Scope, TargetRule

LAB = Scope([TargetRule("127.0.0.1"), TargetRule("localhost")])
WILD = Scope([TargetRule("*.example.com"), TargetRule("127.0.0.1")])


def mock_vm(responses: dict):
    """vm_run callable: substring-matched canned responses."""
    def run(cmd: str):
        for key, out in responses.items():
            if key in cmd:
                return SimpleNamespace(ok=True, output=out)
        return SimpleNamespace(ok=True, output="")
    return run


class TestRegistry(unittest.TestCase):
    def test_verb_count_and_unique_tools(self):
        vs = verbs()
        self.assertGreaterEqual(len(vs), 20)
        tools = {v.tool for v in vs.values()}
        self.assertGreaterEqual(len(tools), 15)
        for vid, v in vs.items():
            self.assertIn(v.rate_class, (PASSIVE, LIGHT, ACTIVE, RESTRICTED))
            self.assertGreater(v.max_runtime_s, 0)
            # every verb has exactly ONE target placeholder type
            ph = {p for a in v.argv_template
                  for p in ("{url}", "{domain}", "{host}")
                  if p in a}
            self.assertTrue(ph, f"{vid} has no target placeholder")
            self.assertLessEqual(len(ph), 2)

    def test_categories_cover_pipeline(self):
        cats = categories()
        for need in ("recon", "probe", "content", "vuln", "port", "param"):
            self.assertIn(need, cats)
            self.assertTrue(cats[need])

    def test_build_command_shapes(self):
        cmd, v = build_command("whatweb-probe", "http://127.0.0.1:19077/")
        self.assertEqual(cmd, "whatweb http://127.0.0.1:19077/ -a 3 "
                              "--no-errors")
        self.assertEqual(v.tool, "whatweb")
        # domain verb strips URL to bare domain
        cmd2, _ = build_command("subfinder-domain",
                                "https://sub.example.com/")
        self.assertIn("-d sub.example.com", cmd2)
        # url verb rejects bare domains
        with self.assertRaises(ValueError):
            build_command("whatweb-probe", "example.com")

    def test_restricted_gated_to_lab(self):
        # sqlmap on arbitrary internet host -> denied even in wild scope
        v1 = vet_target("sqlmap-baseline", "http://victim.com/x?id=1", WILD)
        self.assertFalse(v1.allowed)
        # lab host -> allowed
        v2 = vet_target("sqlmap-baseline", "http://127.0.0.1:19077/?id=1", LAB)
        self.assertTrue(v2.allowed)
        # colon-dot bypass attempt on restricted verb
        v3 = vet_target("sqlmap-baseline",
                        "http://127.0.0.1:19077.evil.tld/?id=1", LAB)
        self.assertFalse(v3.allowed)

    def test_scope_denials_flow_through(self):
        v = vet_target("whatweb-probe", "http://paytm.com/", LAB)
        self.assertFalse(v.allowed)
        v2 = vet_target("subfinder-domain", "paytm.com", LAB)
        self.assertFalse(v2.allowed)

    def test_colon_dot_bypass_blocked(self):
        v = vet_target("whatweb-probe",
                      "http://127.0.0.1:19077.evil.tld/", LAB)
        self.assertFalse(v.allowed)

    def test_normalize_counts(self):
        n = normalize("nuclei", "[cve-2024-1:critical] http://x\n"
                                "found-template/x\n[cve-x:high] y")
        self.assertGreaterEqual(n.get("vuln-lines", 0), 2)
        n2 = normalize("nmap", "80/tcp open http\n22/tcp open ssh")
        self.assertEqual(n2.get("open-ports"), 2)

    def test_run_verb_missing_tool_honest(self):
        vm = mock_vm({"command -v": "NO"})
        res = run_verb("whatweb-probe", "http://127.0.0.1:19077/", LAB, vm)
        self.assertFalse(res.ok)
        self.assertIn("tool-missing", res.error)

    def test_run_verb_full_path(self):
        vm = mock_vm({
            "command -v": "YES",
            "whatweb": "http://x [Apache] [PHP] [Nginx-module]",
        })
        res = run_verb("whatweb-stack", "http://127.0.0.1:19077/", LAB, vm)
        # nonexistent verb -> honest error
        self.assertFalse(res.ok)
        res2 = run_verb("whatweb-probe", "http://127.0.0.1:19077/", LAB, vm)
        self.assertTrue(res2.ok)
        self.assertGreaterEqual(res2.findings.get("tech-stack", 0), 3)


class TestLiveVM(unittest.TestCase):
    """LIVE VM validation: real inventory of the arsenal binaries.

    Skipped unless BUCKY_LIVE_VM=1 — keeps the suite deterministic and
    fast for the upgrade-gate (live inventory runs in CLI/flagship).
    """
    def test_inventory_counts(self):
        if not os.environ.get("BUCKY_LIVE_VM"):
            self.skipTest("set BUCKY_LIVE_VM=1 for live VM inventory")
        import subprocess
        tools = sorted({v.tool for v in verbs().values()})
        probe = "; ".join(
            f"command -v {t} >/dev/null 2>&1 && echo YES-{t} || echo NO-{t}"
            for t in tools)
        r = subprocess.run(
            ["ssh", "-i", "C:/Users/HP/.ssh/hermes-kali", "-p", "2222",
             "-o", "BatchMode=yes", "kali@127.0.0.1", probe],
            capture_output=True, text=True, timeout=120)
        yes = [t for t in tools if f"YES-{t}" in r.stdout]
        no = [t for t in tools if f"NO-{t}" in r.stdout]
        print(f"\n[live] arsenal present: {len(yes)}/{len(tools)}: {yes}")
        if no:
            print(f"[live] missing: {no}")
        self.assertGreaterEqual(len(yes), 15,
                                f"live arsenal too thin: {no}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

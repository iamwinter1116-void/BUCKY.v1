"""Tests for v0.2 modules: skills, packer, scopegate extras."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.packer import PackResult, ReportDraft, pack
from core.skills import Skill, SkillLibrary, seed_from_notes


GOOD_DRAFT = ReportDraft(
    title="Reflected XSS in search parameter of example.com help widget",
    cwe="CWE-79",
    environment="Kali 2026.2, Firefox 150 headless via geckodriver 0.36; target: example.com help v2.3.1 (deps locked in evidence seal)",
    steps=[
        "Open https://example.com/help?q=%3Cscript%3E (one action, one named field). Expected: raw script tag reflected in response body, marker BUCKY-XSS present.",
        "Submit the same payload via the PoC request below. Expected: HTTP 200 with the marker string echoed unescaped.",
    ],
    poc="curl -sk 'https://example.com/help?q=%3Csvg%20onload%3DbuckyMark%3E' | grep -c buckyMark ; expected: 1",
    impact="An attacker crafts a link that executes JavaScript in the victim's session on example.com, letting them perform actions as the victim and read victim-scoped data, turning a reflected input into full session-impersonation.",
    remediation="HTML-encode the q parameter on output and add a nonce-based CSP.",
    evidence_seals=["evidence/example-xss/MANIFEST.json sha256:ab12..."],
    references=["https://example.com/help"],
)


class TestPacker(unittest.TestCase):
    """The report engine gates (R1-R10 + rejection taxonomy)."""

    def test_good_draft_packs(self):
        r = pack(GOOD_DRAFT)
        self.assertTrue(r.ok, r.problems)
        self.assertIn("## Impact", r.rendered)
        self.assertIn("CWE-79", r.rendered)

    def test_missing_oracle_rejected(self):
        bad = ReportDraft(**{**GOOD_DRAFT.__dict__})
        bad.steps = ["step without oracle"]
        r = pack(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("R4" in p for p in r.problems))

    def test_thin_impact_rejected(self):
        bad = ReportDraft(**{**GOOD_DRAFT.__dict__})
        bad.impact = "it is bad"
        r = pack(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("R7" in p for p in r.problems))

    def test_taxonomy_pre_flight_hits(self):
        bad = ReportDraft(**{**GOOD_DRAFT.__dict__})
        bad.impact = ("This behavior of the third-party service is by design "
                      "and only a minor cosmetic issue for the session "
                      "impersonation chain described above in detail.")
        r = pack(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("taxonomy-hit" in p for p in r.problems))


class TestSkillLibrary(unittest.TestCase):
    """Skill CRUD, retrieval, admission gate."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lib = SkillLibrary(Path(self.tmp.name) / "skills")

    def tearDown(self):
        self.tmp.cleanup()

    def test_unverified_refused(self):
        s = Skill(name="ssh-empty", description="d", trigger="t",
                  cause="c", corrected_action="a")
        self.assertFalse(self.lib.add(s))
        self.assertIsNone(self.lib.get("ssh-empty"))

    def test_verified_admitted_and_retrieved(self):
        s = Skill(name="port-leftover", description="test server port already bound blocks rebind",
                  trigger="port bind fails address in use", cause="leftover listener",
                  corrected_action="fuser -k <port>/tcp", verified=True)
        self.assertTrue(self.lib.add(s))
        hits = self.lib.retrieve("port already in use bind", top_k=3)
        self.assertEqual(hits[0].name, "port-leftover")

    def test_admission_gate_requires_two_passes(self):
        cand = Skill(name="retry-lane", description="d", trigger="t",
                     cause="c", corrected_action="a")
        self.assertFalse(self.lib.admit(cand, [True]))          # 1 task only
        self.assertFalse(self.lib.admit(cand, [True, False]))  # not all pass
        self.assertTrue(self.lib.admit(cand, [True, True]))     # >=2 passes
        self.assertIsNotNone(self.lib.get("retry-lane"))

    def test_seed_from_notes(self):
        notes = (
            "ssh returns empty -> tmux pane index shifted: capture by session name\n"
            "browser lane hangs -> zygote crash on chromium 150: use firefox+geckodriver\n"
            "line without arrows should be ignored\n"
        )
        n = seed_from_notes(notes, self.lib)
        self.assertEqual(n, 2)
        self.assertIsNotNone(self.lib.get("ssh-returns-empty"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

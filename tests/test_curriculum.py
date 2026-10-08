"""Tests for curriculum (Voyager tier-3 decomposition + admission gate)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.curriculum import (Curriculum, SubTask, admit_skill,
                             completion_report, decompose)
from core.skills import Skill, SkillLibrary


class TestDecompose(unittest.TestCase):
    def test_csp_objective_gets_csp_plan(self):
        cur = decompose("audit the CSP of the target", "https://x.example")
        self.assertEqual(len(cur.subtasks), 3)
        self.assertEqual(cur.subtasks[0].lane, "probe")
        self.assertTrue(all("{target}" not in s.target for s in cur.subtasks))

    def test_pm_objective(self):
        cur = decompose("postMessage handler audit", "https://x.example")
        lanes = [s.lane for s in cur.subtasks]
        self.assertEqual(lanes, ["probe", "vm_exec", "browse", "seal"])

    def test_recon_objective(self):
        cur = decompose("subdomain takeover recon", "example.com")
        self.assertEqual(len(cur.subtasks), 4)
        self.assertEqual(cur.subtasks[0].goal, "ct_seed(target)")
        self.assertTrue(all(s.target == "example.com" for s in cur.subtasks))

    def test_secrets_objective(self):
        cur = decompose("sweep for leaked api keys", "https://x.example")
        self.assertEqual(cur.subtasks[0].lane, "vm_exec")

    def test_report_objective(self):
        cur = decompose("write up the report", "runs/")
        self.assertEqual(cur.subtasks[0].lane, "vm_exec")

    def test_unknown_defaults_recon(self):
        cur = decompose("generic thing", "example.com")
        self.assertEqual(len(cur.subtasks), 4)  # recon default plan


class TestCurriculumWalk(unittest.TestCase):
    def test_next_and_done(self):
        cur = Curriculum("obj", [SubTask("a", "probe", "t", "g"),
                                  SubTask("b", "seal", "t", "g")])
        self.assertIsNotNone(cur.next())
        self.assertIsNotNone(cur.next())
        self.assertIsNone(cur.next())
        self.assertTrue(cur.done())


class TestAdmission(unittest.TestCase):
    def test_unverified_skill_rejected(self):
        lib = SkillLibrary(Path(tempfile.mkdtemp()))
        sk = Skill(name="x", description="d", trigger="trig x",
                   cause="c", corrected_action="a")
        admitted, why = admit_skill(lib, sk, verifier=lambda s: [False, False])
        self.assertFalse(admitted)
        self.assertIn("verification failed", why)

    def test_verified_skill_admitted(self):
        lib = SkillLibrary(Path(tempfile.mkdtemp()))
        sk = Skill(name="x", description="d", trigger="trig x",
                   cause="c", corrected_action="a")
        admitted, why = admit_skill(lib, sk, verifier=lambda s: [True, True])
        self.assertTrue(admitted)
        self.assertIn("admitted", why)

    def test_duplicate_name_rejected(self):
        lib = SkillLibrary(Path(tempfile.mkdtemp()))
        sk = Skill(name="x", description="d", trigger="trig x",
                   cause="c", corrected_action="a")
        admit_skill(lib, sk, verifier=lambda s: [True, True])
        sk2 = Skill(name="x", description="d2", trigger="trig x",
                    cause="c", corrected_action="a")
        admitted, why = admit_skill(lib, sk2, verifier=lambda s: [True, True])
        self.assertFalse(admitted)
        self.assertIn("duplicate", why)

    def test_same_trigger_different_name_allowed(self):
        lib = SkillLibrary(Path(tempfile.mkdtemp()))
        sk = Skill(name="x", description="d", trigger="trig x",
                   cause="c", corrected_action="a")
        admit_skill(lib, sk, verifier=lambda s: [True, True])
        sk2 = Skill(name="y", description="d", trigger="trig x",
                    cause="c", corrected_action="a2")
        admitted, _ = admit_skill(lib, sk2, verifier=lambda s: [True, True])
        self.assertTrue(admitted)

    def test_short_verification_rejected(self):
        lib = SkillLibrary(Path(tempfile.mkdtemp()))
        sk = Skill(name="z", description="d", trigger="trig z",
                   cause="c", corrected_action="a")
        admitted, why = admit_skill(lib, sk, verifier=lambda s: [True])
        self.assertFalse(admitted)
        self.assertIn(">=2", why)


class TestReport(unittest.TestCase):
    def test_completion_report_shape(self):
        cur = decompose("csp audit", "https://t")
        while cur.next():
            pass
        rep = completion_report(cur, ["ok", "ok", "ok"])
        self.assertIn("COMPLETE", rep)
        self.assertIn("subtasks: 3 completed: 3", rep)


if __name__ == "__main__":
    unittest.main(verbosity=2)

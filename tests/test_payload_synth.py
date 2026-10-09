"""Payload-synthesis tests — Z3 string theory + fallback honesty."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.payload_synth import (synth_deeplink_payload, synth_xss_marker_payload,
                                synth_session_leak_probe)
from core.proof_gate import z3_available


class TestPayloadSynth(unittest.TestCase):
    def test_xss_marker_payload_materialized(self):
        p = synth_xss_marker_payload("ZZMARK9X")
        self.assertIn("ZZMARK9X", p.payload)
        self.assertIn("onerror", p.payload)
        if z3_available():
            self.assertTrue(p.proven)
            self.assertEqual(p.method, "z3-string-theory")
        else:
            self.assertFalse(p.proven)
            self.assertEqual(p.method, "template-fallback")

    def test_xss_no_double_quotes(self):
        p = synth_xss_marker_payload()
        self.assertNotIn('"', p.payload)

    def test_deeplink_payload_shape(self):
        p = synth_deeplink_payload("appx", "mini", "launch", "victim-7")
        self.assertIn("appx://mini?launch=", p.payload)
        self.assertIn("data=", p.payload)

    def test_deeplink_attacker_ref_provable(self):
        p = synth_deeplink_payload("appx", "mini", "launch", "v")
        if z3_available():
            self.assertTrue(p.proven)
            self.assertIn("attacker-", p.payload)
        else:
            self.assertFalse(p.proven)

    def test_secret_probe_regex_oracle(self):
        p = synth_session_leak_probe()
        self.assertTrue(p.proven)
        self.assertIn("AKIA", p.payload)
        self.assertIn("ghp_", p.payload)

    def test_fallback_is_honest_candidate(self):
        """Without z3 the payload must be marked candidate-only."""
        p = synth_xss_marker_payload("M1")
        if not z3_available():
            self.assertIn("candidate", p.detail)

    def test_deterministic_re_run(self):
        a = synth_xss_marker_payload("FIXED1")
        b = synth_xss_marker_payload("FIXED1")
        self.assertEqual(a.payload, b.payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)

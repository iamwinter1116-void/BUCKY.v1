"""Coverage-matrix tests — 98-count, two-metric, CWE axis."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.coverage import (CWE_TOP25, WSTG_CATEGORIES, WSTG_TOTAL,
                           CoverageReport)


class TestCoverage(unittest.TestCase):
    def test_wstg_total_official_98(self):
        """Agent-K verified: official checklist.json = 98 objectives."""
        self.assertEqual(WSTG_TOTAL, 98)
        self.assertEqual(len(WSTG_CATEGORIES), 12)
        self.assertEqual(WSTG_CATEGORIES["CONF"][1], 11)
        self.assertEqual(WSTG_CATEGORIES["ATHZ"][1], 4)
        self.assertEqual(WSTG_CATEGORIES["APIT"][1], 1)

    def test_cwe_top25_axis(self):
        self.assertEqual(len(CWE_TOP25), 25)
        self.assertEqual(CWE_TOP25[0][0], "CWE-79")
        self.assertEqual(CWE_TOP25[0][2], 56.92)
        self.assertEqual(CWE_TOP25[-1][0], "CWE-306")
        # scores descending
        scores = [s for _c, _n, s in CWE_TOP25]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_two_metric_oracle_gaps(self):
        rep = CoverageReport()
        rep.record_touched("WSTG-CONF-07")
        rep.record_oracled("WSTG-SESS-02")
        gaps = rep.oracle_gaps()
        self.assertIn("WSTG-CONF-07", gaps)   # touched not oracled
        self.assertNotIn("WSTG-SESS-02", gaps)  # oracled implies touched
        # untouched objectives never appear as gaps
        self.assertNotIn("WSTG-APIT-01", gaps)

    def test_cwe_gap_list(self):
        rep = CoverageReport()
        gaps = rep.cwe_gaps(covered_cwes={"CWE-79", "CWE-89"})
        self.assertEqual(len(gaps), 23)
        self.assertNotIn("CWE-79", gaps)

    def test_render_cwe_axis(self):
        txt = CoverageReport().render_cwe_axis({"CWE-352"})
        self.assertIn("CWE-352", txt)
        self.assertIn("covered 1/25", txt)

    def test_gap_backlog_prioritized(self):
        from core.coverage import next_build_backlog
        backlog = next_build_backlog()
        self.assertTrue(backlog)
        self.assertTrue(all(e.status == "gap" for e in backlog))


if __name__ == "__main__":
    unittest.main(verbosity=2)

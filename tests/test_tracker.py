"""Tests for the submission tracker (campaign-loop SLA watch)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.tracker import ReportEntry, Tracker


def _tracker(tmp: Path) -> Tracker:
    return Tracker.load(tmp / "tracker.json")


class TestTracker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = _tracker(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_and_persist(self):
        e = self.t.add(ReportEntry(report_id="R7",
                                   title="Freshdesk tenant takeover",
                                   program="paytm"))
        self.assertEqual(e.status, "submitted")
        t2 = _tracker(Path(self.tmp.name))  # reload from disk
        self.assertIn("R7", t2.entries)
        self.assertEqual(t2.entries["R7"].title,
                         "Freshdesk tenant takeover")

    def test_status_update_and_notes(self):
        self.t.add(ReportEntry(report_id="R2", title="x"))
        self.t.update_status("R2", "accepted", "triager confirmed")
        e = self.t.entries["R2"]
        self.assertEqual(e.status, "accepted")
        self.assertTrue(any("triager confirmed" in n for n in e.notes))

    def test_followup_appends(self):
        self.t.add(ReportEntry(report_id="R3", title="y"))
        self.t.followup("R3", "sent reminder")
        self.assertEqual(len(self.t.entries["R3"].followups), 1)

    def test_overdue_detection(self):
        self.t.add(ReportEntry(report_id="R1", title="old",
                               submitted="2026-10-01 10:00", sla_days=7))
        self.t.add(ReportEntry(report_id="R2", title="fresh",
                               submitted="2026-10-08 10:00", sla_days=7))
        od = self.t.overdue(now="2026-10-10 10:00")
        ids = [e.report_id for e in od]
        self.assertIn("R1", ids)      # 9 days elapsed > 7
        self.assertNotIn("R2", ids)  # 2 days elapsed

    def test_accepted_not_overdue(self):
        self.t.add(ReportEntry(report_id="R5", title="z",
                                submitted="2026-10-01 10:00", sla_days=7))
        self.t.update_status("R5", "triaged")
        self.assertEqual(self.t.overdue(now="2026-10-10 10:00"), [])

    def test_summary_counts(self):
        self.t.add(ReportEntry(report_id="A", title="1"))
        self.t.add(ReportEntry(report_id="B", title="2"))
        self.t.update_status("B", "accepted")
        s = self.t.summary()
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["accepted"], 1)
        self.assertEqual(s["submitted"], 1)

    def test_corrupt_tracker_never_crashes(self):
        p = Path(self.tmp.name) / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        t = Tracker.load(p)
        self.assertEqual(t.entries, {})

    def test_unknown_id_raises(self):
        with self.assertRaises(KeyError):
            self.t.update_status("NOPE", "accepted")


if __name__ == "__main__":
    unittest.main(verbosity=2)

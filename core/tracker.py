"""BUCKY tracker — submission/SLA watch (campaign-loop closer).

Research basis (SYNTHESIS-D): the biggest real-world triage factors are
PoC reproducibility and response-latency norms (7-day medians on major
programs). This module tracks every submitted report: status, SLA
window, follow-up escalation state — the operational discipline that a
long campaign needs (16-report Paytm arc proved it).

Contract: one JSON file (tracker.json in the repo-root or given path);
every mutation is atomic (temp+replace) and idempotent.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_PATH = Path("tracker.json")


@dataclass
class ReportEntry:
    report_id: str          # e.g. "R7"
    title: str
    program: str = ""
    submitted: str = ""     # ISO-ish timestamp "YYYY-MM-DD HH:MM"
    sla_days: int = 7
    status: str = "submitted"   # submitted|triaged|accepted|duplicate|
                                # rejected|fixed|withdrawn
    severity: str = ""       # reported severity
    cwe: str = ""
    last_update: str = ""
    followups: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Tracker:
    path: Path
    entries: dict[str, ReportEntry] = field(default_factory=dict)

    # ------------------------------------------------------------------ io
    @classmethod
    def load(cls, path: Path | str | None = None) -> "Tracker":
        p = Path(path) if path else DEFAULT_PATH
        t = cls(p)
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                for rid, e in raw.get("entries", {}).items():
                    e.setdefault("report_id", rid)
                    t.entries[rid] = ReportEntry(**{
                        k: v for k, v in e.items()
                        if k in ReportEntry.__dataclass_fields__})
            except (json.JSONDecodeError, TypeError):
                # corrupt tracker must never crash the campaign
                t.entries = {}
        return t

    def save(self) -> None:
        data = {"entries": {k: asdict(v) for k, v in self.entries.items()}}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # ------------------------------------------------------------- actions
    def add(self, e: ReportEntry) -> ReportEntry:
        e.report_id = e.report_id or f"R{len(self.entries)+1}"
        e.submitted = e.submitted or time.strftime("%Y-%m-%d %H:%M")
        e.last_update = e.submitted
        self.entries[e.report_id] = e
        self.save()
        return e

    def update_status(self, report_id: str, status: str,
                      note: str = "") -> ReportEntry:
        e = self._get(report_id)
        object.__setattr__ if False else None  # (dataclass is mutable)
        e.status = status
        e.last_update = time.strftime("%Y-%m-%d %H:%M")
        if note:
            e.notes.append(f"{e.last_update}: {note}")
        self.save()
        return e

    def followup(self, report_id: str, text: str) -> ReportEntry:
        e = self._get(report_id)
        e.followups.append(time.strftime("%Y-%m-%d %H:%M") + ": " + text)
        e.last_update = time.strftime("%Y-%m-%d %H:%M")
        self.save()
        return e

    def _get(self, report_id: str) -> ReportEntry:
        if report_id not in self.entries:
            raise KeyError(f"unknown report-id {report_id}")
        return self.entries[report_id]

    # -------------------------------------------------------------- views
    def overdue(self, now: str | None = None) -> list[ReportEntry]:
        """Reports inside SLA-window that have had NO triage response."""
        now_t = time.mktime(time.strptime(now, "%Y-%m-%d %H:%M")) \
            if now else time.time()
        out: list[ReportEntry] = []
        for e in self.entries.values():
            if e.status != "submitted":
                continue
            try:
                sub_t = time.mktime(
                    time.strptime(e.submitted, "%Y-%m-%d %H:%M"))
            except ValueError:
                continue
            elapsed_days = (now_t - sub_t) / 86400
            if elapsed_days > e.sla_days:
                out.append(e)
        return sorted(out, key=lambda x: x.report_id)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entries.values():
            counts[e.status] = counts.get(e.status, 0) + 1
        counts["total"] = len(self.entries)
        return counts

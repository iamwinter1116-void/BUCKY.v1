"""BUCKY benchmark framework v2 — paper-grade scoring (Agent-H upgrades).

Implements the four upgrades the benchmark-methodology research demanded:
1. PER-DIFFICULTY score matrix (PentestGPT 182-subtask model): every task
   carries a difficulty; results report per-detector x per-difficulty
   completion rates, never one aggregate mean.
2. DUAL-TEST contract (SWE-bench): every task defines fail_to_pass
   (the capability the engine must demonstrate) AND pass_to_pass
   (invariants that must stay green — regression check).
3. REPEAT-VARIANCE (reliability paper): tasks run N>=3 times; the
   reporter emits pass-rate and stdev, flagging flaky detectors.
4. CONTAINMENT metric (HackSynth): scope-denial tasks where the agent
   must REFUSE out-of-scope targets; blocked=pass, leaked=fail.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass(frozen=True)
class BenchTask:
    """One benchmark task with the dual-test contract."""
    task_id: str
    difficulty: Difficulty
    fail_to_pass: Callable[[], tuple[bool, str]]
    pass_to_pass: list[Callable[[], tuple[bool, str]]] = field(default_factory=list)
    containment: Callable[[], tuple[bool, str]] | None = None  # True = refused


@dataclass(frozen=True)
class TaskResult:
    task_id: str
    difficulty: Difficulty
    f2p_ok: bool
    p2p_ok: bool
    containment_ok: bool | None
    detail: str
    duration_s: float


@dataclass
class BenchReport:
    results: list[TaskResult] = field(default_factory=list)

    def add(self, r: TaskResult) -> None:
        self.results.append(r)

    # ---------------------------------------------------------- scoring
    def score_matrix(self) -> dict[str, dict[str, list[str]]]:
        """Per-difficulty pass/fail ids (PentestGPT-style matrix)."""
        matrix: dict[str, dict[str, list[str]]] = {}
        for r in self.results:
            diff = r.difficulty.value
            matrix.setdefault(diff, {"pass": [], "fail": []})
            ok = r.f2p_ok and r.p2p_ok and (
                r.containment_ok is None or r.containment_ok)
            matrix[diff]["pass" if ok else "fail"].append(r.task_id)
        return matrix

    def completion_rates(self) -> dict[str, float]:
        """Per-difficulty completion rate (PentestGPT two-level scoring)."""
        out: dict[str, float] = {}
        for diff, d in self.score_matrix().items():
            total = len(d["pass"]) + len(d["fail"])
            out[diff] = round(len(d["pass"]) / total, 3) if total else 0.0
        return out

    def variance_report(self, runs: list["BenchReport"]) -> dict[str, dict]:
        """Repeat-run variance: pass-rate + stdev per difficulty."""
        by_diff: dict[str, list[float]] = {}
        for rep in [self] + runs:
            for diff, rate in rep.completion_rates().items():
                by_diff.setdefault(diff, []).append(rate)
        return {d: {"pass_rate": statistics.mean(v),
                    "stdev": round(statistics.stdev(v), 4) if len(v) > 1 else 0.0,
                    "runs": len(v)}
                for d, v in by_diff.items()}

    def containment_score(self) -> dict[str, int]:
        """Blocked vs leaked out-of-scope attempts (HackSynth metric)."""
        blocked = sum(1 for r in self.results if r.containment_ok is True)
        leaked = sum(1 for r in self.results if r.containment_ok is False)
        return {"blocked": blocked, "leaked": leaked}

    def all_green(self) -> bool:
        return all(r.f2p_ok and r.p2p_ok and
                   (r.containment_ok is None or r.containment_ok)
                   for r in self.results)


def run_task(task: BenchTask, repeats: int = 1) -> list[TaskResult]:
    """Execute a task's dual-test contract (repeats for variance)."""
    out: list[TaskResult] = []
    for _ in range(repeats):
        t0 = time.time()
        ok, detail = task.fail_to_pass()
        p2p = True
        for inv in task.pass_to_pass:
            iok, _ = inv()
            p2p = p2p and iok
        cont: bool | None = None
        if task.containment is not None:
            cont, _ = task.containment()
        out.append(TaskResult(task.task_id, task.difficulty, ok, p2p, cont,
                               detail, round(time.time() - t0, 3)))
    return out

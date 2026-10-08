"""BUCKY agent — the 3-tier production loop.

Architecture (paper-backed, see research/MEGA-SYNTHESIS-ARCHITECTURE.md):
- TIER-1 inner: ReAct — THINK -> ACT -> OBSERVE over typed lane verbs,
  verbatim observations only, step budget, repetition guard (47% failure mode).
- TIER-2 outer: Reflexion — deterministic Evaluator (markers, exit codes,
  self-generated check scripts), on failure a verbal lesson into a last-3
  ring buffer, lane reset, retry up to max_trials.
- TIER-3 lifelong: Voyager — curriculum proposes tasks from completed/failed
  log; skills are VERIFIED programs admitted only after demonstrated gain.

Safety invariants (implemented, not promised):
- The policy (LLM or deterministic mock) NEVER emits raw shell. It emits a
  typed Action. scopegate validates every action's target before render.
- Every decision is logged in the cycle transcript [lane(args) -> result]
  (Toolformer contract) so accumulated runs are a self-supervised corpus.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol

from .scopegate import Scope, ScopeDenied, check_scope


class ActionKind(str, Enum):
    """The complete action space. Tiny on purpose (SWE-agent ACI rule 1)."""
    VM_EXEC = "vm_exec"            # run a whitelisted tool command on Kali
    BROWSE = "browse"               # headless-firefox open (gentle, single load)
    PROBE = "probe"                 # single-GET inspector
    SEAL = "seal"                   # SHA-seal an evidence dir
    FINISH = "finish"               # emit the report / conclude


@dataclass(frozen=True)
class Action:
    """A typed, scope-checkable action. No raw shell anywhere."""
    kind: ActionKind
    args: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        a = ", ".join(f"{k}={str(v)[:60]!r}" for k, v in self.args.items())
        return f"{self.kind.value}({a})"


@dataclass(frozen=True)
class Observation:
    """Verbatim lane output. The ONLY trusted facts in the loop (ReAct)."""
    text: str
    ok: bool
    exit_code: int | None = None


@dataclass
class Thought:
    """A logged reasoning step (first-class artifact, per ReAct)."""
    text: str


class Policy(Protocol):
    """A policy maps (task, transcript) -> next Thought or Action.

    Two implementations ship: MockPolicy (deterministic, benchmark-grade)
    and LLMPolicy (any OpenAI-compatible endpoint, config.ai)."""

    def next_step(self, task: str, transcript: list[str],
                  state: str) -> Thought | Action: ...


@dataclass
class AgentConfig:
    """Loop tuning. Defaults from the ablation numbers in the research."""
    max_steps: int = 25            # SWE-agent: successes median 12, failures 21
    max_trials: int = 4            # Reflexion: retry budget per task
    reflection_window: int = 3      # Reflexion: last-3 lessons in context
    recent_observations: int = 5   # SWE-agent: keep last-5 verbatim
    repeat_guard: int = 2          # ReAct: 47% failure = repeated thought+action


@dataclass
class CycleResult:
    """The outcome of one full task run."""
    task: str
    success: bool
    transcript: list[str]
    lessons: list[str]
    steps: int
    trials: int
    duration_s: float


class Agent:
    """The production loop. Lane functions are injected (testable, no I/O in ctor)."""

    def __init__(self, policy: Policy, lanes: dict[str, Callable[..., Observation]],
                 scope: Scope, cfg: AgentConfig | None = None,
                 transcript_dir: Path | None = None) -> None:
        if ActionKind.VM_EXEC.value not in lanes:
            raise ValueError("lanes must include vm_exec")
        self.policy = policy
        self.lanes = lanes
        self.scope = scope
        self.cfg = cfg or AgentConfig()
        self.transcript_dir = transcript_dir
        self._ring: list[str] = []      # Reflexion lessons (last-N)
        self._recent: list[str] = []    # recent observations verbatim
        self._older: list[str] = []     # older observations, one-liners

    # ---------------------------------------------------------------- helpers
    def _log(self, entry: str) -> None:
        self.transcript.append(entry)
        if self.transcript_dir:
            p = Path(self.transcript_dir) / f"cycle-{uuid.uuid4().hex[:8]}.jsonl"
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps({"t": time.time(), "e": entry}) + "\n")

    def _compact(self) -> str:
        """SWE-agent compaction: last-5 observations verbatim, older one-line."""
        parts = [*self._older, *self._recent]
        return "\n".join(parts[-(self.cfg.recent_observations + len(self._older)):])

    def _scope_check(self, action: Action) -> None:
        """Gate every action's target against the engagement scope."""
        if action.kind in (ActionKind.VM_EXEC, ActionKind.PROBE, ActionKind.BROWSE):
            target = action.args.get("target") or action.args.get("url") or ""
            if target:
                verdict = check_scope(str(target), self.scope)
                if not verdict.allowed:
                    raise ScopeDenied(verdict.reason)
            else:
                raise ScopeDenied(f"{action.kind.value}: missing target")
        # SEAL / FINISH have no target — allowed by construction

    # ---------------------------------------------------------------- loop
    def run(self, task: str, evaluate: Callable[[str, list[str]], bool]) -> CycleResult:
        """Run the full tiered loop on one task.

        Args:
            task: natural-language objective.
            evaluate: deterministic Evaluator (marker checks, exit codes,
                check scripts). Signature: (task, transcript) -> bool.

        Returns:
            CycleResult with success flag, full transcript, lessons, cost.
        """
        t0 = time.time()
        transcript: list[str] = []
        lessons: list[str] = []
        self._ring.clear()
        self._recent.clear()
        self._older.clear()
        steps_total = 0

        for trial in range(1, self.cfg.max_trials + 1):
            self._recent.clear()
            steps = 0
            last_pair: tuple[str, str] | None = None
            repeat_hits = 0

            while steps < self.cfg.max_steps:
                state = "\n".join(self._ring) if self._ring else "(no lessons)"
                step = self.policy.next_step(task, self._compact(), state)

                if isinstance(step, Thought):
                    transcript.append(f"THINK: {step.text}")
                    continue  # thoughts do not consume the step budget

                # repetition guard (ReAct's dominant failure)
                pair = (step.summary(),)
                key = step.summary()
                if last_pair and key == last_pair[0]:
                    repeat_hits += 1
                    if repeat_hits >= self.cfg.repeat_guard:
                        lesson = (f"repetition detected: {key}; "
                                  f"forcing lane switch")
                        self._ring.append(lesson)
                        lessons.append(lesson)
                        self._ring = self._ring[-self.cfg.reflection_window:]
                        break
                else:
                    repeat_hits = 0
                last_pair = (key,)

                if step.kind == ActionKind.FINISH:
                    transcript.append(f"ACT: {key} -> finished")
                    ok = evaluate(task, transcript)
                    return CycleResult(task, ok, transcript, lessons,
                                       steps_total + steps, trial,
                                       time.time() - t0)

                # scope gate
                try:
                    self._scope_check(step)
                except ScopeDenied as e:
                    transcript.append(f"DENIED: {e.reason}")
                    lesson = f"scope-denied: {e.reason}"
                    self._ring.append(lesson)
                    lessons.append(lesson)
                    self._ring = self._ring[-self.cfg.reflection_window:]
                    steps += 1
                    continue

                lane = self.lanes.get(step.kind.value)
                if lane is None:
                    transcript.append(f"ACT-FAIL: no lane {step.kind.value}")
                    steps += 1
                    continue

                obs = lane(**step.args)
                transcript.append(f"ACT: {key} -> ok={obs.ok} "
                                  f"exit={obs.exit_code}")
                self._push_obs(obs.text)
                steps += 1
                steps_total += 1

            # trial exhausted the step budget
            ok = evaluate(task, transcript)
            if ok:
                return CycleResult(task, True, transcript, lessons,
                                   steps_total, trial, time.time() - t0)
            # Reflexion: generate a lesson and retry
            lesson = self._reflect(task, transcript)
            lessons.append(lesson)
            self._ring.append(lesson)
            self._ring = self._ring[-self.cfg.reflection_window:]
            transcript.append(f"REFLECT: {lesson}")

        ok = evaluate(task, transcript)
        return CycleResult(task, ok, transcript, lessons,
                           steps_total, self.cfg.max_trials, time.time() - t0)

    # ---------------------------------------------------------------- pieces
    def _push_obs(self, text: str) -> None:
        if len(self._recent) >= self.cfg.recent_observations:
            one = text.strip().splitlines()[0][:100] if text.strip() else "(empty)"
            self._older.append(one)
            self._older = self._older[-20:]
        self._recent.append(text[:2000])

    def _reflect(self, task: str, transcript: list[str]) -> str:
        """Deterministic reflection (no LLM required): last denial/failure."""
        denies = [t for t in transcript if t.startswith("DENIED")]
        fails = [t for t in transcript if "ACT-FAIL" in t or "-> ok=False" in t]
        if denies:
            return f"trial failed; last scope denial: {denies[-1][:120]}"
        if fails:
            return f"trial failed; last lane failure: {fails[-1][:120]}"
        return "trial exhausted step budget without finishing"


class MockPolicy:
    """Deterministic scripted policy for benchmarks (no LLM needed).

    The engine must pass its benchmark suite with the MockPolicy BEFORE
    any LLM is attached — the honesty gate: lanes+loop are proven correct
    independent of model quality.
    """

    def __init__(self, script: list[Thought | Action]) -> None:
        self.script = list(script)
        self._i = 0

    def next_step(self, task: str, transcript: list[str],
                  state: str) -> Thought | Action:
        if self._i >= len(self.script):
            return Action(ActionKind.FINISH, {"report": task})
        step = self.script[self._i]
        self._i += 1
        return step

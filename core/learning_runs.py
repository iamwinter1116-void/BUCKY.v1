"""BUCKY learning-from-runs — closes the self-learning loop operationally.

After every hunt run, this module mines the transcript for REPEATABLE
lessons and (when the operator confirms) proposes registry upgrades:

  transcript -> observations -> candidate lessons -> dedup-vs-library
             -> [operator-confirmed] -> attempt_upgrade -> sealed

Hermes-style: the engine gets BETTER at THIS operator's targets with
every run. Every upgrade still passes the 3-gate benchmark; nothing
self-modifies silently.

Research basis: Reflexion ring (last-3 lessons), Toolformer corpus
([lane(args) -> result] transcripts), Voyager admission (>=2 passes).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .learning import attempt_upgrade
from .registry import PatternRegistry, SecretPattern


@dataclass(frozen=True)
class Lesson:
    text: str
    source: str  # run-id / transcript line
    occurrences: int = 1


@dataclass
class RunMiner:
    """Mines hunt-transcripts for repeatable lessons."""
    lessons: list[Lesson] = field(default_factory=list)

    _PATTERNS: tuple[tuple[str, str], ...] = (
        (r"scope-denied", "scope-denied target requested again"),
        (r"fetch failed", "lane fetch failed once (transient?)"),
        (r"verdict: UNKNOWN", "detector returned UNKNOWN (needs evidence)"),
        (r"FAILED:", "subtask failed (lane error)"),
        (r"no CSP header", "no CSP header on target (record-shape)"),
    )

    def mine(self, transcript: str, source: str = "run") -> list[Lesson]:
        """Extract lessons from one transcript (dedup by pattern)."""
        found: list[Lesson] = []
        for pat, desc in self._PATTERNS:
            hits = len(re.findall(pat, transcript))
            if hits:
                found.append(Lesson(f"{desc} (x{hits})", source, hits))
        self.lessons.extend(found)
        return found

    def top_lessons(self, n: int = 5) -> list[Lesson]:
        """Most-occurring lessons first (Reflexion ring = last-3 window)."""
        agg: dict[str, Lesson] = {}
        for l in self.lessons:
            key = l.text.split(" (x")[0]
            if key in agg:
                agg[key] = Lesson(key, l.source, agg[key].occurrences + 1)
            else:
                agg[key] = Lesson(key, l.source, l.occurrences)
        return sorted(agg.values(), key=lambda x: -x.occurrences)[:n]


def propose_from_lesson(lesson: Lesson) -> SecretPattern | None:
    """Bridge: a lesson about a NEW credential shape -> candidate pattern.

    The lesson text must name an anchor we can generalize (e.g. 'saw
    publishableAccessToken shape'); otherwise None (not every lesson
    is a pattern lesson — that honesty stays).
    """
    m = re.search(r"anchor[:=]\s*([a-z_]+)", lesson.text, re.I)
    if not m:
        return None
    anchor = m.group(1).lower()
    regex = (r"(?i)(?:" + anchor.replace("_", r"[_-]?") +
             r")[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/_=-]{16,80})[\"']")
    return SecretPattern(id=f"lesson-{anchor}", kind=f"lesson-{anchor}",
                          regex=regex)


def confirm_upgrade(registry: PatternRegistry, candidate: SecretPattern,
                    evidence: str, benign: str,
                    repo_root: Path | None = None) -> tuple[bool, str]:
    """Operator-confirmed upgrade path (wraps attempt_upgrade)."""
    verdict = attempt_upgrade(registry, candidate, evidence, benign,
                              repo_root=repo_root)
    return verdict.applied, "; ".join(verdict.reasons)

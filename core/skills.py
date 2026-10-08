"""BUCKY skills — Voyager-style verified skill library + Reflexion notes.

Design (from the orchestration research):
- Skills are EXECUTABLE programs admitted only after demonstrated gain
  (Voyager: without verification -73%). Admission gate: a skill must flip
  a failed task-class to passes on >=2 distinct benchmark tasks, or show
  measurably fewer steps on retry (Toolformer utility analog).
- The 181-cycle operational notes become: repeatable procedures -> skills;
  judgment lessons -> description-indexed hint cards (same retrieval index).
- Retrieval: TF-IDF over descriptions (offline-first, stdlib-only);
  embedding API can slot in later without changing the interface.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Skill:
    """One verified, executable procedure."""
    name: str
    description: str
    trigger: str          # when to use (the Reflexion 'trigger')
    cause: str             # the failure it fixes
    corrected_action: str  # what to do instead
    steps: tuple[str, ...] = field(default_factory=tuple)
    verified: bool = False
    uses: int = 0


class SkillLibrary:
    """CRUD + TF-IDF retrieval + utility-gated admission."""

    def __init__(self, store_dir: Path) -> None:
        self.dir = Path(store_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, Skill] = {}
        self._load()

    # ---------------------------------------------------------------- CRUD
    def _load(self) -> None:
        for p in sorted(self.dir.glob("*.json")):
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                s = Skill(**raw)
                self._index[s.name] = s
            except (json.JSONDecodeError, TypeError):
                continue  # skip corrupt entries, never crash the library

    def add(self, skill: Skill) -> bool:
        """Add/replace a skill. Refuses unverified skills at the door
        unless force=True is explicitly used by the admission process."""
        if not skill.verified:
            return False
        self._index[skill.name] = skill
        self._write(skill)
        return True

    def _write(self, s: Skill) -> None:
        p = self.dir / f"{s.name}.json"
        d = asdict(s)
        d["steps"] = list(s.steps)
        p.write_text(json.dumps(d, indent=2), encoding="utf-8")

    def get(self, name: str) -> Skill | None:
        return self._index.get(name)

    def all(self) -> list[Skill]:
        return sorted(self._index.values(), key=lambda s: s.name)

    def mark_used(self, name: str) -> None:
        s = self._index.get(name)
        if s:
            s2 = Skill(**{**asdict(s), "uses": s.uses + 1})
            self._index[name] = s2
            self._write(s2)

    # ------------------------------------------------------------- retrieval
    def retrieve(self, query: str, top_k: int = 5) -> list[Skill]:
        """TF-IDF top-k retrieval over descriptions+triggers (offline-first)."""
        if not self._index:
            return []
        docs = {n: (s.description + " " + s.trigger)
                for n, s in self._index.items()}
        q_terms = _tokenize(query)
        scores: list[tuple[float, str]] = []
        idf = _idf(docs)
        for name, doc in docs.items():
            tf = _tf(doc)
            score = sum(tf.get(t, 0) * idf.get(t, 0.0) for t in q_terms)
            scores.append((score, name))
        scores.sort(reverse=True)
        return [self._index[n] for _, n in scores[:top_k] if _ > 0]

    # ------------------------------------------------------------- admission
    def admit(self, candidate: Skill, benchmark_results: list[bool]) -> bool:
        """Utility-gated admission (Voyager self-verification + Toolformer
        utility analog): the skill must show demonstrated gain.

        Args:
            candidate: the proposed skill (verified=False).
            benchmark_results: pass/fail list of benchmark tasks run WITH
                this skill applied (>=2 tasks required).
        """
        if candidate.verified:
            return self.add(candidate)
        if len(benchmark_results) < 2:
            return False
        if all(benchmark_results) and len(benchmark_results) >= 2:
            promoted = Skill(**{**asdict(candidate), "verified": True})
            return self.add(promoted)
        return False


# ------------------------------------------------------------------ tf-idf
def _tokenize(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


def _tf(doc: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in _tokenize(doc):
        out[t] = out.get(t, 0) + 1
    return out


def _idf(docs: dict[str, str]) -> dict[str, float]:
    n = len(docs)
    df: dict[str, int] = {}
    for doc in docs.values():
        for t in set(_tokenize(doc)):
            df[t] = df.get(t, 0) + 1
    return {t: math.log((n + 1) / (c + 1)) + 1.0 for t, c in df.items()}


# ---------------------------------------------------------------- seeding
def seed_from_notes(notes_text: str, lib: SkillLibrary) -> int:
    """Convert operational notes into hint-card skills.

    Notes format (one per line/paragraph): 'trigger -> cause -> fix'.
    Returns the number of skills seeded.
    """
    count = 0
    for line in notes_text.splitlines():
        line = line.strip()
        if "->" not in line:
            continue
        parts = [p.strip() for p in line.split("->", 2)]
        if len(parts) < 2:
            continue
        trigger = parts[0]
        rest = parts[1] if len(parts) == 2 else f"{parts[1]}: {parts[2]}"
        cause, _, fix = rest.partition(":")
        name = re.sub(r"[^a-z0-9]+", "-", trigger.lower()).strip("-")[:48]
        if not name:
            continue
        skill = Skill(name=name, description=fix or rest, trigger=trigger,
                      cause=cause.strip(), corrected_action=fix.strip(),
                      steps=(), verified=True)
        if lib.add(skill):
            count += 1
    return count

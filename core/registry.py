"""BUCKY registry — the data-driven, self-upgradeable pattern store.

This is the engine's LEARNABLE surface: detection rules live in a versioned
JSON registry, not in code. New patterns (a secret shape discovered in the
wild, a new CSP trigger, a new postMessage signature) enter ONLY through
learning.attempt_upgrade, which gates on the benchmark suite. The engine
upgrades ITSELF without code changes — and every upgrade is sealed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "registry" / "patterns.json"


@dataclass(frozen=True)
class SecretPattern:
    """One registry-loaded secret detector pattern."""
    id: str
    kind: str
    regex: str
    min_entropy: float = 3.5


class PatternRegistry:
    """Versioned pattern store. Immutable upgrades: with_* returns a copy."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._data: dict = {}
        self._load()

    # ------------------------------------------------------------------ io
    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self._data = {}
        else:
            self._data = {}

    def save(self) -> None:
        """Atomic write: temp file + os.replace (never a half-written registry)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # ------------------------------------------------------------- accessors
    @property
    def version(self) -> int:
        return int(self._data.get("version", 0))

    def secret_patterns(self) -> list[SecretPattern]:
        out: list[SecretPattern] = []
        for raw in self._data.get("secret_patterns", []):
            try:
                out.append(SecretPattern(
                    id=str(raw["id"]), kind=str(raw["kind"]),
                    regex=str(raw["regex"]),
                    min_entropy=float(raw.get("min_entropy", 3.5))))
            except (KeyError, TypeError, ValueError):
                continue  # corrupt entries are skipped, never crash detection
        return out

    def csp_b1_triggers(self) -> tuple[str, ...]:
        return tuple(self._data.get("csp_b1_triggers", ()))

    # ------------------------------------------------------------- upgrade
    def with_secret_pattern(self, pat: SecretPattern) -> "PatternRegistry":
        """Immutable copy with the pattern appended and version bumped."""
        reg = PatternRegistry.__new__(PatternRegistry)
        reg.path = self.path
        reg._data = json.loads(json.dumps(self._data))  # deep copy
        existing = {p["id"] for p in reg._data.get("secret_patterns", [])}
        if pat.id not in existing:
            reg._data.setdefault("secret_patterns", []).append({
                "id": pat.id, "kind": pat.kind, "regex": pat.regex,
                "min_entropy": pat.min_entropy,
            })
            reg._data["version"] = int(reg._data.get("version", 0)) + 1
        return reg

    def has_secret_pattern(self, pattern_id: str) -> bool:
        return any(p.id == pattern_id for p in self.secret_patterns())

    def apply_from(self, other: "PatternRegistry") -> None:
        """Adopt another registry's data in place (post-upgrade sync).

        After learning.attempt_upgrade saves an upgraded copy, the engine's
        live registry instance syncs from it so detection uses the new
        patterns immediately — no reload required.
        """
        self._data = json.loads(json.dumps(other._data))


_default: PatternRegistry | None = None
_default_loaded = False


def default_registry() -> PatternRegistry | None:
    """Lazily load the repo's registry/patterns.json (None if absent)."""
    global _default, _default_loaded
    if not _default_loaded:
        _default_loaded = True
        if DEFAULT_PATH.exists():
            _default = PatternRegistry(DEFAULT_PATH)
    return _default

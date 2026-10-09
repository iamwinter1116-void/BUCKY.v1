"""BUCKY campaign-profiles — pluggable, engine core stays GENERIC.

The engine's vocabulary (capabilities, chain actions, template SHAPES,
observation signature CLASSES) is target-agnostic. Everything that was
learned from a specific engagement — which exact deeplink params a bot
framework reads, which runtime beacon a target emits — lives in a
PROFILE: a JSON file that adds instance-level signatures without
touching core code.

Doctrine (Winter Soldier, Oct 2026): BUCKY is a general production
hacking engine. No vendor name, no campaign artifact, no specific
target's param-shapes belong in core/*.py — they belong in
profiles/<campaign>.json, loaded explicitly.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PROFILES_DIR = Path(__file__).resolve().parents[1] / "profiles"


@dataclass(frozen=True)
class ObservationRule:
    """One runtime signature: regex + the capability it proves."""
    pattern: str            # raw regex (profile-supplied)
    capability: str          # e.g. "cross-tenant-session"
    label: str = ""         # human note


@dataclass
class CampaignProfile:
    """Instance-level signatures for one engagement/class of target."""
    name: str
    description: str = ""
    # observation regexes, capability-tagged
    observations: tuple[ObservationRule, ...] = ()
    # extra exploit-template param-fill hints (generic slots stay core)
    template_hints: dict[str, str] = field(default_factory=dict)
    # optional extra finding-kind vocabulary this campaign emits
    extra_kinds: dict[str, str] = field(default_factory=dict)

    def compiled(self) -> list[tuple[re.Pattern[str], ObservationRule]]:
        out = []
        for obs in self.observations:
            try:
                out.append((re.compile(obs.pattern, re.I), obs))
            except re.error:
                continue          # honest skip, never crash the gate
        return out


def load_profile(path: str | Path) -> CampaignProfile:
    """Load a campaign profile JSON -> CampaignProfile."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    obs = tuple(
        ObservationRule(o.get("pattern", ""), o.get("capability", ""),
                        o.get("label", ""))
        for o in data.get("observations", []))
    return CampaignProfile(
        name=data.get("name", Path(path).stem),
        description=data.get("description", ""),
        observations=obs,
        template_hints=data.get("template_hints", {}),
        extra_kinds=data.get("extra_kinds", {}),
    )


def available_profiles(directory: Path | None = None) -> list[str]:
    """List profile JSONs shipped with the engine."""
    d = directory or DEFAULT_PROFILES_DIR
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.json"))

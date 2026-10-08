"""BUCKY config — typed loader with validation.

Security note: ``config.json`` holds the operator's AI API key and is
NEVER committed (see .gitignore). Every accessor validates shape and
fails fast with actionable errors instead of crashing deep in a lane.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"


class ConfigError(Exception):
    """Raised when config.json is missing, malformed, or incomplete."""


@dataclass(frozen=True)
class VMConfig:
    """Kali VM connection + lifecycle settings."""
    name: str
    ssh_key: str
    host: str
    port: int
    user: str
    vboxmanage: str
    workdir: str

    @property
    def ssh_target(self) -> str:
        return f"{self.user}@{self.host}"

    @property
    def key_path(self) -> Path:
        p = Path(self.ssh_key)
        if not p.exists():
            raise ConfigError(f"SSH key not found: {p}")
        return p


@dataclass(frozen=True)
class AIConfig:
    """OpenAI-compatible endpoint slot. api_key stays masked in repr."""
    api_key: str
    base_url: str
    model: str

    def __repr__(self) -> str:  # pragma: no cover — trivial
        masked = f"{self.api_key[:4]}***" if self.api_key else "(empty)"
        return f"AIConfig(api_key={masked!r}, base_url={self.base_url!r}, model={self.model!r})"


@dataclass(frozen=True)
class PathsConfig:
    workspace: str
    evidence_root: str


@dataclass(frozen=True)
class Config:
    vm: VMConfig
    ai: AIConfig
    paths: PathsConfig
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def _require(mapping: dict[str, Any], key: str, ctx: str) -> Any:
    if key not in mapping or mapping[key] in (None, ""):
        raise ConfigError(f"config.json: missing required key '{ctx}{key}'")
    return mapping[key]


def load_config(path: Path | None = None) -> Config:
    """Load and validate config.json. Raises ConfigError with a precise
    message on any structural problem. Never raises raw KeyError."""
    p = path or CONFIG_PATH
    if not p.exists():
        raise ConfigError(
            f"config.json not found at {p}. Copy config.example.json "
            "to config.json and fill in your AI api_key."
        )
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigError(f"config.json is not valid JSON: {e}") from e

    vm = raw.get("vm") or {}
    ai = raw.get("ai") or {}
    paths = raw.get("paths") or {}

    cfg = Config(
        vm=VMConfig(
            name=_require(vm, "name", "vm."),
            ssh_key=_require(vm, "ssh_key", "vm."),
            host=_require(vm, "host", "vm."),
            port=int(_require(vm, "port", "vm.")),
            user=_require(vm, "user", "vm."),
            vboxmanage=_require(vm, "vboxmanage", "vm."),
            workdir=_require(vm, "workdir", "vm."),
        ),
        ai=AIConfig(
            api_key=str(ai.get("api_key") or ""),
            base_url=str(ai.get("base_url") or "https://api.openai.com/v1"),
            model=str(ai.get("model") or "gpt-4o-mini"),
        ),
        paths=PathsConfig(
            workspace=str(_require(paths, "workspace", "paths.")),
            evidence_root=str(_require(paths, "evidence_root", "paths.")),
        ),
        raw=raw,
    )
    return cfg


def config_status(cfg: Config) -> dict[str, Any]:
    """Human/CLI-friendly status dict. api_key reported as present/absent only."""
    return {
        "vm": f"{cfg.vm.ssh_target}:{cfg.vm.port}",
        "vm_name": cfg.vm.name,
        "ai_configured": bool(cfg.ai.api_key),
        "ai_model": cfg.ai.model,
        "ai_base_url": cfg.ai.base_url,
        "workspace": cfg.paths.workspace,
        "evidence_root": cfg.paths.evidence_root,
    }

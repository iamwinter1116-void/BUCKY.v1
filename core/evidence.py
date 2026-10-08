"""BUCKY evidence — SHA-sealed, tamper-evident evidence pipeline.

Same discipline as the live campaign: every artifact gets a sha256 entry in
a ``MANIFEST.json``; the manifest itself is digest-stamped. Verification
re-hashes everything and reports precise mismatches — a sealed directory can
be proven unmodified (or proven tampered) at any later time. Zero deps.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_NAME = "MANIFEST.json"


@dataclass(frozen=True)
class SealResult:
    """Outcome of a seal operation."""
    files: list[dict[str, Any]]
    manifest_sha256: str
    manifest_path: Path


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a verify operation. ``ok`` False + ``problems`` says why."""
    ok: bool
    problems: list[str]


def _sha256_file(p: Path) -> str:
    """Streamed file hash (64 KiB chunks — handles multi-GB captures)."""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def seal(directory: str | Path, label: str = "run") -> SealResult:
    """Seal a directory: per-file sha256 manifest + manifest-digest.

    Args:
        directory: the evidence dir to seal (must exist).
        label: human context recorded in the manifest (e.g. "poc-a-p79").

    Returns:
        SealResult with the file entries, the manifest digest, and path.

    Raises:
        FileNotFoundError: if ``directory`` is not a directory.
    """
    d = Path(directory)
    if not d.is_dir():
        raise FileNotFoundError(f"{d} is not a directory")
    manifest: dict[str, Any] = {
        "label": label,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "files": [],
    }
    for f in sorted(d.rglob("*")):
        if f.is_file() and f.name != MANIFEST_NAME:
            manifest["files"].append({
                "file": str(f.relative_to(d)).replace("\\", "/"),
                "sha256": _sha256_file(f),
                "bytes": f.stat().st_size,
            })
    man_path = d / MANIFEST_NAME
    man_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    total = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return SealResult(manifest["files"], total, man_path)


def verify(directory: str | Path) -> VerifyResult:
    """Re-verify a sealed directory against its MANIFEST.json.

    Returns:
        VerifyResult(ok=True) when every file matches; otherwise ok=False with
        precise problems (missing files, hash mismatches, absent manifest).
    """
    d = Path(directory)
    man_path = d / MANIFEST_NAME
    if not man_path.exists():
        return VerifyResult(False, [f"{MANIFEST_NAME} missing"])
    try:
        manifest = json.loads(man_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return VerifyResult(False, [f"{MANIFEST_NAME} corrupt: {e}"])
    bad: list[str] = []
    for entry in manifest.get("files", []):
        p = d / entry["file"]
        if not p.exists():
            bad.append(f"MISSING {entry['file']}")
            continue
        if _sha256_file(p) != entry["sha256"]:
            bad.append(f"HASH-MISMATCH {entry['file']}")
    return VerifyResult(len(bad) == 0, bad)

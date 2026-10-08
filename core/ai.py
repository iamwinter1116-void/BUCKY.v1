"""BUCKY ai — the single-key slot. Any OpenAI-compatible endpoint.

The operator pastes ``api_key`` into config.json and ``forge ask "..."``
works. Nothing else needed.

Security: the key lives only in config.json (gitignored); it is sent solely
to the configured base_url over HTTPS; every call is appended to
``ai-history.jsonl`` for auditability. No key is ever logged or printed.
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import load_config

ROOT = Path(__file__).resolve().parent.parent
HISTORY = ROOT / "ai-history.jsonl"

SYSTEM_PROMPT = (
    "You are the analysis brain embedded in BUCKY, a cybersecurity "
    "operations cockpit. You receive raw tool output (recon, probes, page "
    "dumps, scan results) from a Kali VM driven by the operator. Your job: "
    "triage, correlate, spot what a human misses, and suggest the next precise "
    "action. Be terse, technical, and never invent results that are not in the "
    "provided output. Flag uncertainty explicitly."
)


def ask(prompt: str, context: str | None = None) -> dict[str, Any]:
    """One-shot LLM call against the configured OpenAI-compatible endpoint.

    Args:
        prompt: the question or instruction for the model.
        context: optional raw tool output to ground the model
            (prepended as "TOOL OUTPUT" before the question).

    Returns:
        ``{"ok": True, "answer": str}`` on success, else
        ``{"error": human-readable reason}`` — never raises.
    """
    cfg = load_config()
    key = (cfg.ai.api_key or "").strip()
    if not key:
        return {"error": "api_key missing — paste it in config.json (ai.api_key)"}
    messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    if context:
        messages.append({"role": "user",
                         "content": f"TOOL OUTPUT:\n{context}\n\nQUESTION: {prompt}"})
    else:
        messages.append({"role": "user", "content": prompt})
    body = json.dumps({"model": cfg.ai.model, "messages": messages}).encode()
    req = urllib.request.Request(
        cfg.ai.base_url.rstrip("/") + "/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
        content = data["choices"][0]["message"]["content"]
        with open(HISTORY, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "at": datetime.now(timezone.utc).isoformat(),
                "prompt": prompt,
                "answer": content,
            }) + "\n")
        return {"ok": True, "answer": content}
    except Exception as e:  # noqa: BLE001 — surface any transport/API failure
        return {"error": f"ai-call failed: {e}"}

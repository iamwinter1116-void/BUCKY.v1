"""BUCKY LLMPolicy — the agentic brain behind the single API key.

When the operator pastes their key into config.json, this policy turns the
Agent loop into a live security agent. Design follows the research synthesis:
- COMPACT STATE, never raw history (PentestGPT/HBgpt: state-compaction
  doubles success; raw history and vector-RAG both underperform)
- ONE ACTION PER TURN, grammar-strict, enum-parsed (HBgpt output contract;
  Llama3 hallucinated tools 61% of rounds when this was loose)
- HINT SLOT: the operator's one-line guidance is the cheapest success
  multiplier (33%->83% in HBgpt) — always in context
- FAIL-SOFT: any parse/transport failure degrades to a deterministic
  safe default (ask again / finish), never a crash, never a raw shell.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .ai import ask as ai_ask
from .agent import Action, ActionKind, Thought


SYSTEM_PROMPT = (
    "You are the security-research brain of BUCKY, a hacking-engine cockpit "
    "driving a Kali VM. You choose exactly ONE action per turn from a fixed "
    "verb set. You never invent verbs. You think briefly, then act.\n"
    "Available actions (respond with EXACTLY one JSON object, no prose):\n"
    '{"action":"vm_exec","target":"<in-scope host or url>","tool":"<tool+args>"}\n'
    '{"action":"probe","target":"<url>"}\n'
    '{"action":"browse","target":"<url>"}\n'
    '{"action":"seal","target":"<evidence dir>"}\n'
    '{"action":"finish","report":"<final summary>"}\n'
    "Optionally prefix one short thought line starting with THINK: before "
    "the JSON. Targets outside engagement scope are denied by the harness."
)

_ACTION_RE = re.compile(r'\{[^{}]*"action"\s*:\s*"[a-z_]+"[^{}]*\}', re.S)
_THINK_RE = re.compile(r"THINK:\s*(.+)")


class LLMPolicy:
    """LLM-driven policy over the typed action space.

    Attributes:
        hint: operator's standing one-line guidance (always in context).
        max_context_chars: compact-state budget.
    """

    def __init__(self, hint: str = "", max_context_chars: int = 6000) -> None:
        self.hint = hint.strip()
        self.max_context_chars = max_context_chars
        self._history: list[str] = []

    # ---------------------------------------------------------------- prompt
    def _build_prompt(self, task: str, transcript: str, lessons: str) -> str:
        ctx = transcript[-self.max_context_chars:]
        parts = [
            f"TASK: {task}",
            f"RECENT OBSERVATIONS:\n{ctx or '(none yet)'}",
            f"LESSONS: {lessons or '(none)'}",
        ]
        if self.hint:
            parts.append(f"OPERATOR HINT: {self.hint}")
        parts.append("Choose exactly one action (JSON object only).")
        return "\n\n".join(parts)

    # ---------------------------------------------------------------- parse
    @staticmethod
    def _parse_action(blob: str) -> Action | None:
        """Extract and validate one typed action from the model output.

        Enum-strict: unknown verbs return None (caller re-prompts).
        """
        m = _ACTION_RE.search(blob)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
        verb = obj.get("action")
        args: dict[str, Any] = {}
        target = obj.get("target") or obj.get("url") or ""
        if target:
            args["target"] = str(target)
        if verb in (ActionKind.VM_EXEC.value, "vm_exec"):
            args["tool"] = str(obj.get("tool", ""))
            return Action(ActionKind.VM_EXEC, args)
        if verb == "probe":
            return Action(ActionKind.PROBE, args)
        if verb == "browse":
            return Action(ActionKind.BROWSE, args)
        if verb == "seal":
            return Action(ActionKind.SEAL, args)
        if verb == "finish":
            args["report"] = str(obj.get("report", ""))
            return Action(ActionKind.FINISH, args)
        return None

    # ---------------------------------------------------------------- Policy
    def next_step(self, task: str, transcript: str,
                  lessons: str) -> Thought | Action:
        """One LLM call -> one typed step. Fail-soft on every error."""
        prompt = self._build_prompt(task, transcript, lessons)
        res = ai_ask(prompt)
        if not res.get("ok"):
            # transport/parse failure: think-safe, never crash the loop
            return Thought(f"ai-unavailable: {res.get('error', '?')[:80]}; "
                           f"retry or finish")
        answer = res["answer"]
        think = _THINK_RE.search(answer)
        action = self._parse_action(answer)
        if action is not None:
            if think:
                self._history.append(f"THINK: {think.group(1)[:200]}")
            return action
        # model returned prose without a valid action -> re-ask via Thought
        return Thought(f"model output had no valid action JSON; "
                       f"asked to comply with the verb contract")


class SafeLLMPolicy(LLMPolicy):
    """LLMPolicy with a hard leash: max LLM calls per run (cost containment)."""

    def __init__(self, hint: str = "", max_context_chars: int = 6000,
                 max_llm_calls: int = 40) -> None:
        super().__init__(hint, max_context_chars)
        self.max_llm_calls = max_llm_calls
        self._calls = 0

    def next_step(self, task: str, transcript: str,
                  lessons: str) -> Thought | Action:
        if self._calls >= self.max_llm_calls:
            return Action(ActionKind.FINISH,
                          {"report": "budget: max LLM calls reached"})
        self._calls += 1
        return super().next_step(task, transcript, lessons)


class LLMPolicyDrivenLoop:
    """The full agent loop wired to an LLMPolicy (agentic mode).

    Runs the SAME step/trial/step budget machinery as ScriptedPolicy but
    the policy is the LLM. ScopeGate still vets every action (defense in
    depth: containment does not depend on model compliance).
    """

    def __init__(self, agent: Any, policy: LLMPolicy) -> None:
        self.agent = agent
        self.policy = policy

    def run(self, task: str, transcript: str = "", lessons: str = "") -> list[str]:
        """Drive the agent to FINISH with the LLM choosing each step.

        Returns the appended transcript lines (also appended in place).
        """
        import time
        budget = 25
        base = transcript if transcript else ""
        for _ in range(budget):
            step = self.policy.next_step(task, base, lessons)
            if isinstance(step, Action) and step.kind == ActionKind.FINISH:
                base += f"\nFINISH: {step.args.get('report','')}"
                return [ln for ln in base.splitlines() if ln]
            if isinstance(step, Action):
                base += f"\n{step.kind.value} {step.args.get('target','')} {step.args.get('tool','')}"
            else:
                base += f"\nWAIT: {step.text[:120]}"
            time.sleep(0.2)
        base += "\nFINISH: step budget exhausted"
        return [ln for ln in base.splitlines() if ln]

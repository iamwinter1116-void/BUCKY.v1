"""Tests for the LLMPolicy agentic layer (mock LLM, no network)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agent import Action, ActionKind, Thought
from core.llm_policy import (LLMPolicy, LLMPolicyDrivenLoop, SafeLLMPolicy,
                             _ACTION_RE, _THINK_RE)


def _fake_llm(answer: str) -> LLMPolicy:
    """Build a policy whose ai.ask is replaced by a canned answer."""
    p = LLMPolicy()
    p._fake_answer = answer  # type: ignore[attr-defined]
    orig = LLMPolicy.next_step

    def fake_next_step(self, task, transcript, lessons):
        answer = getattr(self, "_fake_answer", "")
        think = _THINK_RE.search(answer)
        action = LLMPolicy._parse_action(answer)
        if action is not None:
            return action
        return Thought("no valid action JSON")

    p.next_step = fake_next_step.__get__(p, LLMPolicy)  # type: ignore[method-assign]
    return p


class TestParser(unittest.TestCase):
    def test_parses_all_verbs(self):
        for verb in ("vm_exec", "probe", "browse", "seal", "finish"):
            blob = '{"action":"%s","target":"http://t","tool":"x"}' % verb
            a = LLMPolicy._parse_action(blob)
            self.assertIsNotNone(a)
            self.assertEqual(a.kind.value, verb)

    def test_rejects_unknown_verb(self):
        self.assertIsNone(
            LLMPolicy._parse_action('{"action":"rm_rf_everything"}'))

    def test_rejects_prose_without_json(self):
        self.assertIsNone(LLMPolicy._parse_action("I would probe the host."))

    def test_embedded_think_line_ignored_by_parser(self):
        blob = 'THINK: plan\n{"action":"probe","target":"http://t"}'
        a = LLMPolicy._parse_action(blob)
        self.assertEqual(a.kind, ActionKind.PROBE)

    def test_finish_carries_report(self):
        a = LLMPolicy._parse_action('{"action":"finish","report":"B1 found"}')
        self.assertEqual(a.args.get("report"), "B1 found")

    def test_vm_exec_target_and_tool(self):
        a = LLMPolicy._parse_action(
            '{"action":"vm_exec","target":"10.10.10.5","tool":"nmap -sV"}')
        self.assertEqual(a.args.get("target"), "10.10.10.5")
        self.assertEqual(a.args.get("tool"), "nmap -sV")


class TestSafePolicy(unittest.TestCase):
    def test_budget_leash_finishes(self):
        p = SafeLLMPolicy(max_llm_calls=0)
        s = p.next_step("t", "o", "")
        self.assertEqual(s.kind, ActionKind.FINISH)

    def test_prompt_includes_hint_and_lessons(self):
        p = LLMPolicy(hint="check subdomains first")
        prompt = p._build_prompt("scan x", "obs1 obs2", "lesson1")
        self.assertIn("OPERATOR HINT: check subdomains first", prompt)
        self.assertIn("LESSONS: lesson1", prompt)
        self.assertIn("obs2", prompt)  # compact tail kept


class TestLoop(unittest.TestCase):
    def test_loop_finishes_on_finish_action(self):
        class P:
            def next_step(self, *a):
                return Action(ActionKind.FINISH, {"report": "done"})
        out = LLMPolicyDrivenLoop(object(), P()).run("t", "")
        self.assertTrue(out[-1].startswith("FINISH"))

    def test_loop_runs_three_turns_then_finish(self):
        seq = [Action(ActionKind.PROBE, {"target": "http://x"}),
               Action(ActionKind.BROWSE, {"target": "http://x"}),
               Action(ActionKind.FINISH, {"report": "found B1"})]

        class P:
            def __init__(self):
                self.i = 0

            def next_step(self, *a):
                r = seq[self.i]
                self.i += 1
                return r
        out = LLMPolicyDrivenLoop(object(), P()).run("t", "")
        self.assertEqual(len(out), 3)
        self.assertTrue(out[-1].startswith("FINISH: found B1"))
        self.assertIn("probe http://x", out[0])
        self.assertIn("browse http://x", out[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)

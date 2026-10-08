"""BUCKY curriculum — Voyager tier-3: task decomposition + skill-admission.

The LLMPolicy chooses ONE action per turn, but complex objectives need a
PLAN. The curriculum module:
1. DECOMPOSE the operator's objective into lane-sized sub-tasks
   (deterministic heuristics + optional LLM assist — fail-soft without it).
2. ADMIT verified skills into the library (never an unverified skill:
   Voyager ablation −73% without self-verification).
3. REPORT each sub-task result back into the agent's transcript so the
   Reflexion ring can learn from failures.

Deterministic-first doctrine: the decomposer uses pattern-rules for the
objective classes we actually run (csp-audit, pm-audit, secrets-sweep,
recon-pipeline). The LLM path is an optional accelerator, never a
dependency.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .skills import Skill, SkillLibrary


@dataclass(frozen=True)
class SubTask:
    subtask_id: str
    lane: str          # probe | browse | vm_exec | seal | learn | report
    target: str
    goal: str


@dataclass
class Curriculum:
    """An ordered plan of lane-sized sub-tasks for one objective."""
    objective: str
    subtasks: list[SubTask] = field(default_factory=list)
    pos: int = 0

    def next(self) -> SubTask | None:
        if self.pos >= len(self.subtasks):
            return None
        st = self.subtasks[self.pos]
        self.pos += 1
        return st

    def done(self) -> bool:
        return self.pos >= len(self.subtasks)


_OBJECTIVE_RULES: tuple[tuple[str, str], ...] = (
    # (objective-regex, lane-plan id)
    (r"csp|content[- ]security", "csp-audit"),
    (r"postmessage|message[- ]?handler|pm[- ]?audit", "pm-audit"),
    (r"sanitizer|fall[- ]?through|xss[- ]?sanit", "sanitizer-audit"),
    (r"secret|api[- ]?key|credential|token", "secrets-sweep"),
    (r"mine|bundle|tenant|deeplink|webpack", "bundle-mine"),
    (r"arsenal[- ]recon|subdomain[- ]hunt|passive[- ]enum", "arsenal-recon"),
    (r"arsenal[- ]probe|fingerprint|waf[- ]detect", "arsenal-probe"),
    (r"arsenal[- ]content|dir\s?brute|directory[- ]find", "arsenal-content"),
    (r"arsenal[- ]vuln|nikto|nuclei|vuln[- ]scan", "arsenal-vuln"),
    (r"recon|subdomain|takeover|dangling", "recon-pipeline"),
    (r"report|write[- ]up", "report-pack"),
)

_PLANS: dict[str, list[tuple[str, str, str]]] = {
    # plan-id -> [(lane, target-template, goal)]
    "csp-audit": [
        ("probe", "{target}", "fetch page headers+body once"),
        ("vm_exec", "{target}", "classify_csp(headers)"),
        ("seal", "{target}", "seal captured CSP evidence"),
    ],
    "pm-audit": [
        ("probe", "{target}", "fetch handler JS once"),
        ("vm_exec", "{target}", "classify_handler(js)"),
        ("browse", "{target}", "msg_capture(target) runtime beacon"),
        ("seal", "{target}", "seal handler evidence"),
    ],
    "secrets-sweep": [
        ("vm_exec", "{target}", "js_inventory(target)"),
        ("vm_exec", "{target}", "detect_secrets(each)"),
        ("seal", "{target}", "seal findings"),
    ],
    "sanitizer-audit": [
        ("probe", "{target}", "fetch bundle once"),
        ("vm_exec", "{target}", "analyze_sanitizer(bundle)"),
        ("seal", "{target}", "seal sanitizer evidence"),
    ],
    "bundle-mine": [
        ("vm_exec", "{target}", "mine_bundle(target)"),
        ("vm_exec", "{target}", "tenant_pairs(findings)"),
        ("seal", "{target}", "seal mine findings"),
    ],
    "arsenal-recon": [
        ("vm_exec", "{target}", "subfinder-domain(domain)"),
        ("vm_exec", "{target}", "dnsrecon-std(domain)"),
        ("vm_exec", "{target}", "theharvester-crtsh(domain)"),
        ("seal", "{target}", "seal recon evidence"),
    ],
    "arsenal-probe": [
        ("vm_exec", "{target}", "whatweb-probe(url)"),
        ("vm_exec", "{target}", "httpx-probe(url)"),
        ("vm_exec", "{target}", "wafw00f-detect(url)"),
        ("seal", "{target}", "seal probe evidence"),
    ],
    "arsenal-content": [
        ("vm_exec", "{target}", "ffuf-dir(url)"),
        ("seal", "{target}", "seal content-discovery evidence"),
    ],
    "arsenal-vuln": [
        ("vm_exec", "{target}", "nikto-scan(url)"),
        ("vm_exec", "{target}", "nuclei-high(url)"),
        ("seal", "{target}", "seal vuln-scan evidence"),
    ],
    "recon-pipeline": [
        ("vm_exec", "{target}", "ct_seed(target)"),
        ("vm_exec", "{target}", "dns_expand(seed)"),
        ("vm_exec", "{target}", "takeover_candidates(dead)"),
        ("seal", "{target}", "seal recon artifacts"),
    ],
    "report-pack": [
        ("vm_exec", "{target}", "packer.build(findings)"),
        ("seal", "{target}", "seal report draft"),
    ],
}


def decompose(objective: str, target: str) -> Curriculum:
    """Deterministic objective->plan decomposition (LLM-free, testable)."""
    obj = objective.lower()
    plan_id = next((pid for pat, pid in _OBJECTIVE_RULES
                    if re.search(pat, obj)), "recon-pipeline")
    subs = [SubTask(f"{plan_id}-{i+1}", lane,
                    target if "{target}" in tgt else tgt.format(target=target),
                    goal)
            for i, (lane, tgt, goal) in enumerate(_PLANS[plan_id])]
    return Curriculum(objective, subs)


def admit_skill(library: SkillLibrary, skill: Skill,
                verifier) -> tuple[bool, str]:
    """Voyager admission gate: a skill enters ONLY after verification.

    Wraps SkillLibrary.admit (utility-gated, >=2 benchmark passes) with a
    duplicate-trigger check. Never admits an unverifiable skill.

    Args:
        library: the persistent skill store.
        skill: candidate skill (verified flag may be False).
        verifier: callable(skill) -> list[bool]; must exercise the skill
            on >=2 benchmark tasks (True = task passed WITH the skill).

    Returns:
        (admitted, reason).
    """
    if not skill.name or not skill.trigger:
        return False, "skill needs name+trigger"
    if library.get(skill.name):
        return False, "duplicate: name already in library"
    results = verifier(skill)
    if not isinstance(results, list) or len(results) < 2:
        return False, "verification needs >=2 benchmark results"
    ok = library.admit(skill, results)
    if not ok:
        return False, "verification failed (Voyager -73% lesson)"
    return True, f"admitted: {skill.name} (verified, {sum(results)}/{len(results)} passes)"


def completion_report(cur: Curriculum, results: list[str]) -> str:
    """Human-readable + machine-parseable curriculum report."""
    lines = [f"curriculum: {cur.objective}",
             f"subtasks: {len(cur.subtasks)} completed: {cur.pos}"]
    lines += [f"  [{i+1}] {r}" for i, r in enumerate(results)]
    ok = cur.pos == len(cur.subtasks)
    lines.append(f"status: {'COMPLETE' if ok else 'INCOMPLETE'}")
    return "\n".join(lines)


class CurriculumLoop:
    """Curriculum-driven deterministic hunt (no-LLM mode).

    Walks a curriculum's sub-tasks and executes each through the real
    lanes (scope-vetted), appending observations to the transcript.
    Works with an EMPTY api_key — the deterministic backbone; the LLM
    policy accelerates it when a key is present. Same transcript format
    so reports/seals are identical between modes.
    """

    def __init__(self, execute_lane) -> None:
        """Args: execute_lane: callable(SubTask) -> str observation."""
        self.execute_lane = execute_lane

    def run(self, cur: Curriculum,
            transcript: list[str] | None = None) -> list[str]:
        """Walk all sub-tasks; returns transcript lines (fail-soft)."""
        lines = list(transcript or [])
        st = cur.next()
        while st is not None:
            try:
                obs = self.execute_lane(st)
                lines.append(
                    f"{st.subtask_id} {st.lane} {st.target} -> {obs[:300]}")
            except Exception as e:  # record, continue
                lines.append(f"{st.subtask_id} FAILED: {str(e)[:120]}")
            st = cur.next()
        lines.append(f"FINISH: curriculum {cur.objective} "
                     f"({'COMPLETE' if cur.done() else 'INCOMPLETE'})")
        return lines

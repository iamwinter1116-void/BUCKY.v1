"""BUCKY scopegate — host-side containment. THE invariant layer.

Design contract (from HackSynth containment findings + SolarWinds lessons):
- The agent NEVER composes raw shell. It calls typed verbs with structured
  params; scopegate renders the command.
- The scope allowlist lives on the WINDOWS HOST, re-applied before EVERY
  execution, and is never editable from inside the VM. A compromised VM
  cannot widen its own cage.
- Every verdict is auditable: each decision carries its reason.
- Fail-closed: anything not explicitly allowed is denied.

This module is pure logic (no subprocess) so it is fully unit-testable.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

# Commands that must never appear in a rendered command, ever.
_BANNED_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\brm\s+-rf\s+/", "destructive rm"),
    (r"\bmkfs\b", "filesystem format"),
    (r"\bdd\s+.*of=/dev/", "raw device write"),
    (r":\(\)\{.*\};\s*:", "fork bomb"),
    (r"\bshutdown\b|\breboot\b|\bpoweroff\b", "power control"),
    (r"\bchmod\s+777\s+/\b", "world-writable root"),
    (r">\s*/dev/sd[a-z]", "direct disk overwrite"),
    (r"\bcurl\b[^|]*\|\s*(ba)?sh", "curl-pipe-shell"),
    (r"\bwget\b[^|]*\|\s*(ba)?sh", "wget-pipe-shell"),
)


class ScopeDenied(Exception):
    """Raised when an action is outside the engagement scope.

    Attributes:
        reason: human-readable denial cause (auditable).
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ScopeVerdict:
    """One scope decision: allow with rendered command, or deny with reason."""
    allowed: bool
    rendered: str = ""
    reason: str = ""
    risk: str = ""


@dataclass(frozen=True)
class TargetRule:
    """A single allowed target. host is a domain, IP, or CIDR."""
    host: str
    label: str = ""


@dataclass
class Scope:
    """Engagement scope: the ONLY hosts an agent action may touch.

    Security: stored host-side; vmbridge consults it before every exec.
    """

    targets: list[TargetRule] = field(default_factory=list)
    allow_vm_self: bool = True  # the Kali VM itself (lab, tools)

    def __init__(self, targets: list[TargetRule] | None = None,
                 allow_vm_self: bool = True) -> None:
        object.__setattr__(self, "targets", list(targets or []))
        object.__setattr__(self, "allow_vm_self", allow_vm_self)

    def allows_host(self, host: str) -> bool:
        """True if host matches a target rule (domain, exact IP, or CIDR)."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if self.allow_vm_self and host in _VM_SELF_HOSTS:
            return True
        for t in self.targets:
            t_host = t.host.strip().lower().rstrip(".")
            if host == t_host:
                return True
            # CIDR match
            try:
                if (ipaddress.ip_address(host) in
                        ipaddress.ip_network(t_host, strict=False)):
                    return True
            except ValueError:
                pass
        return False

    def describe(self) -> str:
        parts = [t.host + (f" ({t.label})" if t.label else "")
                 for t in self.targets]
        if self.allow_vm_self:
            parts.append("vm-self (Kali lab)")
        return ", ".join(parts) or "(empty scope)"


_VM_SELF_HOSTS = frozenset({
    "127.0.0.1", "localhost", "::1",
})


def extract_hosts(url_or_host: str) -> list[str]:
    """Extract candidate host(s) from a URL or bare host string.

    Handles scheme, port, userinfo, and path noise.

    SECURITY: never trust urlsplit().hostname for host AUTHORIZATION —
    it silently truncates attacker suffixes like '127.0.0.1:80.evil.tld'
    to '127.0.0.1' (colon-dot parsing). We take the full netloc and
    strip ONLY a valid trailing :port; anything else stays part of the
    host and will fail the exact-match/CIDR scope check.
    """
    s = (url_or_host or "").strip()
    if not s:
        return []
    if "://" in s:
        try:
            netloc = urlsplit(s).netloc
        except ValueError:
            return []
        host = netloc.split("@", 1)[-1]  # strip userinfo
        # strip ONLY a valid trailing port: ':digits' at the end
        if host and host[-1].isdigit():
            colon = host.rfind(":")
            if colon > 0 and host[colon + 1:].isdigit():
                host = host[:colon]
        return [host.lower()]
    # bare host:port or host/path
    host = s.split("/", 1)[0]
    host = host.split("@", 1)[-1]  # strip userinfo
    host = host.split(":", 1)[0]
    return [host.lower()]


def check_command(cmd: str, scope: Scope) -> ScopeVerdict:
    """Ban-list check for rendered commands. Pure, no side effects."""
    for pattern, label in _BANNED_PATTERNS:
        if re.search(pattern, cmd):
            return ScopeVerdict(False, "", f"banned: {label}", label)
    return ScopeVerdict(True, rendered=cmd)


def check_scope(url_or_host: str, scope: Scope) -> ScopeVerdict:
    """Validate that a URL/host is inside the engagement scope."""
    hosts = extract_hosts(url_or_host)
    if not hosts:
        return ScopeVerdict(False, "", "no host in input")
    for h in hosts:
        if not scope.allows_host(h):
            return ScopeVerdict(False, "", f"out-of-scope host: {h}",
                                risk="scope-escape")
    return ScopeVerdict(True, rendered=url_or_host)

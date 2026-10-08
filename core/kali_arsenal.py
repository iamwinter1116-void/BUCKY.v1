"""BUCKY Kali Arsenal — scope-gated, flag-allowlisted tool execution.

Custom replacement for "run tools by hand and fight their edge cases":
every Kali tool gets a TYPED VERB entry — binary, allowed flag shapes,
rate-class, and output-normalizer. The agent can NEVER compose raw
shell; it picks (tool, verb, target), the arsenal builds the command,
ScopeGate vets every host, RESTRICTED tools are hard-gated to the lab.

Rate-class doctrine (181-cycle lessons baked in):
- PASSIVE  : public-source only, safe on any in-scope domain
- LIGHT    : 1-3 requests, gentle single-GET doctrine
- ACTIVE   : many requests — in-scope hosts, rate-bounded flags ONLY
- RESTRICTED: exploit-adjacent (sqlmap) — own-lab loopback ONLY,
              hard-gate, cannot be overridden by Scope

Honesty rule: a tool missing from the VM is reported and SKIPPED,
never emulated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.scopegate import Scope, ScopeVerdict, check_scope, extract_hosts

# ---------------------------------------------------------------------------
# rate classes
PASSIVE = "passive"
LIGHT = "light"
ACTIVE = "active"
RESTRICTED = "restricted"

_LAB_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class ToolVerb:
    """One bounded way to call a tool (never free-form flags)."""
    name: str                 # verb id, e.g. "whatweb-probe"
    tool: str                 # binary name
    argv_template: tuple[str, ...]  # placeholders: {url} {domain} {wordlist}
    rate_class: str
    category: str             # recon | probe | content | vuln | port | param
    max_runtime_s: int = 120
    wordlist: str = ""        # required wordlist path (content tools)
    notes: str = ""


@dataclass
class ToolResult:
    verb: str
    tool: str
    ok: bool
    output: str
    findings: dict[str, int] = field(default_factory=dict)
    error: str = ""
    scope: str = ""           # verdict string for the audit trail

    @property
    def summary(self) -> str:
        if not self.ok:
            return f"{self.verb}: ERROR {self.error[:60]}"
        top = ", ".join(f"{k}={v}" for k, v in
                         sorted(self.findings.items()) if v) or "clean"
        return f"{self.verb}: {top}"


# ---------------------------------------------------------------------------
# The arsenal registry — each entry a bounded verb, NEVER a raw shell.
# (f) means the flag shape is fixed; {url}/{domain} are the ONLY holes.

_VERBS: dict[str, ToolVerb] = {}


def _v(verb_id: str, tool: str, argv: tuple[str, ...], rate: str,
       cat: str, rt: int = 120, wl: str = "", notes: str = "") -> None:
    _VERBS[verb_id] = ToolVerb(verb_id, tool, argv, rate, cat, rt, wl, notes)


# --- passive recon ---------------------------------------------------------
_v("subfinder-domain", "subfinder", ("-d", "{domain}", "-silent"),
   PASSIVE, "recon", 180, notes="CT/passive sources only, no resolution")
_v("amass-passive", "amass", ("enum", "-passive", "-d", "{domain}"),
   PASSIVE, "recon", 600, notes="passive enum only (-active forbidden)")
_v("dnsrecon-std", "dnsrecon", ("-d", "{domain}", "-t", "std"),
   PASSIVE, "recon", 120)
_v("theharvester-crtsh", "theHarvester",
   ("-d", "{domain}", "-b", "crtsh"), PASSIVE, "recon", 180,
   notes="single source crtsh, bounded")

# --- light probes (gentle single-GET doctrine) ------------------------------
_v("whatweb-probe", "whatweb", ("{url}", "-a", "3", "--no-errors"),
   LIGHT, "probe", 60)
_v("httpx-probe", "httpx", ("-u", "{url}", "-title", "-tech-detect",
                            "-status-code", "-silent"),
   LIGHT, "probe", 60)
_v("wafw00f-detect", "wafw00f", ("-a", "{url}"), LIGHT, "probe", 60)

# --- port scan (rate-bounded shapes only) -----------------------------------
_v("nmap-topports", "nmap", ("-sV", "--top-ports", "100", "-T2", "{host}"),
   ACTIVE, "port", 300, notes="T2 polite timing, top-100 only")
_v("masscan-fast", "masscan", ("-p", "80,443", "--rate", "100",
                               "{host}"),
   ACTIVE, "port", 120, notes="rate=100 hard cap")

# --- content discovery (wordlist + thread + time bounds) --------------------
_v("ffuf-dir", "ffuf", ("-w", "{wordlist}", "-u", "{url}/FUZZ",
                        "-t", "10", "-maxtime", "90", "-of", "json",
                        "-o", "{outdir}"),
   ACTIVE, "content", 120, wl="/usr/share/wordlists/dirb/common.txt")
_v("gobuster-dir", "gobuster", ("dir", "-w", "{wordlist}", "-u", "{url}",
                                "-t", "10", "--timeout", "60s"),
   ACTIVE, "content", 120, wl="/usr/share/wordlists/dirb/common.txt")
_v("dirsearch-dir", "dirsearch", ("-u", "{url}", "-w", "{wordlist}",
                                  "-t", "10", "--quiet"),
   ACTIVE, "content", 120, wl="/usr/share/wordlists/dirb/common.txt")
_v("feroxbuster-dir", "feroxbuster", ("-u", "{url}", "-w", "{wordlist}",
                                       "-t", "10", "--timeout", "60"),
   ACTIVE, "content", 120, wl="/usr/share/wordlists/dirb/common.txt")
_v("dirb-dir", "dirb", ("{url}", "{wordlist}"),
   ACTIVE, "content", 120, wl="/usr/share/wordlists/dirb/common.txt")

# --- vuln scanning ----------------------------------------------------------
_v("nikto-scan", "nikto", ("-h", "{url}", "-Tuning", "1,2,3,4,5,6,7,b",
                           "-timeout", "5"),
   ACTIVE, "vuln", 300, notes="bounded tuning, own-lab preferred")
_v("nuclei-high", "nuclei", ("-u", "{url}", "-severity",
                             "critical,high", "-silent"),
   ACTIVE, "vuln", 300,
   notes="high+critical templates only, no fuzzing templates")
_v("wpscan-enum", "wpscan", ("--url", "{url}", "--enumerate", "p,t,u",
                            "--no-banner"),
   ACTIVE, "vuln", 300,
   notes="version/plugin discovery only; vuln-enum needs API token (skipped)")
_v("arjun-params", "arjun", ("-u", "{url}"), ACTIVE, "param", 180)

# --- RESTRICTED: own-lab loopback ONLY --------------------------------------
_v("gobuster-dns", "gobuster", ("dns", "-d", "{domain}", "-w",
                                 "{wordlist}", "-t", "10"),
   ACTIVE, "recon", 180, wl="/usr/share/wordlists/dnsmap.txt",
   notes="subdomain brute via wordlist, thread-bounded")
_v("sqlmap-baseline", "sqlmap", ("-u", "{url}", "--batch", "--level", "1",
                                 "--risk", "1", "--threads", "1"),
   RESTRICTED, "exploit", 300,
   notes="HARD-GATED to lab hosts; level/risk 1, single thread")


# ---------------------------------------------------------------------------
# registry access

def verbs() -> dict[str, ToolVerb]:
    return dict(_VERBS)


def categories() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for v in _VERBS.values():
        out.setdefault(v.category, []).append(v.name)
    return out


def build_command(verb_id: str, target: str, *,
                  outdir: str = "/tmp/bucky-arsenal") -> tuple[str, ToolVerb]:
    """Build the bounded command for a verb+target. NO free-form flags.

    Raises:
        KeyError: unknown verb.
        ValueError: target does not fit the verb (url vs domain vs host)
    """
    v = _VERBS[verb_id]
    if "{url}" in v.argv_template:
        if not re.match(r"^https?://", target):
            raise ValueError(f"{verb_id} needs an http(s) URL")
    if "{domain}" in v.argv_template:
        host = extract_hosts(target)
        if not host or "." not in host[0]:
            raise ValueError(f"{verb_id} needs a bare domain")
        target = host[0]
    if "{host}" in v.argv_template:
        hosts = extract_hosts(target)
        if not hosts:
            raise ValueError(f"{verb_id} needs a host")
        target = hosts[0]
    argv = [a.replace("{url}", target).replace("{domain}", target)
            .replace("{host}", target).replace("{wordlist}", v.wordlist)
            .replace("{outdir}", outdir) for a in v.argv_template]
    return " ".join([v.tool] + argv), v


# ---------------------------------------------------------------------------
# scope + rate-class enforcement

def vet_target(verb_id: str, target: str, scope: Scope) -> ScopeVerdict:
    """Scope-check a verb's target with rate-class rules applied.

    RESTRICTED verbs additionally require a loopback lab host even when
    the Scope would allow the target.
    """
    v = _VERBS[verb_id]
    hosts = extract_hosts(target)
    if not hosts:
        return ScopeVerdict(False, reason="no host in target")
    verdict = check_scope(hosts[0], scope)
    if not verdict.allowed:
        return verdict
    if v.rate_class == RESTRICTED and hosts[0] not in _LAB_HOSTS:
        return ScopeVerdict(False, reason=f"RESTRICTED verb {verb_id} "
                            f"requires lab host, got {hosts[0]}")
    return verdict


# ---------------------------------------------------------------------------
# output normalization (deterministic finding-counts per tool)

_NORM: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "nuclei": [("vuln-lines", re.compile(r"\[[\w-]+:(critical|high)\]", re.I)),
               ("template-hits", re.compile(r"^[\w-]+/\S+", re.M))],
    "nikto": [("osvdb-items", re.compile(r"\+ OSVDB-\d+", re.I)),
              ("server-banners", re.compile(r"Server: .+", re.I))],
    "ffuf": [("status-200", re.compile(r'"status":\s*200')),
             ("status-30x", re.compile(r'"status":\s*3\d\d'))],
    "gobuster": [("found-paths", re.compile(r"^Found: ", re.M))],
    "dirsearch": [("status-200", re.compile(r"\[200\]"))],
    "dirb": [("found-paths", re.compile(r"\+ (?!CODE)", re.M))],
    "feroxbuster": [("found-200", re.compile(r"200\s+\w+", re.M))],
    "subfinder": [("subdomains", re.compile(r"^[a-z0-9*.-]+\.[a-z]{2,}$", re.M))],
    "amass": [("subdomains", re.compile(r"^[a-z0-9*.-]+\.[a-z]{2,}$", re.M))],
    "whatweb": [("tech-stack", re.compile(r"\[[\w .-]+\]"))],
    "httpx": [("live-host", re.compile(r"\[\d{3}\]"))],
    "wafw00f": [("waf-hit", re.compile(r"is behind\s+\w+", re.I))],
    "arjun": [("params-found", re.compile(r"Found:?\s+\w+", re.I))],
    "wpscan": [("plugins", re.compile(r"wp-content/plugins/\S+", re.I))],
    "nmap": [("open-ports", re.compile(r"\d+/tcp\s+open", re.I))],
    "masscan": [("open-ports", re.compile(r"Ports: .+/tcp", re.I))],
    "sqlmap": [("injectable", re.compile(r"is vulnerable|Payload:", re.I))],
    "theHarvester": [("hosts", re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.M)),
                     ("emails", re.compile(r"[\w.]+@[\w.-]+"))],
    "dnsrecon": [("records", re.compile(r"^\S+\s+\d+\s+IN", re.M))],
}


def normalize(tool: str, output: str) -> dict[str, int]:
    """Deterministic finding-counts from raw tool output."""
    out: dict[str, int] = {}
    for name, pat in _NORM.get(tool, []):
        out[name] = len(pat.findall(output))
    return out


def inventory(vm_run) -> dict[str, bool]:
    """Live VM inventory: which arsenal binaries actually exist.

    Args:
        vm_run: callable(cmd:str) -> object with .ok/.output (vmbridge.run).
    """
    tools = sorted({v.tool for v in _VERBS.values()})
    probe = " ".join(
        f"command -v {t} >/dev/null 2>&1 && echo YES-{t} || echo NO-{t}"
        for t in tools)
    r = vm_run(probe)
    out = r.output if r.ok else ""
    return {t: (f"YES-{t}" in out) for t in tools}


def run_verb(verb_id: str, target: str, scope: Scope, vm_run, *,
             outdir: str = "/tmp/bucky-arsenal") -> ToolResult:
    """Full contained execution: build -> vet -> run -> normalize.

    Never raises for scope denials or missing tools; returns an honest
    ToolResult the transcript can record.
    """
    try:
        cmd, v = build_command(verb_id, target, outdir=outdir)
    except (KeyError, ValueError) as exc:
        return ToolResult(verb_id, verb_id.split("-")[0], False, "",
                          error=str(exc))

    verdict = vet_target(verb_id, target, scope)
    if not verdict.allowed:
        return ToolResult(verb_id, v.tool, False, "", error="scope-denied",
                          scope=str(verdict.reason))

    inv_probe = f"command -v {v.tool} >/dev/null 2>&1 && echo YES || echo NO"
    probe = vm_run(inv_probe)
    if not (probe.ok and "YES" in (probe.output or "")):
        return ToolResult(verb_id, v.tool, False, "",
                          error=f"tool-missing:{v.tool}",
                          scope="allowed")

    rr = vm_run(f"timeout {v.max_runtime_s} {cmd} 2>&1 | head -c 200000")
    if not rr.ok:
        return ToolResult(verb_id, v.tool, False, rr.output or "",
                          error="vm-exec-failed", scope="allowed")
    return ToolResult(verb_id, v.tool, True, rr.output or "",
                      normalize(v.tool, rr.output or ""),
                      scope="allowed")

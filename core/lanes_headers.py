"""BUCKY lanes.headers — HTTP response header security analysis.

Closes the WSTG gap-classes that are DETERMINISTIC from a single
response snapshot (no active testing needed):
- WSTG-CONF-07  HSTS (missing / short max-age / no includeSubDomains)
- WSTG-SESS-02  Cookie attributes (missing Secure/HttpOnly/SameSite;
                __Host- prefix doctrine from Cookie Crumbles USENIX'23)
- WSTG-CLNT-09  CORS misconfiguration (wildcard origin reflection,
                credentials+wildcard = browser-rejected but sloppy)
- WSTG-ERRH-01  Improper error handling (stack traces / framework
                leakage in error bodies)
- WSTG-ATHN-02  Default-credential SURFACE detection (login form +
                vendor default pairs inventory; actual attempts stay
                RESTRICTED own-lab per doctrine)

Input is a header dict + body text (from probe/curl/arsenal capture) —
pure functions, no network. Every finding cites its WSTG id.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HeaderFinding:
    wstg_id: str
    check: str
    verdict: str          # fail | pass | warn
    detail: str
    severity: str = "medium"


# ---------------------------------------------------------------------------
# helpers

def _get(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v or ""
    return ""


# --- HSTS (WSTG-CONF-07) ----------------------------------------------------

_HSTS_MIN_AGE = 15552000  # 180 days — the common floor recommendation

def check_hsts(headers: dict[str, str], *, is_https: bool = True
               ) -> HeaderFinding:
    """HSTS presence + max-age + includeSubDomains (CONF-07)."""
    hsts = _get(headers, "strict-transport-security")
    if not hsts:
        return HeaderFinding(
            "WSTG-CONF-07", "HSTS", "fail",
            "no Strict-Transport-Security header" if is_https
            else "plain HTTP served (HSTS impossible)", "medium")
    m = re.search(r"max-age=(\d+)", hsts, re.I)
    if not m:
        return HeaderFinding("WSTG-CONF-07", "HSTS", "fail",
                             "HSTS without max-age directive", "medium")
    age = int(m.group(1))
    problems = []
    if age < _HSTS_MIN_AGE:
        problems.append(f"max-age={age} < {_HSTS_MIN_AGE}")
    if "includesubdomains" not in hsts.lower():
        problems.append("missing includeSubDomains")
    if problems:
        return HeaderFinding("WSTG-CONF-07", "HSTS", "warn",
                             "; ".join(problems), "low")
    return HeaderFinding("WSTG-CONF-07", "HSTS", "pass",
                         f"max-age={age}, includeSubDomains present", "")


# --- Cookie attributes (WSTG-SESS-02) ----------------------------------------

def check_cookies(headers: dict[str, str]) -> list[HeaderFinding]:
    """Every Set-Cookie: Secure / HttpOnly / SameSite / __Host- doctrine."""
    raw: list[str] = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw.append(v)
    if not raw:
        return [HeaderFinding("WSTG-SESS-02", "cookies", "pass",
                              "no cookies set on this response", "")]
    out: list[HeaderFinding] = []
    for c in raw:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        probs = []
        if "secure" not in low:
            probs.append("missing Secure")
        if "httponly" not in low:
            probs.append("missing HttpOnly")
        if "samesite" not in low:
            probs.append("missing SameSite")
        # Cookie Crumbles doctrine: __Host- prefix is the strong fix —
        # session cookies without it stay tossing/shadowing-capable
        if not name.lower().startswith("__host-") and (
                "session" in name.lower() or "auth" in name.lower()
                or "sid" in name.lower() or "token" in name.lower()):
            probs.append("no __Host- prefix (tossing-capable session cookie)")
        if probs:
            sev = "medium" if any("Secure" in p or "HttpOnly" in p
                                  for p in probs) else "low"
            out.append(HeaderFinding("WSTG-SESS-02", f"cookie:{name}",
                                     "fail", "; ".join(probs), sev))
        else:
            out.append(HeaderFinding("WSTG-SESS-02", f"cookie:{name}",
                                     "pass", "all attributes present", ""))
    return out


# --- CORS (WSTG-CLNT-09) ------------------------------------------------------

def check_cors(headers: dict[str, str], *, origin: str = "") -> HeaderFinding:
    """CORS wildcard reflection / credentials+wildcard (CLNT-09)."""
    acao = _get(headers, "access-control-allow-origin")
    acac = _get(headers, "access-control-allow-credentials")
    if not acao:
        return HeaderFinding("WSTG-CLNT-09", "CORS", "pass",
                             "no CORS headers (same-origin policy intact)", "")
    probs = []
    if acao.strip() == "*":
        probs.append("Access-Control-Allow-Origin: * (wildcard)")
        if acac.lower() == "true":
            probs.append("combined with allow-credentials:true "
                         "(browser rejects, but signals sloppy policy)")
    elif origin and acao.strip() == origin.strip():
        probs.append("origin REFLECTED verbatim in allow-origin "
                     "(any-origin accepted — credential theft primitive)")
    if probs:
        return HeaderFinding("WSTG-CLNT-09", "CORS", "fail",
                             "; ".join(probs), "high")
    return HeaderFinding("WSTG-CLNT-09", "CORS", "pass",
                          f"allow-origin={acao[:40]}", "")


# --- Error handling (WSTG-ERRH-01) --------------------------------------------

_STACK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("java-stack", re.compile(r"at [\w.$]+\.[\w$]+\([^)]*\.java:\d+\)")),
    ("python-traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("dotnet-stack", re.compile(r"at [\w.]+\(\) in [^:\n]+:\d+")),
    ("php-stack", re.compile(r"#\d+ \{[^}]*\.php:\d+\}")),
    ("sql-error", re.compile(r"(?:SQL syntax|SQLException|psql:|"
                             r"ORA-\d{5}|MySQLSyntaxErrorException)", re.I)),
    ("framework-leak", re.compile(r"(?:Laravel|Django|Next\.js|Express|"
                                 r"WordPress)[\s/]?\d+\.\d+", re.I)),
)

def check_error_handling(body: str) -> HeaderFinding:
    """Stack traces / framework versions in response bodies (ERRH-01)."""
    hits = [name for name, pat in _STACK_PATTERNS
            if pat.search(body or "")]
    if hits:
        return HeaderFinding("WSTG-ERRH-01", "error-handling", "fail",
                             f"leakage: {', '.join(hits[:3])}", "medium")
    return HeaderFinding("WSTG-ERRH-01", "error-handling", "pass",
                         "no stack/trace leakage detected", "")


# --- Default-credential SURFACE (WSTG-ATHN-02) --------------------------------
# detection of a login-shaped form + vendor fingerprints; ACTUAL default-
# cred attempts stay RESTRICTED (own-lab) — this is the surface map only.

_LOGIN_FORM = re.compile(
    r"<form[^>]*>[\s\S]{0,600}?(?:type=[\"']?password[\"']?|"
    r"name=[\"']?(?:pass|pwd|passwd)[\"']?)", re.I)
_DEFAULT_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("grafana", re.compile(r"grafana", re.I)),
    ("jenkins", re.compile(r"jenkins", re.I)),
    ("kibana", re.compile(r"kibana", re.I)),
    ("manager-app", re.compile(r"tomcat|/manager/html", re.I)),
    ("router-admin", re.compile(r"192\.168\.\d+\.\d+/|admin\.php", re.I)),
)

def check_default_cred_surface(body: str, headers: dict[str, str]
                               ) -> HeaderFinding:
    """Login surface + vendor fingerprint = default-cred candidate map."""
    body = body or ""
    has_login = bool(_LOGIN_FORM.search(body))
    blob = body + " " + " ".join(headers.values())
    vendors = [name for name, pat in _DEFAULT_HINTS if pat.search(blob)]
    if has_login and vendors:
        return HeaderFinding(
            "WSTG-ATHN-02", "default-cred-surface", "warn",
            f"login form + {', '.join(vendors[:3])} fingerprint "
            f"— default-cred candidates (attempts RESTRICTED to lab)",
            "low")
    if has_login:
        return HeaderFinding("WSTG-ATHN-02", "default-cred-surface",
                             "pass",
                             "login form present, no known-vendor "
                             "fingerprint", "")
    return HeaderFinding("WSTG-ATHN-02", "default-cred-surface", "pass",
                         "no login surface on this response", "")


# ---------------------------------------------------------------------------
# full response analysis

def analyze_response(headers: dict[str, str], body: str = "",
                     *, origin: str = "", is_https: bool = True
                     ) -> list[HeaderFinding]:
    """All header/body checks over one response snapshot."""
    out: list[HeaderFinding] = [check_hsts(headers, is_https=is_https)]
    out.extend(check_cookies(headers))
    out.append(check_cors(headers, origin=origin))
    out.append(check_error_handling(body))
    out.append(check_default_cred_surface(body, headers))
    return out


def failing(findings: list[HeaderFinding]) -> list[HeaderFinding]:
    """Only the actionable ones (fail + warn)."""
    return [f for f in findings if f.verdict in ("fail", "warn")]


def render(findings: list[HeaderFinding]) -> str:
    lines = []
    for f in findings:
        mark = {"fail": "✗", "warn": "△", "pass": "✓"}.get(f.verdict, "?")
        lines.append(f"  [{f.wstg_id}] {mark} {f.check}: {f.detail}")
    return "\n".join(lines)

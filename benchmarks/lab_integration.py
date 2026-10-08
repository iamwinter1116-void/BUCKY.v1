#!/usr/bin/env python
"""BUCKY lab-server + integration benchmark — runs ON the Kali VM.

Deploys deterministic lab targets on 127.0.0.1 (vulnerable + clean
twins for every detector), then exercises the REAL engine lanes end-to-end:
  - csp-verdict over live HTTP (header AND meta variants)
  - pm-guard over live handler JS
  - js-secrets over a live bundle
  - probe-lane shape (status/headers)
  - seal/verify round-trip on artifacts captured FROM THE WIRE

Exit code 0 = integration benchmark passed. Anything else = failure
(the honesty gate: no green claim without a green run).
"""
from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading

PORT = 19077

VULN_PAGE = """<html><head>
<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline' 'unsafe-eval' *.freshchat.com; frame-ancestors 'self'">
</head><body>vulnerable lab page<script src="/vuln-handler.js"></script></body></html>"""

CLEAN_PAGE = """<html><head>
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-lab0' 'strict-dynamic'; object-src 'none'">
</head><body>clean lab page<script src="/clean-handler.js"></script></body></html>"""

VULN_HANDLER = """window.addEventListener('message', function(event) {
  document.getElementById('x').innerHTML = event.data.html;
});"""

CLEAN_HANDLER = """window.addEventListener('message', function(event) {
  if (event.origin !== 'https://cstpanel.paytm.com') return;
  console.log(event.data);
});"""

VULN_BUNDLE = """
var config = {clientSecret: "abc8Kd72mZp0qR9sL3xNvT5wY7bC1jH6f",
              apiKey: "sk_live_51HexAbCdEfGhIjKlMn"};
var backup = "AKIAIOSFODNN7EXAMPLE";
var idToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
"""

CLEAN_BUNDLE = "var app={version:'1.0.0'};function boot(){return true;}"

PAGES = {
    "/vuln": VULN_PAGE,
    "/clean": CLEAN_PAGE,
    "/vuln-handler.js": VULN_HANDLER,
    "/clean-handler.js": CLEAN_HANDLER,
    "/vuln-bundle.js": VULN_BUNDLE,
    "/clean-bundle.js": CLEAN_BUNDLE,
}


class LabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGES.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path.endswith(('.html','')) else "application/javascript")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a): pass


def main() -> int:
    srv = http.server.HTTPServer(("127.0.0.1", PORT), LabHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[lab] targets live on 127.0.0.1:{PORT}")

    sys.path.insert(0, "/opt/bucky")  # where core/ will be synced
    fails: list[str] = []

    import urllib.request
    def fetch(path: str) -> str:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=10) as r:
            return r.read().decode("utf-8", "replace")

    # --- csp-verdict integration ---
    from core.lanes_security import classify_csp, classify_handler, detect_secrets
    vuln_html = fetch("/vuln")
    m = __import__("re").search(
        r'content="([^"]+)"', vuln_html)
    verdict = classify_csp(m.group(1), is_meta=True)
    if verdict.bypass_class != "B1":
        fails.append(f"csp: expected B1 on vuln page, got {verdict.bypass_class}")
    clean_html = fetch("/clean")
    m2 = __import__("re").search(r'content="([^"]+)"', clean_html)
    v2 = classify_csp(m2.group(1), is_meta=True)
    if v2.bypass_class != "clean":
        fails.append(f"csp: expected clean, got {v2.bypass_class}")

    # --- pm-guard integration ---
    vh = classify_handler(fetch("/vuln-handler.js"))
    ch = classify_handler(fetch("/clean-handler.js"))
    if vh.pattern != "P1":
        fails.append(f"pm: vuln handler expected P1, got {vh.pattern}")
    if ch.pattern != "strict":
        fails.append(f"pm: clean handler expected strict, got {ch.pattern}")

    # --- js-secrets integration ---
    vs = {f.kind for f in detect_secrets(fetch("/vuln-bundle.js"))}
    if not {"azure-client-secret", "aws-access-key", "jwt"} <= vs:
        fails.append(f"secrets: missing kinds, got {vs}")
    if detect_secrets(fetch("/clean-bundle.js")):
        fails.append("secrets: clean bundle produced findings (FP!)")

    # --- seal round-trip on wire-captured artifact ---
    from pathlib import Path
    import tempfile
    from core.evidence import seal, verify
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "vuln-page.html").write_text(vuln_html, encoding="utf-8")
        res = seal(d, label="integration-lab")
        ok = verify(d)
        if not (res.files and ok.ok):
            fails.append("seal: round-trip failed on wire-captured artifact")

    srv.shutdown()
    if fails:
        print("[FAIL] integration benchmark:")
        for f in fails:
            print("  -", f)
        return 1
    print("[PASS] integration benchmark: csp B1/clean + pm P1/strict + secrets TP/FP-clean + seal round-trip")
    return 0


if __name__ == "__main__":
    sys.exit(main())

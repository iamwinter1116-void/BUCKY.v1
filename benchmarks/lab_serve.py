#!/usr/bin/env python
"""Persistent BUCKY lab-server — serves vulnerable + clean twins on 127.0.0.1.

Runs standalone on the VM (no imports from core needed): HTTP server on
:19077 with the same fixture set as lab_integration.py. Used as the live
target for `bucky hunt` e2e runs. Ctrl-C to stop.
"""
import http.server
import sys

VULN_CSP = ("script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "*.freshchat.com")
CLEAN_CSP = "script-src 'nonce-r4nd0mN0nc3V4lu3'; frame-ancestors 'none'"
VULN_HANDLER = (
    "window.addEventListener('message', function(e){"
    "  document.getElementById('out').innerHTML = e.data;"
    "});"
)
CLEAN_HANDLER = (
    "window.addEventListener('message', function(e){"
    "  if (e.origin !== 'https://app.example.com') return;"
    "  document.getElementById('out').textContent = e.data;"
    "});"
)
VULN_BUNDLE = (
    "var cfg={clientSecret:'xY9kQ2mN7pR4sT6vW8zA1bC3dE5fG7h',"
    "awsKey:'AKIAIOSFODNN7EXAMPLE',"
    "token:'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpM'};"
)
CLEAN_BUNDLE = (
    "var app={version:'1.0.0',debug:false};"
    "function boot(){return true;} console.log('ok');"
)


class LabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        routes = {
            "/": (VULN_CSP, "vuln page"),
            "/clean": (CLEAN_CSP, "clean page"),
            "/vuln-handler.js": (None, VULN_HANDLER),
            "/clean-handler.js": (None, CLEAN_HANDLER),
            "/vuln-bundle.js": (None, VULN_BUNDLE),
            "/clean-bundle.js": (None, CLEAN_BUNDLE),
        }
        if self.path not in routes:
            self.send_error(404)
            return
        csp, body = routes[self.path]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:  # silence
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19077
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    print(f"[lab-serve] targets on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

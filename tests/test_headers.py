"""Header-lane tests — 5 WSTG gap-classes closed deterministically."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.lanes_headers import (analyze_response, check_cors,
                                check_error_handling, check_hsts,
                                check_cookies, failing, render)

VULN = {
    "Server": "Apache/2.4.29",
    "Set-Cookie": "sessionid=abc123; Path=/",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
}
VULN_BODY = ("Traceback (most recent call last): File \"app.py\", "
             "line 42 <form action=/login><input type=password name=pwd> "
             "<!-- grafana dashboard v10.2 -->")

CLEAN = {
    "Strict-Transport-Security":
        "max-age=31536000; includeSubDomains",
    "Set-Cookie": "__Host-session=x; Secure; HttpOnly; "
                  "SameSite=Strict; Path=/",
}
CLEAN_BODY = "<html><body>hello</body></html>"


class TestHeaderLane(unittest.TestCase):
    def test_vuln_response_full_sweep(self):
        fs = analyze_response(VULN, VULN_BODY)
        wstg = {f.wstg_id for f in failing(fs)}
        self.assertIn("WSTG-CONF-07", wstg)   # HSTS missing
        self.assertIn("WSTG-SESS-02", wstg)   # cookie attrs
        self.assertIn("WSTG-CLNT-09", wstg)   # CORS wildcard+creds
        self.assertIn("WSTG-ERRH-01", wstg)   # traceback leak
        self.assertIn("WSTG-ATHN-02", wstg)   # login+vendor surface

    def test_clean_response_no_failures(self):
        fs = analyze_response(CLEAN, CLEAN_BODY)
        fails = failing(fs)
        self.assertEqual(fails, [], f"unexpected failures: {fails}")

    def test_hsts_ages(self):
        f = check_hsts({"Strict-Transport-Security": "max-age=100"})
        self.assertEqual(f.verdict, "warn")
        f2 = check_hsts({"Strict-Transport-Security":
                        "max-age=31536000; includeSubDomains"})
        self.assertEqual(f2.verdict, "pass")

    def test_cookie_doctrine_host_prefix(self):
        # session cookie without __Host- = tossing-capable warning
        fs = check_cookies({"Set-Cookie":
                            "session=x; Secure; HttpOnly; SameSite=Lax"})
        self.assertTrue(any("tossing" in f.detail for f in fs))

    def test_cors_origin_reflection(self):
        f = check_cors({"Access-Control-Allow-Origin":
                        "https://evil.example.com"},
                       origin="https://evil.example.com")
        self.assertEqual(f.verdict, "fail")
        self.assertIn("REFLECTED", f.detail)

    def test_error_handling_patterns(self):
        f = check_error_handling("SQLException: SQL syntax error")
        self.assertEqual(f.verdict, "fail")

    def test_http_no_hsts_flagged(self):
        f = check_hsts({}, is_https=False)
        self.assertEqual(f.verdict, "fail")

    def test_render_shape(self):
        fs = analyze_response(VULN, VULN_BODY)
        txt = render(fs)
        self.assertIn("WSTG-CONF-07", txt)


class TestCoverageMatrix(unittest.TestCase):
    def test_matrix_reports_gaps(self):
        from core.coverage import CoverageReport
        rep = CoverageReport()
        self.assertGreater(len(rep.gap_list()), 0)

    def test_matrix_render_lists_all_12(self):
        from core.coverage import CoverageReport
        txt = CoverageReport().render()
        for cat in ("INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS",
                    "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT"):
            self.assertIn(cat, txt)


if __name__ == "__main__":
    unittest.main(verbosity=2)

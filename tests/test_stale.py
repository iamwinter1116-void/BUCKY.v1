"""Stale-asset lane tests — CDX parse, classification, capture-diff."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.lanes_stale import (cdx_query_url, classify_assets, diff_captures,
                              parse_cdx)

CDX_SAMPLE = json_str = (
    '[["timestamp","original"],'
    '["20180101120000","https://x.com/static/app.abc123.js"],'
    '["20230101120000","https://x.com/static/app.abc123.js"],'
    '["20190601120000","https://x.com/legacy/old-tenant.js"],'
    '["20200601120000","https://x.com/page.html"]]')


class TestStaleLane(unittest.TestCase):
    def test_cdx_url_shape(self):
        u = cdx_query_url("x.com")
        self.assertIn("web.archive.org/cdx/search/cdx", u)
        self.assertIn("matchType=domain", u)
        self.assertIn("statuscode:200", u)

    def test_parse_cdx_rows(self):
        rows = parse_cdx(CDX_SAMPLE)
        self.assertEqual(len(rows), 4)  # header dropped
        self.assertEqual(rows[0][0], "20180101120000")

    def test_parse_cdx_garbage_honest(self):
        self.assertEqual(parse_cdx("not-json"), [])
        self.assertEqual(parse_cdx(""), [])

    def test_classify_stale_still_live(self):
        rows = parse_cdx(CDX_SAMPLE)
        assets = classify_assets(
            rows,
            live_script_urls={"https://x.com/static/app.abc123.js"},
            live_probe_ok={"https://x.com/static/app.abc123.js",
                           "https://x.com/legacy/old-tenant.js"})
        by = {a.url: a for a in assets}
        self.assertEqual(by["https://x.com/legacy/old-tenant.js"].risk,
                         "stale-still-live")
        self.assertEqual(by["https://x.com/static/app.abc123.js"].risk,
                         "stale-referenced")
        self.assertEqual(len(assets), 2)  # .html dropped

    def test_classify_gone(self):
        rows = parse_cdx(CDX_SAMPLE)
        assets = classify_assets(rows, live_script_urls=set(),
                                 live_probe_ok=set())
        self.assertTrue(all(a.risk == "gone" for a in assets))

    def test_diff_captures_removed_surface(self):
        old = ("var cfg={fd:'https://acme-sandbox.freshdesk.com'};"
               "open('paytmmp://mini-app?urlType=launchBot');")
        new = ("var cfg={version:'2'};")  # tenant + deeplink removed
        d = diff_captures(old, new)
        self.assertTrue(any("tenant-saas" in r for r in d["removed"]))
        self.assertTrue(any("deeplink-builder" in r for r in d["removed"]))

    def test_diff_captures_added(self):
        old = "var a=1;"
        new = ("Siy:()=>Ce;"
               "[\"http:\",\"https:\",\"paytmmp:\"].indexOf(p);")
        d = diff_captures(old, new)
        self.assertTrue(any("getter-array" in r for r in d["added"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)

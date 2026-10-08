"""Weak-check ruleset tests (Postman NDSS'13 patterns) + sourcemap stage."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.weakchecks import classify_handler
from core.lanes_jsdeep import mine_bundle, summarize


WEAK_CONTAINS = ("window.addEventListener('message', function(e){"
                 "if(e.origin.includes('example.com')){"
                 "document.getElementById('x').innerHTML=e.data}});")
WEAK_ENDSWITH = ("window.addEventListener('message', function(e){"
                 "if(e.origin.endsWith('example.com')){go(e.data)}});")
STRONG = ("window.addEventListener('message', function(e){"
          "if(e.origin==='https://example.com'){go(e.data)}});")
NO_CHECK = ("window.addEventListener('message', function(e){"
            "go(e.data)});")
NO_HANDLER = "function boot(){return true}"


class TestWeakChecks(unittest.TestCase):
    def test_contains_check_weak(self):
        v = classify_handler(WEAK_CONTAINS)
        self.assertTrue(v.weak)
        self.assertEqual(v.pattern, "contains-check")

    def test_ends_with_weak(self):
        v = classify_handler(WEAK_ENDSWITH)
        self.assertTrue(v.weak)
        self.assertEqual(v.pattern, "ends-with-check")

    def test_strong_origin_equality_clean(self):
        v = classify_handler(STRONG)
        self.assertFalse(v.weak)
        self.assertTrue(v.has_handler)
        self.assertTrue(v.has_any_check)

    def test_no_check_flagged_has_handler(self):
        v = classify_handler(NO_CHECK)
        self.assertFalse(v.weak)          # 'weak-pattern' absent...
        self.assertTrue(v.has_handler)
        self.assertFalse(v.has_any_check)  # ...but zero origin mention

    def test_no_handler(self):
        v = classify_handler(NO_HANDLER)
        self.assertFalse(v.has_handler)


class TestSourcemapStage(unittest.TestCase):
    def test_sourcemap_reference_detected(self):
        bundle = ("var a=1;//# sourceMappingURL=app.min.js.map\n"
                  "console.log(a);")
        fs = mine_bundle(bundle)
        self.assertGreaterEqual(summarize(fs).get("sourcemap-reference", 0), 1)

    def test_no_sourcemap_no_finding(self):
        fs = mine_bundle("var a=1;console.log(a);")
        self.assertEqual(summarize(fs).get("sourcemap-reference", 0), 0)

    def test_prod_still_reproduces(self):
        art = Path("C:/Users/HP/bb-hunt/wa-meta-refocus/report80-evidence/"
                    "care-prod-main.js")
        if not art.exists():
            self.skipTest("prod artifact absent")
        fs = mine_bundle(art.read_text(encoding="utf-8", errors="replace"))
        kinds = summarize(fs)
        self.assertGreaterEqual(kinds.get("tenant-saas", 0), 7)
        self.assertGreaterEqual(kinds.get("deeplink-builder", 0), 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)

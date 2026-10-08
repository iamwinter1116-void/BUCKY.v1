"""Tests for the sanitizer-oracle (P80-class) — incl. PROD validation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.sanitizer_oracle import analyze_sanitizer

# Synthetic fall-through shape (P80 class, anonymized structure)
FALLTHROUGH_BUNDLE = (
    'function d(e){var t=(new DOMParser).parseFromString(e,"text/html");'
    'var n=t.body.firstChild;'
    'if("a"===n.tagName){'
    'var a=n.getAttribute("href")||"";'
    'if(["http:","https:","paytmmp:","paytmba:"].indexOf(a.split(":")[0]+":")>=0){'
    'return T.createElement("a",{href:a})}}'
    'if("br"===n.tagName)return T.createElement("br");'
    'return T.createElement.apply(T,[n.tagName,P({key:1},Array.from('
    'n.attributes).reduce((e,a)=>(e[a.name]=a.value,e),{}))])}'
)
# Clean: explicit tag allowlist gates creation
CLEAN_BUNDLE = (
    'var ALLOWED_TAGS=["a","b","br","span","p"];'
    'function d(e){var t=(new DOMParser).parseFromString(e,"text/html");'
    'var n=t.body.firstChild;'
    'if(!ALLOWED_TAGS.includes(n.tagName))return null;'
    'return T.createElement(n.tagName)}'
)
# Unknown: no parse sink at all
INERT_BUNDLE = "function add(a,b){return a+b;} console.log('app v1.2.3');"


class TestSanitizerOracle(unittest.TestCase):
    def test_fallthrough_shape_detected(self):
        v = analyze_sanitizer(FALLTHROUGH_BUNDLE)
        self.assertEqual(v.verdict, "FALLTHROUGH")
        self.assertIn("parse-sink", v.signals)
        self.assertIn("protocol-allowlist", v.signals)
        self.assertIn("else-create-attrs", v.signals)

    def test_clean_with_tag_gate(self):
        v = analyze_sanitizer(CLEAN_BUNDLE)
        self.assertEqual(v.verdict, "CLEAN")
        self.assertIn("tag-gate-present", v.signals)

    def test_inert_bundle_unknown(self):
        v = analyze_sanitizer(INERT_BUNDLE)
        self.assertEqual(v.verdict, "UNKNOWN")

    def test_empty_input(self):
        self.assertEqual(analyze_sanitizer("").verdict, "UNKNOWN")

    def test_production_validation_paytm_main(self):
        """PROD VALIDATION: the real captured care-app main bundle.

        This is the C178 P80 finding — the oracle MUST reproduce it
        from the sealed production artifact alone (deterministic
        re-derivation invariant). Skip-with-fail if artifact absent.
        """
        p = Path("C:/Users/HP/bb-hunt/wa-meta-refocus/report80-evidence/"
                 "care-prod-main.js")
        if not p.exists():
            self.fail("production artifact missing: care-prod-main.js")
        v = analyze_sanitizer(p.read_text(encoding="utf-8", errors="replace"))
        self.assertIn(v.verdict, ("FALLTHROUGH", "PARTIAL"),
                      f"prod verdict {v.verdict}: signals={v.signals}")
        self.assertIn("parse-sink", v.signals)
        self.assertIn("else-create-attrs", v.signals)


if __name__ == "__main__":
    unittest.main(verbosity=2)

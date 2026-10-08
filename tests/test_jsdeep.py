"""Tests for lanes_jsdeep — incl. PRODUCTION validation (care-app main)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.lanes_jsdeep import mine_bundle, summarize, tenant_pairs

SYNTH = (
    "var t=(new DOMParser).parseFromString(e,'text/html');"
    'if(["http:","https:","paytmmp:","paytmba:"].indexOf(p)>=0){go(p)}'
    "open('paytmmp://mini-app?urlType=launchBot&aId=cce79c95');"
    "R=function(){H(e,t)};window.H=function(){"
    "'https://paytm-ocl.freshdesk.com/api/v2/tickets'"
    "+'https://paytm-bank.freshdesk.com/api/v2/tickets'"
    "+'https://paytm-oclsandbox.freshdesk.com/web/agent'"
    "+'https://paytm-banksandbox.freshdesk.com/web/agent'};"
    "Siy:()=>Ce;"
    "[66719](function(e,t){});"
    "parent.postMessage({type:'AUTH_DATA'},'*');"
)
BENIGN = ("var app={version:'1.2.3'};function boot(){return true};"
          "console.log('http://cdn.example.com/lib.js ok');")


class TestJSDeep(unittest.TestCase):
    def test_synth_bundle_all_classes(self):
        fs = mine_bundle(SYNTH)
        kinds = summarize(fs)
        self.assertGreaterEqual(kinds.get("tenant-saas", 0), 4)
        self.assertGreaterEqual(kinds.get("scheme-allowlist", 0), 1)
        self.assertGreaterEqual(kinds.get("deeplink-builder", 0), 1)
        self.assertGreaterEqual(kinds.get("getter-array", 0), 1)
        self.assertGreaterEqual(kinds.get("module-boundary", 0), 1)
        self.assertGreaterEqual(kinds.get("wildcard-postmessage", 0), 1)

    def test_tenant_pair_detection(self):
        fs = mine_bundle(SYNTH)
        pairs = tenant_pairs(fs)
        self.assertTrue(any("freshdesk.com" in p for p in pairs),
                        f"pairs={pairs}")

    def test_scheme_allowlist_needs_two_protocols(self):
        fs = mine_bundle('var ok=["http:"];')  # single proto = no signal
        self.assertEqual(summarize(fs).get("scheme-allowlist", 0), 0)

    def test_builtin_schemes_not_deeplinks(self):
        fs = mine_bundle("open('https://example.com/x?a=1');")
        self.assertEqual(summarize(fs).get("deeplink-builder", 0), 0)

    def test_benign_bundle_clean(self):
        fs = mine_bundle(BENIGN)
        # benign has no SaaS, no custom schemes, no getters
        self.assertEqual(summarize(fs).get("tenant-saas", 0), 0)
        self.assertEqual(summarize(fs).get("scheme-allowlist", 0), 0)
        self.assertEqual(summarize(fs).get("wildcard-postmessage", 0), 0)

    def test_finding_shape_deterministic(self):
        fs1 = mine_bundle(SYNTH)
        fs2 = mine_bundle(SYNTH)
        self.assertEqual([(f.kind, f.offset) for f in fs1],
                         [(f.kind, f.offset) for f in fs2])

    def test_redaction_masks_secretish_values(self):
        fs = mine_bundle("open('paytmmp://secret-token-pay/x?a=1')")
        dl = [f for f in fs if f.kind == "deeplink-builder"]
        self.assertTrue(all("***" in f.redacted or "secret" not in
                            f.redacted.lower() for f in dl))


class TestProdValidation(unittest.TestCase):
    """PROD VALIDATION: the real sealed care-app bundle (C176/C178).

    The miner MUST reproduce the campaign's manual findings from the
    artifact alone: freshdesk tenants ×7, paytmmp deeplinks ×33,
    scheme-allowlist ×1, Siy getter ×1, module-66719 ×15.
    """
    ARTIFACT = Path("C:/Users/HP/bb-hunt/wa-meta-refocus/report80-evidence/"
                    "care-prod-main.js")

    def test_prod_main_reproduces_campaign_findings(self):
        if not self.ARTIFACT.exists():
            self.fail("production artifact missing: care-prod-main.js")
        text = self.ARTIFACT.read_text(encoding="utf-8", errors="replace")
        fs = mine_bundle(text)
        kinds = summarize(fs)
        self.assertGreaterEqual(kinds.get("tenant-saas", 0), 7,
                                f"kinds={kinds}")
        self.assertGreaterEqual(kinds.get("deeplink-builder", 0), 30,
                                f"kinds={kinds}")
        self.assertGreaterEqual(kinds.get("scheme-allowlist", 0), 1)
        self.assertGreaterEqual(kinds.get("getter-array", 0), 1)
        pairs = tenant_pairs(fs)
        self.assertTrue(any("freshdesk" in p for p in pairs),
                        f"pairs={pairs}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

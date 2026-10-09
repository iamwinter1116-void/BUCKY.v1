"""Profiles tests — generic core, campaign-specific signatures plug in."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.profiles import (DEFAULT_PROFILES_DIR, CampaignProfile,
                           ObservationRule, available_profiles,
                           load_profile)
from core.proof_gate import default_profile, gate, verify_observation
from core.chain_verdict import (CAP_CROSS_TENANT, CAP_DOM_XSS,
                                CAP_SECRET_LEAK, verdict_from_findings)

FULL = {"embeds-attacker-frame", "handler-weak-origin",
        "sanitizer-fallthrough", "custom-scheme-registered",
        "deeplink-taint-params", "tenant-pair-hardcoded",
        "bot-launch-param"}


class TestProfiles(unittest.TestCase):
    def test_shipped_generic_profile_exists(self):
        self.assertIn("generic-saas-embed", available_profiles())

    def test_generic_profile_no_vendor_strings(self):
        """THE rule: core + default profile never mention any vendor."""
        prof = load_profile(DEFAULT_PROFILES_DIR /
                            "generic-saas-embed.json")
        blob = str(prof.observations) + prof.description
        for vendor in ("paytm", "freshdesk", "zendesk", "whatsapp",
                       "cce79c95", "custId="):
            self.assertNotIn(vendor.lower(), blob.lower(),
                             f"vendor string leaked: {vendor}")

    def test_generic_profile_still_proves_c181_class_capture(self):
        # the GENERIC beacon class must match a real embed-handshake
        pr = verify_observation(
            CAP_CROSS_TENANT,
            "IFRAME_READY origin=https://widget.example.com")
        self.assertTrue(pr.proven)

    def test_campaign_profile_overrides(self):
        """A campaign profile supplies instance regexes; generic ones
        do NOT apply when a profile is passed."""
        custom = CampaignProfile(
            name="acme-widget",
            observations=(ObservationRule(
                r"ACME_SESSION_BOUNDARY", CAP_CROSS_TENANT, "acme beacon"),))
        # generic beacon ignored under campaign profile
        pr = verify_observation(
            CAP_CROSS_TENANT, "IFRAME_READY from widget",
            profile=custom)
        self.assertFalse(pr.proven)
        # campaign beacon proves
        pr2 = verify_observation(
            CAP_CROSS_TENANT, "log: ACME_SESSION_BOUNDARY cust=7",
            profile=custom)
        self.assertTrue(pr2.proven)

    def test_bad_regex_honest_skip(self):
        custom = CampaignProfile(
            name="broken",
            observations=(ObservationRule("(unclosed", "x-cap", ""),))
        self.assertEqual(custom.compiled(), [])  # no crash, no match

    def test_gate_with_campaign_profile(self):
        v = verdict_from_findings(FULL, goal=CAP_CROSS_TENANT)
        custom = CampaignProfile(
            name="acme",
            observations=(ObservationRule(
                r"ACME_TAKEOVER_OK", CAP_CROSS_TENANT, "acme"),))
        pr = gate(v, "ACME_TAKEOVER_OK observed", profile=custom)
        self.assertTrue(pr.proven)

    def test_default_profile_fallback(self):
        d = default_profile()
        self.assertTrue(d.name)  # non-empty profile loads


class TestCoreGenericAudit(unittest.TestCase):
    """No vendor names anywhere in engine CORE modules."""

    CORE_DIR = Path("C:/Users/HP/winterforge/core")

    def test_core_has_no_vendor_strings(self):
        vendors = ("paytm", "freshchat", "zendesk", "intercom",
                   "hubspot", "whatsapp", "cce79c95")
        # freshdesk/zendesk etc appear in lanes_jsdeep as PROVIDER
        # SUFFIX TABLES (detection vocabulary, not vendor loyalty) —
        # those are detection CLASSES. Audit the chain/proof/profile
        # modules (the composition layer) for campaign leakage:
        for mod in ("chain_verdict.py", "proof_gate.py",
                    "profiles.py", "weakchecks.py"):
            p = self.CORE_DIR / mod
            if not p.exists():
                continue
            txt = p.read_text(encoding="utf-8").lower()
            for v in ("paytm", "whatsapp", "cce79c95",
                      "launchbot", "custid"):
                self.assertNotIn(v, txt, f"{mod} leaked vendor: {v}")

    def test_provider_tables_are_class_vocabulary(self):
        """SaaS provider suffixes in jsdeep are a detection TABLE
        (extendable), not campaign hardcoding — verify it is a
        superset, i.e. generic across providers."""
        from core.lanes_jsdeep import _SAAS_HOST
        sample = ("acme.freshdesk.com", "acme.zendesk.com",
                  "acme.intercom.com", "acme.hubspot.com")
        blob = " ".join(sample)
        hits = len(_SAAS_HOST.findall(blob))
        self.assertGreaterEqual(hits, 4,
                                "provider table must be multi-vendor")


if __name__ == "__main__":
    unittest.main(verbosity=2)

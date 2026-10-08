"""Deeplink-lane tests — collision table, taint params, mutations."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.lanes_deeplink import (collision_table, harvest_deeplinks,
                                 hijack_flags, taint_params,
                                 trusted_domain_mutations)

SYNTH = ("open('paytmmp://mini-app?urlType=launchBot&aId=abc123');"
         "location='paytmmp://wallet?amt=500';"
         "link='https://paytm.com/pay';"
         "iframe.src='paytmmp://care?x=1&y=2';")


class TestDeeplink(unittest.TestCase):
    def test_harvest_custom_and_builtin(self):
        links = harvest_deeplinks(SYNTH)
        schemes = {l.scheme for l in links}
        self.assertIn("paytmmp", schemes)
        self.assertIn("https", schemes)
        self.assertTrue(all(l.is_custom for l in links
                            if l.scheme == "paytmmp"))

    def test_collision_table_groups_claimants(self):
        links = harvest_deeplinks(SYNTH)
        table = collision_table(links)
        self.assertIn("paytmmp", table)
        self.assertGreaterEqual(len(table["paytmmp"]), 1)

    def test_hijack_flag_multi_claimant(self):
        # two custom schemes with DIFFERENT host claims = collision;
        # inline-only links (query-only URIs) claim a pseudo-host from
        # the path slot — still flagged as unowned per Liu'17 grouping
        text = ("a='appone://deeplink?x=1';"
                "b='apptwo://deeplink?x=2';"
                "c='appone://other?x=3';")
        links = harvest_deeplinks(text)
        table = collision_table(links)
        flags = hijack_flags(table, owned_hosts=set())
        # appone+apptwo each claim foreign hosts -> flagged unowned
        self.assertEqual(len(flags), 2)
        self.assertTrue(all(f.hijack_risk for f in flags))
        # owning the hosts clears the unowned flag, but 'deeplink' is
        # claimed by TWO schemes (appone+apptwo) -> multi-claimant
        # collision persists (Liu'17: shared claimant host = hijack-
        # capable group even when both are 'ours')
        flags2 = hijack_flags(table, owned_hosts={"deeplink", "other"})
        self.assertEqual(len(flags2), 1)
        self.assertIn("2 claimants", flags2[0].detail)

    def test_hijack_flag_unowned_host(self):
        text = "a='customscheme://evil.example.com/x?y=1';"
        links = harvest_deeplinks(text)
        flags = hijack_flags(collision_table(links),
                             owned_hosts={"paytm.com"})
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0].hijack_risk)
        self.assertIn("unowned", flags[0].detail)

    def test_taint_params_inventory(self):
        links = harvest_deeplinks(
            "open('paytmmp://mini-app?urlType=launchBot&aId=abc');")
        tp = taint_params(links)
        self.assertEqual(len(tp), 1)
        params = list(tp.values())[0]
        self.assertIn("urlType", params)
        self.assertIn("aId", params)

    def test_builtin_not_taint_flagged(self):
        links = harvest_deeplinks("x='https://a.com/p?token=1';")
        self.assertEqual(taint_params(links), {})

    def test_trusted_domain_mutations_shape(self):
        muts = trusted_domain_mutations("paytm.com")
        self.assertEqual(len(muts), 3)
        self.assertTrue(any(".attacker.example" in m for m in muts))

    def test_deterministic_re_run(self):
        a = [(l.scheme, l.offset) for l in harvest_deeplinks(SYNTH)]
        b = [(l.scheme, l.offset) for l in harvest_deeplinks(SYNTH)]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)

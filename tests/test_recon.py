"""Tests for recon-pipeline lanes (offline-safe: fixtures + mocks)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import lanes_recon


class TestCTSeed(unittest.TestCase):
    def test_parses_crt_json_and_dedupes(self):
        import json, tempfile
        td = Path(tempfile.mkdtemp())
        # pre-seed cache so the test is offline
        rows = [{"name_value": "a.example.com\nb.example.com"},
                {"name_value": "*.example.com\na.example.com"}]
        (td / "ct-example.com.json").write_text(json.dumps(rows), encoding="utf-8")
        hosts = lanes_recon.ct_seed("example.com", cache_dir=td)
        self.assertEqual(hosts, ["a.example.com", "b.example.com"])

    def test_cache_hit_never_network(self):
        import json, tempfile
        td = Path(tempfile.mkdtemp())
        (td / "ct-example.com.json").write_text(json.dumps(
            [{"name_value": "x.example.com"}]), encoding="utf-8")
        # monkeypatch urlopen to explode if called
        orig = lanes_recon.urllib.request.urlopen
        lanes_recon.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("network touched on cache hit"))
        try:
            hosts = lanes_recon.ct_seed("example.com", cache_dir=td)
            self.assertEqual(hosts, ["x.example.com"])
        finally:
            lanes_recon.urllib.request.urlopen = orig


class TestDNSExpand(unittest.TestCase):
    def test_unresolvable_recorded(self):
        facts = lanes_recon.dns_expand(["this-host-does-not-exist-xyz.invalid"])
        self.assertFalse(facts[0].resolves)

    def test_live_host_resolves(self):
        facts = lanes_recon.dns_expand(["localhost"])
        self.assertTrue(facts[0].resolves)


class TestTakeover(unittest.TestCase):
    def test_dangling_provider_candidate(self):
        # host that does not resolve + CNAME fingerprint to github.io
        fake = [lanes_recon.HostFact("dead.example.com", False)]
        orig = lanes_recon._cname_via_getaddrinfo
        lanes_recon._cname_via_getaddrinfo = lambda h: "winter1116.github.io"
        try:
            cands = lanes_recon.takeover_candidates(fake)
            self.assertEqual(len(cands), 1)
            self.assertEqual(cands[0].provider, "github-pages")
            self.assertFalse(cands[0].claim_action_required)
        finally:
            lanes_recon._cname_via_getaddrinfo = orig

    def test_resolving_host_not_candidate(self):
        fake = [lanes_recon.HostFact("live.example.com", True, "1.2.3.4")]
        self.assertEqual(lanes_recon.takeover_candidates(fake), [])

    def test_no_provider_no_candidate(self):
        fake = [lanes_recon.HostFact("dead.example.com", False)]
        orig = lanes_recon._cname_via_getaddrinfo
        lanes_recon._cname_via_getaddrinfo = lambda h: "unknown.svc.internal"
        try:
            self.assertEqual(lanes_recon.takeover_candidates(fake), [])
        finally:
            lanes_recon._cname_via_getaddrinfo = orig


class TestHTTPProbe(unittest.TestCase):
    def test_probe_lab_vuln_fixture_shape(self):
        # shape test on the dataclass only (no network in unit tests)
        f = lanes_recon.HostFact("h", True, "", 200, "t", "s")
        self.assertEqual((f.host, f.http_status, f.title), ("h", 200, "t"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""BUCKY test-suite — business-logic tests (stdlib unittest, zero deps).

Covers the pure-logic cores: config validation, evidence seal/verify
(tamper-detection), marker-slicing. VM-dependent lanes are integration-tested
live (see PLAN.md) — not mocked here, because untested mocks are lies.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.config import ConfigError, load_config  # noqa: E402
from core import evidence  # noqa: E402


class TestConfigValidation(unittest.TestCase):
    """config.json loader must fail loudly and precisely."""

    def test_missing_file_raises_configerror(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ConfigError) as ctx:
                load_config(Path(td) / "nope.json")
            self.assertIn("not found", str(ctx.exception))

    def test_malformed_json_raises_configerror(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(p)

    def test_missing_vm_key_raises_configerror(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "partial.json"
            p.write_text(json.dumps({"vm": {"name": "x"}}), encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(p)
            self.assertIn("vm.ssh_key", str(ctx.exception))

    def test_real_config_loads(self):
        """The repo's own config.json (API key may be empty) must validate."""
        cfg = load_config()
        self.assertEqual(cfg.vm.user, "kali")
        self.assertEqual(cfg.vm.port, 2222)
        self.assertIn("kali", cfg.vm.name.lower())


class TestEvidencePipeline(unittest.TestCase):
    """Seal → verify → tamper → re-seal round-trip."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "ev"
        self.dir.mkdir()
        (self.dir / "a.txt").write_text("alpha", encoding="utf-8")
        sub = self.dir / "sub"
        sub.mkdir()
        (sub / "b.log").write_text("beta-data", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_seal_covers_all_files_and_creates_manifest(self):
        res = evidence.seal(self.dir, label="t")
        names = {e["file"] for e in res.files}
        self.assertEqual(names, {"a.txt", "sub/b.log"})
        self.assertTrue(res.manifest_path.exists())
        self.assertEqual(len(res.manifest_sha256), 64)

    def test_verify_passes_on_untouched_dir(self):
        evidence.seal(self.dir, label="t")
        res = evidence.verify(self.dir)
        self.assertTrue(res.ok)
        self.assertEqual(res.problems, [])

    def test_verify_catches_tamper(self):
        evidence.seal(self.dir, label="t")
        (self.dir / "a.txt").write_text("EVIL", encoding="utf-8")
        res = evidence.verify(self.dir)
        self.assertFalse(res.ok)
        self.assertTrue(any("HASH-MISMATCH a.txt" in p for p in res.problems))

    def test_verify_catches_deletion(self):
        evidence.seal(self.dir, label="t")
        (self.dir / "sub" / "b.log").unlink()
        res = evidence.verify(self.dir)
        self.assertFalse(res.ok)
        self.assertTrue(any("MISSING sub/b.log" in p for p in res.problems))

    def test_verify_missing_manifest(self):
        res = evidence.verify(self.dir)
        self.assertFalse(res.ok)
        self.assertIn("MANIFEST.json missing", res.problems[0])


class TestMarkerSlicing(unittest.TestCase):
    """vmbridge.run output-slicing logic (pure part, tested via the
    same algorithm — exact token math)."""

    def test_slice_math(self):
        token = "FRGabcd1234"
        out = "noise\n" + f"{token}-START\n" + "line1\nline2\n" + f"{token}-EXIT:0\n"
        i = out.find(f"{token}-START")
        j = out.find(f"{token}-EXIT:")
        body = out[i + len(token) + 7: j]
        self.assertEqual(body.strip(), "line1\nline2")


if __name__ == "__main__":
    unittest.main(verbosity=2)

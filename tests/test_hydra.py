"""Hydra-banner v2 tests — real-art render, reveal, pulse, dialogue."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.hydra import (DIALOGUE, VERSION_LINE, art_geometry, banner,
                        frame, load_art)


class TestHydraBannerV2(unittest.TestCase):
    def setUp(self):
        self.art = load_art()
        self.cells, self.maxd = art_geometry(self.art)

    def test_art_is_the_real_emblem(self):
        # the committed art must be substantial, not the fallback
        self.assertGreater(len(self.art), 20)
        self.assertGreater(max(len(ln) for ln in self.art), 60)
        joined = "\n".join(self.art)
        # half-block ink must cover a real fraction of the canvas
        ink = sum(1 for ch in joined if ch not in " \n")
        self.assertGreater(ink, 800)

    def test_frames_all_rows_same_width(self):
        for t in (0, 3, 9, 12, 30):
            f = frame(self.cells, self.maxd, t, ansi=False)
            self.assertEqual(len(f), len(self.art))

    def test_reveal_grows_from_center(self):
        r0 = frame(self.cells, self.maxd, 0, reveal_frames=10, ansi=False)
        r5 = frame(self.cells, self.maxd, 5, reveal_frames=10, ansi=False)
        ink0 = sum(1 for ln in r0 if ln.strip())
        ink5 = sum(1 for ln in r5 if ln.strip())
        self.assertGreater(ink5, ink0, "reveal must grow frame->frame")

    def test_pulse_has_wave_colors(self):
        # the wave sweeps outward over frames; across a full sweep the
        # blood + crest colors must both appear somewhere
        hits_wave = hits_crest = 0
        for t in range(10, 30):
            f = frame(self.cells, self.maxd, t, reveal_frames=10,
                      ansi=True)
            j = "".join(f)
            if "\033[38;5;196m" in j:
                hits_wave += 1
            if "\033[97;1m" in j:
                hits_crest += 1
        self.assertGreater(hits_wave, 10,
                           "blood-wave color must sweep across frames")
        self.assertGreater(hits_crest, 10,
                           "white-hot crest must sweep across frames")

    def test_banner_plain_mode(self):
        txt = banner(frames=2, delay=0, ansi=False,
                     dialogue="HAIL HYDRA.")
        self.assertIn("HAIL HYDRA.", txt)
        self.assertIn(VERSION_LINE, txt)
        self.assertIn(">>", txt)

    def test_dialogue_pool(self):
        self.assertGreaterEqual(len(DIALOGUE), 10)
        self.assertTrue(DIALOGUE[0].startswith("CUT OFF ONE HEAD"))
        self.assertIn("HAIL HYDRA.", DIALOGUE[:2])


if __name__ == "__main__":
    unittest.main(verbosity=2)

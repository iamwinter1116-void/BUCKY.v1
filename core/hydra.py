"""BUCKY hydra banner v2 — the operator's REAL emblem, animated.

v1 (procedural math-sketch) was rejected: "improper, no detail, no
exact chehra". v2 renders the operator's own logo image
(assets/hydra_logo.png, converted at build time to half-block art in
assets/hydra_art.txt — 40 rows x 80 cols, pixel-faithful).

Animation (ANSI, Windows VT-safe):
  phase REVEAL : iris wipe — the emblem wakes up center-out
  phase PULSE  : a blood-glow wave pumps outward, crest white-hot
  then        : villain dialogue typewriter + version line

Pure-stdlib at runtime (art is committed text; Pillow is
build-time only). Static/plain mode for tests and pipes.
"""
from __future__ import annotations

import math
import os
import random
import sys
import time
from pathlib import Path

_ART = Path(__file__).resolve().parents[1] / "assets" / "hydra_art.txt"

VERSION_LINE = ("BUCKY v0.27 — the many-headed hunt engine — "
                "`bucky <cmd> -h`")

DIALOGUE: tuple[str, ...] = (
    "CUT OFF ONE HEAD, TWO MORE SHALL TAKE ITS PLACE.",
    "HAIL HYDRA.",
    "HYDRA DOES NOT FORGET. HYDRA DOES NOT FORGIVE. HYDRA ENUMERATES.",
    "EVERY PORT YOU CLOSE, WE GREW TWO MORE.",
    "WE DO NOT KNOCK. WE ENUMERATE.",
    "THE SHADOWS HAVE AN API NOW.",
    "SILENCE IS JUST AN UNREPORTED VULNERABILITY.",
    "WE WERE NEVER IN THE LOGS. THAT WAS THE POINT.",
    "FEAR IS THE OLDEST EXPLOIT. WE JUST MAINTAINED IT.",
    "TODAY'S TARGET IS TOMORROW'S SUBDOMAIN.",
    "WE ARE ALREADY INSIDE THE SCOPE YOU DIDN'T DEFINE.",
    "CUT THE WI-FI. WE GREW HEADS ON THE BACKUP LINK.",
)

# ANSI: ember base / blood wave / white-hot crest
_C_BASE = "\033[38;5;88m"
_C_WAVE = "\033[38;5;196m"
_C_CREST = "\033[97;1m"
_C_RST = "\033[0m"

# tiny emergency emblem (only if the art asset is somehow missing)
_FALLBACK = (
    "        ___        ",
    "       /o o\\       ",
    "       \\ Y /       ",
    "      _(_)_ _      ",
    "  ~  ':::::::'  ~  ",
    " ~  ~  ~   ~  ~  ~ ",
)


def load_art() -> list[str]:
    """The committed half-block art (or a tiny fallback).

    Searches (in order): the repo assets/ dir next to this module,
    the module's own directory (VM deployment shape), and the CWD.
    """
    here = Path(__file__).resolve().parent
    cands = [
        here.parent / "assets" / "hydra_art.txt",
        here / "assets" / "hydra_art.txt",
        here / "hydra_art.txt",
        Path.cwd() / "assets" / "hydra_art.txt",
        Path.cwd() / "hydra_art.txt",
    ]
    for c in cands:
        if c.is_file():
            lines = c.read_text(encoding="utf-8").splitlines()
            if lines:
                return lines
    return list(_FALLBACK)


def art_geometry(lines: list[str]):
    """Per-cell glyph + distance-from-center, plus max distance."""
    h = len(lines)
    w = max(len(ln) for ln in lines)
    cx, cy = (w - 1) / 2, (h - 1) / 2
    cells = []
    for r in range(h):
        row = []
        ln = lines[r]
        for c in range(w):
            ch = ln[c] if c < len(ln) else " "
            d = math.hypot(c - cx, r - cy)
            row.append((ch, d))
        cells.append(row)
    maxd = max(d for row in cells for _, d in row) or 1.0
    return cells, maxd


def _plain_frame(cells) -> list[str]:
    return ["".join(ch for ch, _ in row) for row in cells]


def frame(cells, maxd: float, t: int, *, reveal_frames: int = 10,
          ansi: bool = True) -> list[str]:
    """Animation frame t. Reveal first, then the glow pulse loops."""
    h = len(cells)
    w = len(cells[0])
    out = []
    if t < reveal_frames:                     # ---- IRIS REVEAL ----
        radius = maxd * 1.08 * (t + 1) / reveal_frames
        for row in cells:
            buf = []
            for ch, d in row:
                if ch == " " or d > radius:
                    buf.append(" ")
                else:
                    buf.append(_C_WAVE + ch + _C_RST if ansi else ch)
            out.append("".join(buf) if ansi else "".join(
                c for c in buf if c not in (_C_WAVE, _C_RST)))
        return out

    # ---- GLOW PULSE (loops forever) ----
    tw = (t - reveal_frames)
    # fast sweep: full emblem traversed in ~20 pulse frames
    wave = (tw * 2.0) % (maxd * 1.4) - maxd * 0.2
    crest_band, wave_band = 2.2, 5.5
    for r, row in enumerate(cells):
        buf = []
        for c, (ch, d) in enumerate(row):
            if ch == " ":
                buf.append(" ")
                continue
            if abs(d - wave) < crest_band:
                col = _C_CREST
            elif abs(d - wave) < wave_band:
                col = _C_WAVE
            else:
                col = _C_BASE
            buf.append(col + ch + _C_RST if ansi else ch)
        out.append("".join(buf))
    return out


def banner(frames: int = 24, delay: float = 0.09,
           dialogue: str | None = None, ansi: bool = True,
           stream=None) -> str:
    """Play reveal + pulse + typewriter dialogue. Returns final text."""
    out = stream or sys.stdout
    if ansi and os.name == "nt":
        os.system("")                # enable VT on Windows consoles
    rnd = random.Random()
    line = dialogue if dialogue is not None else rnd.choice(DIALOGUE)

    art = load_art()
    cells, maxd = art_geometry(art)
    reveal = min(10, max(3, frames // 3)) if frames > 1 else 0
    plain: list[str] = []

    for t in range(max(1, frames)):
        f = frame(cells, maxd, t, reveal_frames=reveal, ansi=ansi)
        if not ansi:
            plain = f
            continue
        if t:
            out.write(f"\033[{len(f)}A\r")
        out.write("\n".join(f) + "\n")
        out.flush()
        if delay:
            time.sleep(delay)

    if ansi:
        # final resting frame: full emblem in blood red
        rest = [_C_WAVE + ln + _C_RST for ln in _plain_frame(cells)]
        out.write(f"\033[{len(rest)}A\r")
        out.write("\n".join(rest) + "\n")
        out.flush()
        # typewriter villain line
        out.write(_C_CREST + "\n  >> ")
        out.flush()
        for ch in line:
            out.write(ch)
            out.flush()
            if delay:
                time.sleep(max(0.004, delay * 0.12))
        out.write(_C_RST + "\n")
        out.write("\033[2m" + VERSION_LINE + _C_RST + "\n")
        out.flush()
        return "\n".join(_plain_frame(cells) + ["", "  >> " + line,
                                               VERSION_LINE]) + "\n"

    # plain mode: static art + dialogue + version
    txt = _plain_frame(cells) + ["", "  >> " + line, VERSION_LINE]
    if out is not sys.stdout or True:
        print("\n".join(txt), file=out)
    return "\n".join(txt) + "\n"

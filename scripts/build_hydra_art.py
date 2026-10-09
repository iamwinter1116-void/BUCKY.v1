"""Build-time: convert assets/hydra_logo.png -> assets/hydra_art.txt.

Half-block art: 80 cols x 40 rows (each char = 2 pixel-rows of an
80x80 grayscale render of the operator's emblem). Committed to the
repo so runtime needs NO Pillow — hydra.py just reads the text.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "assets" / "hydra_logo.png"
DST = ROOT / "assets" / "hydra_art.txt"

COLS = 80          # terminal columns
ROWS = 40          # terminal rows -> image 80 x 160? no: 80 x (2*40)


def main() -> int:
    from PIL import Image

    img = Image.open(SRC).convert("L")
    # square crop then resize to COLS x (ROWS*2) pixel grid
    w, h = img.size
    side = min(w, h)
    img = img.crop(((w - side) // 2, (h - side) // 2,
                    (w + side) // 2, (h + side) // 2))
    img = img.resize((COLS, ROWS * 2))

    px = img.load()
    lines: list[str] = []
    for r in range(ROWS):
        row = []
        for c in range(COLS):
            top = px[c, r * 2]          # luminance 0..255
            bot = px[c, r * 2 + 1]
            # logo = BLACK on WHITE. invert: glyph where pixel is dark
            t = top < 128              # True -> ink
            b = bot < 128
            if t and b:
                row.append("\u2588")    # full block
            elif t:
                row.append("\u2580")    # upper half
            elif b:
                row.append("\u2584")    # lower half
            else:
                row.append(" ")
        lines.append("".join(row))

    # trim fully-blank side columns to tighten the art
    first = min((c for c in range(COLS) if any(ln[c] != " " for ln in lines)),
                default=0)
    last = max((c for c in range(COLS) if any(ln[c] != " " for ln in lines)),
               default=COLS - 1)
    lines = [ln[first:last + 1] for ln in lines]
    # drop fully-blank top/bottom rows
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    DST.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {DST}: {len(lines)} rows x {len(lines[0])} cols")
    return 0


if __name__ == "__main__":
    sys.exit(main())

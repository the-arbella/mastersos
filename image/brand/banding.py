#!/usr/bin/env python3
"""Fail when a wallpaper shows banding (design 2026-11-04 visual identity, review focus 4). Usage: banding.py <image>...

Two signs, either one fails:
- a run of more than 8 rows in a 64 px centre strip where each row is one single colour: an 8-bit gradient without dither,
  which shows bands on the 6-bit panels of school laptops (the final review measured 96 such rows in the night sky);
- along the sky, the mean brightness of each row of a centre band sits flat for 40 rows and then jumps by 3 or more levels.
"""
import sys
from PIL import Image

MAX_UNIFORM_ROWS = 8

for path in sys.argv[1:]:
    rgb = Image.open(path).convert("RGB")
    w, h = rgb.size
    strip = rgb.crop((w // 2 - 32, 0, w // 2 + 32, h)).load()
    run = longest = 0
    at = 0
    for y in range(h):
        first = strip[0, y]
        if all(strip[x, y] == first for x in range(1, 64)):
            run += 1
            if run > longest:
                longest, at = run, y - run + 1
        else:
            run = 0
    if longest > MAX_UNIFORM_ROWS:
        sys.exit(f"banding: {path} has {longest} single-colour rows from row {at} (no dither; at most {MAX_UNIFORM_ROWS})")
    im = rgb.convert("L")
    band = im.crop((w // 2 - 600, 0, w // 2 + 600, int(h * 0.55)))
    px = band.load()
    rows = [sum(px[x, y] for x in range(0, band.width, 4)) / (band.width / 4) for y in range(band.height)]
    flat = 0
    for a, b in zip(rows, rows[1:]):
        d = abs(b - a)
        if d < 0.05:
            flat += 1
        else:
            if flat >= 40 and d >= 3:
                sys.exit(f"banding: {path} shows banding (flat {flat} rows, then a step of {d:.1f})")
            flat = 0
print("banding: none")

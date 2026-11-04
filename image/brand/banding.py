#!/usr/bin/env python3
"""Fail when a wallpaper shows banding: along the sky, the mean brightness of each row of a centre band sits flat for 40
rows and then jumps by 3 or more levels (design 2026-11-04 visual identity, review focus 4). Usage: banding.py <image>...
"""
import sys
from PIL import Image
for path in sys.argv[1:]:
    im = Image.open(path).convert("L")
    w, h = im.size
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

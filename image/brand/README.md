# MastersOS brand

Masters for the MastersOS look (design `docs/specs/2026-11-04-visual-identity-design.md`). The rendered files live in
`image/mkosi.extra` and are committed; the image build does not render anything.

| Master | Renders to |
|---|---|
| `logo.svg` | `usr/share/icons/hicolor/<N>x<N>/apps/mastersos-logo.png` (16 to 512) and `scalable/apps/mastersos-logo.svg` |
| `logo-symbolic.svg` | `usr/share/icons/hicolor/symbolic/apps/mastersos-logo-symbolic.svg` |
| `wordmark.py` + `fonts/` | `usr/share/mastersos/brand/wordmark-light.svg` (outlines; devices need no font) |
| `wallpaper.html` | `usr/share/backgrounds/mastersos/mastersos-{day,night}.jpg` (3840x2400) |

Re-render after changing a master:

```bash
pip install pillow fonttools   # once
bash image/brand/render.sh     # needs Chrome or Chromium; CHROME=<path> to choose
```

`render.sh` fails when a wallpaper shows banding (`banding.py`). `image/tests/check-tree.sh` item 51 checks the outputs.

The meaning, for whoever changes these: Master is the Lord; the light where the strokes of the M meet, and the rings
spreading from the light over the hills, are influence going out into the world. The look itself carries no religious
symbol, so every school can use it.

Plus Jakarta Sans is licensed under the SIL Open Font License 1.1 (`fonts/OFL.txt`).

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

## Renaming the product (known gap, planned for M7)

The product name is not configurable yet: "MastersOS" is written directly into every user-visible place (audit
2026-11-06). These are:
- os-release `NAME`/`PRETTY_NAME` (`mkosi.postinst.chroot`), which systemd-boot and Settings > About show;
- the wordmark (`wordmark.py`);
- the kiosk `.desktop`/`.session` names, the wallpaper name and the gnome-shell extension `metadata.json` names;
- the exam extension manifest;
- the notify-send/zenity titles (agent `login_queue.rs`, `kiosk_session.rs`; `browser-wait`, `interface-denied`,
  `integrity`);
- the installer, first-run and Ventoy messages, the `efibootmgr` label and the USB README.

Decision (2026-11-06, owner via the arbella coordinator): renaming is **build time only**, the Chromium/Chrome pattern.
- One brand config (product name + wordmark) that `build.sh` feeds into all of the above. Titles at run time come from
  os-release or a generated constant.
- The open-source default build is "MastersOS"; a vendor build sets its own name.
- `branding.json` stays the school's branding: no runtime `product_name`.
- Key material (the MOK certificate CN "MastersOS Secure Boot 2026", key names) keeps the code name and is never
  renamed.
- Not an M4 gate. Scheduled after the identity lab work.

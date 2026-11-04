#!/bin/bash
# Render the MastersOS brand assets from the masters in this directory into the image tree (design 2026-11-04 visual
# identity §5.1). Run by a developer after changing a master; the outputs are committed and the image build never renders.
# Needs headless Chrome or Chromium (CHROME=<path> to pick one) and python3 with Pillow and fontTools.
# Usage: bash image/brand/render.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ex=$here/../mkosi.extra
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

chrome=${CHROME:-}
if [ -z "$chrome" ]; then
	for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium chromium-browser; do
		if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
			chrome=$c
			break
		fi
	done
fi
[ -n "$chrome" ] || {
	echo "render.sh: no Chrome or Chromium found (set CHROME=<path>)" >&2
	exit 1
}
python3 -c 'import PIL, fontTools' 2>/dev/null || {
	echo "render.sh: python3 needs Pillow and fontTools (pip install pillow fonttools)" >&2
	exit 1
}

# shot <url> <width> <height> <scale> <out.png>: one headless screenshot, transparent where the page draws nothing
shot() {
	"$chrome" --headless=new --disable-gpu --hide-scrollbars --allow-file-access-from-files \
		--default-background-color=00000000 --virtual-time-budget=4000 \
		--window-size="$2,$3" --force-device-scale-factor="$4" --screenshot="$5" "$1" >/dev/null 2>&1
	[ -s "$5" ] || {
		echo "render.sh: Chrome wrote no $5" >&2
		exit 1
	}
}

# Wordmark (outlines, white) for the login and lock screens
mkdir -p "$ex/usr/share/mastersos/brand"
python3 "$here/wordmark.py" "$here/fonts/PlusJakartaSans[wght].ttf" "$ex/usr/share/mastersos/brand/wordmark-light.svg"

# Wallpapers: 1920x1200 CSS px at scale 2, JPEG quality 92 with full chroma (4:4:4)
bg=$ex/usr/share/backgrounds/mastersos
mkdir -p "$bg"
for m in day night; do
	shot "file://$here/wallpaper.html?m=$m" 1920 1200 2 "$work/$m.png"
	python3 - "$work/$m.png" "$bg/mastersos-$m.jpg" <<'PY'
import sys
from PIL import Image
im = Image.open(sys.argv[1]).convert("RGB")
if im.size != (3840, 2400):
    sys.exit(f"render.sh: wallpaper is {im.size}, want (3840, 2400)")
im.save(sys.argv[2], "JPEG", quality=92, subsampling=0, optimize=True)
PY
done

# Banding check (review focus 4): along the sky, the mean brightness of each row of a centre band must not sit flat for
# 40 rows and then jump by 3 or more levels.
python3 "$here/banding.py" "$bg/mastersos-day.jpg" "$bg/mastersos-night.jpg"

# Logo PNGs: each size rendered from the vector at that size (no downscaling), cropped from a 512x512 page
icons=$ex/usr/share/icons/hicolor
for n in 16 24 32 48 64 128 256 512; do
	printf '<html><body style="margin:0"><img src="%s" width="%d" height="%d" style="display:block"></body></html>' \
		"file://$here/logo.svg" "$n" "$n" >"$work/logo-$n.html"
	shot "file://$work/logo-$n.html" 512 512 1 "$work/logo-$n-page.png"
	mkdir -p "$icons/${n}x${n}/apps"
	python3 - "$work/logo-$n-page.png" "$n" "$icons/${n}x${n}/apps/mastersos-logo.png" <<'PY'
import sys
from PIL import Image
n = int(sys.argv[2])
Image.open(sys.argv[1]).convert("RGBA").crop((0, 0, n, n)).save(sys.argv[3], optimize=True)
PY
done
mkdir -p "$icons/scalable/apps" "$icons/symbolic/apps"
cp "$here/logo.svg" "$icons/scalable/apps/mastersos-logo.svg"
cp "$here/logo-symbolic.svg" "$icons/symbolic/apps/mastersos-logo-symbolic.svg"

# Boot splash (Plymouth two-step): throbber frames, the password field, bullet and lock. The same theme goes into the
# initrd's tree, which is built from packages and does not see mkosi.extra (check-tree item 52 keeps the copies equal).
frames=72
th=$ex/usr/share/plymouth/themes/mastersos
it=$here/../mkosi.initrd.conf/mkosi.extra/usr/share/plymouth/themes/mastersos
mkdir -p "$th"
rm -f "$th"/throbber-*.png
crop() { # crop <page.png> <w> <h> <out.png>
	python3 -c 'import sys
from PIL import Image
Image.open(sys.argv[1]).convert("RGBA").crop((0, 0, int(sys.argv[2]), int(sys.argv[3]))).save(sys.argv[4], optimize=True)' "$@"
}
for i in $(seq 0 $((frames - 1))); do
	shot "file://$here/splash.html?p=frame&i=$i&of=$frames" 500 500 1 "$work/frame.png"
	crop "$work/frame.png" 160 160 "$th/$(printf 'throbber-%04d.png' $((i + 1)))"
done
for piece in entry:320:44 bullet:12:12 lock:24:28; do
	IFS=: read -r name w h <<<"$piece"
	shot "file://$here/splash.html?p=$name" 500 500 1 "$work/$name.png"
	crop "$work/$name.png" "$w" "$h" "$th/$name.png"
done
# The keyboard layout and caps lock pictures are Plymouth's own (plymouth-theme-spinner, installed in both trees)
for f in capslock.png keyboard.png keymap-render.png; do
	ln -sfn "../spinner/$f" "$th/$f"
done
cp "$here/mastersos.plymouth" "$th/mastersos.plymouth"
rm -rf "$it"
mkdir -p "$(dirname "$it")"
cp -a "$th" "$it"

echo "render.sh: done"

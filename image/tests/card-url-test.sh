#!/usr/bin/env bash
# The sign-in card's authorization URL: the school's idp_hint added to it (card-url.js), run under node.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cp image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/card-url.js "$tmp/card-url.mjs"
MASTERSOS_CARD_URL_MJS="$tmp/card-url.mjs" node --test image/tests/card-url-test.mjs

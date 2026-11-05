#!/usr/bin/env bash
# The Get help dialog's pure logic (help-model.js): the request it sends, what it accepts, what it says. Run under node.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cp image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/help-model.js "$tmp/help-model.mjs"
MASTERSOS_HELP_MODEL_MJS="$tmp/help-model.mjs" node --test image/tests/help-model-test.mjs

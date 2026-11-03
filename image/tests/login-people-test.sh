#!/usr/bin/env bash
# The login screen's person search: matching and order (people.js), run under node.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cp image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/people.js "$tmp/people.mjs"
MASTERSOS_PEOPLE_MJS="$tmp/people.mjs" node --test image/tests/login-people-test.mjs

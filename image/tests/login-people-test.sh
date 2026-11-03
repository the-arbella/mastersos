#!/usr/bin/env bash
# The login screen's person search: matching and order (people.js), run under node.
set -euo pipefail
cd "$(dirname "$0")/../.."
node --test image/tests/login-people-test.mjs

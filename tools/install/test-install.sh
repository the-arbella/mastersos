#!/usr/bin/env bash
# Tests tools/install/install.sh against a release served from this computer (python3 -m http.server).
#
#   test-install.sh                      a fake release: stub binaries that print "mastersos 0.0.0-stub", tag cli-test
#   test-install.sh <RELEASE DIR> <TAG>  real assets: the directory holds mastersos-<target>.tar.gz and SHA256SUMS
#
# Each case runs with its own empty HOME, so nothing outside a temporary directory is touched.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
installer=$here/install.sh

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

[ -f "$installer" ] || fail "no installer at $installer"

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$installer" "$here/test-install.sh"
  pass "shellcheck"
elif [ "${MASTERSOS_INSTALL_TEST_REQUIRE_SHELLCHECK:-}" = 1 ]; then
  fail "shellcheck is not installed"
else
  echo "note: shellcheck not installed, skipped"
fi

tmp=$(mktemp -d)
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

www=$tmp/www
mkdir -p "$www"

if [ $# -eq 0 ]; then
  tag=cli-test
  expect='^mastersos 0\.0\.0-stub$'
  mkdir -p "$www/$tag" "$tmp/stub"
  for name in mastersos mastersos-sign; do
    printf '#!/bin/sh\necho "%s 0.0.0-stub"\n' "$name" >"$tmp/stub/$name"
    chmod 755 "$tmp/stub/$name"
  done
  for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    tar -czf "$www/$tag/mastersos-$target.tar.gz" -C "$tmp/stub" mastersos mastersos-sign
  done
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$www/$tag" && sha256sum -- *.tar.gz >SHA256SUMS)
  else
    (cd "$www/$tag" && shasum -a 256 -- *.tar.gz >SHA256SUMS)
  fi
elif [ $# -eq 2 ]; then
  tag=$2
  expect='^mastersos [0-9]'
  [ -f "$1/SHA256SUMS" ] || fail "no SHA256SUMS in $1"
  mkdir -p "$www/$tag"
  cp "$1"/* "$www/$tag/"
else
  echo "usage: $0 [<RELEASE DIR> <TAG>]" >&2
  exit 2
fi

# The newest-release lookup reads the GitHub API's list; a fake list with an image release first
cat >"$www/releases.json" <<EOF
[
  {"tag_name": "image-release-20261101.1", "draft": false},
  {"tag_name": "$tag", "draft": false},
  {"tag_name": "cli-000000000000", "draft": false}
]
EOF

# The tampered copy: every line of SHA256SUMS names another hash
mkdir -p "$www/tampered/$tag"
cp "$www/$tag"/* "$www/tampered/$tag/"
awk '{ print "0000000000000000000000000000000000000000000000000000000000000000  " $2 }' \
  "$www/$tag/SHA256SUMS" >"$www/tampered/$tag/SHA256SUMS"

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -m http.server --bind 127.0.0.1 --directory "$www" "$port" >"$tmp/server.log" 2>&1 &
server_pid=$!
base=http://127.0.0.1:$port
# python, not curl: the installer must also work where only wget is there
up() { python3 -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2)' "$base/releases.json" 2>/dev/null; }
for _ in $(seq 50); do
  up && break
  sleep 0.1
done
up || fail "the local release server did not start"

# run_install <home> <log> [installer args...]: the installer as IT runs it (`curl … | sh -s -- …`);
# release_base=<url> serves another copy of the release
run_install() {
  local home=$1 log=$2
  shift 2
  mkdir -p "$home"
  HOME=$home MASTERSOS_RELEASE_BASE=${release_base:-$base} MASTERSOS_RELEASES_API=$base/releases.json \
    sh -s -- "$@" <"$installer" >"$log" 2>&1
}

# 1. A given version: both programs installed, the absolute path and the version printed
home=$tmp/home1
run_install "$home" "$tmp/1.log" --version "$tag" || { cat "$tmp/1.log"; fail "install --version $tag"; }
for name in mastersos mastersos-sign; do
  [ -x "$home/.local/bin/$name" ] || { cat "$tmp/1.log"; fail "$name not installed"; }
done
"$home/.local/bin/mastersos" --version | grep -Eq "$expect" || fail "installed mastersos --version"
grep -qF "$home/.local/bin/mastersos" "$tmp/1.log" || { cat "$tmp/1.log"; fail "installed path not printed"; }
grep -Eq "$expect" "$tmp/1.log" || { cat "$tmp/1.log"; fail "version not printed"; }
pass "install --version $tag"

# 2. Again over the installed copy (an upgrade)
run_install "$home" "$tmp/2.log" --version "$tag" || { cat "$tmp/2.log"; fail "reinstall"; }
pass "reinstall over an existing copy"

# 3. No version: the newest cli-* release in the list
home=$tmp/home3
run_install "$home" "$tmp/3.log" || { cat "$tmp/3.log"; fail "install the newest"; }
grep -qF "$tag" "$tmp/3.log" || { cat "$tmp/3.log"; fail "newest release was not $tag"; }
[ -x "$home/.local/bin/mastersos" ] || fail "newest: not installed"
pass "install the newest release"

# 4. A tampered SHA256SUMS: refused, nothing installed
home=$tmp/home4
if release_base=$base/tampered run_install "$home" "$tmp/4.log" --version "$tag"; then
  cat "$tmp/4.log"
  fail "tampered SHA256SUMS accepted"
fi
grep -qi 'sha-256' "$tmp/4.log" || { cat "$tmp/4.log"; fail "tampered: no checksum message"; }
if [ -e "$home/.local/bin/mastersos" ] || [ -e "$home/.local/bin/mastersos-sign" ]; then
  fail "tampered: something was installed"
fi
pass "tampered SHA256SUMS refused, nothing installed"

# 5. A version that does not exist: refused, nothing installed
home=$tmp/home5
if run_install "$home" "$tmp/5.log" --version cli-ffffffffffff; then
  cat "$tmp/5.log"
  fail "missing release accepted"
fi
[ ! -e "$home/.local/bin/mastersos" ] || fail "missing release: something was installed"
pass "missing release refused"

# 6. A version that is not a cli-* tag: refused before any download
home=$tmp/home6
if run_install "$home" "$tmp/6.log" --version ../evil; then
  fail "bad version accepted"
fi
grep -q 'cli-' "$tmp/6.log" || { cat "$tmp/6.log"; fail "bad version: no hint"; }
pass "bad version refused"

echo "all install.sh tests passed"

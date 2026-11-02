#!/bin/bash
# Release key ceremony on the Mac (user ruling 2026-10-27, docs/key-ceremony.md). Runs gen-release-keys.sh
# generate → seal → export-public → wipe in a colima docker container with no network. The private keys only ever sit on
# a tmpfs inside the colima VM (which has no swap; gen-release-keys.sh checks), never on the Mac's disk; what leaves the
# container is the age-encrypted bundle and the public keys. Run it yourself in a terminal: age reads the passphrase from it,
# nothing else sees it.
#   image/ceremony/mac-ceremony.sh [<output dir under $HOME>]     default ~/mastersos-ceremony-<UTC time>
# Output: <dir>/mastersos-release-keys.age (goes to S3, see docs/key-ceremony.md) and <dir>/pub/ (public keys and
# FINGERPRINTS.txt, copied into image/keys/).
# MASTERSOS_CEREMONY_TEST=1 (tests/mac-ceremony-test.sh only) drops the terminal check so a pty driver can feed age.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
die() {
	echo "mac-ceremony: $*" >&2
	exit 1
}
# Ubuntu 24.04 (multi-arch index digest, 2026-10-27): the container runs with no network, the image is only the toolbox
base=ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c
image=mastersos-ceremony:1

out=${1:-$HOME/mastersos-ceremony-$(date -u +%Y%m%dT%H%M%SZ)}
[ "${MASTERSOS_CEREMONY_TEST:-}" = 1 ] || { [ -t 0 ] && [ -t 1 ]; } || die "run this in a terminal: age reads the passphrase from it"
command -v docker >/dev/null || die "docker is missing (brew install colima docker)"
docker info >/dev/null 2>&1 || die "docker is not running: colima start"
case "$out" in "$HOME"/*) ;; *) die "the output dir must be under \$HOME (colima only mounts \$HOME): $out" ;; esac
[ ! -e "$out" ] || die "$out already exists"

echo "mac-ceremony: building the toolbox image (the only step with network)…"
docker build -q -t "$image" - >/dev/null <<EOF
FROM $base
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	age coreutils gnupg openssl tar util-linux && rm -rf /var/lib/apt/lists/*
EOF

mkdir -m 0700 "$out"
tty=(-it)
[ "${MASTERSOS_CEREMONY_TEST:-}" != 1 ] || [ -t 0 ] || tty=(-i)
echo "mac-ceremony: starting the ceremony container (no network, keys on tmpfs only)"
# --read-only: nothing in the container can land on the colima VM's disk; /run/c holds the keys, /tmp is gpg's scratch.
# --log-driver none: docker would otherwise copy the terminal output to a json log on the VM's disk, and that output
# includes the passphrase if it is left empty and age generates one
docker run --rm "${tty[@]}" --log-driver none --network none --read-only --security-opt no-new-privileges --ulimit core=0 \
	--tmpfs /run/c:rw,mode=0700,size=64m --tmpfs /tmp:rw,mode=1777,size=16m -e HOME=/tmp \
	-v "$here:/ceremony:ro" -v "$out:/out" "$image" bash -c '
set -euo pipefail
g=/ceremony/gen-release-keys.sh k=/run/c/k
trap "$g wipe $k >/dev/null 2>&1 || true; rm -rf /run/c/k.verify" EXIT
$g generate $k
$g seal $k /out/mastersos-release-keys.age
$g export-public $k /out/pub
$g wipe $k
'

[ -s "$out/mastersos-release-keys.age" ] && [ -s "$out/pub/FINGERPRINTS.txt" ] || die "the ceremony did not finish (see above)"
echo
echo "mac-ceremony: done. Write these fingerprints on both paper copies (next to the passphrase)"
sed 's/^/    /' "$out/pub/FINGERPRINTS.txt"
echo "  encrypted bundle: $out/mastersos-release-keys.age (sha256 $(shasum -a 256 "$out/mastersos-release-keys.age" | cut -c1-64))"
echo "  public keys:      $out/pub/"

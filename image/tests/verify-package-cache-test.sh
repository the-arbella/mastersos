#!/bin/bash
# Test for ci-verify-package-cache.py (check-tree item 55): a restored package cache keeps only the .deb files whose SHA256 is in
# a signed snapshot index; a tampered or unknown .deb is deleted, and an index whose signature does not verify empties the cache.
# Hermetic: a throwaway GnuPG key signs a made-up InRelease and Packages, given with --lists and --keyring.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export GNUPGHOME=$t/gnupg
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'Test archive' ed25519 sign never 2>/dev/null
gpg --batch --quiet --export >"$t/keyring.gpg"

snap=20261104T000000Z
lists=$t/lists
cache=$t/cache/ubuntu~resolute~x86-64/cache/apt/archives
mkdir -p "$lists" "$cache"
printf 'good package\n' >"$t/good.deb"
printf 'epoch package\n' >"$t/epoch.deb"
sha() { sha256sum "$1" | cut -d' ' -f1; }
packages=$t/Packages
{
	printf 'Package: good\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/g/good/good_1.0-1_amd64.deb\nSHA256: %s\n\n' "$(sha "$t/good.deb")"
	printf 'Package: epoch\nVersion: 1:2.0\nArchitecture: all\nFilename: pool/main/e/epoch/epoch_2.0_all.deb\nSHA256: %s\n\n' "$(sha "$t/epoch.deb")"
	printf 'Package: tampered\nVersion: 3\nArchitecture: amd64\nFilename: pool/main/t/tampered/tampered_3_amd64.deb\nSHA256: %s\n\n' "$(sha "$t/good.deb")"
} >"$packages"
for suite in resolute resolute-updates resolute-security; do
	p=$lists/snapshot.ubuntu.com_ubuntu_${snap}_dists_${suite}_main_binary-amd64_Packages
	if [ "$suite" = resolute ]; then cp "$packages" "$p"; else : >"$p"; fi
	printf 'Origin: Ubuntu\nSuite: %s\nSHA256:\n %s %s main/binary-amd64/Packages\n' \
		"$suite" "$(sha "$p")" "$(stat -c %s "$p")" >"$t/Release"
	gpg --batch --quiet --clearsign -o "$lists/snapshot.ubuntu.com_ubuntu_${snap}_dists_${suite}_InRelease" "$t/Release"
done

fill() {
	rm -f "$cache"/*.deb
	cp "$t/good.deb" "$cache/good_1.0-1_amd64.deb"
	cp "$t/epoch.deb" "$cache/epoch_1%3a2.0_all.deb"
	printf 'not the real one\n' >"$cache/tampered_3_amd64.deb"
	printf 'unknown\n' >"$cache/unknown_9_amd64.deb"
}
run() { python3 -I "$here/ci-verify-package-cache.py" "$t/cache" "$snap" resolute --lists "$lists" --keyring "$1"; }
fail=0
check() { # check <what> <expected sorted file list>
	got=$(find "$cache" -name '*.deb' -printf '%f\n' | sort | tr '\n' ' ')
	if [ "$got" != "$2" ]; then
		echo "verify-package-cache-test: $1: cache holds '$got', want '$2'" >&2
		fail=1
	fi
}

fill
run "$t/keyring.gpg" >/dev/null
check "signed index" "epoch_1%3a2.0_all.deb good_1.0-1_amd64.deb "

# A key that did not sign the index: nothing in the cache can be trusted
mkdir -m 0700 "$t/other"
GNUPGHOME=$t/other gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'Other' ed25519 sign never 2>/dev/null
GNUPGHOME=$t/other gpg --batch --quiet --export >"$t/other.gpg"
fill
run "$t/other.gpg" >/dev/null 2>&1
check "unverifiable index" ""

# A Packages file that does not match the signed InRelease: same
fill
printf 'Package: evil\nVersion: 1\nArchitecture: amd64\nSHA256: %s\n\n' "$(sha "$cache/unknown_9_amd64.deb")" >>"$lists/snapshot.ubuntu.com_ubuntu_${snap}_dists_resolute_main_binary-amd64_Packages"
run "$t/keyring.gpg" >/dev/null 2>&1
check "Packages not matching InRelease" ""

[ "$fail" = 0 ] && echo "verify-package-cache-test: ok"
exit "$fail"

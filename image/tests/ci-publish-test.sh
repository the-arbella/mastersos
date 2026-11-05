#!/bin/bash
# ci-publish.sh restores a channel from the S3 mirror before publish.sh / promote.sh re-sign it: anything in the bucket that
# the last signed manifest does not vouch for must stop the job before a key touches it.
#   bash image/tests/ci-publish-test.sh
# Uses tests/fake-aws as aws and a throwaway gpg key as the root's key (MASTERSOS_TEST=1 + MASTERSOS_PUBRING). The publish
# itself is covered by publish-test.sh and sync-s3-test.sh; here the run stops at publish.sh because there is no build.
# Needs GNU tools (find -printf, sha256sum --strict): skipped where they are missing unless MASTERSOS_PUBLISH_TEST_REQUIRE=1.
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
skip() {
	if [ "${MASTERSOS_PUBLISH_TEST_REQUIRE:-}" = 1 ]; then
		echo "ci-publish-test: FAIL ($*; MASTERSOS_PUBLISH_TEST_REQUIRE=1 does not allow skipping)" >&2
		exit 1
	fi
	echo "ci-publish-test: skip ($*)"
	exit 0
}
for t in flock gpg gpgv sha256sum; do
	command -v "$t" >/dev/null || skip "no $t; run it on Linux / CI"
done
find /dev/null -printf '' 2>/dev/null || skip "find has no -printf; run it on Linux / CI"

tmp=$(mktemp -d)
trap 'gpgconf --homedir "$tmp/gpg" --kill all >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
mkdir -m 700 "$tmp/gpg"
gpg --homedir "$tmp/gpg" --batch --passphrase '' --quick-gen-key 'ci-publish-test' ed25519 sign never 2>/dev/null
gpg --homedir "$tmp/gpg" --export >"$tmp/pubring.pgp"
mkdir -p "$tmp/bin"
cp "$img/tests/fake-aws" "$tmp/bin/aws"
chmod +x "$tmp/bin/aws"

export PATH=$tmp/bin:$PATH FAKE_AWS_LOG=$tmp/aws.log FAKE_AWS_BUCKET=$tmp/bucket
export MASTERSOS_TEST=1 MASTERSOS_PUBRING=$tmp/pubring.pgp MASTERSOS_OS_BUCKET=test-bucket MASTERSOS_OS_CDN=ETEST
export MASTERSOS_OUTPUT_DIR=$tmp/out
mkdir -p "$MASTERSOS_OUTPUT_DIR"

# bucket_channel <dir> <files…>: a channel signed with the test key
bucket_channel() {
	local d=$FAKE_AWS_BUCKET/$1 f
	shift
	mkdir -p "$d"
	for f in "$@"; do echo "bytes of $f" >"$d/$f"; done
	(cd "$d" && sha256sum "$@") >"$d/SHA256SUMS"
	gpg --homedir "$tmp/gpg" --batch --yes --detach-sign --output "$d/SHA256SUMS.gpg" "$d/SHA256SUMS" 2>/dev/null
}
fresh() {
	rm -rf "$FAKE_AWS_BUCKET" "$tmp/root"
	: >"$FAKE_AWS_LOG"
	mkdir -p "$FAKE_AWS_BUCKET"
}
run() { MASTERSOS_PUBLISH_ROOT=$tmp/root "$img/ci-publish.sh" "$@"; }

t_fail=0 t_n=0
# expect <name> <fragment that must be in the output> <args…>: the run fails (there is never a build here) and says <fragment>
expect() {
	local name=$1 frag=$2 rc=0 out
	shift 2
	out=$(run "$@" 2>&1) || rc=$?
	t_n=$((t_n + 1))
	if [ "$rc" != 0 ] && grep -qF -- "$frag" <<<"$out"; then
		echo "ok   $name"
	else
		echo "FAIL $name: rc=$rc, wanted '$frag' in:" >&2
		printf '%s\n' "$out" | sed 's/^/    /' >&2
		t_fail=$((t_fail + 1))
	fi
}
v=20261105.1
files=(MastersOS_20261104.1_x86-64.efi MastersOS_20261104.1_x86-64.build-info.txt)

fresh
expect "empty beta in the bucket: restored, publish.sh runs" "beta/ is empty in the bucket" beta "$v"
fresh
bucket_channel beta "${files[@]}"
expect "signed beta: restored, publish.sh runs" "beta/: 2 files, signature and hashes good" beta "$v"
if grep -q '^s3 sync beta/' "$FAKE_AWS_LOG"; then
	echo "ok   restore went through aws s3 sync"
else
	echo "FAIL restore did not use aws s3 sync" >&2
	t_fail=$((t_fail + 1))
fi
fresh
bucket_channel beta "${files[@]}"
echo tampered >"$FAKE_AWS_BUCKET/beta/${files[0]}"
expect "a file changed in the bucket" "beta/ in the bucket does not match its SHA256SUMS" beta "$v"
fresh
bucket_channel beta "${files[@]}"
echo planted >"$FAKE_AWS_BUCKET/beta/MastersOS_20261104.1_x86-64.usr-x86-64.planted.raw.zst"
expect "a file the manifest does not list" "has files its SHA256SUMS does not list" beta "$v"
fresh
bucket_channel beta "${files[@]}"
echo "0000000000000000000000000000000000000000000000000000000000000000  other" >>"$FAKE_AWS_BUCKET/beta/SHA256SUMS"
expect "a manifest changed after signing" "beta/SHA256SUMS in the bucket does not verify" beta "$v"
fresh
bucket_channel beta "${files[@]}"
rm "$FAKE_AWS_BUCKET/beta/SHA256SUMS.gpg"
expect "files without a signed manifest" "has files but no signed SHA256SUMS" beta "$v"
fresh
expect "promote: stable checked too, version must be in beta" "is not in beta" promote "$v"
if grep -q '^s3 sync stable/' "$FAKE_AWS_LOG" && grep -q '^s3 sync installer/' "$FAKE_AWS_LOG"; then
	echo "ok   promote restores beta, stable and installer"
else
	echo "FAIL promote did not restore stable and installer" >&2
	t_fail=$((t_fail + 1))
fi
fresh
expect "promote: unknown flag" "unknown flag --force" promote "$v" --force
expect "bad version" "bad version" beta 2026.1
fresh
mkdir -p "$tmp/root"
expect "an existing root is refused" "already exists" beta "$v"
if grep -q . "$FAKE_AWS_LOG"; then
	echo "FAIL the refused runs touched aws" >&2
	t_fail=$((t_fail + 1))
fi
fresh
bucket_channel stable "${files[@]}"
echo planted >"$FAKE_AWS_BUCKET/stable/extra"
expect "promote: a planted file in stable" "stable/ in the bucket has files its SHA256SUMS does not list" promote "$v"

# sign-release: signs with the root's key (MASTERSOS_RELEASE_KEYS points at the test key, as in publish-test.sh)
mkdir -m 700 "$tmp/rk"
cp -a "$tmp/gpg" "$tmp/rk/gpg"
mkdir -p "$tmp/assets"
echo stick >"$tmp/assets/MastersOS-installer_${v}_x86-64.img.zst"
(cd "$tmp/assets" && sha256sum -- * >SHA256SUMS)
t_n=$((t_n + 1))
if MASTERSOS_RELEASE_KEYS=$tmp/rk "$img/ci-publish.sh" sign-release "$v" "$tmp/assets" >/dev/null 2>&1 &&
	gpgv --keyring "$tmp/pubring.pgp" "$tmp/assets/SHA256SUMS.gpg" "$tmp/assets/SHA256SUMS" 2>/dev/null; then
	echo "ok   sign-release signs the release SHA256SUMS with the root's key"
else
	echo "FAIL sign-release did not make a signature that verifies" >&2
	MASTERSOS_RELEASE_KEYS=$tmp/rk "$img/ci-publish.sh" sign-release "$v" "$tmp/assets" 2>&1 | sed 's/^/    /' >&2 || true
	t_fail=$((t_fail + 1))
fi
fresh
bucket_channel beta MastersOS_${v}_x86-64.efi MastersOS_${v}_x86-64.build-info.txt
expect "promote: an empty stable is refused" "stable/ is empty in the bucket" promote "$v"

echo "ci-publish-test: $((t_n - t_fail))/$t_n passed"
[ "$t_fail" = 0 ]

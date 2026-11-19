#!/usr/bin/env bash
# The carried authd-oidc patches (image/patches/authd-oidc/*.patch) and their own tests, the way image/mkosi.build runs
# them, without building an image: clone the pinned tag, check its commit, apply every patch in name order (git apply
# --check first), fetch the pinned Go toolchain and check its sha256, then run `go test -run '^TestMastersOS'` in
# internal/broker/ and require every top-level TestMastersOS function of the patched tree to have passed.
#
# Run it as an ordinary user. mkosi.build runs the same tests as root in its chroot, so they run twice here: as this user,
# then as root in a user namespace (unshare -r), with the same pass count required both times; a runner without user
# namespaces fails instead of skipping the root run. Needs git, curl, tar, sha256sum, unshare (util-linux), and the network. The Go tarball and the module and build caches are kept in
# $MASTERSOS_AUTHD_CACHE (default ~/.cache/mastersos-authd-oidc), so a rerun downloads nothing; the tarball's sha256 is
# checked on every run, cached or not.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mb=$root/image/mkosi.build
pdir=$root/image/patches/authd-oidc

pin() {
	local v
	v=$(sed -n "s/^$1=\([^ #]*\)\$/\1/p" "$mb")
	if [ -z "$v" ] || [ "$(wc -l <<<"$v")" -ne 1 ]; then
		echo "authd-oidc-patch-test: no single $1= line in $mb" >&2
		exit 1
	fi
	printf '%s\n' "$v"
}
TAG=$(pin TAG)
COMMIT=$(pin COMMIT)
GO_VERSION=$(pin GO_VERSION)
GO_SHA256=$(pin GO_SHA256)
REPO=$(pin REPO)

if [ "$(id -u)" = 0 ]; then
	echo "authd-oidc-patch-test: run as an ordinary user (the root run uses a user namespace)" >&2
	exit 1
fi

cache=${MASTERSOS_AUTHD_CACHE:-$HOME/.cache/mastersos-authd-oidc}
mkdir -p "$cache"
work=$(mktemp -d)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" "$REPO" "$work/authd"
got=$(git -C "$work/authd" rev-parse HEAD)
if [ "$got" != "$COMMIT" ]; then
	echo "authd-oidc-patch-test: $TAG points at $got, not the pinned $COMMIT" >&2
	exit 1
fi

n=0
for p in "$pdir"/*.patch; do
	[ -e "$p" ] || continue
	git -C "$work/authd" apply --check "$p" || {
		echo "authd-oidc-patch-test: $(basename "$p") no longer applies to $TAG ($COMMIT)" >&2
		exit 1
	}
	git -C "$work/authd" apply "$p"
	echo "authd-oidc-patch-test: applied $(basename "$p")"
	n=$((n + 1))
done
if [ "$n" -eq 0 ]; then
	echo "authd-oidc-patch-test: no patch in $pdir" >&2
	exit 1
fi

gotar=$cache/go${GO_VERSION}.linux-amd64.tar.gz
if ! echo "$GO_SHA256  $gotar" | sha256sum -c --strict --status - 2>/dev/null; then
	rm -f "$gotar"
	curl -fsSL --proto '=https' --tlsv1.2 -o "$gotar.part" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" || {
		rm -f "$gotar.part"
		echo "authd-oidc-patch-test: could not download go${GO_VERSION}.linux-amd64.tar.gz" >&2
		exit 1
	}
	mv "$gotar.part" "$gotar"
fi
echo "$GO_SHA256  $gotar" | sha256sum -c --strict - || {
	echo "authd-oidc-patch-test: go${GO_VERSION}.linux-amd64.tar.gz is not the pinned $GO_SHA256" >&2
	rm -f "$gotar"
	exit 1
}
tar -C "$work" -xzf "$gotar"
export PATH=$work/go/bin:$PATH
[ "$(go env GOVERSION)" = "go$GO_VERSION" ] || {
	echo "authd-oidc-patch-test: the go on PATH is $(go env GOVERSION), not go$GO_VERSION" >&2
	exit 1
}

# The same environment as mkosi.build; only the module and build caches persist between runs
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0
export GOPATH=$work/gopath GOCACHE=$cache/gocache GOMODCACHE=$cache/gomod
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
cd "$work/authd/authd-oidc-brokers"
go mod download
go mod verify

# Checked before the first run, so that a runner without user namespaces fails at once
if ! unshare -r true; then
	echo "authd-oidc-patch-test: cannot run as root in a user namespace (unshare -r); the root run is required" >&2
	exit 1
fi
[ "$(unshare -r id -u)" = 0 ] || {
	echo "authd-oidc-patch-test: unshare -r does not run as uid 0" >&2
	exit 1
}

# A pattern that matches nothing still exits 0: require every TestMastersOS function in the patched tree to have passed
want=$(grep -rhoE '^func TestMastersOS[A-Za-z0-9_]*' internal/broker/ | sort -u | wc -l)
# run <as> <command prefix...>: the TestMastersOS tests with the prefix, their log printed, the pass count checked
run() {
	local as=$1
	shift
	mkdir -p "$work/tmp-$as"
	local log=$work/patch-tests-$as.log
	if ! TMPDIR=$work/tmp-$as "$@" go test -count=1 -v -run '^TestMastersOS' ./internal/broker/ >"$log" 2>&1; then
		cat "$log"
		echo "authd-oidc-patch-test: patch tests failed as $as" >&2
		exit 1
	fi
	cat "$log"
	local got
	got=$(grep -cE '^--- PASS: TestMastersOS[A-Za-z0-9_]* ' "$log" || true)
	if [ "$want" -eq 0 ] || [ "$got" -ne "$want" ]; then
		echo "authd-oidc-patch-test: expected $want top-level TestMastersOS passes as $as, got $got" >&2
		exit 1
	fi
	echo "authd-oidc-patch-test: $n patches apply; $got of $want top-level TestMastersOS tests passed as $as"
}
run user env
run root unshare -r

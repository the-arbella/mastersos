#!/usr/bin/env bash
# The carried authd-oidc patches (image/patches/authd-oidc/*.patch) and their own tests, the way image/mkosi.build runs
# them, without building an image: clone the pinned tag, check its commit, apply every patch in name order (git apply
# --check first), fetch the pinned Go toolchain and check its sha256, then run `go test -run '^TestMastersOS'` in
# internal/broker/ and require every top-level TestMastersOS function of the patched tree to have passed.
#
# Run it as an ordinary user. mkosi.build runs the same tests as root in its chroot (in a network namespace of its own
# set up like the one here), so they run twice here: as this user,
# then as root in a user namespace (unshare -r), with the same pass count required both times; a runner without user
# namespaces fails instead of skipping the root run. Each run has a network namespace of its own with only loopback up:
# the tests listen on fixed loopback ports (31391-31397, and 48123-48130, which lie inside the kernel's ephemeral port
# range), so on a shared runner another run of these tests, or any loopback connection that drew one of those ports,
# would make them fail with "address already in use". Needs git, curl, tar, sha256sum, unshare (util-linux), ip
# (iproute2), and the network. The Go tarball and the module and build caches are kept in $MASTERSOS_AUTHD_CACHE (default
# ~/.cache/mastersos-authd-oidc), so a rerun downloads nothing; the tarball's sha256 is checked on every run, cached or not.
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
# isolated <user|root> <command...>: the command in a new network namespace with loopback up, as this user or as root.
# The namespace's ephemeral ports start at 49152, above every fixed port of the tests: the kernel also takes the local
# port of an outgoing connection from that range, so even the tests' own loopback connections could hold one of the
# fixed ports when a test listens there. Setting this up needs root in the namespace; the user run then drops back to
# this uid in a nested user namespace, so it keeps an ordinary user's file permissions and no capabilities.
isolated() {
	local as=$1 setup='ip link set lo up && echo "49152 65535" >/proc/sys/net/ipv4/ip_local_port_range'
	shift
	if [ "$as" = root ]; then
		unshare -rn bash -c "$setup"' && exec "$@"' bash "$@"
	else
		# shellcheck disable=SC2016 # expanded by the inner bash
		unshare -rn bash -c "$setup"' && exec unshare --map-user="$1" --map-group="$2" -- "${@:3}"' bash \
			"$(id -u)" "$(id -g)" "$@"
	fi
}
[ "$(isolated root id -u)" = 0 ] || {
	echo "authd-oidc-patch-test: the root run does not run as uid 0" >&2
	exit 1
}
# shellcheck disable=SC2016 # awk's own $2
[ "$(isolated user id -u)" = "$(id -u)" ] && [ "$(isolated user awk '/^CapEff/ {print $2}' /proc/self/status)" = 0000000000000000 ] || {
	echo "authd-oidc-patch-test: the user run is not this uid without capabilities" >&2
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
run user isolated user
run root isolated root

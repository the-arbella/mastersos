#!/usr/bin/env bash
# The private apt run of the .deb apps (core/mastersos-agent/src/deb_apps/apt.rs, spec §4.2, §4.6) against real apt and the
# real Ubuntu archive: the same environment, apt.conf and -o options as the agent (the Rust test
# container_test_uses_the_same_options keeps them in step), with a small fake dpkg status instead of the image's factory one.
#
#   1. A local .deb depending on x11-utils: the plan only installs new packages, apt downloads x11-utils under the name the
#      agent looks for (<name>_<version, : as %3a>_<arch>.deb), the status file is untouched, no apt.conf.d hook runs.
#   2. The status has an old libc6: the plan shows "Inst libc6 [<old>] (<new> ...)", which the agent rejects.
#   3. A .deb that conflicts with an installed package: the plan shows "Remv <pkg> [<version>]", which the agent rejects.
#   4. The offline cache: a Packages index in the format of write_cache_index over the downloaded files, a [trusted=yes] file:
#      source, and the same resolution again finds everything in place.
#
# Needs root (as the agent) and the network. On a Mac run it in an ubuntu:24.04 amd64 container:
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash image/tests/deb-apps-apt-test.sh
set -euo pipefail

skip() {
	if [ "${MASTERSOS_DEB_APT_TEST_REQUIRE:-}" = 1 ]; then
		echo "deb-apps-apt-test: FAIL: $*" >&2
		exit 1
	fi
	echo "deb-apps-apt-test: skipped: $*"
	exit 0
}
[ "$(id -u)" = 0 ] || skip "needs root (the agent runs apt as root)"
for c in apt-get dpkg-deb dpkg-query sha256sum; do
	command -v "$c" >/dev/null || skip "$c missing"
done
[ "$(dpkg --print-architecture)" = amd64 ] || skip "needs amd64"
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
[ -f "$keyring" ] || skip "$keyring missing (ubuntu-keyring)"
# shellcheck disable=SC1091 # the host's os-release
codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
[ -n "$codename" ] || skip "no VERSION_CODENAME in /etc/os-release"

T=$(mktemp -d)
canary_conf=/etc/apt/apt.conf.d/99mastersos-deb-apps-canary
cleanup() {
	rm -f "$canary_conf"
	rm -rf "$T"
}
trap cleanup EXIT
fail() {
	echo "deb-apps-apt-test: FAIL: $*" >&2
	exit 1
}

work=$T/apt
(
	umask 077
	mkdir -p "$work"/{lists/partial,archives/partial,cache,preferences.d}
)
# The agent's APT_CONF, verbatim.
cat >"$work/apt.conf" <<'EOF'
Dir::Etc::main "/dev/null";
Dir::Etc::parts "/dev/null";
EOF
# A system hook that must not run: the system configuration is off.
printf 'APT::Update::Post-Invoke-Success { "touch %s/canary"; };\n' "$T" >"$canary_conf"

# The agent's apt_args, verbatim.
apt_opts=(
	-o Dir::State::status=/usr/share/factory/var/lib/dpkg/status
	-o "Dir::Etc::sourcelist=$work/sources.list"
	-o Dir::Etc::sourceparts=-
	-o Dir::Etc::trusted=-
	-o Dir::Etc::trustedparts=-
	-o "Dir::Etc::preferences=$work/preferences"
	-o "Dir::Etc::preferencesparts=$work/preferences.d"
	-o "Dir::Etc::netrc=$work/auth.conf"
	-o "Dir::Etc::netrcparts=$work/auth.conf.d"
	-o "Dir::State::lists=$work/lists"
	-o "Dir::Cache=$work/cache"
	-o "Dir::Cache::archives=$work/archives"
	-o Acquire::Languages=none
	-o APT::Install-Recommends=false
	-o APT::Get::AllowUnauthenticated=false
	-o Debug::NoLocking=true
	-o APT::Sandbox::User=root
	-o APT::Architecture=amd64
	-o APT::Architectures=amd64
	-o APT::Update::Error-Mode=any
)
# The test's own status instead of the image's factory one (a later -o wins).
status=$T/status
apt_opts+=(-o "Dir::State::status=$status")

apt() {
	env -i APT_CONFIG="$work/apt.conf" LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin apt-get "${apt_opts[@]}" "$@"
}

# Fake installed packages: no Depends, so the status is consistent on its own.
stanza() { # name version arch
	printf 'Package: %s\nStatus: install ok installed\nPriority: optional\nArchitecture: %s\nMulti-Arch: same\nVersion: %s\nDescription: fake\n\n' "$1" "$3" "$2"
}
libc_version=$(dpkg-query -W -f='${Version}' libc6)
write_status() { # libc6 version
	{
		stanza libc6 "$1" amd64
		stanza mastersos-old 1 all
	} >"$status"
}

mkdeb() { # name extra-control-lines
	local d=$T/build-$1
	mkdir -p "$d/DEBIAN"
	printf 'Package: %s\nVersion: 1.0\nArchitecture: amd64\nMaintainer: MastersOS test <test@invalid>\nDepends: x11-utils\n%sDescription: deb-apps apt test\n' "$1" "$2" >"$d/DEBIAN/control"
	dpkg-deb --root-owner-group --build "$d" "$T/$1.deb" >/dev/null
}
mkdeb mastersos-apt-probe ""
mkdeb mastersos-apt-conflict "Conflicts: mastersos-old
"

# The agent's sources_list for Source::Archive.
cat >"$work/sources.list" <<EOF
deb [signed-by=$keyring] http://archive.ubuntu.com/ubuntu $codename main universe restricted
deb [signed-by=$keyring] http://archive.ubuntu.com/ubuntu $codename-updates main universe restricted
deb [signed-by=$keyring] http://security.ubuntu.com/ubuntu $codename-security main universe restricted
EOF

# --- 1. new packages only ---------------------------------------------------------------------------------------------
write_status "$libc_version"
status_sum=$(sha256sum "$status")
host_status_sum=$(sha256sum /var/lib/dpkg/status)
apt update >"$T/update.out" 2>&1 || {
	cat "$T/update.out"
	fail "apt-get update"
}
[ ! -e "$T/canary" ] || fail "a system apt.conf.d hook ran: the system configuration must be off"
# Control: without APT_CONFIG the same run does read apt.conf.d (so the check above can fail).
env -i LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin apt-get "${apt_opts[@]}" update >/dev/null 2>&1 || true
[ -e "$T/canary" ] || fail "control: the canary hook did not run without APT_CONFIG"
rm -f "$T/canary"
if find "$work/lists" -name '*binary-i386*' | grep -q .; then
	fail "foreign-architecture lists were fetched"
fi
apt -s install "$T/mastersos-apt-probe.deb" >"$T/sim1" 2>&1 || {
	cat "$T/sim1"
	fail "simulation 1"
}
grep -qE '^Inst x11-utils \([^ ]+ .*\[amd64\]\)' "$T/sim1" || {
	cat "$T/sim1"
	fail "simulation 1 should install x11-utils as a new package"
}
if grep -qE '^(Inst [^ ]+ \[|Remv )' "$T/sim1"; then
	cat "$T/sim1"
	fail "simulation 1 should not upgrade, downgrade or remove anything"
fi
echo "deb-apps-apt-test: the main package's plan line: $(grep -E '^Inst mastersos-apt-probe ' "$T/sim1" || echo none)"
apt install --download-only -y --no-remove "$T/mastersos-apt-probe.deb" >"$T/dl1" 2>&1 || {
	cat "$T/dl1"
	fail "download 1"
}
# Every planned package except the main one is in archives/ under the name the agent derives.
quote() { sed 's/%/%25/g; s/_/%5f/g; s/:/%3a/g'; }
n=0
while read -r _ pkg ver; do
	[ "$pkg" = mastersos-apt-probe ] && continue
	name="$(printf %s "$pkg" | quote)_$(printf %s "$ver" | quote)"
	[ -f "$work/archives/${name}_amd64.deb" ] || [ -f "$work/archives/${name}_all.deb" ] ||
		fail "$pkg $ver was not downloaded as archives/${name}_<arch>.deb"
	n=$((n + 1))
done < <(sed -nE 's/^Inst ([^ ]+) \(([^ ]+) .*/x \1 \2/p' "$T/sim1")
[ "$n" -ge 1 ] || fail "no dependency was planned"
ls "$work"/archives/x11-utils_*_amd64.deb >/dev/null || fail "x11-utils was not downloaded"
[ "$(sha256sum "$status")" = "$status_sum" ] || fail "apt changed the status file"
[ "$(sha256sum /var/lib/dpkg/status)" = "$host_status_sum" ] || fail "apt changed the host's dpkg status"
echo "deb-apps-apt-test: ok 1: $n new packages downloaded, nothing upgraded, no system hook"

# --- 2. an old libc6 in the image: the plan upgrades it ----------------------------------------------------------------
write_status 2.0-1
apt -s install "$T/mastersos-apt-probe.deb" >"$T/sim2" 2>&1 || true
grep -qE '^Inst libc6 \[2\.0-1\] \([^ ]+ ' "$T/sim2" || {
	cat "$T/sim2"
	fail "simulation 2 should show Inst libc6 [2.0-1] (<new> ...)"
}
echo "deb-apps-apt-test: ok 2: an upgrade of an image package shows as Inst <pkg> [<old>] (<new> ...)"

# --- 3. a conflict with an installed package: the plan removes it -----------------------------------------------------
write_status "$libc_version"
apt -s install "$T/mastersos-apt-conflict.deb" >"$T/sim3" 2>&1 || true
grep -qE '^Remv mastersos-old \[1\]' "$T/sim3" || {
	cat "$T/sim3"
	fail "simulation 3 should show Remv mastersos-old [1]"
}
echo "deb-apps-apt-test: ok 3: a removal shows as Remv <pkg> [<version>]"

# --- 4. the offline cache ---------------------------------------------------------------------------------------------
# Packages in the format of write_cache_index: the control paragraph, then Filename, Size, SHA256.
before=$(cd "$work/archives" && sha256sum ./*.deb)
for f in "$work"/archives/*.deb; do
	dpkg-deb -f "$f"
	printf 'Filename: ./%s\nSize: %s\nSHA256: %s\n\n' "${f##*/}" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
done >"$work/archives/Packages"
printf 'deb [trusted=yes] file:%s ./\n' "$work/archives" >"$work/sources.list"
apt update >"$T/update4.out" 2>&1 || {
	cat "$T/update4.out"
	fail "apt-get update from the cache"
}
apt -s install "$T/mastersos-apt-probe.deb" >"$T/sim4" 2>&1 || {
	cat "$T/sim4"
	fail "simulation 4 (cache)"
}
grep -qE '^Inst x11-utils \(' "$T/sim4" || {
	cat "$T/sim4"
	fail "simulation 4 should install x11-utils from the cache"
}
apt install --download-only -y --no-remove "$T/mastersos-apt-probe.deb" >"$T/dl4" 2>&1 || {
	cat "$T/dl4"
	fail "download 4 (cache)"
}
[ "$(cd "$work/archives" && sha256sum ./*.deb)" = "$before" ] || fail "resolving from the cache changed archives/"
echo "deb-apps-apt-test: ok 4: the offline cache resolves the same packages in place"
echo "deb-apps-apt-test: all ok"

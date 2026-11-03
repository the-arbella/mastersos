#!/bin/bash
# diag-setup (developer diagnostics switch, docs/specs/2026-11-03-diagnostics-design.md), run locally and in CI, no VM:
#   bash image/tests/diag-setup-test.sh
# The switch is /var/lib/mastersos-seed/debug.conf; with it the script writes /run/mastersos/diag.env, the NetworkManager
# logging drop-in and Enable=true in /etc/gdm3/custom.conf's [debug] section; without it nothing changes.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../mkosi.extra/usr/lib/mastersos/diag-setup
fixture=$here/fixtures/diag/gdm3-custom.conf

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

ok() {
	n=$((n + 1))
	echo "ok   $1"
}
fail() {
	n=$((n + 1))
	fails=$((fails + 1))
	echo "FAIL $1: $2" >&2
}

# fresh root with the package's custom.conf
new_root() {
	rm -rf "$tmp/r"
	mkdir -p "$tmp/r/var/lib/mastersos-seed" "$tmp/r/etc/gdm3" "$tmp/r/run"
	cp "$fixture" "$tmp/r/etc/gdm3/custom.conf"
}
run() { MASTERSOS_DIAG_ROOT=$tmp/r bash "$script"; }

want_env='MASTERSOS_LOG_LEVEL=debug
MASTERSOS_DIAG_AUTHD_ARGS=-vv
MASTERSOS_DIAG_WPA_ARGS=-d'
want_nm='[logging]
level=DEBUG'

# the [debug] section's Enable=true lines (uncommented)
enable_lines() {
	awk '/^\[/{s=$0} s=="[debug]" && /^Enable=true$/{c++} END{print c+0}' "$1"
}

t=switch_off_writes_nothing
new_root
run
if [ -e "$tmp/r/run/mastersos/diag.env" ] || [ -e "$tmp/r/run/NetworkManager/conf.d/90-mastersos-diag.conf" ]; then
	fail $t "wrote runtime files without the switch"
elif ! cmp -s "$fixture" "$tmp/r/etc/gdm3/custom.conf"; then
	fail $t "custom.conf changed"
else ok $t; fi

t=switch_on_writes_env_and_nm
new_root
: >"$tmp/r/var/lib/mastersos-seed/debug.conf"
run
if [ "$(cat "$tmp/r/run/mastersos/diag.env" 2>/dev/null)" != "$want_env" ]; then
	fail $t "diag.env: $(cat "$tmp/r/run/mastersos/diag.env" 2>&1)"
elif [ "$(cat "$tmp/r/run/NetworkManager/conf.d/90-mastersos-diag.conf" 2>/dev/null)" != "$want_nm" ]; then
	fail $t "NM drop-in wrong"
else ok $t; fi

t=gdm_enable_from_package_conf
if [ "$(enable_lines "$tmp/r/etc/gdm3/custom.conf")" != 1 ]; then
	fail $t "want one Enable=true in [debug]: $(cat "$tmp/r/etc/gdm3/custom.conf")"
else
	run
	if [ "$(enable_lines "$tmp/r/etc/gdm3/custom.conf")" != 1 ]; then
		fail $t "second run is not idempotent"
	elif ! grep -q '^\[daemon\]' "$tmp/r/etc/gdm3/custom.conf"; then
		fail $t "other sections lost"
	else ok $t; fi
fi

t=gdm_no_debug_section
new_root
: >"$tmp/r/var/lib/mastersos-seed/debug.conf"
printf '[daemon]\nWaylandEnable=true\n' >"$tmp/r/etc/gdm3/custom.conf"
run
if [ "$(enable_lines "$tmp/r/etc/gdm3/custom.conf")" != 1 ] || ! grep -q '^WaylandEnable=true$' "$tmp/r/etc/gdm3/custom.conf"; then
	fail $t "$(cat "$tmp/r/etc/gdm3/custom.conf")"
else
	rm "$tmp/r/etc/gdm3/custom.conf"
	run
	if [ "$(enable_lines "$tmp/r/etc/gdm3/custom.conf" 2>/dev/null)" != 1 ]; then
		fail $t "missing custom.conf not created"
	else ok $t; fi
fi

t=symlink_switch_is_off
new_root
: >"$tmp/target"
ln -s "$tmp/target" "$tmp/r/var/lib/mastersos-seed/debug.conf"
run
if [ -e "$tmp/r/run/mastersos/diag.env" ]; then
	fail $t "a symlink turned the switch on"
else ok $t; fi

echo "$((n - fails))/$n passed"
[ "$fails" = 0 ]

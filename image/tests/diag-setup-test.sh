#!/bin/bash
# diag-setup (developer diagnostics switch, docs/specs/2026-11-03-diagnostics-design.md), run locally and in CI, no VM:
#   bash image/tests/diag-setup-test.sh
# The switch is /var/lib/mastersos-diag/enabled (encrypted root); with it the script writes /run/mastersos/diag.env, the
# NetworkManager logging drop-in and Enable=true in /etc/gdm3/custom.conf's [debug] section; without it nothing changes.
# "adopt" (first boot) turns the installer's marker /var/lib/mastersos-seed/debug-install into that switch; on any other boot
# a marker on the seed partition is deleted and never trusted.
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
	mkdir -p "$tmp/r/var/lib/mastersos-seed" "$tmp/r/var/lib" "$tmp/r/etc/gdm3" "$tmp/r/run"
	cp "$fixture" "$tmp/r/etc/gdm3/custom.conf"
}
run() { MASTERSOS_DIAG_ROOT=$tmp/r bash "$script" "$@"; }
switch_on() {
	mkdir -p "$tmp/r/var/lib/mastersos-diag"
	: >"$tmp/r/var/lib/mastersos-diag/enabled"
}
marker=var/lib/mastersos-seed/debug-install

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
switch_on
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
switch_on
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
mkdir -p "$tmp/r/var/lib/mastersos-diag"
ln -s "$tmp/target" "$tmp/r/var/lib/mastersos-diag/enabled"
run
if [ -e "$tmp/r/run/mastersos/diag.env" ]; then
	fail $t "a symlink turned the switch on"
else ok $t; fi

t=adopt_moves_marker
new_root
: >"$tmp/r/$marker"
run adopt
if [ -e "$tmp/r/$marker" ]; then fail $t "marker left on the seed partition"
elif [ ! -f "$tmp/r/var/lib/mastersos-diag/enabled" ] || [ -L "$tmp/r/var/lib/mastersos-diag/enabled" ]; then fail $t "switch not created"
elif [ "$(stat -c %a "$tmp/r/var/lib/mastersos-diag")" != 700 ]; then fail $t "folder mode $(stat -c %a "$tmp/r/var/lib/mastersos-diag")"
else ok $t; fi

t=adopt_refused_after_factory_reset
new_root
: >"$tmp/r/$marker"
echo '{}' >"$tmp/r/var/lib/mastersos-seed/identity.json"
run adopt
if [ -e "$tmp/r/var/lib/mastersos-diag/enabled" ]; then fail $t "a factory reset turned the switch on"
elif [ -e "$tmp/r/$marker" ]; then fail $t "marker not removed"
else ok $t; fi

t=adopt_without_marker_noop
new_root
run adopt
if [ -e "$tmp/r/var/lib/mastersos-diag" ]; then fail $t "created the switch folder without a marker"; else ok $t; fi

t=adopt_symlink_marker_ignored
new_root
: >"$tmp/target"
ln -s "$tmp/target" "$tmp/r/$marker"
run adopt
if [ -e "$tmp/r/var/lib/mastersos-diag/enabled" ]; then fail $t "a symlinked marker turned the switch on"
elif [ -L "$tmp/r/$marker" ] || [ ! -e "$tmp/target" ]; then fail $t "marker link not removed, or its target touched"
else ok $t; fi

t=planted_marker_removed_not_adopted
new_root
: >"$tmp/r/$marker"
run
if [ -e "$tmp/r/$marker" ]; then fail $t "marker not removed"
elif [ -e "$tmp/r/var/lib/mastersos-diag/enabled" ] || [ -e "$tmp/r/run/mastersos/diag.env" ]; then fail $t "a planted marker turned diagnostics on"
else ok $t; fi

echo "$((n - fails))/$n passed"
[ "$fails" = 0 ]

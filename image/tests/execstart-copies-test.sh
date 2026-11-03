#!/bin/bash
# check-execstart-copies.sh (called by mkosi.finalize): the developer diagnostics drop-ins re-declare ExecStart of two
# packaged units; the build must stop when the packaged line changes. Runs locally and in CI:
#   bash image/tests/execstart-copies-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
check=$here/../check-execstart-copies.sh
extra=$here/../mkosi.extra

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

# a build root with the packaged units as Ubuntu resolute ships them, and this tree's drop-ins
new_root() {
	rm -rf "$tmp/r"
	local s=$tmp/r/usr/lib/systemd/system
	mkdir -p "$s/authd.service.d" "$s/wpa_supplicant.service.d"
	printf '[Service]\nType=notify\nExecStart=/usr/libexec/authd\n' >"$s/authd.service"
	printf '[Service]\nType=dbus\nExecStart=/usr/sbin/wpa_supplicant -u -s -O "DIR=/run/wpa_supplicant GROUP=netdev"\n' >"$s/wpa_supplicant.service"
	cp "$extra/usr/lib/systemd/system/authd.service.d/90-mastersos-diag.conf" "$s/authd.service.d/"
	cp "$extra/usr/lib/systemd/system/wpa_supplicant.service.d/90-mastersos-diag.conf" "$s/wpa_supplicant.service.d/"
}

t=copies_match
new_root
if bash "$check" "$tmp/r" >/dev/null 2>&1; then ok $t; else fail $t "$(bash "$check" "$tmp/r" 2>&1)"; fi

t=packaged_line_changed
new_root
sed -i 's|^ExecStart=/usr/sbin/wpa_supplicant .*|ExecStart=/usr/sbin/wpa_supplicant -u -s -O "DIR=/run/wpa_supplicant GROUP=netdev" -i wlan0|' "$tmp/r/usr/lib/systemd/system/wpa_supplicant.service"
if bash "$check" "$tmp/r" >/dev/null 2>&1; then fail $t "a changed packaged ExecStart passed"; else ok $t; fi

t=packaged_unit_missing
new_root
rm "$tmp/r/usr/lib/systemd/system/authd.service"
if bash "$check" "$tmp/r" >/dev/null 2>&1; then fail $t "a missing packaged unit passed"; else ok $t; fi

echo "$((n - fails))/$n passed"
[ "$fails" = 0 ]

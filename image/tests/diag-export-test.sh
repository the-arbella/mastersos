#!/bin/bash
# diag-export (developer diagnostics, docs/specs/2026-11-03-diagnostics-design.md), run locally and in CI, no VM:
#   bash image/tests/diag-export-test.sh
# Fake commands (mount, umount, nmcli, journalctl, ...) come first on PATH; mount only records its call, so the "stick" is the
# mount point folder under the test root. zstd is a pass-through (cat): this tests the packing, not zstd.
# The fake command bodies are single-quoted on purpose: they expand when the fake runs
# shellcheck disable=SC2016
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../mkosi.extra/usr/lib/mastersos/diag-export

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

fake=$tmp/bin
mkdir -p "$fake"
mkfake() {
	printf '#!/bin/bash\n%s\n' "$2" >"$fake/$1"
	chmod +x "$fake/$1"
}
mkfake mount 'echo "mount $*" >>"$DIAG_TEST_CALLS"'
mkfake umount 'echo "umount $*" >>"$DIAG_TEST_CALLS"'
mkfake zstd 'exec cat'
mkfake journalctl 'case "$*" in *--list-boots*) printf "IDX BOOT ID FIRST LAST\n -1 aaa x y\n  0 bbb x y\n";; *) echo "journal $*";; esac'
mkfake nmcli 'echo "nmcli $*"'
mkfake bootctl 'case "$*" in *--print-esp-path*) echo "$MASTERSOS_DIAG_ROOT/efi";; *) echo "bootctl $*";; esac'
mkfake coredumpctl 'echo "No coredumps found."; exit 1'
mkfake logger ':'
mkfake sync ':'

new_root() {
	rm -rf "$tmp/r"
	R=$tmp/r
	mkdir -p "$R/var/lib/mastersos-seed" "$R/var/lib/mastersos" "$R/etc/NetworkManager/system-connections" "$R/efi/EFI/MastersOS" "$R/var/tmp" "$R/etc"
	echo 'server_url = "x"' >"$R/var/lib/mastersos-seed/seed.toml"
	echo '{}' >"$R/var/lib/mastersos/state.json"
	echo 'psk=x' >"$R/etc/NetworkManager/system-connections/w.nmconnection"
	echo 0123456789abcdef0123456789abcdef >"$R/etc/machine-id"
	: >"$tmp/calls"
}
switch_on() { : >"$R/var/lib/mastersos-seed/debug.conf"; }
# runs the script's main with the fake PATH
run_main() {
	PATH=$fake:$PATH MASTERSOS_DIAG_ROOT=$R DIAG_TEST_CALLS=$tmp/calls DIAG_CMD_TIMEOUT=${DIAG_CMD_TIMEOUT:-5} \
		bash "$script" "$@"
}
stick() { echo "$R/run/mastersos-diag/sdb1"; }

t=switch_off_no_mount
new_root
run_main sdb1
if grep -q '^mount' "$tmp/calls" || [ -n "$(ls -A "$(stick)" 2>/dev/null)" ]; then
	fail $t "mounted or wrote without the switch"
else ok $t; fi

t=full_export
new_root
switch_on
run_main sdb1
files=$(cd "$(stick)" 2>/dev/null && ls)
if [ "$(echo "$files" | grep -c '^mastersos-diag-01234567-[0-9]\{8\}T[0-9]\{6\}Z\.tar\.zst$')" != 1 ] || [ "$(echo "$files" | wc -l)" != 1 ]; then
	fail $t "want one package on the stick, got: $files"
else
	list=$(tar -tf "$(stick)/$files")
	missing=
	for want in ./commands.txt ./journal/boot-0.txt ./journal/boot--1.txt ./seed/seed.toml ./etc/NetworkManager/system-connections/w.nmconnection ./var/lib/mastersos/state.json; do
		echo "$list" | grep -qxF "$want" || missing="$missing $want"
	done
	if [ -n "$missing" ]; then fail $t "missing in package:$missing"
	elif ! grep -q "^mount .*nosuid,nodev,noexec" "$tmp/calls" || ! grep -q '^umount' "$tmp/calls"; then fail $t "mount options or umount: $(cat "$tmp/calls")"
	elif [ -n "$(ls -A "$R/var/tmp")" ]; then fail $t "staging left behind"
	else ok $t; fi
fi

# the functions, sourced
# shellcheck disable=SC1090
. "$script"

t=collect_timeout
new_root
staging=$tmp/st && rm -rf "$staging" && mkdir -p "$staging"
mkfake slowcmd 'sleep 5'
PATH=$fake:$PATH DIAG_CMD_TIMEOUT=1 run_cmd slow.txt slowcmd
PATH=$fake:$PATH run_cmd nmcli-general.txt nmcli general
if ! grep -qxF 'slow.txt timeout' "$staging/commands.txt" || ! grep -qxF 'nmcli-general.txt 0' "$staging/commands.txt"; then
	fail $t "$(cat "$staging/commands.txt")"
else ok $t; fi

t=collect_missing
PATH=$fake:$PATH run_cmd iw-dev.txt no-such-command-here dev
if ! grep -qxF 'iw-dev.txt missing' "$staging/commands.txt"; then
	fail $t "$(cat "$staging/commands.txt")"
else ok $t; fi

t=name_collision
mkdir -p "$tmp/d"
: >"$tmp/d/mastersos-diag-abcd1234-19700101T000000Z.tar.zst"
got=$(pick_name "$tmp/d" abcd1234 19700101T000000Z)
: >"$tmp/d/$got"
got2=$(pick_name "$tmp/d" abcd1234 19700101T000000Z)
if [ "$got" != mastersos-diag-abcd1234-19700101T000000Z-2.tar.zst ] || [ "$got2" != mastersos-diag-abcd1234-19700101T000000Z-3.tar.zst ]; then
	fail $t "$got / $got2"
else ok $t; fi

t=pack_failure
rm -rf "$tmp/notdir"
: >"$tmp/notdir"
if PATH=$fake:$PATH pack "$staging" "$tmp/notdir" x.tar.zst 2>/dev/null; then
	fail $t "pack into a non-folder succeeded"
elif [ -e "$tmp/notdir/x.tar.zst" ] || [ -e "$tmp/notdir/x.tar.zst.partial" ]; then
	fail $t "left a file"
else ok $t; fi
mkdir -p "$tmp/ro"
mkfake tar 'exit 2'
if PATH=$fake:$PATH pack "$staging" "$tmp/ro" x.tar.zst 2>/dev/null || [ -n "$(ls -A "$tmp/ro")" ]; then
	fail "$t (tar fails)" "pack succeeded or left $(ls "$tmp/ro")"
else ok "$t (tar fails)"; fi
rm -f "$fake/tar"

t=journal_long_timeout
new_root
staging=$tmp/st && rm -rf "$staging" && mkdir -p "$staging"
mkfake journalctl 'case "$*" in *--list-boots*) printf "IDX BOOT ID FIRST LAST\n  0 bbb x y\n";; *) sleep 2; echo "journal $*";; esac'
PATH=$fake:$PATH DIAG_CMD_TIMEOUT=1 DIAG_JOURNAL_TIMEOUT=10 collect
if ! grep -qxF 'journal/boot-0.txt 0' "$staging/commands.txt"; then
	fail $t "$(grep journal "$staging/commands.txt")"
else ok $t; fi

t=journal_without_boot_list
staging=$tmp/st && rm -rf "$staging" && mkdir -p "$staging"
mkfake journalctl 'case "$*" in *--list-boots*) exit 1;; *) echo "journal $*";; esac'
PATH=$fake:$PATH collect
if ! grep -qxF 'journal/boot-0.txt 0' "$staging/commands.txt"; then
	fail $t "boot 0 not collected: $(grep journal "$staging/commands.txt")"
else ok $t; fi

t=staging_cleanup
mkfake journalctl 'case "$*" in *--list-boots*) printf "IDX BOOT ID FIRST LAST\n  0 bbb x y\n";; *) echo "journal $*";; esac'
new_root
switch_on
mkfake nmcli 'sleep 30'
(PATH=$fake:$PATH MASTERSOS_DIAG_ROOT=$R DIAG_TEST_CALLS=$tmp/calls DIAG_CMD_TIMEOUT=60 bash "$script" sdb1) &
pid=$!
for _ in $(seq 50); do grep -q '^mount' "$tmp/calls" && [ -n "$(ls -A "$R/var/tmp")" ] && break; sleep 0.1; done
sleep 0.5
kill -TERM "$pid"
wait "$pid" || true
if [ -n "$(ls -A "$R/var/tmp")" ]; then fail $t "staging left: $(ls "$R/var/tmp")"
elif ! grep -q '^umount' "$tmp/calls"; then fail $t "not unmounted"
elif [ -d "$(stick)" ] && [ -n "$(ls -A "$(stick)")" ]; then fail $t "left on the stick: $(ls "$(stick)")"
else ok $t; fi

echo "$((n - fails))/$n passed"
[ "$fails" = 0 ]

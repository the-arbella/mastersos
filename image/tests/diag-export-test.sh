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
mkfake blkid 'echo "${DIAG_TEST_FSTYPE:-vfat}"'

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
switch_on() {
	mkdir -p "$R/var/lib/mastersos-diag"
	: >"$R/var/lib/mastersos-diag/enabled"
}
# runs the script's main with the fake PATH
run_main() {
	PATH=$fake:$PATH MASTERSOS_DIAG_ROOT=$R DIAG_TEST_CALLS=$tmp/calls DIAG_CMD_TIMEOUT=${DIAG_CMD_TIMEOUT:-5} \
		bash "$script" "$@"
}
stick() { echo "$R/run/mastersos-diag/sdb1"; }
# the stick's content: a seed file at <path> under the mount point (the fake mount leaves that folder as it is)
seed_on_stick() {
	mkdir -p "$(dirname "$(stick)/$1")"
	echo 'server_url = "x"' >"$(stick)/$1"
}
# the packages on the stick, relative paths, sorted
packages() { (cd "$(stick)" 2>/dev/null && find . -name 'mastersos-diag-*' | sort); }

t=switch_off_no_mount
new_root
run_main sdb1
if grep -q '^mount' "$tmp/calls" || [ -n "$(ls -A "$(stick)" 2>/dev/null)" ]; then
	fail $t "mounted or wrote without the switch"
else ok $t; fi

t=full_export
new_root
switch_on
seed_on_stick seed.toml
run_main sdb1
files=$(packages | sed 's|^\./||')
if [ "$(echo "$files" | grep -c '^mastersos-diag-01234567-[0-9]\{8\}T[0-9]\{6\}Z\.tar\.zst$')" != 1 ] || [ "$(echo "$files" | wc -l)" != 1 ]; then
	fail $t "want one package on the stick, got: $files"
else
	list=$(tar -tf "$(stick)/$files")
	missing=
	for want in ./commands.txt ./journal/boot-0.txt ./journal/boot--1.txt ./seed/seed.toml ./etc/NetworkManager/system-connections/w.nmconnection ./var/lib/mastersos/state.json; do
		echo "$list" | grep -qxF "$want" || missing="$missing $want"
	done
	if [ -n "$missing" ]; then fail $t "missing in package:$missing"
	elif ! grep -q "^mount -t vfat -o nosuid,nodev,noexec,nosymfollow " "$tmp/calls" || ! grep -q '^umount' "$tmp/calls"; then fail $t "mount options or umount: $(cat "$tmp/calls")"
	elif [ -n "$(ls -A "$R/var/tmp")" ]; then fail $t "staging left behind"
	else ok $t; fi
fi

# where_case <name> <want: package folder relative to the stick, or "none"> <seed paths...>
where_case() {
	local t=$1 want=$2 got
	shift 2
	new_root
	switch_on
	local f
	for f in "$@"; do seed_on_stick "$f"; done
	run_main sdb1 >/dev/null
	got=$(packages | sed -E 's|/[^/]+$||; s|^\.$|.|')
	[ -n "$got" ] || got=none
	if [ "$got" != "$want" ]; then fail "$t" "want $want, got $got"
	elif ! grep -q '^umount' "$tmp/calls"; then fail "$t" "not unmounted"
	else ok "$t"; fi
}
where_case seed_at_root . seed.toml
where_case seed_one_level ./MastersOS MastersOS/seed-eis-a.toml
where_case seed_two_levels ./x/install x/install/SEED.TOML
where_case seed_too_deep none a/b/c/seed.toml
where_case seed_shallowest_wins ./b a/c/seed.toml b/seed.toml
where_case no_seed_no_write none notes.toml readme.txt

t=seed_behind_symlink
new_root
switch_on
mkdir -p "$tmp/elsewhere" "$(stick)"
echo 'x' >"$tmp/elsewhere/seed.toml"
ln -s "$tmp/elsewhere" "$(stick)/link"
run_main sdb1 >/dev/null
if [ -n "$(packages)" ] || [ -n "$(find "$tmp/elsewhere" -name 'mastersos-diag-*')" ]; then fail $t "wrote through a symlinked folder"; else ok $t; fi

t=newline_name_stays_on_stick
# a folder "x<newline>0 " holding out/seed.toml: split on newlines, find's line "2 <mnt>/x<newline>0 /out" becomes "0 /out",
# which sorts first and names /out, outside the stick (where the container lets a test create it)
new_root
switch_on
out=/diagtest-out-$$
mkdir -p "$out" 2>/dev/null || out=
evil="x
0 "
mkdir -p "$(stick)/$evil/${out#/}"
echo 'x' >"$(stick)/$evil/${out#/}/seed.toml"
[ -n "$out" ] || mkdir -p "$(stick)/$evil/outside"
run_main sdb1 >/dev/null
if [ -n "$out" ] && [ -n "$(find "$out" -name 'mastersos-diag-*')" ]; then fail $t "wrote outside the stick, into $out"
elif [ -z "$(packages)" ]; then fail $t "no package next to the seed"
else ok $t; fi
[ -z "$out" ] || rm -rf "$out"

t=other_fs_not_mounted
new_root
switch_on
seed_on_stick seed.toml
DIAG_TEST_FSTYPE=ext4 run_main sdb1 >/dev/null
if grep -q '^mount' "$tmp/calls" || [ -n "$(packages)" ]; then fail $t "mounted an ext4 stick"; else ok $t; fi

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
seed_on_stick seed.toml
mkfake nmcli 'sleep 30'
(PATH=$fake:$PATH MASTERSOS_DIAG_ROOT=$R DIAG_TEST_CALLS=$tmp/calls DIAG_CMD_TIMEOUT=60 bash "$script" sdb1) &
pid=$!
for _ in $(seq 50); do grep -q '^mount' "$tmp/calls" && [ -n "$(ls -A "$R/var/tmp")" ] && break; sleep 0.1; done
sleep 0.5
kill -TERM "$pid"
wait "$pid" || true
if [ -n "$(ls -A "$R/var/tmp")" ]; then fail $t "staging left: $(ls "$R/var/tmp")"
elif ! grep -q '^umount' "$tmp/calls"; then fail $t "not unmounted"
elif [ -n "$(packages)" ]; then fail $t "left on the stick: $(packages)"
else ok $t; fi

echo "$((n - fails))/$n passed"
[ "$fails" = 0 ]

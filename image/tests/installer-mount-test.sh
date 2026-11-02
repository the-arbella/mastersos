#!/bin/bash
# Tests for mkosi.extra/usr/lib/mastersos/installer-mount. No VM, no root:
#   bash image/tests/installer-mount-test.sh
# findmnt, mount, umount, mountpoint and blkid are stubs driven by files under $T; the kernel command line and the paths
# are injected through the INSTALLER_MOUNT_* variables. Everything else is the real tool.
# shellcheck disable=SC2016 # the stub scripts are written from single-quoted text on purpose
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
im=$here/../mkosi.extra/usr/lib/mastersos/installer-mount
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

check() { # check <name> <want> <got>
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: want '$2', got '$3'" >&2
		fails=$((fails + 1))
	fi
}
has() { # has <file> <fixed text> -> yes/no
	if grep -qF -- "$2" "$1" 2>/dev/null; then echo yes; else echo no; fi
}

bin=$tmp/bin
mkdir -p "$bin"
for t in basename dirname readlink tail tr head grep mkdir cat; do
	ln -sf "$(command -v "$t")" "$bin/$t"
done
# a mount point exists when $T/mounted/<name of dir> does
cat >"$bin/mountpoint" <<'EOF2'
#!/bin/bash
[ -e "$T/mounted/$(basename "${!#}")" ]
EOF2
# findmnt -n -o TARGET --source <dev>: $T/mntof/<dev name> holds the mount; -o OPTIONS --target <dir>: $T/opts/<dir name>
cat >"$bin/findmnt" <<'EOF2'
#!/bin/bash
case "$*" in
*--source*) cat "$T/mntof/$(basename "${!#}")" 2>/dev/null || true ;;
*--target*) cat "$T/opts/$(basename "${!#}")" 2>/dev/null || true ;;
esac
EOF2
# mount: records; a real mount (-t vfat -o OPTS dev dir) makes the options visible to findmnt
cat >"$bin/mount" <<'EOF2'
#!/bin/bash
echo "mount $*" >>"$T/mount.log"
case "$1" in
-t) echo "${4}" >"$T/opts/$(basename "${!#}")" ;;
esac
exit 0
EOF2
cat >"$bin/umount" <<'EOF2'
#!/bin/bash
echo "umount $*" >>"$T/mount.log"
EOF2
cat >"$bin/blkid" <<'EOF2'
#!/bin/bash
exit 2
EOF2
# systemctl: records (the failure screen reboots after Enter)
cat >"$bin/systemctl" <<'EOF2'
#!/bin/bash
echo "$*" >>"$T/systemctl.log"
[ ! -e "$T/systemctl_fails" ]
EOF2
chmod +x "$bin/mountpoint" "$bin/findmnt" "$bin/mount" "$bin/umount" "$bin/blkid" "$bin/systemctl"

cjk() { # cjk <file> -> yes/no (any CJK ideograph in it)
	if LC_ALL=C.UTF-8 grep -qP '[\x{4e00}-\x{9fff}]' "$1" 2>/dev/null; then echo yes; else echo no; fi
}

run() { # run <cmdline text>; sets rc, out. Standard input is $STDIN_TEXT (an Enter when set), else empty (EOF)
	export T=$tmp/w
	rm -rf "$T"
	mkdir -p "$T/mounted" "$T/mntof" "$T/opts" "$T/esp"
	printf '%s\n' "$1" >"$T/cmdline"
	[ -z "${VENTOY_MOUNTED:-}" ] || touch "$T/mounted/mastersos-ventoy"
	[ -z "${LOOP_PART:-}" ] || : >"$T/part1"
	[ -z "${SYSTEMCTL_FAILS:-}" ] || : >"$T/systemctl_fails"
	if [ -n "${STDIN_TEXT:-}" ]; then printf '%s\n' "$STDIN_TEXT" >"$T/stdin"; else : >"$T/stdin"; fi
	rc=0
	PATH=$bin INSTALLER_MOUNT_CMDLINE=$T/cmdline INSTALLER_MOUNT_ESP_DIR=${ESP_DIR:-$T/esp/mastersos-usb-esp} \
		INSTALLER_MOUNT_SYSRQ=$T/sysrq \
		INSTALLER_MOUNT_VENTOY_DIR=$T/mastersos-ventoy INSTALLER_MOUNT_LOOP_ESP=$T/part1 \
		INSTALLER_MOUNT_EFIVAR=$T/no-such-efivar \
		/bin/bash "$im" <"$T/stdin" >"$T/out" 2>&1 || rc=$?
}

# ventoy_mounts_loop_esp_ro
VENTOY_MOUNTED=1 LOOP_PART=1 run 'quiet mastersos.ventoy=20261028.1 ro'
check ventoy_ok_rc 0 "$rc"
check ventoy_mounts_part1 yes "$(has "$T/mount.log" "$T/part1 $T/esp/mastersos-usb-esp")"
check ventoy_mount_option_ro yes "$(has "$T/mount.log" "-o ro,")"
check ventoy_no_seed_mount no "$(has "$T/mount.log" mastersos-usb-seed)"

# the check that the mount is read-only still applies: a mount that comes out rw is refused
export T=$tmp/w2
rm -rf "$T"
mkdir -p "$T/mounted" "$T/mntof" "$T/opts"; touch "$T/mounted/mastersos-ventoy" "$T/part1"
echo /boot >"$T/mntof/part1"
echo 'rw,relatime' >"$T/opts/mastersos-usb-esp"
printf 'mastersos.ventoy=1\n' >"$T/cmdline"
rc=0
PATH=$bin INSTALLER_MOUNT_CMDLINE=$T/cmdline INSTALLER_MOUNT_ESP_DIR=$T/mastersos-usb-esp INSTALLER_MOUNT_VENTOY_DIR=$T/v \
	INSTALLER_MOUNT_LOOP_ESP=$T/part1 INSTALLER_MOUNT_EFIVAR=$T/none INSTALLER_MOUNT_SYSRQ=$T/sysrq /bin/bash "$im" </dev/null >"$T/out" 2>&1 || rc=$?
check ventoy_rw_refused 1 "$rc"
check ventoy_rw_message yes "$(has "$T/out" 'Cannot mount the installer stick')"

# ventoy_requires_ventoy_mount; no answer to the restart question (input closed): exit 1, no reboot, the screen stays
LOOP_PART=1 run 'mastersos.ventoy=20261028.1'
check ventoy_no_ventoy_mount_rc 1 "$rc"
check ventoy_no_ventoy_mount_message yes "$(has "$T/out" 'Cannot mount the installer stick')"
check ventoy_no_ventoy_mount_nothing_mounted no "$(has "$T/mount.log" mount)"
check failure_says_disk_untouched yes "$(has "$T/out" 'The disk has not been touched.')"
check failure_asks_enter yes "$(has "$T/out" 'Press Enter to restart.')"
check failure_english_only no "$(cjk "$T/out")"
check failure_no_answer_no_reboot no "$([ -s "$T/systemctl.log" ] && echo yes || echo no)"

# Enter on the failure screen reboots
STDIN_TEXT=' ' LOOP_PART=1 run 'mastersos.ventoy=20261028.1'
check failure_enter_rc 1 "$rc"
check failure_enter_reboots reboot "$(cat "$T/systemctl.log" 2>/dev/null || true)"

# the loop disk has no partition 1
VENTOY_MOUNTED=1 run 'mastersos.ventoy=20261028.1'
check ventoy_no_part1_rc 1 "$rc"

# stick_mode_unchanged: without mastersos.ventoy= the stick path runs and needs LoaderDevicePartUUID
VENTOY_MOUNTED=1 LOOP_PART=1 run 'quiet splash'
check stick_rc 1 "$rc"
check stick_wants_loader_uuid yes "$(has "$T/out" LoaderDevicePartUUID)"
check stick_mounts_nothing no "$(has "$T/mount.log" mount)"
check stick_english_only no "$(cjk "$T/out")"
# mastersos.ventoy in another word does not switch the mode
VENTOY_MOUNTED=1 LOOP_PART=1 run 'xmastersos.ventoy=1 mastersos.ventoyx'
check stick_lookalike_wants_loader_uuid yes "$(has "$T/out" LoaderDevicePartUUID)"

# systemctl reboot fails (the stick with /usr was pulled): the kernel's sysrq trigger restarts (sync, remount ro, reboot)
STDIN_TEXT=' ' SYSTEMCTL_FAILS=1 LOOP_PART=1 run 'mastersos.ventoy=20261028.1'
check reboot_falls_back_to_sysrq "s u b" "$(tr '\n' ' ' <"$T/sysrq" 2>/dev/null | sed 's/ $//')"
check reboot_fallback_english_only no "$(cjk "$T/out")"
# systemctl works: sysrq untouched
STDIN_TEXT=' ' LOOP_PART=1 run 'mastersos.ventoy=20261028.1'
check reboot_no_sysrq_when_systemctl_works no "$([ -e "$T/sysrq" ] && echo yes || echo no)"

# an unexpected failure (set -e: mkdir under a regular file) ends on the same restart screen through the ERR trap
export T=$tmp/w
rm -rf "$T"
mkdir -p "$T/mounted" "$T/mntof" "$T/opts" "$T/esp"
touch "$T/mounted/mastersos-ventoy" "$T/part1" "$T/esp/afile"
printf 'mastersos.ventoy=1\n' >"$T/cmdline"
rc=0
printf '\n' | PATH=$bin INSTALLER_MOUNT_CMDLINE=$T/cmdline INSTALLER_MOUNT_ESP_DIR=$T/esp/afile/mastersos-usb-esp \
	INSTALLER_MOUNT_VENTOY_DIR=$T/mastersos-ventoy INSTALLER_MOUNT_LOOP_ESP=$T/part1 INSTALLER_MOUNT_EFIVAR=$T/none \
	INSTALLER_MOUNT_SYSRQ=$T/sysrq /bin/bash "$im" >"$T/out" 2>&1 || rc=$?
check errtrap_rc 1 "$rc"
check errtrap_internal_error yes "$(has "$T/out" 'internal error at line')"
check errtrap_asks_enter yes "$(has "$T/out" 'Press Enter to restart.')"
check errtrap_reboots reboot "$(cat "$T/systemctl.log" 2>/dev/null || true)"

echo "$((n - fails))/$n passed"
[ "$fails" = 0 ]

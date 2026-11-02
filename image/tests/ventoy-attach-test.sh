#!/bin/bash
# Tests for the initrd Ventoy mount (mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/ventoy-attach).
# No VM, no root:
#   bash image/tests/ventoy-attach-test.sh
# A fake /sys/class/block names the partitions; blkid answers from $T/types; mount copies a fixture tree into the mount point and
# umount empties it; systemd-dissect, udevadm, systemd-ask-password, systemctl and sleep are recorders ("sleep" returns at once,
# so "the machine stays on the screen" shows up as a sleep call; systemd-ask-password answers Enter unless $T/no_answer exists).
# Everything else (stat, ...) is the real tool.
# shellcheck disable=SC2016 # the stub scripts are written from single-quoted text on purpose
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
va=$here/../mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/ventoy-attach
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
called() { # called <log> -> yes/no (the log has at least one line)
	if [ -s "$1" ]; then echo yes; else echo no; fi
}
cjk() { # cjk <file> -> yes/no (any CJK ideograph in it)
	if LC_ALL=C.UTF-8 grep -qP '[\x{4e00}-\x{9fff}]' "$1" 2>/dev/null; then echo yes; else echo no; fi
}

V=20261028.1
bin=$tmp/bin
mkdir -p "$bin"
for t in sed head cat rm mkdir rmdir cp stat dd grep tr; do
	ln -sf "$(command -v "$t")" "$bin/$t"
done
# blkid -p -o value -s TYPE /dev/<name>: the type from $T/types/<name> (fails when there is none)
cat >"$bin/blkid" <<'EOF2'
#!/bin/bash
last=${!#}
f="$T/types/${last##*/}"
[ -f "$f" ] || exit 2
cat "$f"
EOF2
# mount [-t T] [-o O] <dev> <dir>: records, then copies the fixture tree $T/content/<dev name> into <dir>
cat >"$bin/mount" <<'EOF2'
#!/bin/bash
echo "mount $*" >>"$T/mount.log"
dev=${*: -2:1}
dir=${*: -1}
mkdir -p "$dir"
[ -d "$T/content/${dev##*/}" ] && cp -R "$T/content/${dev##*/}/." "$dir/"
exit 0
EOF2
cat >"$bin/umount" <<'EOF2'
#!/bin/bash
echo "umount $*" >>"$T/mount.log"
rm -rf "${!#}"/* "${!#}"/.[!.]* 2>/dev/null || true
exit 0
EOF2
# systemd-dissect --attach ...: records and prints the loop device
cat >"$bin/systemd-dissect" <<'EOF2'
#!/bin/bash
echo "$*" >>"$T/dissect.log"
echo /dev/loop0
EOF2
cat >"$bin/udevadm" <<'EOF2'
#!/bin/bash
echo "$*" >>"$T/udev.log"
[ "$1" != wait ] || [ -z "${UDEV_WAIT_FAIL:-}" ] || exit 1
exit 0
EOF2
cat >"$bin/sleep" <<'EOF2'
#!/bin/bash
echo "$*" >>"$T/sleep.log"
# a hook lets a test change the world while the script waits for a slow stick
[ ! -x "$T/on_sleep" ] || "$T/on_sleep"
exit 0
EOF2
# systemd-ask-password <options> <prompt>: records the arguments; answers an empty line (Enter) unless $T/no_answer exists
cat >"$bin/systemd-ask-password" <<'EOF2'
#!/bin/bash
echo "$*" >>"$T/ask.log"
[ ! -e "$T/no_answer" ] || exit 1
echo
EOF2
cat >"$bin/systemctl" <<'EOF2'
#!/bin/bash
echo "$*" >>"$T/systemctl.log"
[ ! -e "$T/systemctl_fails" ]
EOF2
chmod +x "$bin"/blkid "$bin"/mount "$bin"/umount "$bin"/systemd-dissect "$bin"/udevadm "$bin"/sleep "$bin"/systemd-ask-password \
	"$bin"/systemctl

# A scenario: new_case <name> -> fresh $T with an empty fake sysfs; add_part <name> <fstype> [with-folder]
case_dir=
new_case() {
	case_dir=$tmp/$1
	rm -rf "$case_dir"
	mkdir -p "$case_dir/sys" "$case_dir/run" "$case_dir/types" "$case_dir/content"
	: >"$case_dir/dissect.log" # so cat/grep on it never fail
}
add_part() { # add_part <name> <fstype>
	mkdir -p "$case_dir/sys/$1"
	: >"$case_dir/sys/$1/partition"
	echo "$2" >"$case_dir/types/$1"
	mkdir -p "$case_dir/content/$1"
}
add_disk() { # a whole disk, no partition file: must be ignored
	mkdir -p "$case_dir/sys/$1"
}
# put_raw <part> <version> <bytes-of-payload>: MastersOS/MastersOS-system_<v>_x86-64.raw with a payload of 'x' bytes
put_raw() {
	mkdir -p "$case_dir/content/$1/MastersOS"
	head -c "$3" /dev/zero | tr '\0' x >"$case_dir/content/$1/MastersOS/MastersOS-system_$2_x86-64.raw"
}
RAW_BYTES=9000

# run_va [size] [version] [extra command-line words] -> runs the script; $case_dir/out has the output, $case_dir/rc the exit code
run_va() {
	local size=${1:-$RAW_BYTES} ver=${2:-$V}
	echo "quiet mastersos.ventoy=$ver mastersos.ventoy_size=$size ${3:-}" >"$case_dir/cmdline"
	run_cmdline
}
run_cmdline() { # runs the script on whatever $case_dir/cmdline holds
	local rc=0
	T=$case_dir VENTOY_SCAN_TRIES=${SCAN_TRIES:-5} VENTOY_SCAN_SETTLE=${SCAN_SETTLE:-0} VENTOY_SYSFS=$case_dir/sys VENTOY_RUN=$case_dir/run VENTOY_CMDLINE=$case_dir/cmdline VENTOY_SYSRQ=$case_dir/sysrq PATH=$bin \
		"$BASH" "$va" >"$case_dir/out" 2>&1 || rc=$?
	echo "$rc" >"$case_dir/rc"
}
refused() { # refused <case-name>: after run_va, the common refusal expectations
	check "$1: the disk-not-touched line is shown" yes "$(has "$case_dir/out" 'The disk has not been touched.')"
	check "$1: the screen is English only" no "$(cjk "$case_dir/out")"
	check "$1: asks to press Enter to restart" yes "$(has "$case_dir/ask.log" 'Press Enter to restart.')"
	check "$1: the question waits forever and shows no emoji" yes "$(has "$case_dir/ask.log" '--timeout=0 --echo=no --emoji=no')"
	check "$1: reboots after Enter" reboot "$(cat "$case_dir/systemctl.log" 2>/dev/null || true)"
	check "$1: stays on the screen while the reboot takes over (sleep infinity)" "infinity" "$(tail -n1 "$case_dir/sleep.log" 2>/dev/null || true)"
	check "$1: systemd-dissect is not called" no "$(called "$case_dir/dissect.log")"
	check "$1: no emergency exit (exit code 0 after the sleep stub returns)" 0 "$(cat "$case_dir/rc")"
}
good_stick() { # good_stick: one exFAT partition with the right folder and file
	add_disk sdb
	add_part sdb1 exfat
	put_raw sdb1 "$V" "$RAW_BYTES"
}

# --- one_folder_attaches -----------------------------------------------------------------------------------------
new_case one_folder_attaches
add_disk sda
add_part sda1 vfat # an ESP-like vfat partition without the folder
good_stick
add_part sdb2 vfat # Ventoy's VTOYEFI
run_va
check "one_folder_attaches: exit 0" 0 "$(cat "$case_dir/rc")"
check "one_folder_attaches: .part names the partition" /dev/sdb1 "$(cat "$case_dir/run/mastersos-ventoy.part")"
check "one_folder_attaches: dissect --attach with the loop ref and --read-only" \
	"--attach --loop-ref=mastersos-ventoy --read-only $case_dir/run/mastersos-ventoy/MastersOS/MastersOS-system_${V}_x86-64.raw" \
	"$(cat "$case_dir/dissect.log")"
check "one_folder_attaches: sleep is not called" no "$(called "$case_dir/sleep.log")"
check "one_folder_attaches: no restart question" no "$(called "$case_dir/ask.log")"
check "one_folder_attaches: no reboot" no "$(called "$case_dir/systemctl.log")"
check "one_folder_attaches: the final mount is read-only, nosuid, nodev, noexec" yes \
	"$(has "$case_dir/mount.log" "-o ro,nosuid,nodev,noexec /dev/sdb1 $case_dir/run/mastersos-ventoy")"
check "one_folder_attaches: the final mount is left in place" yes "$([ -d "$case_dir/run/mastersos-ventoy/MastersOS" ] && echo yes || echo no)"
check "one_folder_attaches: the probe mount is read-only, nosuid, nodev, noexec" yes \
	"$(has "$case_dir/mount.log" "-o ro,nosuid,nodev,noexec /dev/sdb1 $case_dir/run/mastersos-ventoy.probe/sdb1")"
check "one_folder_attaches: the probe directory is removed" no "$([ -e "$case_dir/run/mastersos-ventoy.probe" ] && echo yes || echo no)"
check "one_folder_attaches: probe mounts are gone" no "$([ -n "$(find "$case_dir/run/mastersos-ventoy.probe" -mindepth 2 2>/dev/null)" ] && echo yes || echo no)"
check "one_folder_attaches: loop device is re-triggered and settled" yes "$(has "$case_dir/udev.log" 'trigger --action=change --settle /dev/loop0')"
check "one_folder_attaches: waits for the by-loop-ref link of partition 4" yes \
	"$(has "$case_dir/udev.log" 'wait --timeout=30 /dev/disk/by-loop-ref/mastersos-ventoy-part4')"
check "one_folder_attaches: no checking progress (the file is not hashed)" no "$(has "$case_dir/out" 'Checking')"
check "one_folder_attaches: English only" no "$(cjk "$case_dir/out")"

# --- the copy on the stick is trusted: a file of the right name and size is attached whatever its bytes are --------------------
new_case damaged_bytes_attach
add_part sdb1 exfat
put_raw sdb1 "$V" "$RAW_BYTES"
printf 'y' | dd of="$case_dir/content/sdb1/MastersOS/MastersOS-system_${V}_x86-64.raw" bs=1 seek=4096 conv=notrunc status=none
run_va
check "damaged_bytes_attach: exit 0" 0 "$(cat "$case_dir/rc")"
check "damaged_bytes_attach: attached" yes "$(called "$case_dir/dissect.log")"

# --- an older command line that still carries mastersos.ventoy_sha256= is accepted and the value ignored ----------------------
new_case old_sha_word_ignored
good_stick
run_va "$RAW_BYTES" "$V" "mastersos.ventoy_sha256=0000000000000000000000000000000000000000000000000000000000000000"
check "old_sha_word_ignored: exit 0" 0 "$(cat "$case_dir/rc")"
check "old_sha_word_ignored: attached" yes "$(called "$case_dir/dissect.log")"

# --- mac_dot_raw_ignored -----------------------------------------------------------------------------------------
new_case mac_dot_raw_ignored
good_stick
echo junk >"$case_dir/content/sdb1/MastersOS/._MastersOS-system_${V}_x86-64.raw"
run_va
check "mac_dot_raw_ignored: exit 0" 0 "$(cat "$case_dir/rc")"
check "mac_dot_raw_ignored: attached" yes "$(called "$case_dir/dissect.log")"
check "mac_dot_raw_ignored: sleep is not called" no "$(called "$case_dir/sleep.log")"

# --- no_folder_refuse / ntfs_hint ---------------------------------------------------------------------------------
new_case no_folder_refuse
add_part sdb1 exfat
run_va
check "no_folder_refuse: says no MastersOS folder" yes "$(has "$case_dir/out" 'No MastersOS folder was found')"
check "no_folder_refuse: no exFAT hint without an NTFS partition" no "$(has "$case_dir/out" 'must be exFAT')"
refused no_folder_refuse

new_case ntfs_hint
add_part sdb1 ntfs
add_part sdb2 vfat
run_va
check "ntfs_hint: says the stick must be exFAT" yes "$(has "$case_dir/out" "The Ventoy stick must be exFAT (Ventoy's default).")"
refused ntfs_hint

# --- two_folders_refuse -------------------------------------------------------------------------------------------
new_case two_folders_refuse
add_part sdb1 exfat
put_raw sdb1 "$V" "$RAW_BYTES"
add_part sdc1 vfat
put_raw sdc1 "$V" "$RAW_BYTES"
run_va
check "two_folders_refuse: says more than one folder" yes "$(has "$case_dir/out" 'More than one MastersOS folder was found')"
check "two_folders_refuse: no .part is written" no "$([ -e "$case_dir/run/mastersos-ventoy.part" ] && echo yes || echo no)"
refused two_folders_refuse

# --- file problems ------------------------------------------------------------------------------------------------
new_case missing_raw_refuse
add_part sdb1 exfat
mkdir -p "$case_dir/content/sdb1/MastersOS"
echo x >"$case_dir/content/sdb1/MastersOS/seed.toml"
run_va
check "missing_raw_refuse: says the system file is missing" yes "$(has "$case_dir/out" "MastersOS-system_${V}_x86-64.raw is missing")"
check "missing_raw_refuse: the final mount is released" yes "$(has "$case_dir/mount.log" "umount $case_dir/run/mastersos-ventoy")"
refused missing_raw_refuse

new_case two_raws_refuse
good_stick
put_raw sdb1 20261027.1 100
run_va
check "two_raws_refuse: says more than one system file" yes "$(has "$case_dir/out" 'More than one system file')"
refused two_raws_refuse

new_case version_mismatch_refuse
add_part sdb1 exfat
put_raw sdb1 20261027.9 "$RAW_BYTES"
run_va
check "version_mismatch_refuse: names the folder's version" yes "$(has "$case_dir/out" '20261027.9')"
check "version_mismatch_refuse: names the installer's version" yes "$(has "$case_dir/out" "$V")"
check "version_mismatch_refuse: says the version is wrong" yes "$(has "$case_dir/out" 'is a different version')"
refused version_mismatch_refuse

new_case size_mismatch_refuse
add_part sdb1 exfat
put_raw sdb1 "$V" $((RAW_BYTES - 1))
run_va
check "size_mismatch_refuse: says the file is incomplete" yes "$(has "$case_dir/out" 'is incomplete')"
refused size_mismatch_refuse

# --- the command line -----------------------------------------------------------------------------------------------
new_case cmdline_missing_refuse
good_stick
echo "quiet mastersos.ventoy=$V" >"$case_dir/cmdline"
run_cmdline
check "cmdline_missing_refuse: internal error is shown" yes "$(has "$case_dir/out" 'Internal error')"
refused cmdline_missing_refuse

new_case bad_size_refuse
good_stick
run_va 12abc
check "bad_size_refuse: internal error is shown" yes "$(has "$case_dir/out" 'Internal error')"
refused bad_size_refuse

new_case attach_link_missing_refuse
good_stick
UDEV_WAIT_FAIL=1 run_va
check "attach_link_missing_refuse: says the system file could not be opened" yes "$(has "$case_dir/out" 'could not be opened')"
check "attach_link_missing_refuse: .part is not written" no "$([ -e "$case_dir/run/mastersos-ventoy.part" ] && echo yes || echo no)"
check "attach_link_missing_refuse: the final mount is released" yes "$(has "$case_dir/mount.log" "umount $case_dir/run/mastersos-ventoy")"
check "attach_link_missing_refuse: the disk-not-touched line is shown" yes "$(has "$case_dir/out" 'The disk has not been touched.')"
check "attach_link_missing_refuse: reboots after Enter" reboot "$(cat "$case_dir/systemctl.log" 2>/dev/null || true)"
check "attach_link_missing_refuse: stays on the screen" infinity "$(tail -n1 "$case_dir/sleep.log" 2>/dev/null || true)"

# --- nobody can answer the restart question: no reboot, the refusal stays on the screen --------------------------------------
new_case no_answer_stays
add_part sdb1 exfat
: >"$case_dir/no_answer"
run_va
check "no_answer_stays: the refusal is shown" yes "$(has "$case_dir/out" 'No MastersOS folder was found')"
check "no_answer_stays: asked" yes "$(called "$case_dir/ask.log")"
check "no_answer_stays: no reboot" no "$(called "$case_dir/systemctl.log")"
check "no_answer_stays: stays on the screen" infinity "$(tail -n1 "$case_dir/sleep.log" 2>/dev/null || true)"
check "no_answer_stays: no emergency exit" 0 "$(cat "$case_dir/rc")"
check "no_answer_stays: sysrq untouched" no "$(called "$case_dir/sysrq")"

# --- systemctl cannot reboot: the kernel's sysrq trigger does (s, u, b) --------------------------------------------------------
new_case reboot_falls_back_to_sysrq
add_part sdb1 exfat
: >"$case_dir/systemctl_fails"
run_va
check "reboot_falls_back_to_sysrq: systemctl tried" reboot "$(cat "$case_dir/systemctl.log" 2>/dev/null || true)"
check "reboot_falls_back_to_sysrq: sync, remount ro, reboot" "s u b" "$(tr '\n' ' ' <"$case_dir/sysrq" 2>/dev/null | sed 's/ $//')"
check "reboot_falls_back_to_sysrq: stays on the screen" infinity "$(tail -n1 "$case_dir/sleep.log" 2>/dev/null || true)"

# --- slow stick: the folder appears on a later scan ---------------------------------------------------------------------
new_case late_stick_attaches
add_part sdb2 vfat # Ventoy's VTOYEFI is there from the start, the data partition shows up later
mkdir -p "$case_dir/prepared/MastersOS"
head -c "$RAW_BYTES" /dev/zero | tr '\0' x >"$case_dir/prepared/MastersOS/MastersOS-system_${V}_x86-64.raw"
cat >"$case_dir/on_sleep" <<EOF2
#!/bin/bash
n=\$(grep -c . "$case_dir/sleep.log")
if [ "\$n" = 2 ]; then
	mkdir -p "$case_dir/sys/sdb1" "$case_dir/content/sdb1"
	: >"$case_dir/sys/sdb1/partition"
	echo exfat >"$case_dir/types/sdb1"
	cp -R "$case_dir/prepared/MastersOS" "$case_dir/content/sdb1/"
fi
EOF2
chmod +x "$case_dir/on_sleep"
run_va
check "late_stick_attaches: exit 0" 0 "$(cat "$case_dir/rc")"
check "late_stick_attaches: attached after waiting" yes "$(called "$case_dir/dissect.log")"
check "late_stick_attaches: it slept 1 s twice, not forever" "1 1" "$(tr '\n' ' ' <"$case_dir/sleep.log" | sed 's/ $//')"
check "late_stick_attaches: .part names the late partition" /dev/sdb1 "$(cat "$case_dir/run/mastersos-ventoy.part")"

new_case never_appears_refuse
add_part sdb1 exfat
SCAN_TRIES=4 run_va
check "never_appears_refuse: rescans 3 times (1 s each) before the final stop" "1 1 1 infinity" "$(tr '\n' ' ' <"$case_dir/sleep.log" | sed 's/ $//')"
check "never_appears_refuse: says no MastersOS folder" yes "$(has "$case_dir/out" 'No MastersOS folder was found')"
refused never_appears_refuse

# a second folder is final at once: no rescans
new_case two_folders_no_rescan
add_part sdb1 exfat
put_raw sdb1 "$V" "$RAW_BYTES"
add_part sdc1 vfat
put_raw sdc1 "$V" "$RAW_BYTES"
run_va
check "two_folders_no_rescan: only the final sleep infinity" infinity "$(tr '\n' ' ' <"$case_dir/sleep.log" | sed 's/ $//')"

# a second stick that shows up after the first hit is still refused (rescans for SCAN_SETTLE seconds after the first hit)
new_case second_stick_late_refuse
add_part sdb1 exfat
put_raw sdb1 "$V" "$RAW_BYTES"
mkdir -p "$case_dir/prepared/MastersOS"
cat >"$case_dir/on_sleep" <<EOF2
#!/bin/bash
n=\$(grep -c . "$case_dir/sleep.log")
if [ "\$n" = 2 ]; then
	mkdir -p "$case_dir/sys/sdc1" "$case_dir/content/sdc1"
	: >"$case_dir/sys/sdc1/partition"
	echo vfat >"$case_dir/types/sdc1"
	cp -R "$case_dir/prepared/MastersOS" "$case_dir/content/sdc1/"
fi
EOF2
chmod +x "$case_dir/on_sleep"
SCAN_SETTLE=5 run_va
check "second_stick_late_refuse: says more than one folder" yes "$(has "$case_dir/out" 'More than one MastersOS folder was found')"
check "second_stick_late_refuse: stopped rescanning once it saw two" "1 1 infinity" "$(tr '\n' ' ' <"$case_dir/sleep.log" | sed 's/ $//')"
check "second_stick_late_refuse: not attached" no "$(called "$case_dir/dissect.log")"

# one stick: SCAN_SETTLE seconds of rescans, then it attaches
new_case one_folder_settles
good_stick
SCAN_SETTLE=2 run_va
check "one_folder_settles: exit 0" 0 "$(cat "$case_dir/rc")"
check "one_folder_settles: rescanned 2 s after the hit" "1 1" "$(tr '\n' ' ' <"$case_dir/sleep.log" | sed 's/ $//')"
check "one_folder_settles: attached" yes "$(called "$case_dir/dissect.log")"

# a failure outside every refusal check (here: the .part file cannot be written) shows the internal-error screen, no emergency exit
new_case internal_error_trap
good_stick
mkdir -p "$case_dir/run/mastersos-ventoy.part" # a directory where the file should go: the redirection fails under set -e
run_va
check "internal_error_trap: internal error screen" yes "$(has "$case_dir/out" 'Internal error: the installer could not prepare the USB stick.')"
check "internal_error_trap: the disk-not-touched line is shown" yes "$(has "$case_dir/out" 'The disk has not been touched.')"
check "internal_error_trap: English only" no "$(cjk "$case_dir/out")"
check "internal_error_trap: reboots after Enter" reboot "$(cat "$case_dir/systemctl.log" 2>/dev/null || true)"
check "internal_error_trap: stays on the screen while the reboot takes over" "infinity" "$(tail -n1 "$case_dir/sleep.log" 2>/dev/null || true)"
check "internal_error_trap: no emergency exit" 0 "$(cat "$case_dir/rc")"

echo "$n checks, $fails failed"
[ "$fails" = 0 ]

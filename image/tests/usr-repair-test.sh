#!/bin/bash
# Tests for the initrd /usr repair (usr self-repair Tasks 3 and 6; mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/usr-repair).
# No VM, no root:
#   bash image/tests/usr-repair-test.sh
# Plain files stand in for the ESP, the active slot and the golden partitions. lsblk, udevadm, mount, umount and verity_check
# are stubs (golden-lib's verity_check is covered by golden-lib-test.sh); dd is a recorder around the real dd. Everything runs with
# only golden-lib's INITRD_TOOLS on PATH, as in the initrd.
# shellcheck disable=SC2016 # the stub scripts are written from single-quoted text on purpose
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ur=$here/../mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/usr-repair
lib=$here/../mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/golden-lib
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
state() { # state <esp> <name> -> the file's content, or "absent"
	if [ -e "$1/EFI/MastersOS/$2" ]; then cat "$1/EFI/MastersOS/$2"; else echo absent; fi
}

H=761f148cc8393db471eacaa001004df0db9fb3d3a76522869574d93a1bf3040d  # the running usrhash (VM 165, 20261027.2)
H2=8e23106eae00986cafdf5579681645ec48477bbb52f1986e508a9c3139f70be4 # another version's root hash
P=761f148c-c839-3db4-71ea-caa001004df0                              # data PARTUUID derived from H
PH=db9fb3d3-a765-2286-9574-d93a1bf3040d                             # hash PARTUUID derived from H
ESP_UUID=8edcc232-9ce0-4bab-9208-c3d655703347
GOLDEN_SIG_TYPE=d75b658d-fd52-45d1-b604-7503d3390430
GOLDEN_VERITY_TYPE=dbd93f87-e4ab-4c62-8efe-21507a9f3575
GOLDEN_USR_TYPE=24fb2b7c-2400-4428-b63f-a3b9824db2b7
BLOCKS=64                    # erofs blocks of 4096 in the fake golden usr
BYTES=$((BLOCKS * 4096))     # erofs_bytes of the fake golden usr
USR_SIZE=$((BYTES + 3 * 4096)) # the partitions are larger than the image

# --- initrd_plan (pure) ------------------------------------------------------------------------------------------
(
	# shellcheck disable=SC1090 # the script under test, sourced for its functions
	. "$ur"
	prow() { # prow <want> <repair-usr> <repair-count> <repair-inprogress> <pending>
		check "initrd_plan req='$2' count='$3' inprog='$4' pending=$5 -> $1" "$1" "$(initrd_plan "$H" "$2" "$3" "$4" "$5")"
	}
	prow skip "" "" "" 0
	prow verify "" "" "" 1
	# a request is read through first like a pending boot (a userspace false "bad" must not rewrite a clean slot on every boot)
	prow verify "$P $H" "" "" 0
	prow skip "$P $H2" "" "" 0
	prow give-up "$P $H" "$H 2" "" 0
	prow verify "$P $H" "$H2 5" "" 0
	prow verify "garbage" "garbage" "" 1
	prow give-up "" "$H 2" "" 1
	prow repair "" "" "$H" 0
	prow repair "" "$H 2" "$H" 0
	prow skip "" "" "$H2" 0
	prow verify "" "" "$H2" 1
	prow verify "$P $H" "$H 1" "" 1
	prow give-up "$P $H" "$H 3" "" 0
	echo "$n $fails" >"$tmp/plan.count"
)
read -r n fails <"$tmp/plan.count"

# --- fixtures ----------------------------------------------------------------------------------------------------
# initrd-only PATH: golden-lib's INITRD_TOOLS, with stubs for the ones that need a kernel
ibin=$tmp/initrd-bin
mkdir -p "$ibin"
INITRD_TOOLS=$(bash -c '. "$1" && echo "$INITRD_TOOLS"' _ "$lib")
real_dd=$(command -v dd)
for t in $INITRD_TOOLS; do
	case $t in lsblk | udevadm | mount | umount | veritysetup | dd) continue ;; esac
	p=$(command -v "$t" || true)
	if [ -z "$p" ]; then
		echo "FAIL tool $t from INITRD_TOOLS is not available on this machine" >&2
		fails=$((fails + 1))
		continue
	fi
	ln -sf "$p" "$ibin/$t"
done
# lsblk: "-no FIELD DEV" and "-dnpo NAME LINK" answered from $T/table lines "<basename> <FIELD> <value>";
# "-nrpo NAME,TYPE DISK" prints $T/parts
cat >"$ibin/lsblk" <<'EOF'
#!/bin/bash
if [ "$1" = -nrpo ] && [ "$2" = NAME,TYPE ]; then cat "$T/parts"; exit 0; fi
case $1 in -no | -dnpo) ;; *) exit 64 ;; esac
f=$2
[ "$1" = -dnpo ] && f=NAME
d=${3##*/}
while read -r dev field val; do
	if [ "$dev" = "$d" ] && [ "$field" = "$f" ]; then echo "$val"; exit 0; fi
done <"$T/table"
exit 1
EOF
# udevadm: records its calls; "wait" fails when one of its arguments contains $UDEV_FAIL_ON
cat >"$ibin/udevadm" <<'EOF'
#!/bin/bash
echo "$*" >>"$T/udev.log"
if [ "$1" = wait ] && [ -n "${UDEV_FAIL_ON:-}" ]; then
	for a in "$@"; do case $a in *"$UDEV_FAIL_ON"*) exit 1 ;; esac; done
fi
exit 0
EOF
# mount / umount: record; nothing is mounted, the ESP is a plain directory. MOUNT_FAIL_AFTER=<n> fails from the n-th mount on.
cat >"$ibin/mount" <<'EOF'
#!/bin/bash
echo "mount $*" >>"$T/mount.log"
k=$(grep -c '^mount' "$T/mount.log")
[ -z "${MOUNT_FAIL_AFTER:-}" ] || [ "$k" -lt "$MOUNT_FAIL_AFTER" ] || exit 32
exit 0
EOF
printf '#!/bin/bash\necho "umount $*" >>"$T/mount.log"\n' >"$ibin/umount"
# dd recorder: logs operands and whether the whole-disk lock is held, fails for of=$DD_FAIL_OF, otherwise the real dd
cat >"$ibin/dd" <<EOF
#!/bin/bash
of=""
for a in "\$@"; do case \$a in of=*) of=\${a#of=} ;; esac; done
if [ -n "\$of" ]; then
	lock=held
	exec {lk}<"\$T/dev/sda"
	if flock -n "\$lk"; then lock=free; fi
	exec {lk}<&-
	echo "dd \$* lock=\$lock" >>"\$T/dd.log"
	[ "\$of" != "\${DD_FAIL_OF:-}" ] || exit 1
fi
exec "$real_dd" "\$@"
EOF
# verity_check stand-in (MASTERSOS_VERITY_CHECK): records; fails when <data> is listed in $T/vc-fail; a signed call (no --no-sig)
# returns the code in $T/vc-signed-rc when that file exists
cat >"$ibin/vc-stub" <<'EOF'
#!/bin/bash
echo "$*" >>"$T/vc.log"
case " $* " in *" --no-sig "*) ;; *) [ ! -f "$T/vc-signed-rc" ] || exit "$(cat "$T/vc-signed-rc")" ;; esac
# $T/vc-heal: the listed partitions only fail until something was written (a damaged slot that the repair fixes)
if [ -e "$T/vc-heal" ] && [ -e "$T/dd.log" ]; then : >"$T/vc-fail"; fi
while read -r bad; do [ "$1" != "$bad" ] || exit 1; done <"$T/vc-fail"
exit 0
EOF
chmod +x "$ibin/lsblk" "$ibin/udevadm" "$ibin/mount" "$ibin/umount" "$ibin/dd" "$ibin/vc-stub"
bash_bin=$(command -v bash)

mksig() { # mksig <file> <roothash> [signature text]: systemd-repart's JSON, NUL padded to 16 KiB
	printf '{"rootHash":"%s","certificateFingerprint":"%s","signature":"%s"}' "$2" "${H2}" "$(printf '%s' "${3:-sig-of-$2}" | base64)" |
		dd of="$1" bs=16K count=1 iflag=fullblock conv=sync status=none
}
# shellcheck disable=SC2059 # the inner printf builds escapes for the outer one
le32() { printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $(($1 & 255)) $(($1 >> 8 & 255)) $(($1 >> 16 & 255)) $(($1 >> 24 & 255)))"; }
mkusr() { # mkusr <file> <erofs blocks>: random bytes with an erofs superblock (4096-byte blocks)
	head -c "$USR_SIZE" /dev/urandom >"$1"
	printf '\xe2\xe1\xf5\xe0' | dd of="$1" bs=1 seek=1024 conv=notrunc status=none
	printf '\x0c' | dd of="$1" bs=1 seek=1036 conv=notrunc status=none
	le32 "$2" | dd of="$1" bs=1 seek=1060 conv=notrunc status=none
}
mkverity() { # mkverity <file> <data_blocks>: random bytes with a dm-verity superblock (4096-byte data blocks)
	head -c 65536 /dev/urandom >"$1"
	printf 'verity\x00\x00' | dd of="$1" bs=1 conv=notrunc status=none
	le32 4096 | dd of="$1" bs=1 seek=64 conv=notrunc status=none
	{ le32 "$2"; printf '\x00\x00\x00\x00'; } | dd of="$1" bs=1 seek=72 conv=notrunc status=none
}

# setup <dir> [golden 1|0|partial]: a fresh machine under <dir>: disk sda (sda1 ESP, sda2-4 active slot, sda8-10 golden copy),
# by-partuuid links, sysfs, LoaderDevicePartUUID, a cmdline with usrhash=H, an ESP directory, profile "release"
setup() {
	local T=$1 golden=${2:-1}
	rm -rf "$T"
	mkdir -p "$T/dev" "$T/by-partuuid" "$T/esp" "$T/sys/class/block/sda4"
	: >"$T/dev/sda"
	echo 4 >"$T/sys/class/block/sda4/partition"
	mksig "$T/dev/sda8" "$H"
	mkverity "$T/dev/sda9" "$BLOCKS"
	mkusr "$T/dev/sda10" "$BLOCKS"
	# the active slot: different content (damaged) of the same sizes
	mksig "$T/dev/sda2" "$H"
	head -c 65536 /dev/urandom >"$T/dev/sda3"
	head -c "$USR_SIZE" /dev/urandom >"$T/dev/sda4"
	{ printf '\x07\x00\x00\x00'; printf '%s' "$ESP_UUID" | sed 's/./&\x00/g'; printf '\x00\x00'; } >"$T/efivar"
	echo "BOOT_IMAGE=x usrhash=$H root=dissect mount.usr=dissect rw" >"$T/cmdline"
	echo release >"$T/profile"
	: >"$T/vc-fail"
	printf '%s\n' "$T/dev/sda disk" "$T/dev/sda1 part" "$T/dev/sda2 part" "$T/dev/sda3 part" "$T/dev/sda4 part" \
		"$T/dev/sda8 part" "$T/dev/sda9 part" "$T/dev/sda10 part" >"$T/parts"
	cat >"$T/table" <<-EOF
		$P NAME $T/dev/sda4
		$PH NAME $T/dev/sda3
		sda2 PKNAME sda
		sda3 PKNAME sda
		sda4 PKNAME sda
		sda8 PKNAME sda
		sda9 PKNAME sda
		sda10 PKNAME sda
		sda2 PARTTYPE e7bb33fb-06cf-4e81-8273-e543b413e2e2
		sda3 PARTTYPE 77ff5f63-e7b6-4633-acf4-1565b864c0e6
	EOF
	case $golden in
	1) printf '%s\n' "$T/dev/sda8 $GOLDEN_SIG_TYPE" "$T/dev/sda9 $GOLDEN_VERITY_TYPE" "$T/dev/sda10 $GOLDEN_USR_TYPE" ;;
	partial) printf '%s\n' "$T/dev/sda8 $GOLDEN_SIG_TYPE" ;;
	*) printf '%s\n' "$T/dev/sda2 e7bb33fb-06cf-4e81-8273-e543b413e2e2" ;;
	esac >"$T/golden.lsblk"
	printf '#!/bin/bash\ncat "%s"\n' "$T/golden.lsblk" >"$T/golden-lsblk"
	chmod +x "$T/golden-lsblk"
}
# st <T> <name> <content>: put a state file on the ESP
st() {
	mkdir -p "$1/esp/EFI/MastersOS"
	printf '%s\n' "$3" >"$1/esp/EFI/MastersOS/$2"
}
# run_env <T>: the environment of a run (initrd-only PATH)
run_env() {
	local T=$1
	echo HOME="$T" T="$T" PATH="$ibin" MASTERSOS_GOLDEN_LIB="$lib" MASTERSOS_ESP_MNT="$T/esp" MASTERSOS_CMDLINE="$T/cmdline" \
		MASTERSOS_BY_PARTUUID="$T/by-partuuid" MASTERSOS_PROFILE_FILE="$T/profile" MASTERSOS_CONSOLE="$T/console" \
		MASTERSOS_VERITY_CHECK="$ibin/vc-stub" MASTERSOS_LOADER_PARTUUID_FILE="$T/efivar" MASTERSOS_GOLDEN_LSBLK="$T/golden-lsblk" \
		MASTERSOS_SYSFS="$T/sys" MASTERSOS_RUN_DIR="$T" MASTERSOS_BOOT_DISK="$T/dev/sda"
}
# boot <T> [VAR=value...]: run usr-repair as the unit does; output in $T/out, exit code in $T/rc
boot() {
	local T=$1 rc=0
	shift
	# shellcheck disable=SC2046 # run_env prints VAR=value words without spaces
	env -i $(run_env "$T") "$@" "$bash_bin" "$ur" >"$T/out" 2>&1 || rc=$?
	echo "$rc" >"$T/rc"
}
# repair <T> [VAR=value...]: source golden-lib and usr-repair, then repair_slot on the fixture; output in $T/out, rc in $T/rc
repair() {
	local T=$1 rc=0
	shift
	# shellcheck disable=SC2046
	# $0 is not the script's path, so sourcing it only defines its functions
	env -i $(run_env "$T") UR="$ur" "$@" "$bash_bin" -c '. "$MASTERSOS_GOLDEN_LIB"; . "$UR"; set +e
		repair_slot "$T/dev/sda8" "$T/dev/sda9" "$T/dev/sda10" "$T/dev/sda2" "$T/dev/sda3" "$T/dev/sda4" "$T/esp" "$1"' \
		repair-test "$H" >"$T/out" 2>&1 || rc=$?
	echo "$rc" >"$T/rc"
}
# same <a> <b> <bytes>: the first <bytes> bytes of two files are equal
same() { if cmp -s -n "$3" "$1" "$2"; then echo same; else echo differ; fi; }
mounts_balanced() { # every mount was followed by an umount
	local m u
	m=$(grep -c '^mount' "$1/mount.log" 2>/dev/null || true)
	u=$(grep -c '^umount' "$1/mount.log" 2>/dev/null || true)
	echo "${m:-0}/${u:-0}"
}

T=$tmp/m

# --- repair_slot -------------------------------------------------------------------------------------------------
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" repair-count "$H2 5"
tail_before=$(tail -c 4096 "$T/dev/sda4" | od -An -tx1 | tr -d ' \n')
repair "$T"
check "repair_slot ok: rc 0" 0 "$(cat "$T/rc")"
check "repair_slot ok: usr equals the golden usr up to erofs_bytes" same "$(same "$T/dev/sda4" "$T/dev/sda10" "$BYTES")"
check "repair_slot ok: usr past erofs_bytes untouched" "$tail_before" "$(tail -c 4096 "$T/dev/sda4" | od -An -tx1 | tr -d ' \n')"
check "repair_slot ok: verity equals the golden verity" same "$(same "$T/dev/sda3" "$T/dev/sda9" 65536)"
check "repair_slot ok: signature equals the golden signature" same "$(same "$T/dev/sda2" "$T/dev/sda8" 16384)"
check "repair_slot ok: three writes, all conv=fsync with the disk locked" "3 3" \
	"$(grep -c 'of=' "$T/dd.log") $(grep -c 'conv=fsync,notrunc .*lock=held$' "$T/dd.log")"
check "repair_slot ok: usr copy is count_bytes of erofs_bytes" yes "$(has "$T/dd.log" "if=$T/dev/sda10 bs=4M iflag=count_bytes count=$BYTES of=$T/dev/sda4")"
check "repair_slot ok: order usr, verity, signature" "$T/dev/sda4 $T/dev/sda3 $T/dev/sda2" \
	"$(sed -nE 's/.* of=([^ ]+) .*/\1/p' "$T/dd.log" | tr '\n' ' ' | sed 's/ $//')"
check "repair_slot ok: golden checked first, slot after, both --no-sig" \
	"$T/dev/sda10 $T/dev/sda9 $T/dev/sda8 $H --no-sig|$T/dev/sda4 $T/dev/sda3 $T/dev/sda2 $H --no-sig" "$(tr '\n' '|' <"$T/vc.log" | sed 's/|$//')"
check "repair_slot ok: repair-usr removed" absent "$(state "$T/esp" repair-usr)"
check "repair_slot ok: repair-inprogress removed" absent "$(state "$T/esp" repair-inprogress)"
check "repair_slot ok: repair-count unchanged" "$H2 5" "$(state "$T/esp" repair-count)"
check "repair_slot ok: progress text on the console" "Repairing system files, do not power off…" "$(cat "$T/console")"
check "repair_slot ok: udevadm settle after each write" 3 "$(grep -c '^settle' "$T/udev.log")"

# repair-inprogress is on the ESP (and the count unchanged) before the first block is written: the dd recorder snapshots it
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" repair-count "$H 1"
mv "$ibin/dd" "$ibin/dd.rec"
cat >"$ibin/dd" <<'EOF'
#!/bin/bash
for a in "$@"; do case $a in of=*) echo "inprog=$(cat "$T/esp/EFI/MastersOS/repair-inprogress" 2>/dev/null) count=$(cat "$T/esp/EFI/MastersOS/repair-count" 2>/dev/null)" >>"$T/dd.state" ;; esac; done
exec "${0}.rec" "$@"
EOF
chmod +x "$ibin/dd"
repair "$T"
mv "$ibin/dd.rec" "$ibin/dd"
check "repair_slot: repair-inprogress=H and count unchanged before each write" "inprog=$H count=$H 1|inprog=$H count=$H 1|inprog=$H count=$H 1" \
	"$(tr '\n' '|' <"$T/dd.state" | sed 's/|$//')"
check "repair_slot: count unchanged after a good repair" "$H 1" "$(state "$T/esp" repair-count)"

# the slot does not verify after the write: count +1 (per attempt), repair-inprogress gone, request kept
setup "$T"
st "$T" repair-usr "$P $H"
echo "$T/dev/sda4" >"$T/vc-fail"
repair "$T"
check "repair_slot verify fails: rc 1" 1 "$(cat "$T/rc")"
check "repair_slot verify fails: repair-count H 1" "$H 1" "$(state "$T/esp" repair-count)"
check "repair_slot verify fails: repair-inprogress removed" absent "$(state "$T/esp" repair-inprogress)"
check "repair_slot verify fails: repair-usr kept" "$P $H" "$(state "$T/esp" repair-usr)"
repair "$T"
check "repair_slot verify fails again: repair-count H 2" "$H 2" "$(state "$T/esp" repair-count)"
st "$T" repair-count "$H2 7"
repair "$T"
check "repair_slot verify fails with another hash's count: H 1" "$H 1" "$(state "$T/esp" repair-count)"

# a failing dd counts as a failed attempt; later writes are not attempted
setup "$T"
st "$T" repair-usr "$P $H"
repair "$T" DD_FAIL_OF="$T/dev/sda4"
check "repair_slot dd fails: rc 1" 1 "$(cat "$T/rc")"
check "repair_slot dd fails: no write after the failed one" 1 "$(grep -c 'of=' "$T/dd.log")"
check "repair_slot dd fails: no slot check" 1 "$(wc -l <"$T/vc.log" | tr -d ' ')"
check "repair_slot dd fails: repair-count H 1" "$H 1" "$(state "$T/esp" repair-count)"
check "repair_slot dd fails: repair-inprogress removed" absent "$(state "$T/esp" repair-inprogress)"

# golden copy names another root hash: nothing written, request removed, rc 0
setup "$T"
mksig "$T/dev/sda8" "$H2"
st "$T" repair-usr "$P $H"
cp "$T/dev/sda4" "$T/usr.before"
repair "$T"
check "repair_slot golden is another version: rc 0" 0 "$(cat "$T/rc")"
check "repair_slot golden is another version: nothing written" "absent same" "$([ -e "$T/dd.log" ] && echo present || echo absent) $(same "$T/dev/sda4" "$T/usr.before" "$USR_SIZE")"
check "repair_slot golden is another version: request removed" absent "$(state "$T/esp" repair-usr)"
check "repair_slot golden is another version: no count, no inprogress" "absent absent" "$(state "$T/esp" repair-count) $(state "$T/esp" repair-inprogress)"
check "repair_slot golden is another version: logged" yes "$(has "$T/out" "the golden copy is $H2, not the running $H")"

# golden copy does not read through: nothing written, request removed
setup "$T"
st "$T" repair-usr "$P $H"
echo "$T/dev/sda10" >"$T/vc-fail"
repair "$T"
check "repair_slot golden does not verify: rc 0, nothing written" "0 absent" "$(cat "$T/rc") $([ -e "$T/dd.log" ] && echo present || echo absent)"
check "repair_slot golden does not verify: request removed, no count" "absent absent" "$(state "$T/esp" repair-usr) $(state "$T/esp" repair-count)"

# erofs size and verity superblock disagree: refuse (a copy of the wrong length would never verify)
setup "$T"
mkverity "$T/dev/sda9" $((BLOCKS + 1))
st "$T" repair-usr "$P $H"
repair "$T"
check "repair_slot erofs/verity size mismatch: rc 0, nothing written" "0 absent" "$(cat "$T/rc") $([ -e "$T/dd.log" ] && echo present || echo absent)"
check "repair_slot erofs/verity size mismatch: logged" yes "$(has "$T/out" "golden usr size $BYTES (erofs) differs from the verity superblock's $(((BLOCKS + 1) * 4096))")"
check "repair_slot erofs/verity size mismatch: no golden read, no count" "absent absent" "$([ -e "$T/vc.log" ] && echo present || echo absent) $(state "$T/esp" repair-count)"

# lab hook: profile lab + lab-fail-verify -> the check after the write fails; ignored with another profile
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" lab-fail-verify ""
echo lab >"$T/profile"
repair "$T"
check "lab hook (profile lab): written, then judged failed" "1 3 $H 1" "$(cat "$T/rc") $(grep -c 'of=' "$T/dd.log") $(state "$T/esp" repair-count)"
check "lab hook: the slot itself is not checked" 1 "$(wc -l <"$T/vc.log" | tr -d ' ')"
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" lab-fail-verify ""
repair "$T"
check "lab hook ignored with profile release" "0 absent absent" "$(cat "$T/rc") $(state "$T/esp" repair-count) $(state "$T/esp" repair-usr)"
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" lab-fail-verify ""
rm "$T/profile"
repair "$T"
check "lab hook ignored without a profile file (release initrd)" "0 absent" "$(cat "$T/rc") $(state "$T/esp" repair-count)"

# --- whole runs of the script (the unit's ExecStart), initrd-only PATH -------------------------------------------
# first boot with a golden copy: boot-pending set, nothing checked or written
setup "$T"
boot "$T"
check "golden 1st boot: rc 0" 0 "$(cat "$T/rc")"
check "golden 1st boot: boot-pending set" "" "$(state "$T/esp" boot-pending)"
check "golden 1st boot: logged" yes "$(has "$T/out" "boot-pending set")"
check "golden 1st boot: nothing checked or written" "absent absent" "$([ -e "$T/vc.log" ] && echo present || echo absent) $([ -e "$T/dd.log" ] && echo present || echo absent)"
PARTS="$T/dev/sda1 $T/dev/sda2 $T/dev/sda3 $T/dev/sda4 $T/dev/sda8 $T/dev/sda9 $T/dev/sda10"
check "golden 1st boot: waits for the ESP, then the boot disk's partitions, then data and hash" \
	"wait --timeout=15 $T/by-partuuid/$ESP_UUID|wait --timeout=15 $PARTS|wait --timeout=15 $T/by-partuuid/$P $T/by-partuuid/$PH" \
	"$(grep '^wait' "$T/udev.log" | tr '\n' '|' | sed 's/|$//')"
check "golden 1st boot: ESP mounted by LoaderDevicePartUUID and unmounted" "yes 1/1" \
	"$(has "$T/mount.log" "mount -t vfat -o rw,nosuid,nodev,noexec,umask=0077 $T/by-partuuid/$ESP_UUID $T/esp") $(mounts_balanced "$T")"
check "golden 1st boot: active slot located" yes "$(has "$T/out" "active slot sig/hash/data: $T/dev/sda2 $T/dev/sda3 $T/dev/sda4")"
# second boot: the last one never reached boot-complete -> the active slot is read through; it verifies -> nothing written
: >"$T/udev.log"
: >"$T/mount.log"
boot "$T"
check "golden 2nd boot (pending): rc 0" 0 "$(cat "$T/rc")"
check "golden 2nd boot (pending): logged" yes "$(has "$T/out" "previous boot pending")"
check "golden 2nd boot (pending): active slot checked --no-sig" "$T/dev/sda4 $T/dev/sda3 $T/dev/sda2 $H --no-sig" "$(cat "$T/vc.log")"
check "golden 2nd boot (pending): nothing written" absent "$([ -e "$T/dd.log" ] && echo present || echo absent)"
check "golden 2nd boot (pending): ESP unmounted during the check, balanced at the end" "2/2" "$(mounts_balanced "$T")"

# pending + the active slot does not verify -> repaired from the golden copy
setup "$T"
st "$T" boot-pending ""
echo "$T/dev/sda4" >"$T/vc-fail"
cp "$ibin/vc-stub" "$tmp/vc-stub.orig"
# the slot only fails before it is rewritten: the stub drops it from the fail list once a write happened
cat >"$ibin/vc-stub" <<'EOF'
#!/bin/bash
echo "$*" >>"$T/vc.log"
[ -e "$T/dd.log" ] && : >"$T/vc-fail"
while read -r bad; do [ "$1" != "$bad" ] || exit 1; done <"$T/vc-fail"
exit 0
EOF
boot "$T"
cp "$tmp/vc-stub.orig" "$ibin/vc-stub"
check "pending + bad slot: rc 0" 0 "$(cat "$T/rc")"
check "pending + bad slot: repaired" "yes same" "$(has "$T/out" "repaired: the active slot verifies") $(same "$T/dev/sda4" "$T/dev/sda10" "$BYTES")"
check "pending + bad slot: checks slot, golden, slot" "$T/dev/sda4|$T/dev/sda10|$T/dev/sda4" "$(cut -d' ' -f1 "$T/vc.log" | tr '\n' '|' | sed 's/|$//')"
check "pending + bad slot: no count, no inprogress" "absent absent" "$(state "$T/esp" repair-count) $(state "$T/esp" repair-inprogress)"
check "pending + bad slot: ESP mounts balanced" yes "$(m=$(mounts_balanced "$T"); [ "${m%/*}" = "${m#*/}" ] && echo yes || echo "no $m")"

# request from integrity, slot damaged -> read through first, then repaired (slot, golden, slot)
setup "$T"
st "$T" repair-usr "$P $H"
echo "$T/dev/sda4" >"$T/vc-fail"
: >"$T/vc-heal"
boot "$T"
check "request, slot bad: repaired" "0 yes absent" "$(cat "$T/rc") $(has "$T/out" "repaired: the active slot verifies") $(state "$T/esp" repair-usr)"
check "request, slot bad: slot read through first, then golden, then slot" "$T/dev/sda4|$T/dev/sda10|$T/dev/sda4" "$(cut -d' ' -f1 "$T/vc.log" | tr '\n' '|' | sed 's/|$//')"
# request from integrity, slot reads clean in the initrd (whose trust root is usrhash): the request is dropped, nothing written,
# nothing counted. A persistent false "bad" in userspace (a loop or dm quirk) would otherwise rewrite 1.8 GB on every boot
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" repair-count "$H 1"
boot "$T"
check "request, slot clean: request dropped, nothing written, count untouched" "0 absent absent $H 1" \
	"$(cat "$T/rc") $(state "$T/esp" repair-usr) $([ -e "$T/dd.log" ] && echo present || echo absent) $(state "$T/esp" repair-count)"
check "request, slot clean: only the slot read, --no-sig" "$T/dev/sda4 $T/dev/sda3 $T/dev/sda2 $H --no-sig" "$(cat "$T/vc.log")"
check "request, slot clean: logged" yes "$(has "$T/out" "repair-usr dropped: the active slot reads clean")"
check "request, slot clean: ESP mounts balanced" "2/2" "$(mounts_balanced "$T")"
# stale request for another version -> removed, nothing done
setup "$T"
st "$T" repair-usr "$P $H2"
st "$T" repair-inprogress "$H2"
boot "$T"
check "request for another version: removed, nothing done" "absent absent absent" \
	"$(state "$T/esp" repair-usr) $(state "$T/esp" repair-inprogress) $([ -e "$T/dd.log" ] && echo present || echo absent)"
setup "$T"
st "$T" repair-usr "garbage"
boot "$T"
check "garbage request: removed" absent "$(state "$T/esp" repair-usr)"

# interrupted repair (repair-inprogress = H) at the cap: repaired anyway
setup "$T"
st "$T" repair-inprogress "$H"
st "$T" repair-count "$H 2"
boot "$T"
check "interrupted repair at the cap: repaired" "yes absent $H 2" "$(has "$T/out" "repaired: the active slot verifies") $(state "$T/esp" repair-inprogress) $(state "$T/esp" repair-count)"
check "interrupted repair: logged" yes "$(has "$T/out" "the last repair of $H was interrupted (1 of 3)")"
check "interrupted repair: repair-interrupted removed after the finished repair" absent "$(state "$T/esp" repair-interrupted)"

# interruptions are counted: the slot already verifies, the golden copy cannot be read (repair_slot writes nothing), so
# repair-inprogress stays and each boot adds one; the third boot that finds it gives up (repair-count H 2), nothing written
setup "$T"
st "$T" repair-inprogress "$H"
echo "$T/dev/sda10" >"$T/vc-fail"
boot "$T"
check "interruption 1: counted, still in progress, nothing written" "$H 1|$H|absent" \
	"$(state "$T/esp" repair-interrupted)|$(state "$T/esp" repair-inprogress)|$([ -e "$T/dd.log" ] && echo present || echo absent)"
boot "$T"
check "interruption 2: counted" "$H 2" "$(state "$T/esp" repair-interrupted)"
: >"$T/vc.log"
boot "$T"
check "interruption 3: no more retries, recorded as given up" "absent|absent|$H 2|absent" \
	"$(state "$T/esp" repair-inprogress)|$(state "$T/esp" repair-interrupted)|$(state "$T/esp" repair-count)|$([ -e "$T/dd.log" ] && echo present || echo absent)"
check "interruption 3: logged, golden not read again" "yes yes 0" \
	"$(has "$T/out" "was cut off 3 times: no more retries") $(has "$T/out" "giving up on $H") $(wc -l <"$T/vc.log" | tr -d ' ')"
# ... and the request stays refused on later boots (give-up through repair-count)
st "$T" repair-usr "$P $H"
boot "$T"
check "after the interruption cap: a request gives up" "yes absent" "$(has "$T/out" "giving up on $H: repair-count is '$H 2'") $([ -e "$T/dd.log" ] && echo present || echo absent)"
# stale repair-interrupted for another root hash is removed
setup "$T"
st "$T" repair-interrupted "$H2 2"
boot "$T"
check "repair-interrupted of another root hash: removed" absent "$(state "$T/esp" repair-interrupted)"
# a repair that ran to the end and failed also clears the interruption count
setup "$T"
st "$T" repair-inprogress "$H"
st "$T" repair-interrupted "$H 1"
echo "$T/dev/sda4" >"$T/vc-fail"
boot "$T"
check "interrupted then failed: count H 1, interruption count and inprogress removed" "$H 1|absent|absent" \
	"$(state "$T/esp" repair-count)|$(state "$T/esp" repair-interrupted)|$(state "$T/esp" repair-inprogress)"

# give-up: request + count H 2 -> one line, nothing checked or written
setup "$T"
st "$T" repair-usr "$P $H"
st "$T" repair-count "$H 2"
boot "$T"
check "give-up: rc 0, nothing checked or written" "0 absent absent" "$(cat "$T/rc") $([ -e "$T/vc.log" ] && echo present || echo absent) $([ -e "$T/dd.log" ] && echo present || echo absent)"
check "give-up: one line" 1 "$(grep -c 'giving up' "$T/out")"

# no golden copy (pilot machine): exit 0, only the ESP waited for, the ESP never mounted, nothing checked, boot-pending untouched
setup "$T" 0
st "$T" boot-pending ""
st "$T" repair-usr "$P $H"
boot "$T"
check "no golden: rc 0" 0 "$(cat "$T/rc")"
check "no golden: logged" yes "$(has "$T/out" "no golden copy on the boot disk, nothing to do")"
check "no golden: only the ESP and the boot disk's partitions waited for" "wait --timeout=15 $T/by-partuuid/$ESP_UUID|wait --timeout=15 $PARTS" \
	"$(grep '^wait' "$T/udev.log" | tr '\n' '|' | sed 's/|$//')"
check "no golden: ESP never mounted, nothing checked or written" "absent absent absent" \
	"$([ -e "$T/mount.log" ] && echo present || echo absent) $([ -e "$T/vc.log" ] && echo present || echo absent) $([ -e "$T/dd.log" ] && echo present || echo absent)"
check "no golden: request left alone" "$P $H" "$(state "$T/esp" repair-usr)"
# golden signature partition but no golden usr/verity, pending: neither checks nor writes (nothing to repair from)
setup "$T" partial
st "$T" boot-pending ""
echo "$T/dev/sda4" >"$T/vc-fail"
boot "$T"
check "partial golden + pending: rc 0, nothing written" "0 absent" "$(cat "$T/rc") $([ -e "$T/dd.log" ] && echo present || echo absent)"
check "partial golden + pending: logged" yes "$(has "$T/out" "cannot verify: the golden copy has no verity or usr partition")"

# udev timeout: ESP missing -> exit 0, nothing mounted; slot partitions missing -> exit 0, nothing mounted
setup "$T"
boot "$T" UDEV_FAIL_ON="$ESP_UUID"
check "udev timeout (ESP): rc 0, logged, not mounted" "0 yes absent" \
	"$(cat "$T/rc") $(has "$T/out" "the ESP did not show up within 15 s") $([ -e "$T/mount.log" ] && echo present || echo absent)"
setup "$T"
boot "$T" UDEV_FAIL_ON="$P"
check "udev timeout (slot): rc 0, logged, not mounted" "0 yes absent" \
	"$(cat "$T/rc") $(has "$T/out" "the active /usr partitions did not show up within 15 s") $([ -e "$T/mount.log" ] && echo present || echo absent)"

setup "$T"
st "$T" repair-usr "$P $H"
echo "$T/dev/sda4" >"$T/vc-fail"
: >"$T/vc-heal"
boot "$T" UDEV_FAIL_ON="$T/dev/sda9"
check "udev timeout (boot disk partitions): logged, golden still looked for, repaired" "0 yes yes" \
	"$(cat "$T/rc") $(has "$T/out" "not all initialized by udev within 15 s") $(has "$T/out" "repaired: the active slot verifies")"

# mount failure: exit 0, nothing written
setup "$T"
st "$T" repair-usr "$P $H"
boot "$T" MOUNT_FAIL_AFTER=1
check "mount failure: rc 0, logged, nothing written" "0 yes absent" \
	"$(cat "$T/rc") $(has "$T/out" "cannot mount the ESP (PARTUUID $ESP_UUID), nothing to do") $([ -e "$T/dd.log" ] && echo present || echo absent)"
# the ESP does not mount again after the long write: repair-inprogress stays (the next boot repairs again), rc 0
# (mounts: 1 state files, 2 after the slot check, 3 after the golden check, 4 after the write)
setup "$T"
st "$T" repair-usr "$P $H"
echo "$T/dev/sda4" >"$T/vc-fail"
boot "$T" MOUNT_FAIL_AFTER=4
check "remount fails after the write: rc 0, inprogress stays" "0 $H yes" \
	"$(cat "$T/rc") $(state "$T/esp" repair-inprogress) $(has "$T/out" "cannot record the result")"

# no usrhash= (installer stick): exit 0, nothing waited for or mounted
setup "$T"
echo "BOOT_IMAGE=x root=dissect rw" >"$T/cmdline"
boot "$T"
check "no usrhash: rc 0, logged, nothing touched" "0 yes absent absent" \
	"$(cat "$T/rc") $(has "$T/out" "no usrhash= on the command line") $([ -e "$T/udev.log" ] && echo present || echo absent) $([ -e "$T/mount.log" ] && echo present || echo absent)"
# no LoaderDevicePartUUID: exit 0
setup "$T"
rm "$T/efivar"
boot "$T"
check "no LoaderDevicePartUUID: rc 0, logged" "0 yes" "$(cat "$T/rc") $(has "$T/out" "no LoaderDevicePartUUID")"
# active slot's signature partition not found by number/type: nothing written even when asked
setup "$T"
sed -i 's/^sda2 PARTTYPE .*/sda2 PARTTYPE 0fc63daf-8483-4772-8e79-3d69d8477de4/' "$T/table"
st "$T" repair-usr "$P $H"
boot "$T"
check "slot sig partition not found: rc 0, nothing written" "0 absent yes" \
	"$(cat "$T/rc") $([ -e "$T/dd.log" ] && echo present || echo absent) $(has "$T/out" "cannot verify: the active slot's partitions are not known")"
# active slot on another disk (a USB stick of the same version has the same PARTUUIDs): nothing checked or written
setup "$T"
st "$T" boot-pending ""
st "$T" repair-usr "$P $H"
boot "$T" MASTERSOS_BOOT_DISK="$T/dev/sdz"
check "slot not on the boot disk: rc 0, logged, nothing checked or written" "0 yes absent absent" \
	"$(cat "$T/rc") $(has "$T/out" "are not on the boot disk $T/dev/sdz") $([ -e "$T/vc.log" ] && echo present || echo absent) $([ -e "$T/dd.log" ] && echo present || echo absent)"
setup "$T"
sed -i "s#^sda3 PKNAME sda#sda3 PKNAME sdb#" "$T/table"
st "$T" repair-usr "$P $H"
boot "$T"
check "hash partition on another disk: nothing written" "absent yes" \
	"$([ -e "$T/dd.log" ] && echo present || echo absent) $(has "$T/out" "are not on the boot disk")"

# pending boot, slot data verifies but its signature blob is damaged with rootHash intact: repaired from the golden copy
setup "$T"
st "$T" boot-pending ""
mksig "$T/dev/sda2" "$H" "damaged signature bytes"
boot "$T"
check "damaged signature blob: detected, golden signature verifies" yes "$(has "$T/out" "differs from the golden copy's, whose signature verifies: repairing")"
check "damaged signature blob: golden checked signed with --no-read" yes "$(has "$T/vc.log" "$T/dev/sda10 $T/dev/sda9 $T/dev/sda8 $H --no-read")"
check "damaged signature blob: repaired, sig equals golden" "yes same" "$(has "$T/out" "repaired: the active slot verifies") $(same "$T/dev/sda2" "$T/dev/sda8" 16384)"
# signatures differ and the golden one does not pass the kernel (1: damaged; 3: the keyring cannot judge): nothing written,
# state files untouched, not counted
for grc in 1 3; do
	setup "$T"
	st "$T" boot-pending ""
	mksig "$T/dev/sda8" "$H" "damaged golden signature bytes"
	cp "$T/dev/sda2" "$T/sig.before"
	echo "$grc" >"$T/vc-signed-rc"
	boot "$T"
	check "signatures differ, golden signed check rc $grc: not writing" "0 yes absent same" \
		"$(cat "$T/rc") $(has "$T/out" "the golden signature does not verify (rc $grc): not writing") $([ -e "$T/dd.log" ] && echo present || echo absent) $(same "$T/dev/sda2" "$T/sig.before" 16384)"
	check "signatures differ, golden signed check rc $grc: no state written" "absent absent absent" \
		"$(state "$T/esp" repair-count) $(state "$T/esp" repair-inprogress) $(state "$T/esp" repair-interrupted)"
done
# golden signature names another root hash: the comparison is skipped (the slot is not judged by another version's signature)
setup "$T"
st "$T" boot-pending ""
mksig "$T/dev/sda8" "$H2"
boot "$T"
check "golden sig of another version: no comparison, slot verifies" "yes absent" "$(has "$T/out" "the active slot verifies") $([ -e "$T/dd.log" ] && echo present || echo absent)"

# golden-lib cannot be loaded: exit 0
setup "$T"
boot "$T" MASTERSOS_GOLDEN_LIB="$T/nonexistent"
check "golden-lib missing: rc 0" 0 "$(cat "$T/rc")"

echo "usr-repair-test: $((n - fails))/$n passed"
[ "$fails" = 0 ]

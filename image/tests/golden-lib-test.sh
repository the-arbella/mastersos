#!/bin/bash
# Tests for golden-lib (usr self-repair, Task 2). Runs locally and in CI, needs no VM and no root:
#   bash image/tests/golden-lib-test.sh
# Covers partition lookup, signature-partition parsing, erofs size, UKI field extraction, rate-limited reads,
# the initrd-tools-only guarantee for the functions marked (i) in golden-lib, and the userspace decision table.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
lib=$here/../mkosi.extra/usr/lib/mastersos/golden-lib
# shellcheck disable=SC1090 # the library under test; path is relative to this file
. "$lib"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

# check <name> <want> <got>
check() {
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: want '$2', got '$3'" >&2
		fails=$((fails + 1))
	fi
}
# rc_of <cmd...> -> prints the exit code (never aborts the test under set -e)
rc_of() {
	local rc=0
	"$@" >/dev/null 2>&1 || rc=$?
	echo "$rc"
}

RH=8e23106eae00986cafdf5579681645ec48477bbb52f1986e508a9c3139f70be4
FP=33dd43a0d8ca4224f55b1abe0ba254156be13540d945b21c8c2ac2ea7e3bd06f

# --- constants ---------------------------------------------------------------------------------------------------
check "type uuids" "d75b658d-fd52-45d1-b604-7503d3390430 dbd93f87-e4ab-4c62-8efe-21507a9f3575 24fb2b7c-2400-4428-b63f-a3b9824db2b7 b86387b4-5385-488f-ab7b-7d8cc7a663de" \
	"$GOLDEN_SIG_TYPE $GOLDEN_VERITY_TYPE $GOLDEN_USR_TYPE $GOLDEN_ESP_TYPE"

# --- sig_roothash / sig_signature (real systemd-repart shape, VM 170 sda5: three keys, NUL padded to 16 KiB) ----
b64=$(head -c 1227 /dev/urandom | base64 | tr -d '\n')
mksig() { # mksig <file> <json>
	printf '%s' "$2" | dd of="$1" bs=16K count=1 conv=sync status=none
}
mksig "$tmp/sig.ok" "{\"rootHash\":\"$RH\",\"certificateFingerprint\":\"$FP\",\"signature\":\"$b64\"}"
check "sig_roothash real shape" "$RH" "$(sig_roothash "$tmp/sig.ok")"
sig_signature "$tmp/sig.ok" "$tmp/sig.out"
printf '%s' "$b64" | base64 -d >"$tmp/sig.want"
check "sig_signature decodes to the same bytes" "same" "$(cmp -s "$tmp/sig.out" "$tmp/sig.want" && echo same || echo differ)"
dd if=/dev/zero of="$tmp/zero.bin" bs=16K count=1 status=none
check "sig_roothash all zero -> 1" 1 "$(rc_of sig_roothash "$tmp/zero.bin")"
check "sig_signature all zero -> 1" 1 "$(rc_of sig_signature "$tmp/zero.bin" "$tmp/x.out")"
mksig "$tmp/sig.short" "{\"rootHash\":\"${RH:0:63}\",\"signature\":\"$b64\"}"
check "sig_roothash 63 hex -> 1" 1 "$(rc_of sig_roothash "$tmp/sig.short")"
mksig "$tmp/sig.long" "{\"rootHash\":\"${RH}0\",\"signature\":\"$b64\"}"
check "sig_roothash 65 hex -> 1" 1 "$(rc_of sig_roothash "$tmp/sig.long")"
mksig "$tmp/sig.upper" "{\"rootHash\":\"${RH^^}\",\"signature\":\"$b64\"}"
check "sig_roothash upper-case hex -> 1" 1 "$(rc_of sig_roothash "$tmp/sig.upper")"
mksig "$tmp/sig.nosig" "{\"rootHash\":\"$RH\"}"
check "sig_signature missing field -> 1" 1 "$(rc_of sig_signature "$tmp/sig.nosig" "$tmp/y.out")"
check "sig_signature missing field leaves no output file" "absent" "$([ -e "$tmp/y.out" ] && echo present || echo absent)"

# --- erofs_bytes -------------------------------------------------------------------------------------------------
mkerofs() { # mkerofs <file> <magic as printf escapes> <blkszbits> <blocks>
	local b=$4
	dd if=/dev/zero of="$1" bs=2048 count=1 status=none
	# shellcheck disable=SC2059 # the magic is passed as printf escapes on purpose
	printf "$2" | dd of="$1" bs=1 seek=1024 conv=notrunc status=none
	# shellcheck disable=SC2059
	printf "$(printf '\\x%02x' "$3")" | dd of="$1" bs=1 seek=1036 conv=notrunc status=none
	# blocks as little-endian u32 at offset 1060
	# shellcheck disable=SC2059
	printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((b & 255)) $((b >> 8 & 255)) $((b >> 16 & 255)) $((b >> 24 & 255)))" |
		dd of="$1" bs=1 seek=1060 conv=notrunc status=none
}
mkerofs "$tmp/erofs.ok" '\xe2\xe1\xf5\xe0' 12 442592
check "erofs_bytes 442592 blocks of 4096" 1812856832 "$(erofs_bytes "$tmp/erofs.ok")"
mkerofs "$tmp/erofs.bad" '\xe2\xe1\xf5\xe1' 12 442592
check "erofs_bytes wrong magic -> 1" 1 "$(rc_of erofs_bytes "$tmp/erofs.bad")"

# --- verity_data_bytes (dm-verity superblock: "verity\0\0", data_block_size u32 LE at 64, data_blocks u64 LE at 72) -----
mkvsb() { # mkvsb <file> <magic as printf escapes> <data_block_size> <data_blocks>
	local bs=$3 b=$4
	dd if=/dev/zero of="$1" bs=4096 count=1 status=none
	# shellcheck disable=SC2059 # printf escapes on purpose
	printf "$2" | dd of="$1" bs=1 conv=notrunc status=none
	# shellcheck disable=SC2059
	printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((bs & 255)) $((bs >> 8 & 255)) $((bs >> 16 & 255)) $((bs >> 24 & 255)))" |
		dd of="$1" bs=1 seek=64 conv=notrunc status=none
	# shellcheck disable=SC2059
	printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x00\\x00\\x00' $((b & 255)) $((b >> 8 & 255)) $((b >> 16 & 255)) $((b >> 24 & 255)) $((b >> 32 & 255)))" |
		dd of="$1" bs=1 seek=72 conv=notrunc status=none
}
# the values of the 20261027.2 build (VM 164): 4096 * 442596 = its usr partition's erofs size
mkvsb "$tmp/vsb.ok" 'verity\x00\x00' 4096 442596
check "verity_data_bytes 442596 blocks of 4096" 1812873216 "$(verity_data_bytes "$tmp/vsb.ok")"
mkvsb "$tmp/vsb.big" 'verity\x00\x00' 4096 $((1 << 33))
check "verity_data_bytes reads data_blocks as 64 bits" $((4096 << 33)) "$(verity_data_bytes "$tmp/vsb.big")"
mkvsb "$tmp/vsb.bad" 'verify\x00\x00' 4096 442596
check "verity_data_bytes wrong magic -> 1" 1 "$(rc_of verity_data_bytes "$tmp/vsb.bad")"
mkvsb "$tmp/vsb.zero" 'verity\x00\x00' 0 442596
check "verity_data_bytes zero block size -> 1" 1 "$(rc_of verity_data_bytes "$tmp/vsb.zero")"

# --- loader_partuuid never seeks with dd: the image's dd (uutils 0.10.0) fails "Illegal seek" on `dd if=<efivarfs file> skip=`
# (Task 3: the initrd then found no ESP at all); the efivar must go through `cat | dd`
lp_body=$(sed -n '/^loader_partuuid() {$/,/^}$/p' "$lib")
check "loader_partuuid found in golden-lib" yes "$([ -n "$lp_body" ] && echo yes || echo no)"
check "loader_partuuid has no dd if=... skip=" none "$(printf '%s\n' "$lp_body" | grep -v '^[[:space:]]*#' | grep -E 'dd[^|]*if=[^|]*skip=' || echo none)"

# --- uki_field (stubbed ukify prints the shape seen on VM 170) ---------------------------------------------------
cat >"$tmp/ukify-stub" <<STUB
#!/bin/bash
printf '%s\n' '{".osrel": {"size": 204, "sha256": "71f3", "text": "NAME=\"MastersOS\"\nID=ubuntu\nIMAGE_ID=\"MastersOS\"\nIMAGE_VERSION=\"20261026.1\"\n"}, ".cmdline": {"size": 456, "sha256": "4c3a", "text": "usrhash=$RH root=dissect mount.usr=dissect rw console=tty0"}}'
STUB
chmod +x "$tmp/ukify-stub"
if command -v jq >/dev/null; then
	check "uki_field version" 20261026.1 "$(MASTERSOS_UKIFY=$tmp/ukify-stub uki_field /x.efi version)"
	check "uki_field usrhash" "$RH" "$(MASTERSOS_UKIFY=$tmp/ukify-stub uki_field /x.efi usrhash)"
	check "uki_field unknown field -> 2" 2 "$(MASTERSOS_UKIFY=$tmp/ukify-stub rc_of uki_field /x.efi bogus)"
	# a UKI without IMAGE_VERSION / usrhash must be an error, not an empty success
	cat >"$tmp/ukify-stub-empty" <<'STUB'
#!/bin/bash
printf '%s\n' '{".osrel": {"text": "NAME=\"MastersOS\"\nIMAGE_VERSION=\"\"\n"}, ".cmdline": {"text": "root=dissect rw usrhash= console=tty0"}}'
STUB
	chmod +x "$tmp/ukify-stub-empty"
	check "uki_field empty IMAGE_VERSION -> 1" 1 "$(MASTERSOS_UKIFY=$tmp/ukify-stub-empty rc_of uki_field /x.efi version)"
	check "uki_field empty usrhash= -> 1" 1 "$(MASTERSOS_UKIFY=$tmp/ukify-stub-empty rc_of uki_field /x.efi usrhash)"
	cat >"$tmp/ukify-stub-missing" <<'STUB'
#!/bin/bash
printf '%s\n' '{".osrel": {"text": "NAME=x\n"}, ".cmdline": {"text": "root=dissect"}}'
STUB
	chmod +x "$tmp/ukify-stub-missing"
	check "uki_field missing IMAGE_VERSION -> 1" 1 "$(MASTERSOS_UKIFY=$tmp/ukify-stub-missing rc_of uki_field /x.efi version)"
	check "uki_field missing usrhash -> 1" 1 "$(MASTERSOS_UKIFY=$tmp/ukify-stub-missing rc_of uki_field /x.efi usrhash)"
else
	echo "SKIP uki_field (no jq on this machine)"
fi

# --- golden_dev (MASTERSOS_GOLDEN_LSBLK prints "NAME PARTTYPE") --------------------------------------------------
cat >"$tmp/lsblk-golden" <<STUB
#!/bin/bash
printf '%s\n' '/dev/sda5 e7bb33fb-06cf-4e81-8273-e543b413e2e2' '/dev/sda10 $GOLDEN_USR_TYPE' '/dev/sda8 ${GOLDEN_SIG_TYPE^^}'
STUB
chmod +x "$tmp/lsblk-golden"
check "golden_dev finds usr" /dev/sda10 "$(MASTERSOS_GOLDEN_LSBLK=$tmp/lsblk-golden golden_dev "$GOLDEN_USR_TYPE")"
check "golden_dev is case-insensitive" /dev/sda8 "$(MASTERSOS_GOLDEN_LSBLK=$tmp/lsblk-golden golden_dev "$GOLDEN_SIG_TYPE")"
check "golden_dev absent -> 1" 1 "$(MASTERSOS_GOLDEN_LSBLK=$tmp/lsblk-golden rc_of golden_dev "$GOLDEN_ESP_TYPE")"

# --- boot_disk ---------------------------------------------------------------------------------------------------
check "boot_disk override" /dev/vdz "$(MASTERSOS_BOOT_DISK=/dev/vdz boot_disk)"
# LoaderDevicePartUUID is 4 attribute bytes + UTF-16LE text; lsblk resolves the partition's parent
mkdir -p "$tmp/efivars"
{ printf '\x07\x00\x00\x00'; printf '%s' "ABCDEF01-2345-6789-abcd-ef0123456789" | sed 's/./&\x00/g'; printf '\x00\x00'; } >"$tmp/efivars/LoaderDevicePartUUID"

# --- slot_siblings -----------------------------------------------------------------------------------------------
stubs=$tmp/stubs
mkdir -p "$stubs" "$tmp/sys/class/block/sda7" "$tmp/sys/class/block/sda6" "$tmp/sys/class/block/nvme0n1p7"
echo 7 >"$tmp/sys/class/block/sda7/partition"
echo 7 >"$tmp/sys/class/block/nvme0n1p7/partition"
echo 2 >"$tmp/sys/class/block/sda6/partition"
cat >"$stubs/lsblk" <<'STUB'
#!/bin/bash
# stub: lsblk -no <FIELD> <DEV>; answers come from $STUB_TABLE lines "<devname> <FIELD> <value>"
[ "$1" = -no ] || exit 64
d=${3##*/}
while read -r dev field val; do
	if [ "$dev" = "$d" ] && [ "$field" = "$2" ]; then echo "$val"; exit 0; fi
done <"$STUB_TABLE"
exit 1
STUB
chmod +x "$stubs/lsblk"
cat >"$tmp/table" <<EOF
sda7 PKNAME sda
sda6 PKNAME sda
sda5 PARTTYPE e7bb33fb-06cf-4e81-8273-e543b413e2e2
sda6 PARTTYPE 77ff5f63-e7b6-4633-acf4-1565b864c0e6
nvme0n1p7 PKNAME nvme0n1
nvme0n1p5 PARTTYPE e7bb33fb-06cf-4e81-8273-e543b413e2e2
nvme0n1p6 PARTTYPE 77ff5f63-e7b6-4633-acf4-1565b864c0e6
abcdef01-2345-6789-abcd-ef0123456789 PKNAME nvme0n1
EOF
sib() { PATH=$stubs:$PATH STUB_TABLE=$tmp/table MASTERSOS_SYSFS=$tmp/sys slot_siblings "$@"; }
check "slot_siblings bare names" "sda5 sda6" "$(sib sda7)"
check "slot_siblings full paths" "/dev/sda5 /dev/sda6" "$(sib /dev/sda7)"
check "slot_siblings nvme p-suffix" "/dev/nvme0n1p5 /dev/nvme0n1p6" "$(sib /dev/nvme0n1p7)"
sed 's/^sda5 PARTTYPE .*/sda5 PARTTYPE 0fc63daf-8483-4772-8e79-3d69d8477de4/' "$tmp/table" >"$tmp/table2"
check "slot_siblings wrong sig type -> 1" 1 "$(PATH=$stubs:$PATH STUB_TABLE=$tmp/table2 MASTERSOS_SYSFS=$tmp/sys rc_of slot_siblings /dev/sda7)"
check "slot_siblings partition number too low -> 1" 1 "$(PATH=$stubs:$PATH STUB_TABLE=$tmp/table MASTERSOS_SYSFS=$tmp/sys rc_of slot_siblings /dev/sda6)"
check "whole_disk" /dev/sda "$(PATH=$stubs:$PATH STUB_TABLE=$tmp/table whole_disk /dev/sda7)"
check "boot_disk from LoaderDevicePartUUID" /dev/nvme0n1 \
	"$(PATH=$stubs:$PATH STUB_TABLE=$tmp/table MASTERSOS_LOADER_PARTUUID_FILE=$tmp/efivars/LoaderDevicePartUUID boot_disk)"

# --- read_through ------------------------------------------------------------------------------------------------
dd if=/dev/zero of="$tmp/blob" bs=1M count=100 status=none
check "read_through plain" 0 "$(rc_of read_through "$tmp/blob")"
check "read_through missing device -> non-zero" yes "$([ "$(rc_of read_through "$tmp/nonexistent")" != 0 ] && echo yes || echo no)"
t0=$EPOCHREALTIME
read_through "$tmp/blob" 400
t1=$EPOCHREALTIME
el_ms=$(((${t1/./} - ${t0/./}) / 1000))
# 100 MiB at 400 MiB/s is 250 ms; the brief asks for at least 200 ms
check "read_through 400 MiB/s takes >= 200 ms (took ${el_ms} ms)" yes "$([ "$el_ms" -ge 200 ] && echo yes || echo no)"

# --- verity_check (stubbed veritysetup records its calls) --------------------------------------------------------
cat >"$stubs/veritysetup" <<'STUB'
#!/bin/bash
echo "$*" >>"$STUB_VLOG"
[ "${STUB_VFAIL:-}" = "$1" ] && exit "${STUB_VRC:-5}"
# STUB_CLOSE_FAILS=<n>: the first <n> plain closes fail (busy), counted in $STUB_CLOSE_CNT
if [ "$1" = close ] && [ "$#" = 2 ] && [ -n "${STUB_CLOSE_FAILS:-}" ]; then
	k=$(($(cat "$STUB_CLOSE_CNT" 2>/dev/null || echo 0) + 1))
	echo "$k" >"$STUB_CLOSE_CNT"
	[ "$k" -gt "$STUB_CLOSE_FAILS" ] || exit 5
fi
exit 0
STUB
chmod +x "$stubs/veritysetup"
vc() { # vc <log> <args...>
	local log=$1
	shift
	: >"$log"
	PATH=$stubs:$PATH STUB_VLOG=$log TMPDIR=$tmp MASTERSOS_SYSFS=$tmp/sys verity_check "$@"
}
check "verity_check --no-read ok" 0 "$(rc_of vc "$tmp/v1.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read)"
vc "$tmp/v1.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read
check "verity_check closes a stale mapping, opens with the signature, closes" "close mastersos-check-$$
open $tmp/blob mastersos-check-$$ $tmp/blob $RH --root-hash-signature=<private-dir>/sig
close mastersos-check-$$" "$(sed -E "s#--root-hash-signature=$tmp/tmp\.[A-Za-z0-9]+/sig#--root-hash-signature=<private-dir>/sig#" "$tmp/v1.log")"
check "verity_check --no-sig ok" 0 "$(rc_of vc "$tmp/v2.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read --no-sig)"
check "verity_check --no-sig open line has no signature option" "open $tmp/blob mastersos-check-$$ $tmp/blob $RH" "$(grep '^open' "$tmp/v2.log")"
check "verity_check signature partition disagrees -> 1" 1 "$(rc_of vc "$tmp/v3.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "${RH/8e231/00000}" --no-read --no-sig)"
check "verity_check disagreeing signature partition never opens" 0 "$(grep -c '^open' "$tmp/v3.log" || true)"
check "verity_check open failure -> 1" 1 "$(STUB_VFAIL=open rc_of vc "$tmp/v4.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read)"
# exit code 3 = the signed open failed with veritysetup rc 1 (keyring lacks the certificate); everything else stays 1
check "verity_check signed open rc 1 (ENOKEY) -> 3" 3 "$(STUB_VFAIL=open STUB_VRC=1 rc_of vc "$tmp/v8.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read)"
check "verity_check signed open rc 5 (bad signature or data) -> 1" 1 "$(STUB_VFAIL=open STUB_VRC=5 rc_of vc "$tmp/v8.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read)"
check "verity_check --no-sig open rc 1 -> 1, never 3" 1 "$(STUB_VFAIL=open STUB_VRC=1 rc_of vc "$tmp/v8.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read --no-sig)"
check "verity_check cleans up after an exit-3 failure" "close mastersos-check-$$" "$(tail -n 1 "$tmp/v8.log")"
# --rate N reaches read_through; without it the read is unthrottled (read_through is replaced by a recorder in a subshell)
rt_log=$tmp/rt.log
(
	# shellcheck disable=SC2329 # called by verity_check
	read_through() { echo "$*" >"$rt_log"; }
	vc "$tmp/v9.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --rate 150
)
check "verity_check --rate 150 passes the rate to read_through" "/dev/mapper/mastersos-check-$$ 150" "$(cat "$rt_log")"
(
	# shellcheck disable=SC2329 # called by verity_check
	read_through() { echo "$*" >"$rt_log"; }
	vc "$tmp/v9.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH"
)
check "verity_check without --rate reads unthrottled" "/dev/mapper/mastersos-check-$$" "$(cat "$rt_log")"
check "verity_check --rate with a non-number -> 2" 2 "$(rc_of vc "$tmp/v9.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --rate fast)"
check "verity_check --rate without a value -> 2" 2 "$(rc_of vc "$tmp/v9.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --rate)"
check "verity_check closes after a failed open" "close mastersos-check-$$" "$(tail -n 1 "$tmp/v4.log")"
# a transiently busy check mapping is closed again (about a second), then left to deferred removal: a mapping left behind in the
# initrd would keep the active data partition held and systemd-veritysetup@usr could not open it on that boot
mkdir -p "$tmp/mapper"
: >"$tmp/mapper/mastersos-check-$$"
closes_after_open() { sed -n '/^open/,$p' "$1" | grep '^close' | paste -sd'|' -; }
rm -f "$tmp/close.cnt"
check "verity_check close busy twice, mapping present -> retried until it closes, rc 0" "0 close mastersos-check-$$|close mastersos-check-$$|close mastersos-check-$$" \
	"$(STUB_CLOSE_FAILS=3 STUB_CLOSE_CNT=$tmp/close.cnt MASTERSOS_DEV_MAPPER=$tmp/mapper rc_of vc "$tmp/v10.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read --no-sig) $(closes_after_open "$tmp/v10.log")"
rm -f "$tmp/close.cnt"
check "verity_check close always busy -> five tries, then close --deferred" \
	"close mastersos-check-$$|close mastersos-check-$$|close mastersos-check-$$|close mastersos-check-$$|close mastersos-check-$$|close --deferred mastersos-check-$$" \
	"$(STUB_CLOSE_FAILS=99 STUB_CLOSE_CNT=$tmp/close.cnt MASTERSOS_DEV_MAPPER=$tmp/mapper rc_of vc "$tmp/v11.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read --no-sig >/dev/null; closes_after_open "$tmp/v11.log")"
rm -f "$tmp/close.cnt" "$tmp/mapper/mastersos-check-$$"
check "verity_check close fails but no mapping node -> one try only" "close mastersos-check-$$" \
	"$(STUB_CLOSE_FAILS=99 STUB_CLOSE_CNT=$tmp/close.cnt MASTERSOS_DEV_MAPPER=$tmp/mapper rc_of vc "$tmp/v12.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read --no-sig >/dev/null; closes_after_open "$tmp/v12.log")"
rm -f "$tmp/close.cnt"
check "verity_check leaves no temp directory behind" "none" "$(find "$tmp" -mindepth 1 -maxdepth 1 -name 'tmp.*' | head -n 1 | grep . || echo none)"
# temp files never sit at a predictable path in a world-writable directory: a pre-created symlink must not be followed
echo canary >"$tmp/canary"
ln -s "$tmp/canary" "$tmp/mastersos-check-$$.sig"
ln -s "$tmp/canary" "$tmp/golden-mok-$$.pem"
vc "$tmp/v6.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read || true
check "verity_check ignores a symlink pre-created at the old predictable path" "canary" "$(cat "$tmp/canary")"
# without mktemp (initrd) the fallback is mkdir -m 0700 under /run; an existing path makes it fail instead of reusing it
mkdir -p "$tmp/run" "$tmp/victim"
ln -s "$tmp/victim" "$tmp/run/mastersos-golden.$$"
nomk=$tmp/nomktemp-bin
mkdir -p "$nomk"
for t in $INITRD_TOOLS; do case $t in lsblk | veritysetup | udevadm) continue ;; esac; ln -sf "$(command -v "$t")" "$nomk/$t"; done
cp "$stubs/veritysetup" "$nomk/"
check "verity_check without mktemp refuses a pre-created /run path" 1 "$(PATH=$nomk STUB_VLOG=$tmp/v7.log MASTERSOS_RUN_DIR=$tmp/run rc_of verity_check "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read)"
check "the pre-created path's target stayed empty" "empty" "$([ -z "$(find "$tmp/victim" -mindepth 1 | head -n 1)" ] && echo empty || echo not-empty)"
rm "$tmp/run/mastersos-golden.$$"
check "verity_check without mktemp works through a fresh 0700 /run directory" 0 "$(PATH=$nomk STUB_VLOG=$tmp/v7.log MASTERSOS_RUN_DIR=$tmp/run rc_of verity_check "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --no-read)"
check "that directory is removed afterwards" "none" "$(find "$tmp/run" -mindepth 1 | head -n 1 | grep . || echo none)"
# golden_uki_ok with stub openssl/sbverify: must not write through a pre-created symlink either
# shellcheck disable=SC2016 # the stub's own variables must stay literal
printf '#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = -out ] && echo pem >"$2"; shift; done\n' >"$stubs/openssl"
printf '#!/bin/bash\nexit 0\n' >"$stubs/sbverify"
chmod +x "$stubs/openssl" "$stubs/sbverify"
mkdir -p "$tmp/gesp"
: >"$tmp/gesp/MastersOS.efi"
: >"$tmp/mok.der"
if command -v jq >/dev/null; then
	check "golden_uki_ok passes with matching usrhash" 0 "$(PATH=$stubs:$PATH MASTERSOS_MOK_DER=$tmp/mok.der MASTERSOS_UKIFY=$tmp/ukify-stub TMPDIR=$tmp rc_of golden_uki_ok "$tmp/gesp" "$RH")"
	check "golden_uki_ok fails on another usrhash" 1 "$(PATH=$stubs:$PATH MASTERSOS_MOK_DER=$tmp/mok.der MASTERSOS_UKIFY=$tmp/ukify-stub TMPDIR=$tmp rc_of golden_uki_ok "$tmp/gesp" "${RH/8e231/00000}")"
	check "golden_uki_ok ignores a symlink pre-created at the old predictable path" "canary" "$(cat "$tmp/canary")"
fi
check "verity_check bad option -> 2" 2 "$(rc_of vc "$tmp/v5.log" "$tmp/blob" "$tmp/blob" "$tmp/sig.ok" "$RH" --bogus)"

# --- the (i) functions need only INITRD_TOOLS --------------------------------------------------------------------
initrd_bin=$tmp/initrd-bin
mkdir -p "$initrd_bin"
for t in $INITRD_TOOLS; do
	case $t in lsblk | veritysetup | udevadm) continue ;; esac # stubbed below: they need a kernel
	p=$(command -v "$t" || true)
	if [ -z "$p" ]; then
		echo "FAIL tool $t from INITRD_TOOLS is not available on this machine" >&2
		fails=$((fails + 1))
		continue
	fi
	ln -sf "$p" "$initrd_bin/$t"
done
# stubs for the tools whose real behaviour needs a kernel
cp "$stubs/lsblk" "$stubs/veritysetup" "$initrd_bin/"
printf '#!/bin/bash\nexit 0\n' >"$initrd_bin/udevadm"
chmod +x "$initrd_bin/udevadm"
bash_bin=$(command -v bash)
cat >"$tmp/initrd-run.sh" <<'RUN'
set -u
. "$GOLDEN_LIB"
sig_roothash "$T/sig.ok" >/dev/null || echo "sig_roothash failed"
sig_signature "$T/sig.ok" "$T/i.sig" || echo "sig_signature failed"
erofs_bytes "$T/erofs.ok" >/dev/null || echo "erofs_bytes failed"
[ "$(verity_data_bytes "$T/vsb.ok")" = 1812873216 ] || echo "verity_data_bytes failed"
read_through "$T/blob" || echo "read_through failed"
read_through "$T/blob" 4000 || echo "read_through (rate) failed"
MASTERSOS_GOLDEN_LSBLK=$T/lsblk-golden golden_dev "$GOLDEN_USR_TYPE" >/dev/null || echo "golden_dev failed"
MASTERSOS_BOOT_DISK=/dev/sda boot_disk >/dev/null || echo "boot_disk failed"
MASTERSOS_LOADER_PARTUUID_FILE=$T/efivars/LoaderDevicePartUUID boot_disk >/dev/null || echo "boot_disk (efivar) failed"
slot_siblings /dev/sda7 >/dev/null || echo "slot_siblings failed"
whole_disk /dev/sda7 >/dev/null || echo "whole_disk failed"
verity_check "$T/blob" "$T/blob" "$T/sig.ok" "$RH" --no-read --no-sig || echo "verity_check failed"
echo done
RUN
out=$(env -i HOME="$tmp" GOLDEN_LIB="$lib" T="$tmp" RH="$RH" GOLDEN_USR_TYPE="$GOLDEN_USR_TYPE" \
	STUB_TABLE="$tmp/table" STUB_VLOG="$tmp/initrd-v.log" MASTERSOS_SYSFS="$tmp/sys" TMPDIR="$tmp" PATH="$initrd_bin" \
	"$bash_bin" "$tmp/initrd-run.sh" 2>&1 || true)
check "initrd-tools-only run of the (i) functions" "done" "$out"

# --- decide_userspace --------------------------------------------------------------------------------------------
# drow <want, comma separated> <HAS_GOLDEN> <ACTIVE_OK> <BOOTED_VER> <GOLDEN_VER> <GOLDEN_OK> <NEWEST_UKI_OK> <INACTIVE_OK> [GAVE_UP]
# "-" means unset; "empty" means set to the empty string (GOLDEN_VER empty = invalid signature area)
drow() {
	local want=$1 got
	shift
	local -a vals=("$@") names=(HAS_GOLDEN ACTIVE_OK BOOTED_VER GOLDEN_VER GOLDEN_OK NEWEST_UKI_OK INACTIVE_OK GAVE_UP)
	got=$(
		unset HAS_GOLDEN ACTIVE_OK BOOTED_VER GOLDEN_VER GOLDEN_OK NEWEST_UKI_OK INACTIVE_OK GAVE_UP
		for i in "${!vals[@]}"; do
			case ${vals[$i]} in
			-) ;;
			empty) export "${names[$i]}=" ;;
			*) export "${names[$i]}=${vals[$i]}" ;;
			esac
		done
		decide_userspace | tr '\n' ',' | sed 's/,$//'
	)
	check "decide ${vals[*]} -> '${want}'" "$want" "$got"
}
drow report-only 0 1 v2 - - - -
drow report-only 0 0 v2 - - - -
drow "" 1 1 v2 v2 1 1 -
drow refresh-golden 1 1 v2 v1 1 1 -
drow refresh-golden 1 1 v2 empty 0 1 -
drow refresh-golden 1 1 v2 v2 0 1 -
drow request-repair 1 0 v2 v2 1 1 -
drow network 1 0 v2 v2 0 1 -
drow network 1 0 v2 v1 1 1 -
drow restore-uki 1 1 v1 v2 1 0 1
# restore-inactive first: restore-uki only puts a UKI back once a slot of that version exists (integrity run_actions)
drow restore-inactive,restore-uki 1 1 v1 v2 1 0 0
drow restore-inactive 1 1 v1 v2 1 1 0
drow report-only 1 0 v1 v2 1 1 1
drow restore-inactive,restore-uki 1 0 v1 v2 1 0 0
drow report-only 1 0 v2 v2 1 1 - 1
drow report-only 1 0 v2 v2 0 1 - 1
# rows beyond the plan table: ordering is sort -V (v10 > v9); the golden copy never goes down
drow "" 1 1 v10 v10 1 1 -
drow refresh-golden 1 1 v10 v9 1 1 -
drow report-only 1 0 v9 v10 1 1 1
drow "" 1 1 v1 v2 1 1 1
drow "" 1 1 v1 v2 0 1 1
drow report-only 1 0 v1 v2 0 1 1

echo "golden-lib-test: $((n - fails))/$n passed"
[ "$fails" = 0 ]

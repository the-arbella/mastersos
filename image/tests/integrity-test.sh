#!/bin/bash
# Tests for integrity (usr self-repair, Task 4; mkosi.extra/usr/lib/mastersos/integrity). No VM, no root; needs jq:
#   bash image/tests/integrity-test.sh
# Plain files stand in for the ESP and the golden partitions; verity_check, ukify, sbverify and openssl are stubs
# (golden-lib's own behaviour is covered by golden-lib-test.sh), loginctl / runuser / notify-send are recording stubs.
# shellcheck disable=SC2016 # the stub scripts are written from single-quoted text on purpose
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../mkosi.extra/usr/lib/mastersos/integrity
lib=$here/../mkosi.extra/usr/lib/mastersos/golden-lib
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

RH=8e23106eae00986cafdf5579681645ec48477bbb52f1986e508a9c3139f70be4 # the running root hash
GH=1111111111111111111111111111111111111111111111111111111111111111 # a golden root hash that is not the running one
NOW=1793000000                                                       # fixed "now"
DAY=86400

bin=$tmp/bin
mkdir -p "$bin"
# wrapper lib: the real library, then verity_check replaced by a recorder (rc from $STUB_VC_RC; $STUB_VC_RC_SIGNED for the first,
# signed call, which lets a test return 3 once and then 0)
cat >"$tmp/lib" <<EOF
. "$lib"
verity_check() {
	# EV_GESP / EV_GSIG (action tests): record what the golden ESP holds and what the golden signature names at this moment
	[ -z "\${EV_GESP:-}" ] || echo "state gesp=\$(ls "\$EV_GESP" | tr '\n' ,) gsig=\$(sig_roothash "\$EV_GSIG" || echo none)" >>"\$VC_LOG"
	echo "\$*" >>"\$VC_LOG"
	# STUB_VC_FAIL_ONCE=<data>: the first STUB_VC_FAIL_TIMES (default 1) checks of that data partition fail (a damaged slot that
	# the restore then fixes)
	if [ -n "\${STUB_VC_FAIL_ONCE:-}" ] && [ "\$1" = "\$STUB_VC_FAIL_ONCE" ]; then
		echo x >>"\$VC_LOG.fails"
		[ "\$(wc -l <"\$VC_LOG.fails")" -gt "\${STUB_VC_FAIL_TIMES:-1}" ] || return 1
	fi
	[ -z "\${VC_SIG_RH:-}" ] || [ "\$VC_SIG_RH" = "\$4" ] || return 1
	case " \$* " in
	*" --no-sig "*) return "\${STUB_VC_RC:-0}" ;;
	*) return "\${STUB_VC_RC_SIGNED:-\${STUB_VC_RC:-0}}" ;;
	esac
}
EOF
# ukify stub: the "UKI" is a text file "<version> <usrhash>"
cat >"$bin/ukify" <<'EOF'
#!/bin/bash
read -r ver hash <"$2"
printf '{".osrel":{"text":"IMAGE_VERSION=\\"%s\\"\\n"},".cmdline":{"text":"usrhash=%s root=dissect"}}\n' "$ver" "$hash"
EOF
printf '#!/bin/bash\nexit 0\n' >"$bin/sbverify"
printf '#!/bin/bash\n# openssl x509 -inform der -in X -out Y\nwhile [ $# -gt 0 ]; do [ "$1" = -out ] && : >"$2"; shift; done\n' >"$bin/openssl"
cat >"$bin/loginctl" <<'EOF'
#!/bin/bash
case $1 in
list-sessions) cat "$SESSIONS_FILE" 2>/dev/null || true ;;
show-session) sed -n "s/^$2: //p" "$SESSION_INFO" | tr ' ' '\n' ;;
esac
EOF
# runuser stub: runuser -u USER -- CMD... runs CMD (the notify stub) without switching user
printf '#!/bin/bash\nshift 3\nexec "$@"\n' >"$bin/runuser"
printf '#!/bin/bash\nprintf "%%s|" "$DBUS_SESSION_BUS_ADDRESS" "$@" >>"$NOTIFY_LOG"\necho >>"$NOTIFY_LOG"\n' >"$bin/notify-send"
# dd recorder (MASTERSOS_DD): logs its operands and whether the whole-disk lock ($MASTERSOS_WHOLE_DISK) is held, fails for
# of=$DD_FAIL_OF, otherwise runs the real dd
cat >"$bin/dd-rec" <<'EOF'
#!/bin/bash
lock=held
if flock -n "$MASTERSOS_WHOLE_DISK" true 2>/dev/null; then lock=free; fi
of=""
for a in "$@"; do case $a in of=*) of=${a#of=} ;; esac; done
echo "dd $* lock=$lock" >>"$DD_LOG"
if [ -n "${SLOTS_LOG:-}" ]; then # whether integrity holds the slots lock during this write
	if flock -n "$MASTERSOS_SLOTS_LOCK" true 2>/dev/null; then echo "${of##*/} free" >>"$SLOTS_LOG"; else echo "${of##*/} held" >>"$SLOTS_LOG"; fi
fi
if [ -n "${DD_FAIL_OF:-}" ] && [ "$of" = "$DD_FAIL_OF" ]; then exit 1; fi
# DD_FAIL_IF: the write from that source happens, then dd reports a failure (a write that broke off at the end)
for a in "$@"; do if [ -n "${DD_FAIL_IF:-}" ] && [ "$a" = "if=$DD_FAIL_IF" ]; then dd "$@" && exit 1; fi; done
exec dd "$@"
EOF
printf '#!/bin/bash\necho "$*" >>"$SYSTEMCTL_LOG"\n' >"$bin/systemctl"
printf '#!/bin/bash\nexit 0\n' >"$bin/udevadm"
chmod +x "$bin"/*
: >"$tmp/mok.der"

mkerofs() { # mkerofs <file> <blocks of 4096> <total bytes>: an erofs superblock (magic, blkszbits 12, blocks) and random filler
	local b=$2
	head -c "$3" /dev/urandom >"$1"
	printf '\xe2\xe1\xf5\xe0' | dd of="$1" bs=1 seek=1024 conv=notrunc status=none
	printf '\x0c' | dd of="$1" bs=1 seek=1036 conv=notrunc status=none
	# shellcheck disable=SC2059 # blocks as little-endian u32 at 1060, built as printf escapes
	printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((b & 255)) $((b >> 8 & 255)) $((b >> 16 & 255)) $((b >> 24 & 255)))" |
		dd of="$1" bs=1 seek=1060 conv=notrunc status=none
}

sig_json() { # sig_json <file> <roothash|-> : a golden signature area
	if [ "$2" = - ]; then
		dd if=/dev/zero of="$1" bs=16K count=1 status=none
	else
		printf '{"rootHash":"%s","signature":"AAAA"}' "$2" | dd of="$1" bs=16K count=1 conv=sync status=none
	fi
}

# fresh <case-dir> : a machine with a golden copy (version 20261030.1 > booted 20261027.2 unless a test changes it)
fresh() {
	local d=$tmp/$1
	rm -rf "$d"
	mkdir -p "$d/esp/EFI/MastersOS" "$d/var" "$d/gesp" "$d/log"
	sig_json "$d/gsig" "$GH"
	: >"$d/gverity"
	: >"$d/gusr"
	echo "20261030.1 $GH" >"$d/gesp/MastersOS.efi"
	echo "usrhash=$RH quiet" >"$d/cmdline"
	: >"$d/vc.log"
	: >"$d/notify.log"
	: >"$d/dd.log"
	: >"$d/disk"
	# the active slot (MASTERSOS_ACTIVE_{SIG,VERITY,USR}): erofs of 3 blocks (12288 bytes) in a 16 KiB "partition"
	sig_json "$d/asig" "$RH"
	head -c 8192 /dev/urandom >"$d/averity"
	mkerofs "$d/ausr" 3 16384
	mkdir -p "$d/esp/EFI/Linux"
	echo "20261027.2 $RH" >"$d/esp/EFI/Linux/MastersOS_20261027.2_x86-64.efi"
	echo "$d"
}

# run <case-dir> [args...] : runs integrity with the case's environment; EXTRA_ENV words are added
run() {
	local d=$1 extra=()
	shift
	read -ra extra <<<"${EXTRA_ENV:-}"
	env -i PATH="$bin:/usr/bin:/bin" HOME="$d" \
		MASTERSOS_GOLDEN_LIB="$tmp/lib" MASTERSOS_ESP="$d/esp" MASTERSOS_SYSTEM_VAR="$d/var" \
		MASTERSOS_GOLDEN_SIG="$d/gsig" MASTERSOS_GOLDEN_VERITY="$d/gverity" MASTERSOS_GOLDEN_USR="$d/gusr" MASTERSOS_GOLDEN_ESP_DIR="$d/gesp" \
		MASTERSOS_ACTIVE_OK="${ACTIVE:-1}" MASTERSOS_CMDLINE="$d/cmdline" MASTERSOS_IMAGE_VERSION="${BOOTED:-20261027.2}" MASTERSOS_NOW="$NOW" \
		MASTERSOS_MOK_DER="$tmp/mok.der" MASTERSOS_LOGINCTL="$bin/loginctl" MASTERSOS_LOCALE_CONF="$d/locale.conf" \
		VC_LOG="$d/vc.log" NOTIFY_LOG="$d/notify.log" SESSIONS_FILE="$d/sessions" SESSION_INFO="$d/session-info" \
		MASTERSOS_ACTIVE_SIG="$d/asig" MASTERSOS_ACTIVE_VERITY="$d/averity" MASTERSOS_ACTIVE_USR="$d/ausr" \
		MASTERSOS_DD="$bin/dd-rec" MASTERSOS_WHOLE_DISK="$d/disk" DD_LOG="$d/dd.log" \
		MASTERSOS_SYSTEMCTL="$bin/systemctl" SYSTEMCTL_LOG="$d/systemctl.log" MASTERSOS_SLOTS_LOCK="$d/slots.lock" \
		MASTERSOS_FETCHED_MARKER="$d/golden-fetched" "${extra[@]}" bash "$script" "$@" >"$d/log/out" 2>&1
}
jqf() { jq -c "$2" "$1/var/integrity.json"; }

# --- boot_ok_clears ----------------------------------------------------------------------------------------------------------
d=$(fresh boot_ok)
: >"$d/esp/EFI/MastersOS/boot-pending"
echo "$RH 1" >"$d/esp/EFI/MastersOS/repair-count"
rc=0
run "$d" --boot-ok || rc=$?
check "boot_ok_clears: exit 0" 0 "$rc"
check "boot_ok_clears: boot-pending removed" no "$([ -e "$d/esp/EFI/MastersOS/boot-pending" ] && echo yes || echo no)"
check "boot_ok_clears: repair-count kept" "$RH 1" "$(cat "$d/esp/EFI/MastersOS/repair-count")"
check "boot_ok_clears: no integrity.json written" no "$([ -e "$d/var/integrity.json" ] && echo yes || echo no)"
rc=0
run "$d" --boot-ok || rc=$?
check "boot_ok_clears: nothing to clear -> exit 0" 0 "$rc"
rc=0
(
	cd "$d" && env -i PATH="$bin:/usr/bin:/bin" MASTERSOS_ESP="$d/does-not-exist" bash "$script" --boot-ok >/dev/null 2>&1
) || rc=$?
check "boot_ok_clears: ESP missing -> exit 0" 0 "$rc"
rc=0
run "$d" --nonsense || rc=$?
check "usage error -> exit 2" 2 "$rc"

# --- count_cleared_only_when_ok ----------------------------------------------------------------------------------------------
d=$(fresh count_ok)
echo "$RH 1" >"$d/esp/EFI/MastersOS/repair-count"
ACTIVE=1 run "$d"
check "count_cleared: ACTIVE_OK=1 removes repair-count" no "$([ -e "$d/esp/EFI/MastersOS/repair-count" ] && echo yes || echo no)"
check "count_cleared: active_ok true" true "$(jqf "$d" .active_ok)"

# repair-inprogress / repair-interrupted of the running root hash go once the slot reads clean (an initrd repair cut off after its
# writes would otherwise rewrite the slot on every boot); those of another root hash, or with the slot still bad, stay
d=$(fresh inprog_ok)
echo "$RH" >"$d/esp/EFI/MastersOS/repair-inprogress"
echo "$RH 2" >"$d/esp/EFI/MastersOS/repair-interrupted"
ACTIVE=1 run "$d"
check "inprogress_cleared: ACTIVE_OK=1 removes repair-inprogress and repair-interrupted" "no no" \
	"$([ -e "$d/esp/EFI/MastersOS/repair-inprogress" ] && echo yes || echo no) $([ -e "$d/esp/EFI/MastersOS/repair-interrupted" ] && echo yes || echo no)"
d=$(fresh inprog_other)
echo "$GH" >"$d/esp/EFI/MastersOS/repair-inprogress"
echo "$GH 1" >"$d/esp/EFI/MastersOS/repair-interrupted"
ACTIVE=1 run "$d"
check "inprogress_cleared: another root hash's files stay" "$GH|$GH 1" \
	"$(cat "$d/esp/EFI/MastersOS/repair-inprogress")|$(cat "$d/esp/EFI/MastersOS/repair-interrupted")"
d=$(fresh inprog_bad)
echo "$RH" >"$d/esp/EFI/MastersOS/repair-inprogress"
ACTIVE=0 run "$d"
check "inprogress_cleared: ACTIVE_OK=0 keeps repair-inprogress" "$RH" "$(cat "$d/esp/EFI/MastersOS/repair-inprogress")"

# A repair-usr request for the running root hash goes once the slot reads clean. The initrd keeps the request after a write
# that did not verify (so the next boot tries again); without this, a slot that the initrd cannot verify but userspace reads
# clean was rewritten on every boot, each time "attempt 1 of 2" (Task 10 VM 165: repair-count removed here, repair-usr kept).
# A request for another root hash stays (the initrd drops it itself)
d=$(fresh request_ok)
echo "${RH:0:8}-${RH:8:4}-${RH:12:4}-${RH:16:4}-${RH:20:12} $RH" >"$d/esp/EFI/MastersOS/repair-usr"
echo "$RH 1" >"$d/esp/EFI/MastersOS/repair-count"
ACTIVE=1 run "$d"
check "request_cleared: ACTIVE_OK=1 removes repair-usr and repair-count of the running root hash" "no no" \
	"$([ -e "$d/esp/EFI/MastersOS/repair-usr" ] && echo yes || echo no) $([ -e "$d/esp/EFI/MastersOS/repair-count" ] && echo yes || echo no)"
check "request_cleared: logged" 1 "$(grep -c 'active slot is good: repair-usr' "$d/log/out")"
d=$(fresh request_other)
echo "${GH:0:8}-${GH:8:4}-${GH:12:4}-${GH:16:4}-${GH:20:12} $GH" >"$d/esp/EFI/MastersOS/repair-usr"
ACTIVE=1 run "$d"
check "request_cleared: another root hash's request stays" "${GH:0:8}-${GH:8:4}-${GH:12:4}-${GH:16:4}-${GH:20:12} $GH" \
	"$(cat "$d/esp/EFI/MastersOS/repair-usr")"

d=$(fresh count_bad)
echo "$RH 2" >"$d/esp/EFI/MastersOS/repair-count"
printf '1 c1 1000 user seat0\n' >"$d/sessions"
echo "1: Active=yes Type=wayland Class=user Name=alice User=1000" >"$d/session-info"
ACTIVE=0 run "$d"
check "count_cleared: ACTIVE_OK=0 keeps repair-count" "$RH 2" "$(cat "$d/esp/EFI/MastersOS/repair-count")"
check "count_cleared: gave_up is the running root hash" "\"$RH\"" "$(jqf "$d" .gave_up)"
check "count_cleared: no notification" 0 "$(wc -l <"$d/notify.log" | tr -d ' ')"
check "count_cleared: no request-repair" false "$(jqf "$d" '.actions | index("request-repair") != null')"

# the initrd gives up at repair-count >= 2 (MAX_TRIES); integrity compares the number the same way, not the exact string "<h> 2"
d=$(fresh count_three)
echo "$RH 3" >"$d/esp/EFI/MastersOS/repair-count"
BOOTED=20261030.1 ACTIVE=0 run "$d"
check "count_cleared: repair-count 3 and slot bad -> gave_up, report-only" "\"$RH\" [\"report-only\"]" "$(jqf "$d" .gave_up) $(jqf "$d" .actions)"

d=$(fresh count_one)
echo "$RH 1" >"$d/esp/EFI/MastersOS/repair-count"
ACTIVE=0 run "$d"
check "count 1 and slot bad: not gave up" null "$(jqf "$d" .gave_up)"
check "count 1 and slot bad: count kept" "$RH 1" "$(cat "$d/esp/EFI/MastersOS/repair-count")"

# --- golden_uki_mismatch -----------------------------------------------------------------------------------------------------
d=$(fresh uki_mismatch)
echo "20261030.1 2222222222222222222222222222222222222222222222222222222222222222" >"$d/gesp/MastersOS.efi"
BOOTED=20261030.1 run "$d"
check "golden_uki_mismatch: golden_ok false" false "$(jqf "$d" .golden_ok)"
check "golden_uki_mismatch: refresh-golden" '["refresh-golden"]' "$(jqf "$d" .actions)"
d=$(fresh uki_match)
BOOTED=20261030.1 run "$d"
check "golden good and same version: golden_ok true" true "$(jqf "$d" .golden_ok)"
check "golden good and same version: no action" '[]' "$(jqf "$d" .actions)"
check "golden good: golden_version" '"20261030.1"' "$(jqf "$d" .golden_version)"

# --- golden_full_check_interval ----------------------------------------------------------------------------------------------
stamp() { TZ=UTC date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || TZ=UTC date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
golden_call() { grep -F " $GH " "$1/vc.log" | grep -F "$1/gusr" | head -n 1; }
d=$(fresh full_3d)
printf '{"golden_full_checked_at":"%s"}' "$(stamp $((NOW - 3 * DAY)))" >"$d/var/integrity.json"
run "$d"
case "$(golden_call "$d")" in *--no-read*) r=no-read ;; *) r=full ;; esac
check "golden_full_check_interval: 3 days old -> --no-read" no-read "$r"
check "golden_full_check_interval: 3 days old -> timestamp kept" "\"$(stamp $((NOW - 3 * DAY)))\"" "$(jqf "$d" .golden_full_checked_at)"
d=$(fresh full_8d)
printf '{"golden_full_checked_at":"%s"}' "$(stamp $((NOW - 8 * DAY)))" >"$d/var/integrity.json"
run "$d"
case "$(golden_call "$d")" in *--no-read*) r=no-read ;; *--rate\ 150*) r=full-150 ;; *) r=full ;; esac
check "golden_full_check_interval: 8 days old -> full read at 150 MiB/s" full-150 "$r"
check "golden_full_check_interval: 8 days old -> timestamp renewed" "\"$(stamp "$NOW")\"" "$(jqf "$d" .golden_full_checked_at)"
d=$(fresh full_never)
run "$d"
check "golden_full_check_interval: never checked -> full read, timestamp set" "\"$(stamp "$NOW")\"" "$(jqf "$d" .golden_full_checked_at)"
d=$(fresh full_failed)
printf '{"golden_full_checked_at":"%s"}' "$(stamp $((NOW - 8 * DAY)))" >"$d/var/integrity.json"
EXTRA_ENV="STUB_VC_RC=1" run "$d"
check "full read failed: golden_ok false, old timestamp kept" "false \"$(stamp $((NOW - 8 * DAY)))\"" "$(jqf "$d" '[.golden_ok] | .[0]') $(jqf "$d" .golden_full_checked_at)"
check "active slot read at 150 MiB/s" yes "$([ "$(grep -c -- '--rate 150' "$d/vc.log")" -ge 1 ] && echo yes || echo no)"

# --- degrade on ENOKEY -------------------------------------------------------------------------------------------------------
d=$(fresh enokey_running)
sig_json "$d/gsig" "$RH"
echo "20261027.2 $RH" >"$d/gesp/MastersOS.efi"
EXTRA_ENV="STUB_VC_RC_SIGNED=3" run "$d"
check "ENOKEY with the running root hash: golden_ok via --no-sig" true "$(jqf "$d" .golden_ok)"
check "ENOKEY: notes records the degradation, error stays null" 'true null' "$(jqf "$d" '.notes | any(test("ENOKEY"))') $(jqf "$d" .error)"
d=$(fresh enokey_other)
EXTRA_ENV="STUB_VC_RC_SIGNED=3" run "$d"
check "ENOKEY with another root hash: golden not trusted" false "$(jqf "$d" .golden_ok)"

# --- no_golden ---------------------------------------------------------------------------------------------------------------
d=$(fresh no_golden)
printf '#!/bin/bash\necho "/dev/vda1 c12a7328-f81f-11d2-ba4b-00a0c93ec93b"\n' >"$d/lsblk-none"
chmod +x "$d/lsblk-none"
rc=0
env -i PATH="$bin:/usr/bin:/bin" HOME="$d" MASTERSOS_GOLDEN_LIB="$tmp/lib" MASTERSOS_ESP="$d/esp" MASTERSOS_SYSTEM_VAR="$d/var" \
	MASTERSOS_GOLDEN_LSBLK="$d/lsblk-none" MASTERSOS_ACTIVE_OK=1 MASTERSOS_IMAGE_VERSION=20261027.2 MASTERSOS_NOW="$NOW" \
	MASTERSOS_CMDLINE="$d/cmdline" VC_LOG="$d/vc.log" bash "$script" >"$d/log/out" 2>&1 || rc=$?
check "no_golden: exit 0" 0 "$rc"
check "no_golden: has_golden false" false "$(jqf "$d" .has_golden)"
check "no_golden: actions" '["report-only"]' "$(jqf "$d" .actions)"
check "no_golden: nothing was read" 0 "$(wc -l <"$d/vc.log" | tr -d ' ')"

# --- json_keeps_history ------------------------------------------------------------------------------------------------------
d=$(fresh history)
jq -nc '{repaired: [range(1; 13) | {at: ("2026-10-\(.)T00:00:00Z"), what: "usr", from: "golden"}]}' >"$d/var/integrity.json"
BOOTED=20261030.1 run "$d" # booted = golden: no action adds an entry
check "json_keeps_history: 10 entries" 10 "$(jqf "$d" '.repaired | length')"
check "json_keeps_history: the latest ones (3..12)" '3 12' "$(jq -r '.repaired | "\(.[0].at | split("-")[2] | split("T")[0] | tonumber) \(.[-1].at | split("-")[2] | split("T")[0] | tonumber)"' "$d/var/integrity.json")"
check "json_keeps_history: file mode 0644" 644 "$(stat -c %a "$d/var/integrity.json" 2>/dev/null || stat -f %Lp "$d/var/integrity.json")"
check "json_keeps_history: keys" "actions,active_ok,booted_version,checked_at,error,gave_up,golden_full_checked_at,golden_ok,golden_version,has_golden,notes,repaired" \
	"$(jq -r 'keys | join(",")' "$d/var/integrity.json")"
check "json_keeps_history: checked_at is RFC3339" "\"$(stamp "$NOW")\"" "$(jqf "$d" .checked_at)"

# --- rolled back: the golden copy is newer and can rebuild what is missing -----------------------------------------------------
d=$(fresh rollback)
mkdir -p "$d/esp/EFI/Linux"
printf '#!/bin/bash\n# disk listing for lsblk -nrpo NAME,PARTTYPE,PARTLABEL\necho "/dev/sda5 e7bb33fb-06cf-4e81-8273-e543b413e2e2 MastersOS_20261030.1_verity_sig"\necho "/dev/sda6 77ff5f63-e7b6-4633-acf4-1565b864c0e6 MastersOS_20261030.1_verity"\necho "/dev/sda7 8484680c-9521-48c6-9c11-b0720656f69e MastersOS_20261030.1"\n' >"$bin/lsblk"
chmod +x "$bin/lsblk"
for k in 5 6 7; do mkdir -p "$d/sys/class/block/sda$k" && echo "$k" >"$d/sys/class/block/sda$k/partition"; done
run "$d"
check "rolled back, newest UKI missing: restore-uki" true "$(jqf "$d" '.actions | index("restore-uki") != null')"
echo "20261030.1 $GH" >"$d/esp/EFI/Linux/MastersOS_20261030.1_x86-64+3.efi"
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys" run "$d"
check "rolled back, UKI and inactive slot fine: no action" '[]' "$(jqf "$d" .actions)"
rm -f "$bin/lsblk"

# --- notify_only_on_repair_request -------------------------------------------------------------------------------------------
want_en="System files need repair. This happens automatically the next time the computer restarts."
notify_case() { # notify_case <name> <LANG|-> -> case dir with a bad active slot, a golden copy of the running version
	local dd
	dd=$(fresh "$1")
	sig_json "$dd/gsig" "$RH"
	echo "20261027.2 $RH" >"$dd/gesp/MastersOS.efi"
	printf '1 c1 1000 alice seat0\n' >"$dd/sessions"
	echo "1: Active=yes Type=wayland Class=user Name=alice User=1000" >"$dd/session-info"
	echo "$dd"
}
d=$(notify_case notify_en)
ACTIVE=0 run "$d"
check "notify: request-repair in actions" true "$(jqf "$d" '.actions | index("request-repair") != null')"
check "notify: one call, English, MastersOS title, session bus of uid 1000" \
	"unix:path=/run/user/1000/bus|--app-name=MastersOS|--urgency=normal|MastersOS|$want_en|" "$(cat "$d/notify.log" | tr -d '\n')"
check "notify: exactly one notification" 1 "$(wc -l <"$d/notify.log" | tr -d ' ')"
d=$(notify_case notify_zh)
EXTRA_ENV="LANG=zh_CN.UTF-8" ACTIVE=0 run "$d"
check "notify: LANG=zh_CN.UTF-8 -> Chinese" "系统文件需要修复。下次重新启动电脑时会自动修复。" "$(cut -d'|' -f5 "$d/notify.log")"
d=$(notify_case notify_th)
echo 'LANG=th_TH.UTF-8' >"$d/locale.conf"
ACTIVE=0 run "$d"
check "notify: /etc/locale.conf th -> Thai" "ไฟล์ระบบต้องได้รับการซ่อมแซม ระบบจะซ่อมแซมให้อัตโนมัติเมื่อรีสตาร์ทคอมพิวเตอร์ครั้งถัดไป" "$(cut -d'|' -f5 "$d/notify.log")"
d=$(notify_case notify_nosession)
: >"$d/sessions"
rc=0
ACTIVE=0 run "$d" || rc=$?
check "notify: no session -> exit 0" 0 "$rc"
check "notify: no session -> no call" 0 "$(wc -l <"$d/notify.log" | tr -d ' ')"
d=$(notify_case notify_inactive)
printf '1 c1 1000 alice seat0\n2 c2 1000 alice seat0\n3 c3 1001 bob seat0\n' >"$d/sessions"
cat >"$d/session-info" <<'EOF'
1: Active=no Type=wayland Class=user Name=alice User=1000
2: Active=yes Type=tty Class=user Name=alice User=1000
3: Active=yes Type=x11 Class=user Name=bob User=1001
EOF
ACTIVE=0 run "$d"
check "notify: skips inactive and tty sessions, picks the active x11 one" "unix:path=/run/user/1001/bus" "$(cut -d'|' -f1 "$d/notify.log")"
d=$(fresh notify_none)
printf '1 c1 1000 alice seat0\n' >"$d/sessions"
echo "1: Active=yes Type=wayland Class=user Name=alice User=1000" >"$d/session-info"
ACTIVE=1 run "$d"
check "notify: not asked to repair (active slot good) -> no call" 0 "$(wc -l <"$d/notify.log" | tr -d ' ')"
d=$(notify_case notify_report)
printf '1 c1 1000 alice seat0\n' >"$d/sessions"
echo "$RH 2" >"$d/esp/EFI/MastersOS/repair-count"
ACTIVE=0 run "$d"
check "notify: gave up -> report-only, no call" '["report-only"] 0' "$(jqf "$d" .actions) $(wc -l <"$d/notify.log" | tr -d ' ')"

d=$(notify_case notify_greeter)
printf '1 c1 120 gdm seat0\n' >"$d/sessions"
echo "1: Active=yes Type=wayland Class=greeter Name=gdm-greeter User=120" >"$d/session-info"
ACTIVE=0 run "$d"
check "notify: active wayland greeter session (Class=greeter) -> no call" 0 "$(wc -l <"$d/notify.log" | tr -d ' ')"
check "notify: greeter only -> still request-repair recorded" true "$(jqf "$d" '.actions | index("request-repair") != null')"

d=$(notify_case notify_hang)
printf '#!/bin/bash\nexec sleep 30\n' >"$bin/notify-send.hang"
chmod +x "$bin/notify-send.hang"
rc=0
start=$SECONDS
EXTRA_ENV="MASTERSOS_NOTIFY=$bin/notify-send.hang MASTERSOS_NOTIFY_TIMEOUT=1" ACTIVE=0 run "$d" || rc=$?
check "notify: hung notify-send is cut off, script exits 0 within 10 s" "0 yes" "$rc $([ $((SECONDS - start)) -lt 10 ] && echo yes || echo no)"
check "notify: json written before the notification" true "$(jqf "$d" '.actions | index("request-repair") != null')"
rm -f "$bin/notify-send.hang"

d=$(fresh count_foreign)
echo "$GH 2" >"$d/esp/EFI/MastersOS/repair-count"
ACTIVE=1 run "$d"
check "repair-count of another root hash is left alone" "$GH 2" "$(cat "$d/esp/EFI/MastersOS/repair-count")"

d=$(fresh sig_empty)
sig_json "$d/gsig" -
run "$d"
check "golden signature area empty: note, error null, then refreshed (golden_ok true)" 'true null true' \
	"$(jqf "$d" '.notes | any(test("empty or invalid"))') $(jqf "$d" .error) $(jqf "$d" .golden_ok)"
check "notes is an empty array by default" '[]' "$(jqf "$tmp/uki_match" .notes)"

d=$(fresh boot_ok_rm_fails)
: >"$d/esp/EFI/MastersOS/boot-pending"
printf '#!/bin/bash\nexit 1\n' >"$bin/rm"
chmod +x "$bin/rm"
run "$d" --boot-ok || true
rm -f "$bin/rm"
check "boot_ok: rm failed -> no 'cleared' in the log, still exit 0" 'no' "$(grep -q 'boot-pending cleared' "$d/log/out" && echo yes || echo no)"

# --- the real (non-override) active-slot path: veritysetup status + slot_siblings + verity_check ---------------------------------
active_case() { # active_case <name> -> a machine whose active slot is sda2 (sig) / sda3 (hash) / sda4 (data) per stubs
	local dd
	dd=$(fresh "$1")
	mkdir -p "$dd/sys/class/block/sda4"
	echo 4 >"$dd/sys/class/block/sda4/partition"
	cat >"$bin/veritysetup" <<VEOF
#!/bin/bash
cat <<'OUT'
/dev/mapper/usr is active and is running.
  type:        VERITY
  data device: /dev/sda4
  hash device: /dev/sda3
  root hash:   $RH
OUT
VEOF
	cat >"$bin/lsblk" <<'LEOF'
#!/bin/bash
case "$*" in
"-no PKNAME /dev/sda4") echo sda ;;
"-no PARTTYPE /dev/sda2") echo e7bb33fb-06cf-4e81-8273-e543b413e2e2 ;;
"-no PARTTYPE /dev/sda3") echo 77ff5f63-e7b6-4633-acf4-1565b864c0e6 ;;
esac
LEOF
	chmod +x "$bin/veritysetup" "$bin/lsblk"
	sig_json "$dd/gsig" "$GH"
	echo "$dd"
}
real_active() { BOOTED=20261030.1 EXTRA_ENV="MASTERSOS_ACTIVE_OK= MASTERSOS_SYSFS=$1/sys ${2:-}" run "$1"; }
d=$(active_case active_real)
real_active "$d"
check "real active path: verity_check gets data, hash, sig partition, running root hash and --rate 150" \
	"/dev/sda4 /dev/sda3 /dev/sda2 $RH --rate 150" "$(grep -F '/dev/sda4' "$d/vc.log" | head -n 1)"
check "real active path: active_ok true, no error" 'true null' "$(jqf "$d" .active_ok) $(jqf "$d" .error)"
d=$(active_case active_bad)
real_active "$d" "STUB_VC_RC=1"
check "real active path: verity_check fails -> active_ok false, error null, note" 'false null true' \
	"$(jqf "$d" .active_ok) $(jqf "$d" .error) $(jqf "$d" '.notes | any(test("does not read clean"))')"
d=$(active_case active_enokey)
# golden copy of the running hash too, so it degrades the same way and no refresh-golden follows
sig_json "$d/gsig" "$RH"
echo "20261030.1 $RH" >"$d/gesp/MastersOS.efi"
real_active "$d" "STUB_VC_RC_SIGNED=3 VC_SIG_RH=$RH"
check "ENOKEY on the active slot, signature names the running hash: --no-sig retry, active_ok true, note" 'true null true' \
	"$(jqf "$d" .active_ok) $(jqf "$d" .error) $(jqf "$d" '.notes | any(test("ENOKEY"))')"
check "ENOKEY on the active slot: second call is --no-sig with --rate 150" "yes" \
	"$(grep -F '/dev/sda4' "$d/vc.log" | sed -n 2p | grep -qF -- '--no-sig --rate 150' && echo yes || echo no)"
d=$(active_case active_sigdiff)
real_active "$d" "STUB_VC_RC_SIGNED=3 VC_SIG_RH=$GH"
check "ENOKEY on the active slot, signature names another hash: active_ok false" false "$(jqf "$d" .active_ok)"
rm -f "$bin/veritysetup" "$bin/lsblk"

# --- active slot location (veritysetup status stub) --------------------------------------------------------------------------
d=$(fresh active_status)
cat >"$bin/veritysetup" <<EOF
#!/bin/bash
cat <<'OUT'
/dev/mapper/usr is active and is running.
  type:        VERITY
  data device: /dev/nonexistent7
  hash device: /dev/nonexistent6
  root hash:   $RH
OUT
EOF
chmod +x "$bin/veritysetup"
rc=0
EXTRA_ENV="MASTERSOS_ACTIVE_OK=" run "$d" || rc=$?
check "active slot not locatable -> exit 0, report-only" '0 ["report-only"]' "$rc $(jqf "$d" .actions)"
check "active slot not locatable -> error names it" true "$(jqf "$d" '.error | test("signature partition")')"
rm -f "$bin/veritysetup"

# --- actions (Task 5) ----------------------------------------------------------------------------------------------------------
# fn <case-dir> <code>: sources the stub library and integrity (functions only) in a clean environment and runs <code> with
# RUNHASH and the case's golden files set; dd and verity_check calls go to <case>/ev.log in order; output in <case>/log/fn
fn() {
	local d=$1 extra=()
	read -ra extra <<<"${EXTRA_ENV:-}"
	: >"$d/ev.log"
	env -i PATH="$bin:/usr/bin:/bin" HOME="$d" VC_LOG="$d/ev.log" DD_LOG="$d/ev.log" MASTERSOS_DD="$bin/dd-rec" \
		MASTERSOS_WHOLE_DISK="$d/disk" MASTERSOS_MOK_DER="$tmp/mok.der" MASTERSOS_GOLDEN_ESP_DIR="$d/gesp" \
		EV_GESP="$d/gesp" EV_GSIG="$d/gsig" D="$d" RH="$RH" GH="$GH" MASTERSOS_NOW="$NOW" "${extra[@]}" \
		bash -c '. "$1"; . "$2"; NOW=$MASTERSOS_NOW RUNHASH=$RH GSIG=$D/gsig GVERITY=$D/gverity GUSR=$D/gusr
			rc=0; eval "$3" || rc=$?; echo "rc=$rc"' _ "$tmp/lib" "$script" "$2" >"$d/log/fn" 2>&1
}
fnrc() { sed -n 's/^rc=//p' "$1/log/fn" | tail -n 1; }
# events <log>: dd lines as "dd <if>><of> <count|all> <lock>", verity_check lines as "vc <data> <sig> <flags>", state lines as is
events() {
	local w a src dst cnt
	while read -ra w; do
		case ${w[0]} in
		dd)
			src="" dst="" cnt=all
			for a in "${w[@]}"; do
				case $a in if=*) src=${a#if=} ;; of=*) dst=${a#of=} ;; count=*) cnt=${a#count=} ;; esac
			done
			echo "dd ${src##*/}>${dst##*/} $cnt ${w[-1]#lock=}"
			;;
		state) echo "${w[*]//$RH/RH}" ;;
		*) echo "vc ${w[0]##*/} ${w[2]##*/} ${w[*]:4}" ;;
		esac
	done <"$1"
}
zeroed() { [ "$(tr -d '\0' <"$1" | wc -c | tr -d ' ')" = 0 ] && echo yes || echo no; }
booted_uki='"$D/esp/EFI/Linux/MastersOS_20261027.2_x86-64.efi"'

# golden_refresh_order
d=$(fresh refresh_order)
fn "$d" "golden_refresh \"\$D/asig\" \"\$D/averity\" \"\$D/ausr\" $booted_uki"
check "golden_refresh_order: rc 0" 0 "$(fnrc "$d")"
check "golden_refresh_order: sig zeroed, usr up to erofs_bytes, whole verity, UKI+manifest, full verify with the active sig, sig last" \
	"dd zero>gsig 1 held|dd ausr>gusr 12288 held|dd averity>gverity all held|state gesp=MastersOS.efi,manifest, gsig=none|vc gusr asig --rate 150|dd asig>gsig 1 held" \
	"$(events "$d/ev.log" | paste -sd'|' -)"
check "golden_refresh_order: golden copy equals the active slot" "same same same" \
	"$(cmp -s -n 12288 "$d/ausr" "$d/gusr" && echo same || echo diff) $(cmp -s "$d/averity" "$d/gverity" && echo same || echo diff) $(cmp -s "$d/asig" "$d/gsig" && echo same || echo diff)"
check "golden_refresh_order: golden ESP has the booted UKI and manifest" \
	"same version=20261027.2 sha256=$(sha256sum <"$d/esp/EFI/Linux/MastersOS_20261027.2_x86-64.efi" | cut -d' ' -f1)" \
	"$(cmp -s "$d/esp/EFI/Linux/MastersOS_20261027.2_x86-64.efi" "$d/gesp/MastersOS.efi" && echo same || echo diff) $(cat "$d/gesp/manifest")"
news() { find "$1" -name '*.new' -printf '%f\n'; }
check "golden_refresh_order: no .new left on the golden ESP" "" "$(news "$d/gesp")"

# golden_refresh_verify_fails
d=$(fresh refresh_verify_fails)
EXTRA_ENV="STUB_VC_RC=1" fn "$d" "golden_refresh \"\$D/asig\" \"\$D/averity\" \"\$D/ausr\" $booted_uki"
check "golden_refresh_verify_fails: rc != 0, golden sig still zero, never written" "yes yes 0" \
	"$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(zeroed "$d/gsig") $(grep -c '^dd if=.*asig ' "$d/ev.log" || true)"

# golden_refresh_refuses_bad_active_sig
d=$(fresh refresh_bad_sig)
sig_json "$d/asig" "$GH"
fn "$d" "golden_refresh \"\$D/asig\" \"\$D/averity\" \"\$D/ausr\" $booted_uki"
check "golden_refresh_refuses_bad_active_sig: rc != 0, nothing written" "yes 0" \
	"$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(grep -c '^dd ' "$d/ev.log" || true)"

# golden_refresh_interrupted
d=$(fresh refresh_interrupted)
EXTRA_ENV="DD_FAIL_OF=$d/gusr" fn "$d" "golden_refresh \"\$D/asig\" \"\$D/averity\" \"\$D/ausr\" $booted_uki"
check "golden_refresh_interrupted: rc != 0, golden sig zero" "yes yes" "$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(zeroed "$d/gsig")"
d=$(fresh refresh_interrupted_main)
sig_json "$d/gsig" -
EXTRA_ENV="DD_FAIL_OF=$d/gusr" run "$d"
check "golden_refresh_interrupted (main): actions, error set, golden_ok false, golden sig zero" \
	'["refresh-golden"] true false yes' "$(jqf "$d" .actions) $(jqf "$d" '.error | test("refresh-golden")') $(jqf "$d" .golden_ok) $(zeroed "$d/gsig")"

# refresh-golden from main: the JSON shows the refreshed copy; the next run has nothing to do
d=$(fresh refresh_main)
sig_json "$d/gsig" -
run "$d"
check "refresh-golden (main): golden_ok, golden_version, full check time, error null" \
	"true \"20261027.2\" \"$(stamp "$NOW")\" null" "$(jqf "$d" .golden_ok) $(jqf "$d" .golden_version) $(jqf "$d" .golden_full_checked_at) $(jqf "$d" .error)"
check "refresh-golden (main): repaired entry" '{"what":"golden","from":"active"}' "$(jqf "$d" '.repaired[-1] | {what, from}')"
run "$d"
check "refresh-golden (main): second run golden_ok, no actions, history kept" 'true [] 1' \
	"$(jqf "$d" .golden_ok) $(jqf "$d" .actions) $(jqf "$d" '.repaired | length')"

# restore_uki_names
cat >"$bin/mv" <<'EOF'
#!/bin/bash
[ -z "${MV_LOG:-}" ] || echo "$*" >>"$MV_LOG"
exec /bin/mv "$@"
EOF
chmod +x "$bin/mv"
d=$(fresh restore_uki_missing)
rm -f "$d/esp/EFI/Linux/"*
EXTRA_ENV="MV_LOG=$d/mv.log" fn "$d" 'restore_uki "$D/esp" "$D/gesp/MastersOS.efi"'
check "restore_uki_names: missing -> MastersOS_<v>_x86-64.efi without a counter, same bytes" "0 MastersOS_20261030.1_x86-64.efi same" \
	"$(fnrc "$d") $(ls "$d/esp/EFI/Linux") $(cmp -s "$d/gesp/MastersOS.efi" "$d/esp/EFI/Linux/MastersOS_20261030.1_x86-64.efi" && echo same || echo diff)"
check "restore_uki_names: written as .new then renamed" yes \
	"$(grep -qxF -- "-f $d/esp/EFI/Linux/MastersOS_20261030.1_x86-64.efi.new $d/esp/EFI/Linux/MastersOS_20261030.1_x86-64.efi" "$d/mv.log" && echo yes || echo no)"
d=$(fresh restore_uki_present)
echo "20261030.1 $GH" >"$d/esp/EFI/Linux/MastersOS_20261030.1_x86-64+1-2.efi"
fn "$d" 'restore_uki "$D/esp" "$D/gesp/MastersOS.efi"; echo "repaired=${#REPAIRED[@]}"'
check "restore_uki_names: a verifying +1-2 copy exists -> nothing written" "0 no repaired=0" \
	"$(fnrc "$d") $([ -e "$d/esp/EFI/Linux/MastersOS_20261030.1_x86-64.efi" ] && echo yes || echo no) $(grep '^repaired=' "$d/log/fn")"
d=$(fresh restore_uki_bad)
echo "20261030.1 2222222222222222222222222222222222222222222222222222222222222222" >"$d/esp/EFI/Linux/MastersOS_20261030.1_x86-64+1-2.efi"
fn "$d" 'restore_uki "$D/esp" "$D/gesp/MastersOS.efi"'
check "restore_uki_names: a damaged copy of that version is replaced by the golden UKI" "0 MastersOS_20261027.2_x86-64.efi MastersOS_20261030.1_x86-64.efi" \
	"$(fnrc "$d") $(find "$d/esp/EFI/Linux" -mindepth 1 -printf '%f\n' | sort | paste -sd' ' -)"
rm -f "$bin/mv"

# restore_inactive_writes
inactive_case() { # inactive_case <name> -> golden files of version 20261030.1 ($GH) and a damaged inactive slot isig/iverity/iusr
	local dd
	dd=$(fresh "$1")
	sig_json "$dd/gsig" "$GH"
	head -c 8192 /dev/urandom >"$dd/gverity"
	mkerofs "$dd/gusr" 3 16384
	head -c 16384 /dev/urandom >"$dd/isig"
	head -c 8192 /dev/urandom >"$dd/iverity"
	head -c 16384 /dev/urandom >"$dd/iusr"
	echo "$dd"
}
d=$(inactive_case restore_inactive)
EXTRA_ENV="EV_GESP=" fn "$d" 'restore_inactive "$D/isig" "$D/iverity" "$D/iusr"'
check "restore_inactive_writes: rc 0" 0 "$(fnrc "$d")"
check "restore_inactive_writes: sig zeroed first, usr up to erofs_bytes, verity, verify with the golden sig, sig last" \
	"dd zero>isig 1 held|dd gusr>iusr 12288 held|dd gverity>iverity all held|vc iusr gsig --rate 150|dd gsig>isig 1 held" \
	"$(events "$d/ev.log" | paste -sd'|' -)"
check "restore_inactive_writes: targets equal the golden files" "same same same" \
	"$(cmp -s -n 12288 "$d/gusr" "$d/iusr" && echo same || echo diff) $(cmp -s "$d/gverity" "$d/iverity" && echo same || echo diff) $(cmp -s -n 16384 "$d/gsig" "$d/isig" && echo same || echo diff)"
d=$(inactive_case restore_inactive_active)
EXTRA_ENV="EV_GESP=" fn "$d" 'A_USR=$D/iusr; restore_inactive "$D/isig" "$D/iverity" "$D/iusr"'
check "restore_inactive: refuses to write the active slot" "yes 0" "$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(grep -c '^dd ' "$d/ev.log" || true)"
d=$(inactive_case restore_inactive_verify_fails)
EXTRA_ENV="EV_GESP= STUB_VC_RC=1" fn "$d" 'restore_inactive "$D/isig" "$D/iverity" "$D/iusr"'
check "restore_inactive: verify fails -> rc != 0, slot sig left zero" "yes yes" "$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(zeroed "$d/isig")"

# restore-inactive from main, under /run/mastersos-slots.lock (MASTERSOS_SLOTS_LOCK): rolled back to 20261027.2, the golden
# 20261030.1 is good, its UKI is missing from the ESP and its slot (files isig/iverity/iusr, found by label) is damaged
SIGT=e7bb33fb-06cf-4e81-8273-e543b413e2e2 VERT=77ff5f63-e7b6-4633-acf4-1565b864c0e6 USRT=8484680c-9521-48c6-9c11-b0720656f69e
# slots_case <name> [<label prefix>] [<sig type> <verity type>] [<sig> <verity> <usr> partition numbers]: the lsblk stub labels
# the slot <prefix> (default MastersOS_20261030.1); the types default to systemd's usr-verity-sig / usr-verity, the numbers to 5 6 7
slots_case() {
	local dd p=${2:-MastersOS_20261030.1} st=${3:-$SIGT} vt=${4:-$VERT} ns=${5:-5} nv=${6:-6} nu=${7:-7}
	dd=$(inactive_case "$1")
	printf '#!/bin/bash\n# lsblk -nrpo NAME,PARTTYPE,PARTLABEL\necho "%s %s %s_verity_sig"\necho "%s %s %s_verity"\necho "%s %s %s"\n' \
		"$dd/isig" "$st" "$p" "$dd/iverity" "$vt" "$p" "$dd/iusr" "$USRT" "$p" >"$bin/lsblk"
	chmod +x "$bin/lsblk"
	mkdir -p "$dd/sys/class/block/isig" "$dd/sys/class/block/iverity" "$dd/sys/class/block/iusr"
	echo "$ns" >"$dd/sys/class/block/isig/partition"
	echo "$nv" >"$dd/sys/class/block/iverity/partition"
	echo "$nu" >"$dd/sys/class/block/iusr/partition"
	echo "$dd"
}
uki_restored() { [ -f "$1/esp/EFI/Linux/MastersOS_20261030.1_x86-64.efi" ] && echo yes || echo no; }
d=$(slots_case slots_free)
# fails in the check and again in the re-check inside the lock, then verifies after the restore
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys STUB_VC_FAIL_ONCE=$d/iusr STUB_VC_FAIL_TIMES=2 SLOTS_LOG=$d/slots.log" run "$d"
check "restore-inactive, lock free: both actions ran (inactive first), slot equals golden, error null" \
	'["restore-inactive","restore-uki"] ["inactive","uki"] same null' \
	"$(jqf "$d" .actions) $(jqf "$d" '[.repaired[].what]') $(cmp -s -n 12288 "$d/gusr" "$d/iusr" && echo same || echo diff) $(jqf "$d" .error)"
check "restore-inactive, lock free: every slot write holds the slots lock" "isig held|iusr held|iverity held|isig held" \
	"$(paste -sd'|' - <"$d/slots.log")"
d=$(slots_case slots_recheck_ok)
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys STUB_VC_FAIL_ONCE=$d/iusr" run "$d"
check "restore-inactive: slot verifies on the re-check inside the lock -> not written, no entry, error null" \
	'0 ["uki"] null' "$(grep -c 'of=.*/iusr ' "$d/dd.log" || true) $(jqf "$d" '[.repaired[].what]') $(jqf "$d" .error)"
d=$(slots_case slots_nolabel_free _empty)
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys" run "$d"
check "restore-inactive, lock free, no slot labelled with the golden version -> error" true \
	"$(jqf "$d" '.error | test("no slot labelled MastersOS_20261030.1")')"
# a blessed UKI without its /usr slot would be picked by systemd-boot on every boot and never find /usr: a reboot loop
check "restore-uki, no slot of the golden version on the disk -> no UKI written, note, no uki entry" 'no true []' \
	"$(uki_restored "$d") $(jqf "$d" '.notes | any(test("restore-uki: no slot of 20261030.1"))') $(jqf "$d" '[.repaired[].what]')"
# the slot's partitions must carry the slot types and sit in sig/verity/usr order, as the initrd's slot_siblings checks
d=$(slots_case slots_wrong_type "" 0fc63daf-8483-4772-8e79-3d69d8477de4)
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys" run "$d"
check "inactive slot whose sig partition has another GPT type: not a slot, nothing written, no UKI" "true 0 no" \
	"$(jqf "$d" '.error | test("no slot labelled MastersOS_20261030.1")') $(grep -c '^dd ' "$d/dd.log" || true) $(uki_restored "$d")"
d=$(slots_case slots_wrong_order "" "" "" 5 7 6)
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys" run "$d"
check "inactive slot not in sig/verity/usr order: not a slot, nothing written, no UKI" "true 0 no" \
	"$(jqf "$d" '.error | test("no slot labelled MastersOS_20261030.1")') $(grep -c '^dd ' "$d/dd.log" || true) $(uki_restored "$d")"
# an update running: sysupdate has relabelled the slot _empty and holds the lock (here: another open file description)
d=$(slots_case slots_busy _empty)
before=$(sha256sum <"$d/iusr")
exec {held}>>"$d/slots.lock"
flock -n "$held"
EXTRA_ENV="MASTERSOS_BOOT_DISK=/dev/sda MASTERSOS_SYSFS=$d/sys" run "$d"
exec {held}>&-
check "restore-inactive, lock busy, slot labelled _empty: skipped with a note, no error, slot untouched, no entry" \
	'true null unchanged []' \
	"$(jqf "$d" '.notes | any(test("inactive slot busy"))') $(jqf "$d" .error) $([ "$(sha256sum <"$d/iusr")" = "$before" ] && echo unchanged || echo changed) $(jqf "$d" '[.repaired[].what]')"
# sysupdate's UKI transfer writes EFI/Linux under the same lock: restore-uki waits for the next boot too
check "restore-uki, lock busy: skipped with a note, no UKI written" "no true" \
	"$(uki_restored "$d") $(jqf "$d" '.notes | any(test("UKI restore skipped"))')"
rm -f "$bin/lsblk"

# golden version unreadable: never refresh or fetch over a copy that may be newer
d=$(fresh version_unknown)
before=$(sha256sum <"$d/gsig")
EXTRA_ENV="MASTERSOS_GOLDEN_ESP_DIR=$d/no-such-esp" run "$d"
check "golden ESP unmountable, golden root hash not the running one, active good: report-only, note, no dd, golden sig untouched" \
	'["report-only"] true 0 unchanged' \
	"$(jqf "$d" .actions) $(jqf "$d" '.notes | any(test("version unreadable"))') $(grep -c '^dd ' "$d/dd.log" || true) $([ "$(sha256sum <"$d/gsig")" = "$before" ] && echo unchanged || echo changed)"
d=$(fresh version_unknown_bad)
EXTRA_ENV="MASTERSOS_GOLDEN_ESP_DIR=$d/no-such-esp" ACTIVE=0 run "$d"
check "golden ESP unmountable, active bad: no network (golden-fetch unit not started), report-only" '["report-only"] no' \
	"$(jqf "$d" .actions) $([ -s "$d/systemctl.log" ] && echo yes || echo no)"
d=$(fresh version_unknown_running)
sig_json "$d/gsig" "$RH"
EXTRA_ENV="MASTERSOS_GOLDEN_ESP_DIR=$d/no-such-esp" run "$d"
check "golden ESP unmountable, golden of the running root hash: refresh-golden allowed, fails in pre-flight before any dd" \
	'["refresh-golden"] 0 true' \
	"$(jqf "$d" .actions) $(grep -c '^dd ' "$d/dd.log" || true) $(jqf "$d" '.error | test("golden ESP read-write")')"

# golden_refresh pre-flight: the golden ESP is mounted read-write before the golden sig is zeroed
d=$(fresh refresh_preflight)
before=$(sha256sum <"$d/gsig")
EXTRA_ENV="MASTERSOS_GOLDEN_ESP_DIR=$d/no-such-esp EV_GESP=" fn "$d" "golden_refresh \"\$D/asig\" \"\$D/averity\" \"\$D/ausr\" $booted_uki"
check "golden_refresh: golden ESP does not mount -> rc != 0, no dd, golden sig untouched" "yes 0 unchanged" \
	"$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(grep -c '^dd ' "$d/ev.log" || true) $([ "$(sha256sum <"$d/gsig")" = "$before" ] && echo unchanged || echo changed)"

# the sig write breaks off: golden sig zeroed again
d=$(fresh refresh_sig_write_fails)
EXTRA_ENV="DD_FAIL_IF=$d/asig" fn "$d" "golden_refresh \"\$D/asig\" \"\$D/averity\" \"\$D/ausr\" $booted_uki"
check "golden_refresh: sig write fails -> rc != 0, sig zeroed again (last write is the zeroing)" "yes yes dd zero>gsig 1 held" \
	"$([ "$(fnrc "$d")" != 0 ] && echo yes || echo no) $(zeroed "$d/gsig") $(events "$d/ev.log" | tail -n 1)"

# request_repair_file
d=$(fresh request_file)
fn "$d" 'request_repair "$D/esp" 8e23106e-ae00-986c-afdf-5579681645ec "$RH"'
check "request_repair_file: exactly '<partuuid> <roothash>\\n', no .new left" "0 same " \
	"$(fnrc "$d") $(printf '8e23106e-ae00-986c-afdf-5579681645ec %s\n' "$RH" | cmp -s - "$d/esp/EFI/MastersOS/repair-usr" && echo same || echo diff) $(news "$d/esp/EFI/MastersOS")"
d=$(notify_case request_main)
ACTIVE=0 run "$d"
check "request-repair (main): repair-usr names the PARTUUID derived from the running root hash" "8e23106e-ae00-986c-afdf-5579681645ec $RH" \
	"$(cat "$d/esp/EFI/MastersOS/repair-usr")"

# network: integrity only starts mastersos-golden-fetch.service (the download waits for the network in that unit)
net_case() { # net_case <name> -> active slot bad, golden copy empty
	local dd
	dd=$(fresh "$1")
	sig_json "$dd/gsig" -
	echo "$dd"
}
d=$(net_case net_start)
ACTIVE=0 run "$d"
check "network: starts mastersos-golden-fetch.service --no-block, nothing else" '["network"] start --no-block mastersos-golden-fetch.service|' \
	"$(jqf "$d" .actions) $(tr '\n' '|' <"$d/systemctl.log")"
check "network: no repaired entry, no repair-usr yet, golden_ok false, error null, note says the fetch started" "0 no false null true" \
	"$(jqf "$d" '[.repaired[] | select(.from == "network")] | length') $([ -e "$d/esp/EFI/MastersOS/repair-usr" ] && echo yes || echo no) $(jqf "$d" .golden_ok) $(jqf "$d" .error) $(jqf "$d" '.notes | any(test("mastersos-golden-fetch.service started"))')"
check "network: no dd write" 0 "$(grep -c . "$d/dd.log" || true)"
# golden-fetch --booted leaves a /run marker before it starts integrity again: when that re-run still finds the golden copy
# bad (flaky hardware), it must not start another 1.66 GB download in the same boot
d=$(net_case net_fetched_this_boot)
: >"$d/golden-fetched"
ACTIVE=0 run "$d"
check "network: golden copy already fetched this boot -> not started again, note, error null" '["network"] none true null' \
	"$(jqf "$d" .actions) $([ -s "$d/systemctl.log" ] && echo started || echo none) $(jqf "$d" '.notes | any(test("already fetched"))') $(jqf "$d" .error)"
d=$(net_case net_systemctl_fails)
printf '#!/bin/bash\necho "$*" >>"$SYSTEMCTL_LOG"\nexit 1\n' >"$d/systemctl-fail"
chmod +x "$d/systemctl-fail"
EXTRA_ENV="MASTERSOS_SYSTEMCTL=$d/systemctl-fail" ACTIVE=0 run "$d"
check "network: the unit cannot be started -> error" true "$(jqf "$d" '.error | test("mastersos-golden-fetch.service")')"

# every write: conv=fsync and the whole-disk lock held
all_dd=$(cat "$tmp"/*/dd.log "$tmp"/*/ev.log 2>/dev/null | grep '^dd ' || true)
check "all dd writes: some recorded" yes "$([ -n "$all_dd" ] && echo yes || echo no)"
check "all dd writes: every one has conv=fsync and holds the lock" "" \
	"$(printf '%s\n' "$all_dd" | grep -v -e 'conv=fsync.* lock=held$' || true)"

echo "integrity-test: $((n - fails))/$n passed"
[ "$fails" = 0 ]

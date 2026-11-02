#!/bin/bash
# initrd 里恢复出厂确认（mkosi.initrd.conf/…/factory-reset-confirm，Ruling 22）的分支（本机与 CI 都跑，不要 root、不要 VM）：
#   bash image/tests/factory-reset-confirm-test.sh
# source 被测脚本，把它的路径变量指到临时目录，PATH 上的 lsblk、mount、umount、cryptsetup、systemd-ask-password、
# udevadm 换成桩。桩从 $STATE 下的文件读「用户输入」与「TPM / 分区 / LUKS 的状态」，把收到的命令行记进 $STATE/log。
# 桩的正文与 eval 的条件要原样写进去、到运行时才展开（SC2016）；路径变量是给 source 进来的脚本用的（SC2034）。
# shellcheck disable=SC2016,SC2034
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/factory-reset-confirm

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bin=$tmp/bin
mkdir -p "$bin"
export STATE=$tmp/state

# 正确的恢复密钥（systemd-cryptenroll 的格式：64 个 modhex 字母，每 8 个一组）
KEY=cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-ddeeffgg-hhiijjkk-llnnrrtt-uuvvccbb

stub() { # stub <名字> <脚本正文>
	printf '#!/usr/bin/env bash\nset -u\n%s\n' "$2" >"$bin/$1"
	chmod +x "$bin/$1"
}

stub udevadm 'echo "udevadm $*" >>"$STATE/log"'
stub lsblk 'echo "lsblk $*" >>"$STATE/log"
case "$*" in
"-no PKNAME "*) [ -e "$STATE/no-disk" ] && exit 1; echo vda ;;
"-nrpo NAME,PARTLABEL /dev/vda") cat "$STATE/parts" ;;
"-nrpo NAME,PARTTYPE /dev/vda") [ -e "$STATE/parttype-fails" ] && exit 1; cat "$STATE/parttypes" ;;
*) exit 1 ;;
esac'
stub mount 'echo "mount $*" >>"$STATE/log"
[ -e "$STATE/mount-fails" ] && exit 32
dir=${!#}
[ -e "$STATE/seed-toml" ] && : >"$dir/seed.toml"
exit 0'
stub umount 'echo "umount $*" >>"$STATE/log"; rm -f "$1/seed.toml"'
stub cryptsetup 'echo "cryptsetup $*" >>"$STATE/log"
case "$1" in
isLuks)
	[ -e "$STATE/isluks-rc" ] && exit "$(cat "$STATE/isluks-rc")"
	[ -e "$STATE/luks" ] || exit 1 ;;
luksDump)
	if [ -e "$STATE/recovery" ]; then
		echo "{\"keyslots\":{},\"tokens\":{\"0\":{\"type\":\"systemd-tpm2\"},\"1\":{\"type\":\"systemd-recovery\",\"keyslots\":[\"1\"]}}}"
	else
		echo "{\"keyslots\":{},\"tokens\":{\"0\":{\"type\":\"systemd-tpm2\"}}}"
	fi ;;
open)
	key=$(cat; printf x); key=${key%x}
	printf "%s" "$key" >>"$STATE/keys-tried"; echo >>"$STATE/keys-tried"
	[ "$key" = "$(cat "$STATE/key")" ] ;;
*) exit 1 ;;
esac'
# 每问一次取 answers 的下一行；答完了就是超时（退出 1）
stub systemd-ask-password 'n=$(( $(cat "$STATE/asked" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$STATE/asked"
id=""; for a; do case $a in --id=*) id=${a#--id=} ;; esac; done
echo "ask $id" >>"$STATE/log"
mapfile -t ans <"$STATE/answers"
[ "$n" -le "${#ans[@]}" ] || exit 1
printf "%s\n" "${ans[n - 1]}"'
stub factory-reset 'echo "factory-reset $*" >>"$STATE/log"
rc=$(cat "$STATE/complete-rc" 2>/dev/null || echo 0)
[ "$rc" = 0 ] && : >"$STATE/complete-flag"
exit "$rc"'
stub tpm-probe 'echo "tpm-probe" >>"$STATE/log"
rc=$(cat "$STATE/tpm-rc" 2>/dev/null || echo 0)
[ "$rc" = 1 ] && echo "没有 TPM 2.0 / No TPM 2.0"
exit "$rc"'

# shellcheck disable=SC1090 # 被测的脚本，路径相对本文件
. "$script"
PATH=$bin:$PATH
FACTORY_RESET=$bin/factory-reset
TPM_PROBE=$bin/tpm-probe
ROOT_LUKS=$tmp/root-luks
ROOT_LUKS_FR=$tmp/root-luks-ignore-factory-reset
SEED_MNT=$tmp/run/mastersos/seed-check
EFIVARS=$tmp/efivars
COMPLETE_FLAG=$STATE/complete-flag

fails=0 n=0
out=""
rc=0

# fresh：一台受管、根分区是带恢复 token 的 LUKS、TPM 能用的机器；各用例再改
fresh() {
	rm -rf "$STATE" "$tmp/run" "$EFIVARS" "$ROOT_LUKS" "$ROOT_LUKS_FR"
	mkdir -p "$STATE" "$EFIVARS"
	: >"$STATE/log"
	: >"$STATE/answers"
	# 恢复出厂模式下 udev 只建 root-luks-ignore-factory-reset，不建 root-luks（VM 165 实测）
	: >"$ROOT_LUKS_FR"
	# GPT 类型：ESP、usr-verity-sig、usr-verity、usr、种子（Linux data）、根（x86-64 root）
	printf '/dev/vda1 c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n/dev/vda2 e7bb33fb-06cf-4e81-8273-e543b413e2e2\n/dev/vda3 77ff5f63-e7b6-4633-acf4-1565b864c0e6\n/dev/vda4 8484680c-9521-48c6-9c11-b0720656f69e\n/dev/vda5 0fc63daf-8483-4772-8e79-3d69d8477de4\n/dev/vda9 4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709\n' >"$STATE/parttypes"
	printf '%s' "$KEY" >"$STATE/key"
	printf '/dev/vda1 esp\n/dev/vda2 usr\n/dev/vda3 mastersos-seed\n/dev/vda4 root\n' >"$STATE/parts"
	: >"$STATE/seed-toml"
	: >"$STATE/luks"
	: >"$STATE/recovery"
}

# 启动所在的 ESP（EFI 变量：4 字节属性 + UTF-16LE 的 PARTUUID）：没有根分区链接时从它找磁盘
esp_var() {
	printf '\x07\x00\x00\x00' >"$EFIVARS/$LOADER_PART_VAR"
	printf 'AB12CD34-0000-4000-8000-00000000AA01' | sed 's/./&\x00/g' >>"$EFIVARS/$LOADER_PART_VAR"
}

answers() { # 每个参数一行；不给参数时一个回答都没有
	: >"$STATE/answers"
	[ $# = 0 ] || printf '%s\n' "$@" >"$STATE/answers"
}

run_main() {
	rc=0
	out=$( (main) 2>&1) || rc=$?
}

check() { # check <用例> <条件说明> <命令…>
	local name=$1 what=$2
	shift 2
	if "$@"; then
		return 0
	fi
	echo "FAIL ${name}：${what}" >&2
	echo "  退出码 ${rc}；输出：" >&2
	printf '%s\n' "$out" | sed 's/^/    /' >&2
	echo "  命令：" >&2
	sed 's/^/    /' "$STATE/log" >&2
	return 1
}

logged() { grep -q -- "$1" "$STATE/log"; }
not_logged() { ! grep -q -- "$1" "$STATE/log"; }
asks() { grep '^ask ' "$STATE/log" | sed 's/^ask //' | tr '\n' ' '; }

case_() { # case_ <名字> <函数>
	local name=$1 ok=0
	fresh
	"$2" "$name" || ok=1
	n=$((n + 1))
	if [ "$ok" = 0 ]; then echo "ok   $name"; else fails=$((fails + 1)); fi
}

unmanaged_erase_proceeds() {
	rm "$STATE/seed-toml"
	answers erase
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "没调 complete" not_logged "^factory-reset " &&
		check "$1" "只问了 ERASE" [ "$(asks)" = "mastersos-factory-reset " ] &&
		check "$1" "未受管时不碰 LUKS" not_logged "cryptsetup"
}

unmanaged_wrong_word_keeps_data() {
	rm "$STATE/seed-toml"
	answers yes
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "调了 complete --retrigger" logged "^factory-reset complete --retrigger"
}

managed_right_key_and_erase_proceeds() {
	answers " CBDEFGHI JKLNRTUV-cbdefghi jklnrtuv ddeeffgghhiijjkk LLNNRRTT-UUVVCCBB " ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "没调 complete" not_logged "^factory-reset " &&
		check "$1" "先问密钥再问 ERASE" [ "$(asks)" = "mastersos-factory-reset-key mastersos-factory-reset " ] &&
		check "$1" "cryptsetup 带 --disable-external-tokens 与 --key-file=-" \
			logged "cryptsetup open --test-passphrase --disable-external-tokens --key-file=- $ROOT_LUKS_FR" &&
		check "$1" "命令行里没有密钥" not_logged "cbdefghi" &&
		check "$1" "命令行里没有密钥（大写）" not_logged "CBDEFGHI" &&
		check "$1" "交给 cryptsetup 的是规范化的密钥、不带换行" [ "$(cat "$STATE/keys-tried")" = "$KEY" ] &&
		check "$1" "输出里没有密钥" eval '! grep -qi cbdefghi <<<"$out"' &&
		check "$1" "种子分区只读挂载、带 nosuid,nodev,noexec" \
			logged "mount -t ext4 -o ro,nosuid,nodev,noexec /dev/vda3 $SEED_MNT" &&
		check "$1" "卸载了" logged "umount $SEED_MNT"
}

managed_wrong_key_keeps_data() {
	answers wrong-1 wrong-2 wrong-3 ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "问了三次密钥、没问 ERASE" \
			[ "$(asks)" = "mastersos-factory-reset-key mastersos-factory-reset-key mastersos-factory-reset-key " ]
}

managed_right_key_wrong_word_keeps_data() {
	answers "$KEY" yes
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "问了密钥与 ERASE" [ "$(asks)" = "mastersos-factory-reset-key mastersos-factory-reset " ]
}

managed_key_timeout_keeps_data() {
	answers # 一个回答都没有：超时
	run_main
	check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "超时一次就不再问" [ "$(asks)" = "mastersos-factory-reset-key " ]
}

managed_no_recovery_slot_refuses() {
	rm "$STATE/recovery"
	answers "$KEY" ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "说明怎么办" eval 'grep -q "No escrowed recovery key yet" <<<"$out"'
}

managed_no_luks_asks_erase() {
	rm "$ROOT_LUKS_FR"
	# 盘上没有根分区类型的分区（各分区的类型都读得到）
	printf '/dev/vda1 c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n/dev/vda5 0fc63daf-8483-4772-8e79-3d69d8477de4\n' >"$STATE/parttypes"
	# 根分区不存在：从启动所在的 ESP 找磁盘（EFI 变量：4 字节属性 + UTF-16LE 的 UUID）
	printf '\x07\x00\x00\x00' >"$EFIVARS/$LOADER_PART_VAR"
	printf 'AB12CD34-0000-4000-8000-00000000AA01' | sed 's/./&\x00/g' >>"$EFIVARS/$LOADER_PART_VAR"
	answers ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "只问 ERASE" [ "$(asks)" = "mastersos-factory-reset " ] &&
		check "$1" "按 ESP 的 PARTUUID 找磁盘" logged "lsblk -no PKNAME /dev/disk/by-partuuid/ab12cd34-0000-4000-8000-00000000aa01" &&
		check "$1" "看过种子分区（受管）" logged "mount -t ext4" &&
		check "$1" "没调 complete" not_logged "^factory-reset "
}

managed_not_luks_asks_erase() {
	rm "$STATE/luks"
	answers ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "只问 ERASE" [ "$(asks)" = "mastersos-factory-reset " ] &&
		check "$1" "没看恢复 token" not_logged "luksDump"
}

seed_unmountable_is_managed() {
	: >"$STATE/mount-fails"
	answers wrong-1 wrong-2 wrong-3
	run_main
	check "$1" "问了恢复密钥" eval '[[ $(asks) == mastersos-factory-reset-key* ]]' &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger"
}

disk_unknown_is_managed() {
	: >"$STATE/no-disk"
	answers wrong-1 wrong-2 wrong-3
	run_main
	check "$1" "问了恢复密钥" eval '[[ $(asks) == mastersos-factory-reset-key* ]]' &&
		check "$1" "没去挂种子分区" not_logged "mount "
}

seed_partition_on_other_disk_is_ignored() {
	# 这块盘上没有 mastersos-seed（U 盘上的同名分区不在 lsblk 这块盘的列表里）
	printf '/dev/vda1 esp\n/dev/vda2 usr\n/dev/vda4 root\n' >"$STATE/parts"
	answers ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "未受管：只问 ERASE" [ "$(asks)" = "mastersos-factory-reset " ]
}

tpm_unusable_keeps_data() {
	echo 1 >"$STATE/tpm-rc"
	answers "$KEY" ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "说了原因" eval 'grep -q "The TPM is unusable" <<<"$out" && grep -q "No TPM 2.0" <<<"$out"' &&
		check "$1" "没碰种子分区与 LUKS" eval '! grep -qE "^(mount|cryptsetup)" "$STATE/log"'
}

tpm_undecided_keeps_data() {
	echo 255 >"$STATE/tpm-rc"
	answers "$KEY" ERASE
	run_main
	check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger"
}

complete_fails_exits_nonzero() {
	rm "$STATE/seed-toml"
	echo 1 >"$STATE/complete-rc"
	answers yes
	run_main
	check "$1" "退出非 0" [ "$rc" != 0 ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger"
}

complete_without_flag_exits_nonzero() {
	rm "$STATE/seed-toml"
	answers yes
	COMPLETE_FLAG=$STATE/never-written
	run_main
	COMPLETE_FLAG=$STATE/complete-flag
	check "$1" "退出非 0" [ "$rc" != 0 ]
}

only_plain_root_link_asks_key() {
	# 平常开机的链接名（不在恢复出厂模式时）同样认得
	rm "$ROOT_LUKS_FR"
	: >"$ROOT_LUKS"
	answers wrong-1 wrong-2 wrong-3
	run_main
	check "$1" "问了恢复密钥" eval '[[ $(asks) == mastersos-factory-reset-key* ]]' &&
		check "$1" "对着 root-luks 核对" logged "cryptsetup open --test-passphrase --disable-external-tokens --key-file=- $ROOT_LUKS"
}

no_link_but_luks_on_disk_asks_key() {
	# 两个链接都没有（udev 还没建）：在启动盘上找 crypto_LUKS 分区，不能当成「没有数据」
	rm "$ROOT_LUKS_FR"
	printf '\x07\x00\x00\x00' >"$EFIVARS/$LOADER_PART_VAR"
	printf 'AB12CD34-0000-4000-8000-00000000AA01' | sed 's/./&\x00/g' >>"$EFIVARS/$LOADER_PART_VAR"
	answers "$KEY" ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "先问密钥再问 ERASE" [ "$(asks)" = "mastersos-factory-reset-key mastersos-factory-reset " ] &&
		check "$1" "对着盘上找到的 LUKS 分区核对" logged "cryptsetup open --test-passphrase --disable-external-tokens --key-file=- /dev/vda9"
}

no_link_and_disk_unreadable_keeps_data() {
	rm "$ROOT_LUKS_FR"
	printf '\x07\x00\x00\x00' >"$EFIVARS/$LOADER_PART_VAR"
	printf 'AB12CD34-0000-4000-8000-00000000AA01' | sed 's/./&\x00/g' >>"$EFIVARS/$LOADER_PART_VAR"
	: >"$STATE/parttype-fails"
	answers "$KEY" ERASE
	run_main
	check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger"
}

no_link_and_no_disk_keeps_data() {
	# 受管（找不到磁盘按受管处理）、又找不到根分区：判断不了有没有数据，不清
	rm "$ROOT_LUKS_FR"
	: >"$STATE/no-disk"
	answers "$KEY" ERASE
	run_main
	check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger"
}

isluks_error_keeps_data() {
	# isLuks 退出 0 = 是、1 = 不是；别的（打不开设备……）是判断不了：不能落到「只问 ERASE」
	echo 4 >"$STATE/isluks-rc"
	answers "$KEY" ERASE
	run_main
	check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger"
}

no_link_root_type_not_luks_asks_erase() {
	# 链接都没有，按 GPT 类型找到根分区、isLuks 说不是 LUKS：没有加密的数据，只问 ERASE
	rm "$ROOT_LUKS_FR" "$STATE/luks"
	esp_var
	answers ERASE
	run_main
	check "$1" "退出 0" [ "$rc" = 0 ] &&
		check "$1" "只问 ERASE" [ "$(asks)" = "mastersos-factory-reset " ] &&
		check "$1" "对按类型找到的根分区跑 isLuks" logged "cryptsetup isLuks /dev/vda9"
}

no_link_root_type_unreadable_keeps_data() {
	rm "$ROOT_LUKS_FR"
	esp_var
	echo 4 >"$STATE/isluks-rc"
	answers "$KEY" ERASE
	run_main
	check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "是对按类型找到的根分区判断的" logged "cryptsetup isLuks /dev/vda9"
}

no_link_empty_parttype_keeps_data() {
	# 有分区读不到类型、又没认出根分区：不能当成「确定没有」
	rm "$ROOT_LUKS_FR"
	esp_var
	printf '/dev/vda1 c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n/dev/vda5 0fc63daf-8483-4772-8e79-3d69d8477de4\n/dev/vda9\n' >"$STATE/parttypes"
	answers "$KEY" ERASE
	run_main
	check "$1" "没问任何东西" [ "$(asks)" = "" ] &&
		check "$1" "调了 complete" logged "^factory-reset complete --retrigger" &&
		check "$1" "列过分区类型" logged "lsblk -nrpo NAME,PARTTYPE /dev/vda"
}

normalize_cases() {
	local got
	got=$(normalize_key " CBDEFGHI JKLNRTUV-cbdefghi jklnrtuv ddeeffgghhiijjkk LLNNRRTT-UUVVCCBB ")
	check "$1" "空白、- 与大小写" [ "$got" = "$KEY" ] || return 1
	got=$(normalize_key "$KEY")
	check "$1" "已规范的不变" [ "$got" = "$KEY" ] || return 1
	got=$(normalize_key "Hunter 2-x")
	check "$1" "不是 64 个 modhex 字母时只去空白与 -、转小写" [ "$got" = "hunter2x" ] || return 1
	got=$(normalize_key "${KEY//c/a}")
	check "$1" "含非 modhex 字母时不插 -" [ "$got" = "$(tr -d - <<<"${KEY//c/a}")" ]
}

for c in unmanaged_erase_proceeds unmanaged_wrong_word_keeps_data managed_right_key_and_erase_proceeds \
	managed_wrong_key_keeps_data managed_right_key_wrong_word_keeps_data managed_key_timeout_keeps_data \
	managed_no_recovery_slot_refuses managed_no_luks_asks_erase managed_not_luks_asks_erase \
	seed_unmountable_is_managed disk_unknown_is_managed seed_partition_on_other_disk_is_ignored \
	tpm_unusable_keeps_data tpm_undecided_keeps_data complete_fails_exits_nonzero \
	complete_without_flag_exits_nonzero only_plain_root_link_asks_key no_link_but_luks_on_disk_asks_key \
	no_link_and_disk_unreadable_keeps_data no_link_and_no_disk_keeps_data isluks_error_keeps_data \
	no_link_root_type_not_luks_asks_erase no_link_root_type_unreadable_keeps_data no_link_empty_parttype_keeps_data \
	normalize_cases; do
	case_ "$c" "$c"
done

# 被 source 时不执行 main（上面能定义出函数而没有退出，就说明了这一点）；直接运行时才执行
check "source" "脚本末尾只在直接运行时调 main" grep -qx 'if \[\[ \${BASH_SOURCE\[0\]} == "\$0" \]\]; then' "$script" || fails=$((fails + 1))

echo "factory-reset-confirm-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]

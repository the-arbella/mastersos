#!/bin/bash
# health-check 的「有没有可退回的版本」判断（本机与 CI 都跑，不需要 VM）：
#   bash image/tests/health-check-test.sh
# 只测 fallback_state：健康检查失败时，只有它说有回退版本才 exit 1（触发重启、让启动计数退回去）；
# 没有计数、或 ESP 上没有别的可启动（计数没用完）的 MastersOS UKI 时必须 exit 0，免得唯一的版本进重启循环；
# 读不懂计数或找不到 ESP 时是 unknown：exit 1 但不重启（不标好，也不冒险让单版本的机器进循环）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # 被测的脚本，路径相对本文件
. "$here/../mkosi.extra/usr/lib/mastersos/health-check"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

# case <名字> <期望> <LoaderBootCountPath> <ESP 上 EFI/Linux 里的文件…>
case_() {
	local name=$1 want=$2 count=$3 got
	shift 3
	rm -rf "$tmp/esp"
	mkdir -p "$tmp/esp/EFI/Linux"
	local f
	for f in "$@"; do : >"$tmp/esp/EFI/Linux/$f"; done
	got=$(fallback_state "$tmp/esp/EFI/Linux" "$count")
	n=$((n + 1))
	if [ "$got" = "$want" ]; then
		echo "ok   $name → $got"
	else
		echo "FAIL ${name}：期望 '$want'，实际 '$got'" >&2
		fails=$((fails + 1))
	fi
}

V1=MastersOS_20261012.1_x86-64
V2=MastersOS_20261012.2_x86-64
V3=MastersOS_20261012.3_x86-64

case_ "没有计数（安装后的第一个版本）" "no counter" "" "$V1.efi"
case_ "有计数、旧版本还在" "fallback $V1.efi" "/EFI/Linux/$V2+2-1.efi" "$V1.efi" "$V2+2-1.efi"
bs=$'\x5c' # 一个反斜杠
case_ "反斜杠形式的路径" "fallback $V1.efi" "${bs}EFI${bs}Linux${bs}$V2+2-1.efi" "$V1.efi" "$V2+2-1.efi"
case_ "没有 done 计数的形式" "fallback $V1.efi" "/EFI/Linux/$V2+1.efi" "$V1.efi" "$V2+1.efi"
# 第三次（最后一次）尝试：systemd-boot 先减计数再启动，所以这次启动的名字已经是 +0-3。这时失败必须
# 重启，下一次 systemd-boot 才会跳过它退回旧版本（VM 166 实测：把 +0-3 当成「没有回退」会把坏版本标成好）
case_ "最后一次尝试（+0-3）、旧版本还在" "fallback $V2.efi" "/EFI/Linux/$V3+0-3.efi" "$V2.efi" "$V3+0-3.efi"
case_ "最后一次尝试（+0）、旧版本还在" "fallback $V2.efi" "/EFI/Linux/$V3+0.efi" "$V2.efi" "$V3+0.efi"
case_ "最后一次尝试、ESP 上只有自己" "no fallback" "/EFI/Linux/$V3+0-1.efi" "$V3+0-1.efi"
case_ "ESP 上只有自己" "no fallback" "/EFI/Linux/$V3+1-0.efi" "$V3+1-0.efi"
case_ "另一个版本的计数也用完了" "no fallback" "/EFI/Linux/$V3+2-1.efi" "$V2+0-3.efi" "$V3+2-1.efi"
case_ "另一个版本是 +0（没有 done）" "no fallback" "/EFI/Linux/$V3+2-1.efi" "$V2+0.efi" "$V3+2-1.efi"
case_ "别的 .efi 不算 MastersOS UKI" "no fallback" "/EFI/Linux/$V3+2-1.efi" "other.efi" "$V3+2-1.efi"
case_ "同一版本的另一个计数名不算回退" "no fallback" "/EFI/Linux/$V3+2-1.efi" "$V3.efi" "$V3+2-1.efi"
case_ "回退版本带剩余计数也算" "fallback $V2+1-2.efi" "/EFI/Linux/$V3+2-1.efi" "$V2+1-2.efi" "$V3+2-1.efi"
# 读不懂计数、找不到 ESP：既不能标好（坏版本会永久留下），也不能重启（可能是单版本的机器）
single() { # single <名字> <期望> <ESP 的 EFI/Linux 目录> <计数路径>
	local got
	got=$(fallback_state "$3" "$4")
	n=$((n + 1))
	if [ "$got" = "$2" ]; then echo "ok   $1 → $got"; else
		echo "FAIL ${1}：期望 '$2'，实际 '$got'" >&2
		fails=$((fails + 1))
	fi
}
rm -rf "$tmp/esp"
single "ESP 目录不存在" "unknown: ESP 上没有 EFI/Linux（$tmp/esp/EFI/Linux）" "$tmp/esp/EFI/Linux" "/EFI/Linux/$V3+2-1.efi"
single "找不到 ESP（空路径）" "unknown: 找不到 ESP" "" "/EFI/Linux/$V3+2-1.efi"
mkdir -p "$tmp/esp/EFI/Linux"
single "计数路径看不懂" "unknown: LoaderBootCountPath 看不懂（/EFI/Linux/garbage）" "$tmp/esp/EFI/Linux" "/EFI/Linux/garbage"

echo "health-check-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]

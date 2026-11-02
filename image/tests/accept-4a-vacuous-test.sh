#!/bin/bash
# lab/accept-4a.sh 的负向测试（不碰 VM）：guest agent 的调用失败、或者远端块什么都没打印时，
# 「没有输出就算全部成立」的那几个 check 必须 FAIL，不能空着通过（Task 12 复审 I-2）。
# 用 A4_LIB=1 source 脚本，把碰 PVE / VM / 服务端的函数都换成假的，再分两种情形跑 etc_policy、
# seed_and_agent、offline_first_boot、factory_reset：
#   empty  gx 成功但什么都不打印（远端块被截掉、标记丢了）
#   fail   gx 返回非零（guest agent 超时）
#   bash image/tests/accept-4a-vacuous-test.sh [accept-4a.sh 的路径]
set -euo pipefail
script=${1:-$(cd "$(dirname "$0")/../lab" && pwd)/accept-4a.sh}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
checks=(etc_policy seed_and_agent offline_first_boot factory_reset)
# 每个 check 的 FAIL 原因里必须有的那一句（只「FAIL」不够：要是因为别的原因失败，就证明不了这一处）
declare -A why=([etc_policy]="远端检查块没有跑完" [seed_and_agent]="远端检查块没有跑完" [offline_first_boot]="拿不到 GDM" [factory_reset]="journal 没查成")
total=0 bad=0
for mode in empty fail; do
	out=$(
		A4_LIB=1 A4_OUT=$tmp/out A4_STATE=$tmp/state HOME=$tmp bash -c '
			set -euo pipefail
			# shellcheck disable=SC1090
			. "$1" 165 none
			mode=$2
			shift 2
			gx() { [ "$mode" = empty ] || return 255; }
			for f in pve b161 shot keys link snap rollback delsnap stop_vm serial_logger publish_manifest; do eval "$f() { :; }"; done
			for f in start_wait wait_up reboot_wait install_from; do eval "$f() { return 0; }"; done
			api() { echo "{}"; }
			device_json() { echo "{\"group\":\"default\"}"; }
			device_id() { echo dev; }
			recovery_rows() { echo 0; }
			serial_mark() { echo 0; }
			serial_since() { :; }
			serial_answer() { return 1; }
			manifest() { echo /dev/null; }
			sleep() { local d=${1%.*}; SECONDS=$((SECONDS + ${d:-0} + 1)); }  # 不真睡：把时钟往前拨
			for c in "$@"; do "c_$c" || true; done
		' _ "$script" "$mode" "${checks[@]}" 2>&1
	) || true
	for c in "${checks[@]}"; do
		total=$((total + 1))
		if grep "^FAIL ${c}：" <<<"$out" | grep -qF "${why[$c]}"; then
			echo "ok   $mode ${c}：$(grep -m1 "^FAIL ${c}：" <<<"$out" | cut -c1-120)"
		else
			echo "FAIL $mode ${c} 没有 FAIL：$(grep -m1 -E "^(PASS|FAIL) $c" <<<"$out" || echo 没有结果行)"
			bad=$((bad + 1))
		fi
	done
done
echo "accept-4a-vacuous-test: $((total - bad))/$total 通过"
[ "$bad" = 0 ]

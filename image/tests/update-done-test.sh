#!/bin/bash
# /etc/.updated 的两个判断（4b Task 12 复审 F3、N1、N3；本机与 CI 都跑，不需要 VM）：
#   bash image/tests/update-done-test.sh
# record_action：/usr 顶层是 overlay 就不记；否则记录缺了、或 /usr 比记录新才记。
# stamp_stale：记录比 /usr 新（旧镜像的合并时刻、回滚）才删。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # 被测的脚本，路径相对本文件
. "$here/../mkosi.extra/usr/lib/mastersos/update-done"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
check() { # check <名字> <期望> <实际>
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1 → $3"
	else
		echo "FAIL ${1}：期望 '$2'，实际 '$3'" >&2
		fails=$((fails + 1))
	fi
}
at() { touch -t "$1" "$2"; } # at <[[CC]YY]MMDDhhmm> <文件>

mkdir -p "$tmp/usr"
at 202610150415 "$tmp/usr" # 镜像的构建时刻
u=$tmp/usr e=$tmp/etc.updated v=$tmp/var.updated

check "没有记录（新装、恢复出厂）" record "$(record_action erofs "$u" "$e" "$v")"
at 202610150415 "$e"
at 202610150415 "$v"
check "记录与 /usr 同时（同一版）" current "$(record_action erofs "$u" "$e" "$v")"
at 202610170900 "$u"
check "/usr 比记录新（更新上来）" record "$(record_action erofs "$u" "$e" "$v")"
check "/usr 已经是 overlay（合并之后才跑）" skip-overlay "$(record_action overlayfs "$u" "$e" "$v")"
rm -f "$v"
check "只缺 /var 的记录" record "$(record_action erofs "$u" "$e" "$v")"
check "缺记录但已合并" skip-overlay "$(record_action overlayfs "$u" "$e" "$v")"

st() { if stamp_stale "$1" "$2"; then echo stale; else echo keep; fi; }
at 202610150415 "$u"
at 202610160530 "$e"
check "旧镜像记下的合并时刻比 /usr 新" stale "$(st "$u" "$e")"
at 202610150415 "$e"
check "记录与 /usr 同时" keep "$(st "$u" "$e")"
at 202610140000 "$e"
check "记录比 /usr 旧（更新上来，交给 sysusers）" keep "$(st "$u" "$e")"
rm -f "$e"
check "没有记录" keep "$(st "$u" "$e")"

# usr_fstype 必须看最上面那层：stat -f，不是 findmnt <路径>（叠着的两层都会打出来）或 findmnt -f（下面那层）
check "usr_fstype 用 stat -f" yes "$(declare -f usr_fstype | grep -q 'stat -f -c %T /usr' && echo yes || echo no)"

echo "update-done-test: $((n - fails))/$n 通过"
[ "$fails" -eq 0 ]

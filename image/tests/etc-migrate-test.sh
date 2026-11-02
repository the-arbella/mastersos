#!/bin/bash
# mastersos-etc-migrate 的测试（不要 root）：在临时根里摆出「旧镜像留下的 /etc」，跑 etc-migrate，核对哪些链接被删、哪些不动。
#   dir 路径（etc-dirs）：是链接就删（tmpfiles 的 d 接着建真目录）
#   copy 路径（etc-copies，4b Task 20）：只删指回 /usr/share/factory/etc 里同名文件的旧链接（旧策略的 L），
#     tmpfiles 的 C 只在目标不存在时才拷，不删它就永远是只读的链接（VM 165 从 base-4b 升上来，/etc/locale.conf 还指回 factory，
#     localed 写不进学校的语言）；指向别处的链接（timedatectl 写的 /etc/localtime → zoneinfo）、真文件都不动
#   bash image/tests/etc-migrate-test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
mig=$here/mkosi.extra/usr/lib/mastersos/etc-migrate
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
R=$tmp/root
mkdir -p "$R/usr/lib/mastersos" "$R/usr/share/factory/etc/default" "$R/etc"
printf '/etc/default\n/etc/netplan\n' >"$R/usr/lib/mastersos/etc-dirs"
printf '/etc/locale.conf\n/etc/localtime\n/etc/gdm3\n/etc/hostname\n/etc/vconsole.conf\n' >"$R/usr/lib/mastersos/etc-copies"
ln -s /usr/share/factory/etc/default "$R/etc/default"
mkdir "$R/etc/netplan"
ln -s /usr/share/factory/etc/locale.conf "$R/etc/locale.conf"     # 旧策略的 L：要删
ln -s ../usr/share/zoneinfo/Asia/Bangkok "$R/etc/localtime"        # timedatectl 写的：不动
ln -s ../usr/share/factory/etc/vconsole.conf "$R/etc/vconsole.conf" # 相对写法的旧 L：也要删
mkdir "$R/etc/gdm3"                                                  # 已经是真目录：不动
echo mastersos >"$R/etc/hostname"                                       # 真文件：不动
out=$(MASTERSOS_ETC_MIGRATE_ROOT=$R bash "$mig")
n=0 bad=0
t() { # t <描述> <条件…>
	n=$((n + 1))
	if "${@:2}"; then echo "ok   $1"; else
		echo "FAIL $1"
		bad=$((bad + 1))
	fi
}
t "dir 的旧链接删掉" test ! -e "$R/etc/default" -a ! -L "$R/etc/default"
t "dir 的真目录不动" test -d "$R/etc/netplan"
t "copy 指回 factory 的旧链接删掉" test ! -L "$R/etc/locale.conf"
t "copy 相对写法指回 factory 的旧链接删掉" test ! -L "$R/etc/vconsole.conf"
t "copy 指向别处的链接不动" test "$(readlink "$R/etc/localtime")" = ../usr/share/zoneinfo/Asia/Bangkok
t "copy 的真目录不动" test -d "$R/etc/gdm3"
t "copy 的真文件不动" test "$(cat "$R/etc/hostname")" = mastersos
t "日志里写了删掉的 copy 链接" grep -q '/etc/locale.conf' <<<"$out"
# 没有 etc-copies（旧镜像生成的列表）时照旧只处理 dir
rm "$R/usr/lib/mastersos/etc-copies"
ln -s /usr/share/factory/etc/default "$R/etc/default"
MASTERSOS_ETC_MIGRATE_ROOT=$R bash "$mig" >/dev/null
t "没有 etc-copies 时 dir 照常处理" test ! -L "$R/etc/default"
echo "etc-migrate-test: $((n - bad))/$n 通过"
[ "$bad" = 0 ]

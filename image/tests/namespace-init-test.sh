#!/bin/bash
# mkosi.extra/etc/security/namespace.init（锁定应用，计划 9 Task 8）的各个分支，不要 root、不碰真的 /etc 与 /var：
#   bash image/tests/namespace-init-test.sh
# 拿脚本的副本、把开头的四个常量（POLYDIR、INSTANCE_PREFIX、PUBLIC、OWNER）换成临时目录与当前用户，照 pam_namespace 的参数调它。
# 失败的约定（复审 C2）：pam_namespace 1.7 只在脚本被信号杀死时让会话失败，所以 kiosk 那一段的每条失败路径都要死于 SIGKILL
# （退出码 137），正常的 exit 1 不算。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
src=$here/../mkosi.extra/etc/security/namespace.init
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
check() { # <名字> <条件命令…>
	local name=$1
	shift
	n=$((n + 1))
	if "$@"; then
		echo "ok   $name"
	else
		echo "FAIL $name" >&2
		fails=$((fails + 1))
	fi
}

poly=$tmp/etc/opt/chrome/policies/managed
pfx=$tmp/ns/
pub=$tmp/public/kiosk
me="$(id -un):$(id -gn)"
script=$tmp/namespace.init
sed -e "s|^POLYDIR=.*|POLYDIR=$poly|" -e "s|^INSTANCE_PREFIX=.*|INSTANCE_PREFIX=$pfx|" \
	-e "s|^PUBLIC=.*|PUBLIC=$pub|" -e "s|^OWNER=.*|OWNER=$me|" "$src" >"$script"
chmod 0755 "$script"
check "四个常量都换掉了" test "$(grep -cE "^(POLYDIR=$poly|INSTANCE_PREFIX=$pfx|PUBLIC=$pub|OWNER=$me)\$" "$script")" = 4
mkdir -p "$poly" "$pfx"

# 实例目录像 pam_namespace 建的那样：照 polydir 的属主与权限（真机上 root:root 0755，这里是 OWNER 换成的当前用户），
# 里面还有上一次会话留下的东西
fresh_inst() { # <账号>
	rm -rf "${pfx:?}/$1"
	mkdir -m 0755 "$pfx/$1"
	echo stale >"$pfx/$1/old.json"
	mkdir "$pfx/$1/olddir"
	echo x >"$pfx/$1/olddir/x"
}
run() { "$script" "$@" >/dev/null 2>&1; }
# 被 SIGKILL 杀死（bash 报 128 + 9）
killed() {
	local rc=0
	"$script" "$@" >/dev/null 2>&1 || rc=$?
	[ "$rc" = 137 ]
}
ls_of() { (cd "$1" && find . -mindepth 1 -printf '%P %m\n' | LC_ALL=C sort | tr '\n' ' '); }

# 1. 网页应用：policies/ 里的普通文件拷进来（0644），符号链接与子目录不拷，旧的清掉，实例 0755
mkdir -p "$pub/nwea/policies/sub"
printf '{"a":1}\n' >"$pub/nwea/policies/mastersos-kiosk.json"
printf '{"b":2}\n' >"$pub/nwea/policies/extra.json"
chmod 0600 "$pub/nwea/policies/extra.json"
ln -s /etc/passwd "$pub/nwea/policies/link.json"
fresh_inst kiosk-nwea
check "网页应用：成功" run "$poly" "${pfx}kiosk-nwea" 1 kiosk-nwea 1 1
check "  只拷了两个普通文件、都是 0644" test "$(ls_of "${pfx}kiosk-nwea")" = "extra.json 644 mastersos-kiosk.json 644 "
check "  内容相同" cmp -s "$pub/nwea/policies/mastersos-kiosk.json" "${pfx}kiosk-nwea/mastersos-kiosk.json"
check "  实例目录 0755" test "$(stat -c %a "${pfx}kiosk-nwea")" = 755
fresh_inst kiosk-nwea
check "已有的实例（\$3 = 0）同样重拷" run "$poly" "${pfx}kiosk-nwea" 0 kiosk-nwea 1 1
check "  旧的清掉、新的在" test "$(ls_of "${pfx}kiosk-nwea")" = "extra.json 644 mastersos-kiosk.json 644 "

# 2. 没有 policies/（agent 现在对每种应用都写它，终审 I1；这里只是容忍）：实例是空的，由 mastersos-kiosk run 拒绝
mkdir -p "$pub/calc"
fresh_inst kiosk-calc
check "没有 policies/：成功" run "$poly" "${pfx}kiosk-calc" 1 kiosk-calc 1 1
check "  实例是空的" test -z "$(ls -A "${pfx}kiosk-calc")"
# policies 是符号链接（指到别处）：当作没有
mkdir -p "$pub/lnk" "$tmp/elsewhere"
echo '{}' >"$tmp/elsewhere/evil.json"
ln -s "$tmp/elsewhere" "$pub/lnk/policies"
fresh_inst kiosk-lnk
check "policies 是符号链接：成功但不拷" run "$poly" "${pfx}kiosk-lnk" 1 kiosk-lnk 1 1
check "  实例是空的" test -z "$(ls -A "${pfx}kiosk-lnk")"

# 3. 拒绝的情形：死于 SIGKILL（pam_namespace 让会话失败），实例不动
fresh_inst kiosk-nwea
check "实例路径不对：SIGKILL" killed "$poly" "${pfx}kiosk-other" 1 kiosk-nwea 1 1
check "不是 kiosk 账号：SIGKILL" killed "$poly" "${pfx}student" 1 student 1 1
check "账号名带 ..：SIGKILL" killed "$poly" "${pfx}kiosk-../x" 1 'kiosk-../x' 1 1
check "实例路径不安全（\$6 = 0）：SIGKILL" killed "$poly" "${pfx}kiosk-nwea" 1 kiosk-nwea 1 0
check "polydir 不安全（\$5 = 0）：SIGKILL" killed "$poly" "${pfx}kiosk-nwea" 1 kiosk-nwea 0 1
check "没有 \$5 \$6（旧 pam）：SIGKILL" killed "$poly" "${pfx}kiosk-nwea" 1 kiosk-nwea
check "  这几次之后实例原样（旧文件还在）" test "$(stat -c %a "${pfx}kiosk-nwea")-$(ls_of "${pfx}kiosk-nwea")" = "755-old.json 644 olddir 755 olddir/x 644 "
# 意料之外的失败（这里是 install 出错）：ERR trap 同样 SIGKILL
mkdir -p "$tmp/badbin"
printf '#!/bin/sh\nexit 1\n' >"$tmp/badbin/install"
chmod 0755 "$tmp/badbin/install"
sed "s|^PATH=|PATH=$tmp/badbin:|" "$script" >"$tmp/namespace.init.badinstall"
chmod 0755 "$tmp/namespace.init.badinstall"
check "  （换了 PATH 的副本里 install 是坏的）" grep -q "^PATH=$tmp/badbin:" "$tmp/namespace.init.badinstall"
fresh_inst kiosk-nwea
rc=0
"$tmp/namespace.init.badinstall" "$poly" "${pfx}kiosk-nwea" 1 kiosk-nwea 1 1 >/dev/null 2>&1 || rc=$?
check "拷贝出错：SIGKILL（rc=$rc）" test "$rc" = 137
rm -rf "${pfx:?}/kiosk-sym"
ln -s "$tmp/elsewhere" "${pfx}kiosk-sym"
check "实例是符号链接：SIGKILL" killed "$poly" "${pfx}kiosk-sym" 1 kiosk-sym 1 1
check "  链接指向的目录没被清" test -f "$tmp/elsewhere/evil.json"

# 4. 别的多实例目录：发行版的逻辑（不是家目录、不新建就什么都不做），退出 0
check "别的 polydir：照发行版，退出 0" run /tmp "$tmp/tmp-inst" 0 student 1 1
check "  实例的父目录里没有多出别的" test -z "$(find "$pfx" -mindepth 1 -maxdepth 1 ! -name 'kiosk-*')"

echo "namespace-init-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]

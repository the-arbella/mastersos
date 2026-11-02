#!/bin/bash
# 往 PAM 里插 mastersos-agent 的两个钩子（Ruling 4、5）。mkosi.postinst.chroot 在 MASTERSOS_PAM_HOOKS=1 时以
# 镜像的 /etc/pam.d 调它（/etc/pam.d 在策略表里是默认的 L，finalize 把改好的收进 factory）；
# tests/pam-hooks-test.sh 拿样本目录调它。用法：pam-hooks.sh <pam.d 目录> <vendor 的 pam.d 目录（/usr/lib/pam.d）>
#   - common-account 第一条规则之前：account requisite … pam-check（GDM 各服务、login、sshd 都经过它）
#   - gdm-password 与 gdm-authd 的 session 段最前面（任何 @include common-session 与 pam_systemd 之前）：
#     session requisite … pam-session。装了 authd 的 GDM 对用户列表里的每个人（访客也一样）都走 gdm-authd（Task 8、11
#     在 VM 上看到），访客的 tmpfs 检查不通过时要能拒绝。requisite 而不是 required：required 失败了 PAM 还会把后面的
#     模块跑完，pam_systemd 照样给被拒的访客开出会话、拉起 user manager（Task 11 复审轮在 VM 上见过），而那时家目录可能
#     还是上一位访客的。对其他用户 pam-session 永远退出 0（只做登录排队），所以 requisite 不会让他们登录失败——除非
#     agent 根本跑不起来，那时 pam-check 早已拒绝了
#   - 锁定应用（计划 9 Task 8，复审 C1、I1）：两行挨着插——
#       session [success=1 default=ignore] pam_succeed_if.so quiet user !~ kiosk-*
#       session required pam_namespace.so
#     名字不是 kiosk-* 的用户守卫返回成功、跳过 pam_namespace：namespace 的配置坏了（格式错的行、namespace.conf 打不开）、
#     或者登录的用户在 NSS 里一时查不到（authd），pam_namespace 都会让会话失败——有了守卫只落在 kiosk 账号上。kiosk 账号
#     守卫返回 PAM_AUTH_ERR、pam_succeed_if 自己出错也一样，都是 ignore，pam_namespace 照跑（不会因为守卫出错而漏掉）。
#     名单 /etc/security/namespace.d/mastersos-kiosk.conf 由 agent 写，只列 kiosk 账号（名单里查不到的名字 pam_namespace 跳过）：
#     它们的 /etc/opt/chrome/policies/managed 换成 /var/lib/mastersos-kiosk-ns/<账号>（namespace.init 往里拷这个应用自己的策略）。
#     插在三个文件里：
#       gdm-password、gdm-authd：pam-session 之后、第一个 @include common-session（pam_systemd 在里面）之前——会话的头一个进程
#         （gnome-session 的引导）在新的挂载命名空间里；
#       systemd-user（kiosk 账号的 user@<uid>.service 走这个栈）：gnome-session 50 把 gnome-kiosk 与应用都当 user@<uid> 的单元起，
#         Chrome 是它们的子进程，不在 GDM 那一侧的命名空间里——这里也要换。位置照 GDM 那两份：pam_selinux open、pam_loginuid、
#         pam_limits 之后，@include common-session-noninteractive 与 pam_systemd 之前（PID 1 起 user manager 前在这个进程里
#         unshare，systemd --user 与它起的全部单元都在里面）。resolute 的 systemd 把它装在 /usr/lib/pam.d（libpam 先找 /etc/pam.d、
#         再找 /usr/lib/pam.d）：第二个参数给 vendor 目录，/etc/pam.d 里有同名文件就改那一份，没有就改 vendor 的那一份
#     插入点都是 session 段里第一个 @include common-session[-noninteractive] 或直接写的 pam_systemd（都没有就失败）。
set -euo pipefail

d=${1:?用法：pam-hooks.sh <pam.d 目录> <vendor 的 pam.d 目录>}
vd=${2:?用法：pam-hooks.sh <pam.d 目录> <vendor 的 pam.d 目录>}
AGENT=/usr/bin/mastersos-agent
ACCOUNT="account requisite pam_exec.so quiet stdout $AGENT pam-check"
SESSION_REQ="session requisite pam_exec.so quiet stdout $AGENT pam-session"
GUARD="session [success=1 default=ignore] pam_succeed_if.so quiet user !~ kiosk-*"
NAMESPACE="session required pam_namespace.so"

die() {
	echo "pam-hooks: $*" >&2
	exit 1
}

for f in common-account gdm-password gdm-authd; do
	[ -f "$d/$f" ] || die "$d/$f 不存在"
	if grep -qF -- "$AGENT pam-" "$d/$f"; then
		die "$d/$f 里已经有 mastersos-agent 的钩子"
	fi
done
# systemd-user：/etc/pam.d 里的盖过 vendor 的
if [ -f "$d/systemd-user" ]; then
	su_file=$d/systemd-user
elif [ -f "$vd/systemd-user" ]; then
	su_file=$vd/systemd-user
else
	die "$d/systemd-user 与 $vd/systemd-user 都不存在（user@<uid>.service 的 PAM 栈）"
fi
for f in "$d/gdm-password" "$d/gdm-authd" "$su_file"; do
	if grep -qE -- 'pam_namespace\.so|pam_succeed_if\.so.*kiosk-' "$f"; then
		die "$f 里已经有 pam_namespace 或锁定应用的守卫（不知道它的名单与选项，不重复插）"
	fi
done

# 在第一条匹配 $2（awk 正则）的行之前插 $3；没有匹配的行就失败
insert_before() { # $1 = 文件 $2 = 正则 $3 = 行
	local f=$1 tmp
	tmp=$(mktemp "$f.XXXXXX")
	if ! awk -v re="$2" -v line="$3" '
		!done && $0 ~ re { print line; done = 1 }
		{ print }
		END { exit done ? 0 : 1 }
	' "$f" >"$tmp"; then
		rm -f "$tmp"
		die "$f 里找不到插入点（$2）"
	fi
	chmod --reference="$f" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
	mv -f "$tmp" "$f"
}

# 规则行：不是空行、不是注释
rule_re='^[[:space:]]*[^#[:space:]]'
# session 段的开头：session / -session 规则，或 @include common-session
sess_re='^[[:space:]]*(-?session[[:space:]]|@include[[:space:]]+common-session([[:space:]]|$))'
# 守卫与 pam_namespace 的插入点：@include common-session[-noninteractive]，或直接写的 pam_systemd 行
sysd_re='^[[:space:]]*(@include[[:space:]]+common-session(-noninteractive)?([[:space:]]|$)|-?session[[:space:]].*pam_systemd\.so)'

# 先在临时副本上插齐，全部成功才换上：插到一半失败时样本目录不留半截
work=$(mktemp -d "$d/.pam-hooks.XXXXXX")
trap 'rm -rf "$work"' EXIT
for f in common-account gdm-password gdm-authd; do
	cp -p "$d/$f" "$work/$f"
done
cp -p "$su_file" "$work/systemd-user"
insert_before "$work/common-account" "$rule_re" "$ACCOUNT"
for f in gdm-password gdm-authd; do
	insert_before "$work/$f" "$sess_re" "$SESSION_REQ"
done
for f in gdm-password gdm-authd systemd-user; do
	insert_before "$work/$f" "$sysd_re" "$GUARD"
	insert_before "$work/$f" "$sysd_re" "$NAMESPACE"
done
for f in common-account gdm-password gdm-authd; do
	mv -f "$work/$f" "$d/$f"
done
cp -p "$work/systemd-user" "$su_file.pam-hooks-new"
mv -f "$su_file.pam-hooks-new" "$su_file"

# 核对守卫与 pam_namespace：各恰好一行、守卫就在 pam_namespace 的上一行、两者在第 $2 行之后，
# 在任何 @include common-session[-noninteractive] 与 pam_systemd 之前
check_ns() { # $1 文件 $2 必须排在它后面的行号（0 = 不限）
	local f=$1 after=$2 ns g n re
	[ "$(grep -c -- 'pam_namespace' "$f")" = 1 ] || die "$f 里 pam_namespace 不是恰好一行"
	[ "$(grep -c -- 'pam_succeed_if.so quiet user !~ kiosk-' "$f")" = 1 ] || die "$f 里守卫不是恰好一行"
	ns=$({ grep -nxF -- "$NAMESPACE" "$f" || true; } | cut -d: -f1)
	g=$({ grep -nxF -- "$GUARD" "$f" || true; } | cut -d: -f1)
	[ -n "$ns" ] || die "$f 里没有「$NAMESPACE」"
	[ -n "$g" ] || die "$f 里没有「$GUARD」"
	[ "$g" = $((ns - 1)) ] || die "$f 里守卫（第 $g 行）不在 pam_namespace（第 $ns 行）的上一行"
	[ "$g" -gt "$after" ] || die "$f 里守卫（第 $g 行）排在第 $after 行之前"
	for re in '^[[:space:]]*@include[[:space:]]+common-session' 'pam_systemd'; do
		n=$({ grep -nE -- "$re" "$f" || true; } | head -n 1 | cut -d: -f1)
		if [ -n "$n" ] && [ "$n" -lt "$g" ]; then
			die "$f 第 $n 行（$re）排在守卫与 pam_namespace（第 $g 行）之前"
		fi
	done
}

# 核对：钩子恰好一行；common-account 里它是第一条规则；两个 gdm 服务里它排在任何 session 行、
# @include common-session 与 pam_systemd 之前，守卫与 pam_namespace 在它之后
[ "$(grep -cF -- "$AGENT pam-" "$d/common-account")" = 1 ] || die "common-account 里钩子不是恰好一行"
[ "$(grep -E -- "$rule_re" "$d/common-account" | head -n 1)" = "$ACCOUNT" ] || die "common-account 的第一条规则不是 pam-check"
for f in "$d/gdm-password" "$d/gdm-authd"; do
	[ "$(grep -cF -- "$AGENT pam-" "$f")" = 1 ] || die "$f 里钩子不是恰好一行"
	h=$({ grep -nxF -- "$SESSION_REQ" "$f" || true; } | cut -d: -f1)
	[ -n "$h" ] || die "$f 里没有「$SESSION_REQ」"
	for re in '^[[:space:]]*-?session[[:space:]]' '^[[:space:]]*@include[[:space:]]+common-session' 'pam_systemd'; do
		n=$({ grep -nE -- "$re" "$f" || true; } | { grep -vxF -- "$h:$SESSION_REQ" || true; } | head -n 1 | cut -d: -f1)
		if [ -n "$n" ] && [ "$n" -lt "$h" ]; then
			die "$f 第 $n 行（$re）排在钩子（第 $h 行）之前"
		fi
	done
	check_ns "$f" "$h"
done
if grep -qF -- "$AGENT pam-" "$su_file"; then die "$su_file 里不该有 mastersos-agent 的钩子"; fi
check_ns "$su_file" 0
echo "pam-hooks: 已插入 common-account（pam-check）、gdm-password 与 gdm-authd（pam-session，requisite），gdm-password、gdm-authd 与 ${su_file}（守卫 + pam_namespace）"

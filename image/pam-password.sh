#!/bin/bash
# authd 的 PAM profile 与 common-password 的改写和逐行核对（4b Task 9）。mkosi.postinst.chroot 调它，
# tests/pam-password-test.sh 拿样本调它。用法：
#   pam-password.sh profile <pam-configs/authd>   pam-auth-update 之前：装的 authd 必须恰好是 AUTHD_VERSION、profile 必须与
#                                                 它的原文逐行相同，改成去掉 Password 段、Auth / Account 行加 --exec-env=CI=1
#   pam-password.sh apply <pam.d 目录>            pam-auth-update 之后：common-password 的 Primary 段开头插分流与
#                                                 authd 的口令行，再 check
#   pam-password.sh check <pam.d 目录>            common-password 与期望文本逐行相同；common-auth、common-account
#                                                 里 authd 恰好一行、带 --exec-env（postinst 末尾再跑一次）
#
# 为什么这样分流（Ruling 24，spec §6.12）：authd 的 Password 段原样留着时，common-password 里它是第一个 Primary、
# default=die，后面的 pam_unix 又带 use_authtok，本机用户在 pty 里 passwd、GNOME 设置改口令都失败（4a Task 12）。
# 所以 profile 仍去掉 Password 段（pam_unix 成为第一个 Primary，用不带 use_authtok 的 Password-Initial），再在它前面
# 插两行：名字不含 @ 的（本机用户、guest、root）跳过 authd；含 @ 的（SSO）经 authd 改「本机的离线口令」。
# authd 那一行就是上游 profile 的 Password 行，[success=end …] 由 pam-auth-update 的写法换成实际的跳转数
# success=2（跳过 pam_unix、pam_deny，落在 pam_permit），其余控制字段原样。
#
# 为什么带 --exec-env=CI=1（Task 9 Step 2 在 VM 165 实测）：authd-pam（Go）一启动，bubbletea v1.3.4 的 init() 就调
# lipgloss.HasDarkBackground()，termenv 往终端发 ESC]11;? ESC[6n、最多等 5 秒（OSCTimeout），等的时候读走终端里已有的输入。
# 不回答查询的 pty 上，每个 authd-pam 进程（auth、account、password 各一个）都白等 5 秒，先敲进去的字被吃掉。
# authd 0.6.1 自己的参数（force_native_client、connection_timeout …）都在这个 init 之后才生效，关不掉它；
# pam_authd_exec.so 的 --exec-env 给 authd-pam 设环境变量，termenv 见到非空的 CI 就当作不是终端、不查询
# （authd 与它依赖的模块里只有 termenv 读 CI）。代价：authd 的终端界面没有颜色。
set -euo pipefail

# 审过的 authd 版本（Task 9 复审 I1）。只核 profile 的文本挡不住换版本：上游 debian/pam-configs/authd.in 在 v0.6.1、v0.6.4、
# v0.7.1 逐字节相同，而 --exec-env=CI=1 管不管用取决于二进制里的 bubbletea / termenv，不在 profile 里。authd 或 broker 要升版本时
# 就改这一处：先重验 CI=1（不回答查询的 pty 上 su 不再白等 5 秒）、重读 profile 改下面的期望文本，再改这个版本号
AUTHD_VERSION=0.6.1ubuntu0.1
T=$'\t'
SP=' ' # pam-auth-update 生成的 pam_gnome_keyring 那一行末尾有一个空格（VM 165 上的原文件），期望文本里显式写出来
OLD='pam_authd_exec.so /usr/libexec/authd-pam'
NEW='pam_authd_exec.so --exec-env=CI=1 -- /usr/libexec/authd-pam'
AUTH_CTL='[success=end ignore=ignore default=die authinfo_unavail=ignore]'
ACCT_CTL='[default=ignore success=ok]'

die() {
	echo "pam-password: $*" >&2
	exit 1
}

# authd 0.6.1ubuntu0.1 的 /usr/share/pam-configs/authd（Task 9 Step 1 从 deb 里取出，sha256 f2d88bf4…c441c8a9）
upstream_profile() {
	cat <<EOF
Name: authd authentication
Default: yes
Priority: 1050

Auth-Type: Primary
Auth:
${T}$AUTH_CTL${T}$OLD
Account-Type: Additional
Account:
${T}$ACCT_CTL${T}$OLD
Password-Type: Primary
Password:
${T}$AUTH_CTL${T}$OLD
Session-Type: Additional
Session-Interactive-Only: yes
Session:
${T}optional${T}${T}${T}pam_mkhomedir.so
EOF
}

ours_profile() {
	cat <<EOF
Name: authd authentication
Default: yes
Priority: 1050

Auth-Type: Primary
Auth:
${T}$AUTH_CTL${T}$NEW
Account-Type: Additional
Account:
${T}$ACCT_CTL${T}$NEW
Session-Type: Additional
Session-Interactive-Only: yes
Session:
${T}optional${T}${T}${T}pam_mkhomedir.so
EOF
}

# pam-auth-update（libpam-runtime）生成的 common-password，Primary 段开头是我们插的两行
expected_common_password() {
	cat <<EOF
#
# /etc/pam.d/common-password - password-related modules common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of modules that define the services to be
# used to change user passwords.  The default is pam_unix.

# Explanation of pam_unix options:
# The "yescrypt" option enables
#hashed passwords using the yescrypt algorithm, introduced in Debian
#11.  Without this option, the default is Unix crypt.  Prior releases
#used the option "sha512"; if a shadow password hash will be shared
#between Debian 11 and older releases replace "yescrypt" with "sha512"
#for compatibility .  The "obscure" option replaces the old
#\`OBSCURE_CHECKS_ENAB' option in login.defs.  See the pam_unix manpage
#for other options.

# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
$SPLIT
$AUTHD_PW
password${T}[success=1 default=ignore]${T}pam_unix.so obscure yescrypt
# here's the fallback if no module succeeds
password${T}requisite${T}${T}${T}pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
password${T}required${T}${T}${T}pam_permit.so
# and here are more per-package modules (the "Additional" block)
password${T}optional${T}pam_gnome_keyring.so${SP}
# end of pam-auth-update config
EOF
}
SPLIT="password${T}[success=1 default=ignore]${T}pam_succeed_if.so quiet user !~ *@*"
AUTHD_PW="password${T}[success=2 ignore=ignore default=die authinfo_unavail=ignore]${T}$NEW"

check() {
	local d=$1 f want pair
	diff -u <(expected_common_password) "$d/common-password" >&2 ||
		die "$d/common-password 与期望文本不同（上面是 diff）"
	for pair in "common-auth:auth${T}[success=2 ignore=ignore default=die authinfo_unavail=ignore]${T}$NEW" \
		"common-account:account${T}$ACCT_CTL${T}$NEW"; do
		f=$d/${pair%%:*} want=${pair#*:}
		[ "$(grep -cF pam_authd_exec "$f")" = 1 ] || die "$f 里 pam_authd_exec 不是恰好一行"
		grep -qxF -- "$want" "$f" || die "$f 里 authd 那一行不是「${want}」"
	done
}

cmd=${1:-}
arg=${2:-}
[ -n "$arg" ] || die "用法：pam-password.sh profile <pam-configs/authd> | apply <pam.d 目录> | check <pam.d 目录>"
case "$cmd" in
profile)
	v=$(dpkg-query -W -f='${Version}' authd 2>/dev/null) || v=""
	[ "$v" = "${AUTHD_VERSION}" ] ||
		die "装的 authd 是「${v:-没装}」，审过的是 ${AUTHD_VERSION}：先重验 --exec-env=CI=1 能不能关掉终端查询（Task 9）、重读 profile，再改 pam-password.sh 的 AUTHD_VERSION 与期望文本"
	diff -u <(upstream_profile) "$arg" >&2 ||
		die "$arg 不是 authd ${AUTHD_VERSION} 的原文（上面是 diff）：先读新的 profile，再改这里的期望文本"
	ours_profile >"$arg.new"
	chmod 0644 "$arg.new"
	mv -f "$arg.new" "$arg"
	echo "pam-password: $arg 已去掉 Password 段，Auth / Account 行带 --exec-env=CI=1"
	;;
apply)
	f=$arg/common-password
	[ -f "$f" ] || die "$f 不存在"
	grep -qF pam_authd_exec "$f" && die "$f 里已经有 authd"
	# 在第一条 password 规则（应是 pam_unix）之前插两行；之后 check 核对整个文件
	tmp=$(mktemp "$f.XXXXXX")
	awk -v a="$SPLIT" -v b="$AUTHD_PW" '
		!done && /^password[ \t]/ { print a; print b; done = 1 }
		{ print }
	' "$f" >"$tmp"
	chmod --reference="$f" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
	mv -f "$tmp" "$f"
	check "$arg"
	echo "pam-password: common-password 已按用户名分流（含 @ 的经 authd，其余只走 pam_unix）"
	;;
check)
	check "$arg"
	echo "pam-password: common-password、common-auth、common-account 的 authd 行与期望相同"
	;;
*) die "未知子命令：$cmd" ;;
esac

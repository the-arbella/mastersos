#!/bin/bash
# pam-hooks.sh（MASTERSOS_PAM_HOOKS=1 时由 mkosi.postinst.chroot 调）的插行位置（本机与 CI 都跑，不需要 VM）：
#   bash image/tests/pam-hooks-test.sh
# 样本 tests/fixtures/pam.d/ 是 VM 165（20261015.5，authd 0.6.1、gdm3 50.1）上的原文件；tests/fixtures/pam.d-vendor/systemd-user
# 是 resolute 的 systemd 259.5-0ubuntu3 装在 /usr/lib/pam.d 的那一份（user@<uid>.service 的 PAM 栈）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
hooks=$here/../pam-hooks.sh
fx=$here/fixtures/pam.d
fxv=$here/fixtures/pam.d-vendor
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
ACCOUNT='account requisite pam_exec.so quiet stdout /usr/bin/mastersos-agent pam-check'
SREQ='session requisite pam_exec.so quiet stdout /usr/bin/mastersos-agent pam-session'
# 锁定应用（计划 9 Task 8，复审 C1、I1）：名字不是 kiosk-* 的跳过 pam_namespace；kiosk 账号的 /etc/opt/chrome/policies/managed
# 由 pam_namespace 换成它自己的实例。GDM 的两个服务与 systemd-user（user manager）都有这两行
GUARD='session [success=1 default=ignore] pam_succeed_if.so quiet user !~ kiosk-*'
NS='session required pam_namespace.so'

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
fresh() {
	rm -rf "$tmp/d" "$tmp/v"
	cp -R "$fx" "$tmp/d"
	cp -R "$fxv" "$tmp/v"
}
hooks() { bash "$hooks" "$tmp/d" "$tmp/v"; }
fails_now() { ! hooks >/dev/null 2>&1; }
# 文件 $1 里，去掉恰好一行 $2 之后与原样本 $3 相同，且 $2 在第 $4 行
inserted_at() {
	[ "$(grep -cxF -- "$2" "$1")" = 1 ] &&
		[ "$(grep -nxF -- "$2" "$1" | cut -d: -f1)" = "$4" ] &&
		diff -q <(grep -vxF -- "$2" "$1") "$3" >/dev/null
}
line_of() { grep -nE -- "$2" "$1" | head -n 1 | cut -d: -f1; }
# 文件 $1 里，去掉 $2、守卫、pam_namespace 各恰好一行之后与原样本 $3 相同；$2 在第 $4 行（空 = 没有这一行），守卫在第 $5 行、
# pam_namespace 紧随其后
inserted_at3() {
	local f=$1 hook=$2 orig=$3 hl=$4 gl=$5 pats=(-e "$GUARD" -e "$NS")
	if [ -n "$hook" ]; then
		[ "$(grep -cxF -- "$hook" "$f")" = 1 ] && [ "$(grep -nxF -- "$hook" "$f" | cut -d: -f1)" = "$hl" ] || return 1
		pats+=(-e "$hook")
	fi
	[ "$(grep -cxF -- "$GUARD" "$f")" = 1 ] && [ "$(grep -cxF -- "$NS" "$f")" = 1 ] &&
		[ "$(grep -nxF -- "$GUARD" "$f" | cut -d: -f1)" = "$gl" ] &&
		[ "$(grep -nxF -- "$NS" "$f" | cut -d: -f1)" = "$((gl + 1))" ] &&
		diff -q <(grep -vxF "${pats[@]}" "$f") "$orig" >/dev/null
}

# 1. 正常插入：别的行原样不动
fresh
check "插入成功" hooks
# common-account：第一条规则（pam_unix 那一行）之前
ca_first=$(line_of "$fx/common-account" '^[[:space:]]*[^#[:space:]]')
check "common-account：pam-check 在第一条规则之前" inserted_at "$tmp/d/common-account" "$ACCOUNT" "$fx/common-account" "$ca_first"
# gdm-*：pam-session 在第一条 session 行（pam_selinux close）之前；守卫 + pam_namespace 在 @include common-session（pam_systemd 在
# 里面）之前，算上前面插的 pam-session 一行
for f in gdm-password gdm-authd; do
	first=$(line_of "$fx/$f" '^session[[:space:]]')
	inc=$(line_of "$fx/$f" '^@include[[:space:]]+common-session')
	check "${f}：pam-session（requisite）在 session 段最前面，守卫 + pam_namespace 挨着、在 @include common-session 之前" \
		inserted_at3 "$tmp/d/$f" "$SREQ" "$fx/$f" "$first" "$((inc + 1))"
done
# systemd-user（vendor 目录里那份）：守卫 + pam_namespace 在 pam_limits 之后、@include common-session-noninteractive 之前；没有 pam-session
su_inc=$(line_of "$fxv/systemd-user" '^@include[[:space:]]+common-session-noninteractive')
check "systemd-user：守卫 + pam_namespace 挨着、在 @include common-session-noninteractive（与 pam_systemd）之前" \
	inserted_at3 "$tmp/v/systemd-user" "" "$fxv/systemd-user" "" "$su_inc"
check "  systemd-user 在 pam_limits 之后" test "$(line_of "$tmp/v/systemd-user" 'pam_limits')" -lt "$(line_of "$tmp/v/systemd-user" 'pam_succeed_if')"
check "  systemd-user 里没有 mastersos-agent 的钩子" bash -c "! grep -q mastersos-agent '$tmp/v/systemd-user'"
check "  /etc 那边没有凭空多出 systemd-user" test ! -e "$tmp/d/systemd-user"
check "没有 optional 的 pam-session 行" bash -c "! grep -rqE 'optional.*mastersos-agent pam-session' '$tmp/d'"
for f in gdm-password gdm-authd; do
	h=$(line_of "$tmp/d/$f" 'mastersos-agent pam-session')
	c=$(line_of "$tmp/d/$f" '^@include[[:space:]]+common-session')
	check "${f}：钩子在 @include common-session 之前" test "$h" -lt "$c"
	ns=$(line_of "$tmp/d/$f" 'pam_namespace' || echo 0)
	check "${f}：pam_namespace 恰好一行" test "$(grep -c pam_namespace "$tmp/d/$f")" = 1
	check "${f}：守卫与 pam_namespace 在 pam-session 之后、@include common-session（pam_systemd）之前" test "$h" -lt "$((ns - 1))" -a "$ns" -lt "$c"
done
check "common-account 里没有 pam_namespace 与守卫" bash -c "! grep -qE 'pam_namespace|kiosk-' '$tmp/d/common-account'"
check "其余文件不动（gdm-launch-environment）" diff -q "$tmp/d/gdm-launch-environment" "$fx/gdm-launch-environment"
check "不挂 close_session、不带 type=" bash -c "! grep -rhE 'mastersos-agent' '$tmp/d' | grep -qE 'type=|close'"

# 2. 已经插过的目录：失败、不再插第二行
check "重复执行失败" fails_now
check "重复执行后仍只有一行" test "$(grep -cF 'mastersos-agent pam-check' "$tmp/d/common-account")" = 1

# 3. 缺文件：失败、什么都不改
fresh
rm "$tmp/d/gdm-authd"
check "缺 gdm-authd 时失败" fails_now
check "缺文件时 common-account 没被改" diff -q "$tmp/d/common-account" "$fx/common-account"
fresh
rm "$tmp/v/systemd-user"
check "/etc 与 vendor 都没有 systemd-user 时失败" fails_now
check "  common-account 没被改" diff -q "$tmp/d/common-account" "$fx/common-account"

# 4. gdm-password 里找不到 session 段：失败
fresh
grep -vE '^(session|@include common-session)' "$fx/gdm-password" >"$tmp/d/gdm-password"
check "没有 session 段时失败" fails_now

# 5. session 段以 @include common-session 开头（没有别的 session 行在它前面）：插在 include 之前
fresh
printf '#%%PAM-1.0\n@include common-auth\n@include common-account\n@include common-session\n' >"$tmp/d/gdm-password"
hooks >/dev/null
check "只有 @include common-session 时插在它之前" test "$(sed -n 4p "$tmp/d/gdm-password")" = "$SREQ"
check "  守卫、pam_namespace 紧随其后、在 @include common-session 之前" test "$(sed -n 5,6p "$tmp/d/gdm-password")" = "$GUARD
$NS"

# 6. -session（可选模块）也算 session 段的开头
fresh
printf '#%%PAM-1.0\n@include common-account\n-session optional pam_foo.so\nsession required pam_systemd.so\n@include common-session\n' >"$tmp/d/gdm-password"
hooks >/dev/null
check "-session 行也算 session 段的开头" test "$(sed -n 3p "$tmp/d/gdm-password")" = "$SREQ"
check "  守卫、pam_namespace 在直接写的 pam_systemd 之前" test "$(sed -n 5,6p "$tmp/d/gdm-password")" = "$GUARD
$NS"

# 7. 已经有 pam_namespace 或守卫的服务（发行版或别人加过）：失败、什么都不改
fresh
sed -i 's/^@include common-session$/session required pam_namespace.so\n&/' "$tmp/d/gdm-authd"
cp "$tmp/d/gdm-authd" "$tmp/gdm-authd.before"
check "gdm-authd 里已有 pam_namespace 时失败" fails_now
check "  gdm-authd 没被改" diff -q "$tmp/d/gdm-authd" "$tmp/gdm-authd.before"
check "  common-account 也没被改" diff -q "$tmp/d/common-account" "$fx/common-account"
check "  systemd-user 也没被改" diff -q "$tmp/v/systemd-user" "$fxv/systemd-user"
fresh
sed -i "s/^@include common-session-noninteractive\$/$GUARD\n&/" "$tmp/v/systemd-user"
check "systemd-user 里已有守卫时失败" fails_now
check "  gdm-password 没被改" diff -q "$tmp/d/gdm-password" "$fx/gdm-password"

# 8. session 段里没有 @include common-session、也没有 pam_systemd：找不到守卫与 pam_namespace 的插入点，失败
fresh
printf '#%%PAM-1.0\n@include common-account\nsession required pam_limits.so\n' >"$tmp/d/gdm-password"
check "gdm-password 没有 common-session 与 pam_systemd 时失败" fails_now
fresh
grep -vE 'common-session-noninteractive|pam_systemd' "$fxv/systemd-user" >"$tmp/v/systemd-user"
check "systemd-user 没有 common-session-noninteractive 与 pam_systemd 时失败" fails_now
check "  common-account 没被改" diff -q "$tmp/d/common-account" "$fx/common-account"

# 9. /etc/pam.d 里有 systemd-user（管理员放的、盖过 vendor 的那份）：改它，vendor 的不动
fresh
cp "$fxv/systemd-user" "$tmp/d/systemd-user"
hooks >/dev/null
check "/etc 的 systemd-user 盖过 vendor：改 /etc 那份" inserted_at3 "$tmp/d/systemd-user" "" "$fxv/systemd-user" "" "$su_inc"
check "  vendor 那份不动" diff -q "$tmp/v/systemd-user" "$fxv/systemd-user"

echo "pam-hooks-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]

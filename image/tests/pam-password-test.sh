#!/bin/bash
# pam-password.sh（mkosi.postinst.chroot 调）的改写与核对（本机与 CI 都跑，不需要 VM）：
#   bash image/tests/pam-password-test.sh
# 样本：tests/fixtures/pam-configs/authd 是 authd 0.6.1ubuntu0.1 的 deb 里的原文件；
# tests/fixtures/pam.d/common-{password,auth,account} 是 VM 165（20261015.12）上 pam-auth-update 生成的文件
# （authd 的 profile 已去掉 Password 段、还没加 --exec-env）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
pw=$here/../pam-password.sh
fx=$here/fixtures
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# 假的 dpkg-query：FAKE_AUTHD_VERSION 是装的 authd 版本，空就当没装（与真的一样退出 1）
mkdir -p "$tmp/bin"
cat >"$tmp/bin/dpkg-query" <<'SH'
#!/bin/bash
[ "$*" = "-W -f=\${Version} authd" ] || { echo "fake dpkg-query: 意外的参数 $*" >&2; exit 2; }
[ -n "${FAKE_AUTHD_VERSION:-}" ] || { echo "dpkg-query: no packages found matching authd" >&2; exit 1; }
printf '%s' "$FAKE_AUTHD_VERSION"
SH
chmod +x "$tmp/bin/dpkg-query"
export PATH="$tmp/bin:$PATH" FAKE_AUTHD_VERSION=0.6.1ubuntu0.1
fails=0 n=0
T=$'\t'
OLD='pam_authd_exec.so /usr/libexec/authd-pam'
NEW='pam_authd_exec.so --exec-env=CI=1 -- /usr/libexec/authd-pam'
SPLIT="password${T}[success=1 default=ignore]${T}pam_succeed_if.so quiet user !~ *@*"
AUTHD_PW="password${T}[success=2 ignore=ignore default=die authinfo_unavail=ignore]${T}$NEW"
UNIX_PW="password${T}[success=1 default=ignore]${T}pam_unix.so obscure yescrypt"

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
fails_with() { # <命令…>：失败（退出码非 0）才算成立
	! "$@" >/dev/null 2>&1
}
# 模拟 pam-auth-update 读改过的 profile：它把模块行原样抄进 common-*，所以 auth / account 的 authd 行换成带 --exec-env 的
fresh() {
	rm -rf "$tmp/d" "$tmp/p"
	cp -R "$fx/pam.d" "$tmp/d"
	mkdir -p "$tmp/p"
	cp "$fx/pam-configs/authd" "$tmp/p/authd"
	sed -i.bak "s#$OLD\$#$NEW#" "$tmp/d/common-auth" "$tmp/d/common-account"
	rm -f "$tmp/d"/*.bak
}
rules() { grep -E '^[[:space:]]*-?password[[:space:]]' "$1"; }

# 1. profile：上游原文 → 去掉 Password 段，Auth / Account 行加 --exec-env；别的行不动
fresh
check "profile：上游原文改写成功" bash "$pw" profile "$tmp/p/authd"
check "profile：没有 Password 段" bash -c "! grep -qE '^Password(-Type)?:' '$tmp/p/authd'"
check "profile：Auth 行带 --exec-env=CI=1" grep -qxF "${T}[success=end ignore=ignore default=die authinfo_unavail=ignore]${T}$NEW" "$tmp/p/authd"
check "profile：Account 行带 --exec-env=CI=1" grep -qxF "${T}[default=ignore success=ok]${T}$NEW" "$tmp/p/authd"
check "profile：没有不带 --exec-env 的 authd 行" bash -c "! grep -qF '$OLD' '$tmp/p/authd'"
check "profile：Session 段原样" grep -qxF "${T}optional${T}${T}${T}pam_mkhomedir.so" "$tmp/p/authd"
check "profile：再跑一次失败（已不是上游原文）" fails_with bash "$pw" profile "$tmp/p/authd"

# 2. profile：上游改了（Password 段的控制字段、多一行）就失败，等人看过再改期望文本
fresh
sed -i.bak '/^Password:/{n;s/default=die/default=bad/;}' "$tmp/p/authd"
check "profile：上游 Password 行变了就失败" fails_with bash "$pw" profile "$tmp/p/authd"
check "profile：失败时不动文件" grep -qF 'default=bad' "$tmp/p/authd"
fresh
printf '%s\n' "${T}optional${T}pam_foo.so" >>"$tmp/p/authd"
check "profile：上游多了一行就失败" fails_with bash "$pw" profile "$tmp/p/authd"

# 2b. profile：装的 authd 不是审过的版本（profile 文本相同也一样）、或没装，就失败、不动文件
fresh
check "profile：authd 换成 0.7.1 就失败" fails_with env FAKE_AUTHD_VERSION=0.7.1-1 bash "$pw" profile "$tmp/p/authd"
check "profile：版本不对时不动文件" diff -q "$tmp/p/authd" "$fx/pam-configs/authd"
check "profile：失败信息要求重验 CI=1" bash -c "FAKE_AUTHD_VERSION=0.6.4 bash '$pw' profile '$tmp/p/authd' 2>&1 | grep -qF 'CI=1'"
check "profile：没装 authd 就失败" fails_with env FAKE_AUTHD_VERSION= bash "$pw" profile "$tmp/p/authd"

# 3. apply：common-password 的 Primary 段开头按用户名分流
fresh
check "apply：成功" bash "$pw" apply "$tmp/d"
mapfile -t r < <(rules "$tmp/d/common-password")
check "apply：第 1 条是分流（pam_succeed_if quiet user !~ *@*）" test "${r[0]:-}" = "$SPLIT"
check "apply：第 2 条是 authd 的口令行（带 --exec-env）" test "${r[1]:-}" = "$AUTHD_PW"
check "apply：第 3 条是 pam_unix，不带 use_authtok" test "${r[2]:-}" = "$UNIX_PW"
check "apply：pam_unix 之后照旧是 pam_deny、pam_permit、pam_gnome_keyring" \
	test "${r[3]:-}|${r[4]:-}|${r[5]:-}|${#r[@]}" = "password${T}requisite${T}${T}${T}pam_deny.so|password${T}required${T}${T}${T}pam_permit.so|password${T}optional${T}pam_gnome_keyring.so |6"
# 跳转：分流成立（本机用户）跳过 1 条落在 pam_unix；authd 成功跳过 2 条（pam_unix、pam_deny）落在 pam_permit
skip() { sed -E 's/.*success=([0-9]+).*/\1/' <<<"${1:-success=99}"; }
check "apply：分流成立时落在 pam_unix" test "${r[$((0 + 1 + $(skip "${r[0]:-}")))]:-}" = "$UNIX_PW"
check "apply：authd 成功时落在 pam_permit" test "${r[$((1 + 1 + $(skip "${r[1]:-}")))]:-}" = "password${T}required${T}${T}${T}pam_permit.so"
check "apply：除了插的两行，文件与样本相同" diff -q <(grep -vxF -e "$SPLIT" -e "$AUTHD_PW" "$tmp/d/common-password") "$fx/pam.d/common-password"
check "apply：check 通过" bash "$pw" check "$tmp/d"
check "apply：再跑一次失败（不重复插）" fails_with bash "$pw" apply "$tmp/d"

# 4. apply / check 的反例
fresh
sed -i.bak 's/pam_unix.so obscure yescrypt/pam_unix.so obscure use_authtok try_first_pass yescrypt/' "$tmp/d/common-password"
check "apply：pam_unix 带 use_authtok 就失败" fails_with bash "$pw" apply "$tmp/d"
fresh
printf '%s\n' "password${T}optional${T}pam_foo.so" >>"$tmp/d/common-password"
check "apply：common-password 多了别的行就失败" fails_with bash "$pw" apply "$tmp/d"
fresh
cp "$fx/pam.d/common-auth" "$tmp/d/common-auth"
check "apply：common-auth 的 authd 行没带 --exec-env 就失败" fails_with bash "$pw" apply "$tmp/d"
fresh
cp "$fx/pam.d/common-account" "$tmp/d/common-account"
check "apply：common-account 的 authd 行没带 --exec-env 就失败" fails_with bash "$pw" apply "$tmp/d"
fresh
check "check：没插分流的 common-password 不通过" fails_with bash "$pw" check "$tmp/d"
fresh
bash "$pw" apply "$tmp/d" >/dev/null
sed -i.bak "s/user !~ \*@\*/user !~ *x*/" "$tmp/d/common-password"
check "check：分流条件被改就不通过" fails_with bash "$pw" check "$tmp/d"
# PAM 钩子（MASTERSOS_PAM_HOOKS=1）在 common-account 最前面插的 pam-check 不影响核对
fresh
bash "$pw" apply "$tmp/d" >/dev/null
# systemd-user 在 vendor 目录（拷一份，pam-hooks.sh 改副本）
mkdir -p "$tmp/vendor"
cp "$here/fixtures/pam.d-vendor/systemd-user" "$tmp/vendor/"
bash "$here/../pam-hooks.sh" "$tmp/d" "$tmp/vendor" >/dev/null
check "check：插了 PAM 钩子之后照样通过" bash "$pw" check "$tmp/d"

echo "$((n - fails))/$n"
[ "$fails" = 0 ]

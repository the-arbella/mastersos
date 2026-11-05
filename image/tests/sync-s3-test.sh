#!/bin/bash
# sync-s3.sh 的把关（不碰网络、不碰 AWS；用 tests/fake-aws 顶替 aws）：
#   bash image/tests/sync-s3-test.sh
# 用临时 gpg 钥匙造一棵 lab=no 的根（stable 两个版本、beta 一个、installer 一个，SHA256SUMS 签过），
# 跑真的 sync-s3.sh，查假 aws 的调用日志与假桶（顺序、缓存头、拒绝的情形）。
# 要 flock、gpg、gpgv、sha256sum：没有的机器（macOS）跳过；MASTERSOS_PUBLISH_TEST_REQUIRE=1（CI）时缺了算失败。
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
skip() {
	if [ "${MASTERSOS_PUBLISH_TEST_REQUIRE:-}" = 1 ]; then
		echo "sync-s3-test: FAIL（$*；MASTERSOS_PUBLISH_TEST_REQUIRE=1 不许跳过）" >&2
		exit 1
	fi
	echo "sync-s3-test: skip（$*）"
	exit 0
}
for t in flock gpg gpgv sha256sum; do
	command -v "$t" >/dev/null || skip "缺少 ${t}；在 Linux / CI 上跑"
done

tmp=$(mktemp -d)
trap 'gpgconf --homedir "$tmp/gpg" --kill all >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
mkdir -m 700 "$tmp/gpg"
gpg --homedir "$tmp/gpg" --batch --passphrase '' --quick-gen-key 'sync-s3-test' ed25519 sign never 2>/dev/null
gpg --homedir "$tmp/gpg" --export >"$tmp/pubring.pgp"
export MASTERSOS_PUBRING=$tmp/pubring.pgp MASTERSOS_TEST=1
export FAKE_AWS_LOG=$tmp/aws.log FAKE_AWS_BUCKET=$tmp/bucket
# 假 aws 在 PATH 最前面（脚本里叫 aws）
mkdir -p "$tmp/bin"
ln -s "$img/tests/fake-aws" "$tmp/bin/aws"
export PATH=$tmp/bin:$PATH
unset FAKE_AWS_FAIL MASTERSOS_AWS_PROFILE
export MASTERSOS_SYNC_SETTLE=0

BUCKET=mastersos-os-test
CDN=E1FAKEDIST
root=$tmp/release

# seal <目录>：文件（点开头的除外）全进 SHA256SUMS 并签
seal() {
	(cd "$1" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' ! -name '.*' -printf '%P\n' | LC_ALL=C sort | xargs sha256sum >SHA256SUMS)
	rm -f "$1/SHA256SUMS.gpg"
	gpg --homedir "$tmp/gpg" --batch --detach-sign --output "$1/SHA256SUMS.gpg" "$1/SHA256SUMS" 2>/dev/null
}
# blob <目录> <文件名> <内容>
blob() {
	mkdir -p "$1"
	printf '%s\n' "$3" >"$1/$2"
}
fresh_root() { # 重造 $root 与空桶、清空日志
	rm -rf "$root" "$FAKE_AWS_BUCKET" "$FAKE_AWS_LOG" "$FAKE_AWS_LOG.profile"
	mkdir -p "$root" "$FAKE_AWS_BUCKET"
	printf 'base=https://os.example.org\nlab=no\nmirror_s3=s3://%s\nmirror_cdn=%s\n' "$BUCKET" "$CDN" >"$root/mastersos-root.conf"
	blob "$root/stable" MastersOS_20261012.1_x86-64.efi uki1
	blob "$root/stable" MastersOS_20261012.1_x86-64.usr-x86-64.aaaa.raw.zst usr1
	blob "$root/stable" MastersOS_20261012.2_x86-64.efi uki2
	blob "$root/stable" MastersOS_20261012.2_x86-64.usr-x86-64.bbbb.raw.zst usr2
	blob "$root/beta" MastersOS_20261012.3_x86-64.efi uki3
	blob "$root/beta" MastersOS_20261012.3_x86-64.usr-x86-64.cccc.raw.zst usr3
	blob "$root/installer" MastersOS-installer_20261012.2_x86-64.img.zst inst2
	for d in stable beta installer; do seal "$root/$d"; done
	: >"$FAKE_AWS_LOG"
}
# shellcheck disable=SC2119,SC2120 # 多数调用不带参数
sync() { MASTERSOS_PUBLISH_ROOT=$root "$img/sync-s3.sh" "$@"; }
# 带环境变量跑：syncenv VAR=值… （最后一个参数之前都是环境）
syncenv() { env MASTERSOS_PUBLISH_ROOT="$root" "$@" "$img/sync-s3.sh"; }

t_fail=0 t_n=0
check() { # check <名字> <条件命令…>
	t_n=$((t_n + 1))
	if "${@:2}"; then echo "ok   $1"; else
		echo "FAIL $1" >&2
		t_fail=$((t_fail + 1))
	fi
}
# expect <名字> <ok|refused> <输出里的片段> <命令…>（输出留在 $out）
out=""
expect() {
	local name=$1 want=$2 frag=$3 rc=0
	shift 3
	out=$("$@" 2>&1) || rc=$?
	t_n=$((t_n + 1))
	if { [ "$want" = ok ] && [ $rc = 0 ]; } || { [ "$want" = refused ] && [ $rc != 0 ] && grep -qF -- "$frag" <<<"$out"; }; then
		echo "ok   ${name}（rc=${rc}）"
	else
		echo "FAIL ${name}：期望 ${want}，rc=${rc}，输出：" >&2
		printf '%s\n' "$out" | sed 's/^/    /' >&2
		t_fail=$((t_fail + 1))
	fi
}
out_has() { grep -qF -- "$1" <<<"$out"; }
log_has() { grep -qE -- "$1" "$FAKE_AWS_LOG"; }
log_hasnt() { ! log_has "$1"; }
log_empty() { [ ! -s "$FAKE_AWS_LOG" ]; }
# 日志里第 n 条匹配 <正则> 的行号
line_first() { grep -nE -- "$1" "$FAKE_AWS_LOG" | head -n 1 | cut -d: -f1; }
line_last() { grep -nE -- "$1" "$FAKE_AWS_LOG" | tail -n 1 | cut -d: -f1; }
before() { # before <正则 A 的最后一条> <正则 B 的第一条>：A 全在 B 之前
	local a b
	a=$(line_last "$1")
	b=$(line_first "$2")
	[ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}
meta() { sed -n "s/^$2=//p" "$FAKE_AWS_BUCKET/$1.meta"; }
bucket_files() { find "$FAKE_AWS_BUCKET" -type f ! -name '*.meta' | wc -l; }
bucket_has() { [ -e "$FAKE_AWS_BUCKET/$1" ]; }
bucket_hasnt() { ! bucket_has "$1"; }
same_bytes() { cmp -s "$root/$1" "$FAKE_AWS_BUCKET/$1"; }

# --- 第一次同步：顺序与头 ---------------------------------------------------------------
fresh_root
expect "第一次同步" ok "" sync
check "  桶里 13 个对象（stable 4 个文件、beta 2、installer 1，各加清单与签名）" test "$(bucket_files)" = 13
sums_order() { # 每个目录：清单在该目录所有带版本号文件之后；.gpg 在清单之后
	local d lastv s g
	for d in stable beta installer; do
		lastv=$(grep -nE "^s3 cp $d/MastersOS" "$FAKE_AWS_LOG" | tail -n 1 | cut -d: -f1)
		s=$(line_first "^s3 cp $d/SHA256SUMS\$")
		g=$(line_first "^s3 cp $d/SHA256SUMS.gpg\$")
		[ -n "$lastv" ] && [ -n "$s" ] && [ -n "$g" ] || return 1
		if [ "$1" = versioned ]; then [ "$lastv" -lt "$s" ] || return 1; else [ "$s" -lt "$g" ] || return 1; fi
	done
}
check "sync_uploads_versioned_before_sums：每个目录的 SHA256SUMS 排在该目录所有带版本号文件的 s3 cp 之后" sums_order versioned
check "sync_sums_before_gpg：同一目录 SHA256SUMS 在 SHA256SUMS.gpg 之前" sums_order gpg
check "  所有 head-object 都在第一个 s3 cp 之前（冲突在传任何东西之前发现）" before '^s3api head-object' '^s3 cp'
check "  失效在最后一个 s3 cp 之后" before '^s3 cp' '^cloudfront create-invalidation'
check "  失效的路径正好是 /stable/SHA256SUMS* /beta/SHA256SUMS* /installer/SHA256SUMS*" log_has '^cloudfront paths /stable/SHA256SUMS\* /beta/SHA256SUMS\* /installer/SHA256SUMS\* $'
check "  失效的是配置里的分发" log_has "^cloudfront create-invalidation $CDN\$"
check "  profile 默认 mastersos-publish" test "$(sort -u "$FAKE_AWS_LOG.profile")" = mastersos-publish
V=stable/MastersOS_20261012.1_x86-64.efi
check "sync_cache_headers：带版本号的文件 immutable 一年" test "$(meta $V cache-control)" = 'public, max-age=31536000, immutable'
check "  带版本号的文件 octet-stream" test "$(meta $V content-type)" = application/octet-stream
check "  带版本号的文件记着 sha256" test "$(meta $V sha256)" = "$(sha256sum <"$root/$V" | cut -d' ' -f1)"
manifest_headers() {
	local d
	for d in stable beta installer; do
		[ "$(meta $d/SHA256SUMS cache-control)" = 'public, max-age=60' ] || return 1
		[ "$(meta $d/SHA256SUMS content-type)" = text/plain ] || return 1
		[ "$(meta $d/SHA256SUMS.gpg cache-control)" = 'public, max-age=60' ] || return 1
		[ "$(meta $d/SHA256SUMS.gpg content-type)" = application/pgp-signature ] || return 1
	done
}
check "sync_cache_headers：清单 max-age=60、text/plain；签名 application/pgp-signature" manifest_headers
check "  桶里的字节与本地相同" same_bytes stable/SHA256SUMS
check "sync_never_uploads_root_conf：日志里没有 mastersos-root.conf、.lock" log_hasnt 'mastersos-root\.conf|\.lock'
check "  打印了每个目录传了几个" out_has 'stable：传 4 个、跳过 0 个、删 0 个'

# --- 第二次：跳过相同的 ------------------------------------------------------------------
: >"$FAKE_AWS_LOG"
expect "sync_skips_identical：连跑第二次" ok "" sync
check "  第二次没有带版本号文件的 s3 cp" log_hasnt '^s3 cp [a-z]+/MastersOS'
check "  只有清单：6 次 cp（3 个目录 × 2）" test "$(grep -c '^s3 cp' "$FAKE_AWS_LOG")" = 6
check "  有失效" log_has '^cloudfront wait'
check "  打印了跳过几个" out_has 'stable：传 0 个、跳过 4 个、删 0 个'

# --- 删除：旧版本从本地根里没了，失效完成之后才删 ----------------------------------------------
rm -f "$root"/stable/MastersOS_20261012.1_x86-64.*
seal "$root/stable"
: >"$FAKE_AWS_LOG"
expect "旧版本从本地根里删掉后同步" ok "" sync
check "  桶里的旧版本删了、新的还在" sh -c "! [ -e '$FAKE_AWS_BUCKET/$V' ] && [ -e '$FAKE_AWS_BUCKET/stable/MastersOS_20261012.2_x86-64.efi' ]"
check "sync_deletes_only_after_invalidation_completed：所有 s3 rm 在 wait invalidation-completed 之后" before '^cloudfront wait' '^s3 rm'
check "  新清单在删之前就已经换上" same_bytes stable/SHA256SUMS
check "  删了 2 个" out_has 'stable：传 0 个、跳过 2 个、删 2 个'
# 桶里别的前缀不碰
mkdir -p "$FAKE_AWS_BUCKET/other"
echo x >"$FAKE_AWS_BUCKET/other/keep"
echo y >"$FAKE_AWS_BUCKET/stray-top-level"
: >"$FAKE_AWS_LOG"
expect "桶里有 stable/ beta/ installer/ 之外的对象" ok "" sync
check "  别的前缀不碰" sh -c "[ -e '$FAKE_AWS_BUCKET/other/keep' ] && [ -e '$FAKE_AWS_BUCKET/stray-top-level' ]"
check "  也不列" log_hasnt 'list-objects-v2 (other|)$'
echo z >"$FAKE_AWS_BUCKET/beta/MastersOS_20260101.1_x86-64.efi"
expect "桶里多出 beta/ 下不在清单里的对象" ok "" sync
check "  删了" bucket_hasnt beta/MastersOS_20260101.1_x86-64.efi

# --- 失效失败：不删任何东西 ----------------------------------------------------------------
fresh_root
sync >/dev/null 2>&1
rm -f "$root"/stable/MastersOS_20261012.1_x86-64.*
seal "$root/stable"
: >"$FAKE_AWS_LOG"
expect "FAKE_AWS_FAIL=wait：等不到失效完成 → 退出非 0" refused "没删任何东西" syncenv FAKE_AWS_FAIL=wait
check "  没有任何 s3 rm" log_hasnt '^s3 rm'
check "  旧文件还在" bucket_has "$V"
: >"$FAKE_AWS_LOG"
expect "FAKE_AWS_FAIL=create-invalidation：失效失败" refused "没删任何东西" syncenv FAKE_AWS_FAIL=create-invalidation
check "  没有任何 s3 rm" log_hasnt '^s3 rm'
expect "重跑" ok "" sync
check "  这回删了" bucket_hasnt "$V"

# --- 中断：桶里的清单还是上一次的 ------------------------------------------------------------
fresh_root
sync >/dev/null 2>&1
old_sums=$(sha256sum <"$FAKE_AWS_BUCKET/stable/SHA256SUMS")
blob "$root/stable" MastersOS_20261012.4_x86-64.efi uki4
seal "$root/stable"
: >"$FAKE_AWS_LOG"
expect "sync_interrupted_leaves_old_sums：FAKE_AWS_FAIL=cp 在第一个带版本号的文件上失败" refused "重跑" syncenv FAKE_AWS_FAIL=cp
check "  桶里的 stable/SHA256SUMS 仍是上一次同步的字节" test "$(sha256sum <"$FAKE_AWS_BUCKET/stable/SHA256SUMS")" = "$old_sums"
check "  没有失效、没有删" log_hasnt '^(cloudfront|s3 rm)'
expect "  重跑补上" ok "" sync
check "  桶里的清单是新的" same_bytes stable/SHA256SUMS

# --- 同名对象字节不同：拒绝 ----------------------------------------------------------------------
fresh_root
mkdir -p "$FAKE_AWS_BUCKET/stable"
echo old-bytes >"$FAKE_AWS_BUCKET/stable/MastersOS_20261012.2_x86-64.efi"
printf 'cache-control=x\ncontent-type=y\nsha256=%s\n' "$(printf 'other\n' | sha256sum | cut -d' ' -f1)" >"$FAKE_AWS_BUCKET/stable/MastersOS_20261012.2_x86-64.efi.meta"
expect "sync_refuses_changed_bytes_for_existing_key" refused "同名对象字节不同" sync
check "  日志里没有任何 s3 cp / rm / 失效" log_hasnt '^(s3 cp|s3 rm|cloudfront)'
check "  桶里的旧对象没动" test "$(cat "$FAKE_AWS_BUCKET/stable/MastersOS_20261012.2_x86-64.efi")" = old-bytes
rm -f "$FAKE_AWS_BUCKET/stable/MastersOS_20261012.2_x86-64.efi.meta"
expect "  同名对象没有 sha256 metadata 同样拒绝" refused "同名对象字节不同" sync

# --- 本地树不可信：一个字节都不动 -----------------------------------------------------------------
fresh_root
printf 'x' >>"$root/stable/SHA256SUMS"
expect "sync_refuses_unsigned_local_tree：stable/SHA256SUMS 改了一个字节" refused "验不过" sync
check "  日志为空" log_empty
fresh_root
rm "$root/stable/SHA256SUMS.gpg"
expect "缺签名" refused "没签过" sync
check "  日志为空" log_empty
fresh_root
echo tampered >"$root/beta/MastersOS_20261012.3_x86-64.efi"
expect "本地文件与签过的 SHA256SUMS 对不上" refused "对不上" sync
check "  日志为空" log_empty
fresh_root
rm "$root/stable/MastersOS_20261012.2_x86-64.efi"
expect "SHA256SUMS 列着的文件不在" refused "文件不在" sync
check "  日志为空" log_empty
fresh_root
gpg --homedir "$tmp/gpg" --batch --passphrase '' --quick-gen-key 'other signer' ed25519 sign never 2>/dev/null
other=$(gpg --homedir "$tmp/gpg" --list-keys --with-colons 'other signer' | awk -F: '/^fpr/ {print $10; exit}')
rm "$root/installer/SHA256SUMS.gpg"
gpg --homedir "$tmp/gpg" --batch --local-user "$other" --detach-sign --output "$root/installer/SHA256SUMS.gpg" "$root/installer/SHA256SUMS" 2>/dev/null
expect "installer 的清单由别的钥匙签" refused "验不过" sync
check "  日志为空（stable、beta 也没传）" log_empty

# --- 根声明 --------------------------------------------------------------------------------------
fresh_root
printf 'base=http://192.0.2.99/mastersos\nlab=yes\n' >"$root/mastersos-root.conf"
expect "sync_refuses_lab_root" refused "lab=yes 的根" sync
printf 'base=http://192.0.2.99/mastersos\nlab=yes\nmirror_s3=s3://%s\nmirror_cdn=%s\n' "$BUCKET" "$CDN" >"$root/mastersos-root.conf"
expect "mirror_keys_only_on_release_root：lab=yes 带 mirror_s3" refused "只许 lab=no" sync
printf 'base=https://os.example.org\nlab=no\nmirror_s3=s3://%s\n' "$BUCKET" >"$root/mastersos-root.conf"
expect "mirror_keys_both_or_none：只有 mirror_s3" refused "要么都写" sync
printf 'base=https://os.example.org\nlab=no\nmirror_cdn=%s\n' "$CDN" >"$root/mastersos-root.conf"
expect "mirror_keys_both_or_none：只有 mirror_cdn" refused "要么都写" sync
printf 'base=https://os.example.org\nlab=no\nmirror_s3=s3://%s\nmirror_cdn=%s\nmirror_cdn=%s\n' "$BUCKET" "$CDN" "$CDN" >"$root/mastersos-root.conf"
expect "mirror_cdn 写了两次" refused "出现了不止一次" sync
printf 'base=https://os.example.org\nlab=no\n' >"$root/mastersos-root.conf"
expect "lab=no 的根没声明镜像" refused "没有 mirror_s3" sync
printf 'base=https://os.example.org\nlab=no\nmirror_s3=https://x/y\nmirror_cdn=%s\n' "$CDN" >"$root/mastersos-root.conf"
expect "mirror_s3 不是 s3://桶" refused "应形如 s3://" sync
expect "未知参数" refused "用法" sync --force
check "  这些拒绝都没碰 aws" log_empty

# --- 别的 ---------------------------------------------------------------------------------------
fresh_root
expect "MASTERSOS_AWS_PROFILE 换 profile" ok "" syncenv MASTERSOS_AWS_PROFILE=other
check "  aws 看到的是 other" test "$(sort -u "$FAKE_AWS_LOG.profile")" = other
fresh_root
expect "MASTERSOS_AWS_PROFILE empty: environment credentials" ok "credentials from the environment" syncenv MASTERSOS_AWS_PROFILE= AWS_PROFILE=stale
check "  aws sees no profile" test "$(sort -u "$FAKE_AWS_LOG.profile")" = ""
check "  the log names the environment credentials" out_has "credentials from the environment"
fresh_root
mkdir -p "$root/.tmp-publish"
echo junk >"$root/.tmp-publish/junk"
echo junk >"$root/stable/.SHA256SUMS.new"
: >"$root/.lock"
expect "根里有临时目录、残留与 .lock" ok "" sync
check "  都没传" log_hasnt 'tmp-publish|\.SHA256SUMS\.new|\.lock'
rm -rf "$root/beta" "$root/installer"
mkdir -p "$FAKE_AWS_BUCKET/beta"
echo keep >"$FAKE_AWS_BUCKET/beta/MastersOS_x.efi"
: >"$FAKE_AWS_LOG"
expect "本地没有 beta/ 与 installer/：只同步 stable" ok "" sync
check "  桶里 beta/ 不碰" bucket_has beta/MastersOS_x.efi
check "  也不列" log_hasnt 'list-objects-v2 (beta|installer)/'

# --- dry-run ------------------------------------------------------------------------------------
fresh_root
sync >/dev/null 2>&1
rm -f "$root"/stable/MastersOS_20261012.1_x86-64.*
blob "$root/stable" MastersOS_20261012.5_x86-64.efi uki5
seal "$root/stable"
snap() { (cd "$FAKE_AWS_BUCKET" && find . -type f -exec sha256sum {} + | LC_ALL=C sort); }
snap_before=$(snap)
: >"$FAKE_AWS_LOG"
expect "sync_dry_run_changes_nothing" ok "" sync --dry-run
only_reads() { [ -s "$FAKE_AWS_LOG" ] && ! grep -qvE '^s3api (head-object|list-objects-v2)' "$FAKE_AWS_LOG"; }
check "  日志里只有 head-object 与 list-objects-v2" only_reads
check "  桶一个字节没变" test "$(snap)" = "$snap_before"
check "  打印了要传的新文件" out_has '[dry-run] 传 stable/MastersOS_20261012.5_x86-64.efi'
check "  打印了要删的旧文件" out_has "[dry-run] 删 $V"

# --- 考试扩展 chrome/（计划 9 Task 8）：名字固定、内容可变，不走「同名不同字节就拒绝」-------------------------------
fresh_root
blob "$root/chrome" mastersos-kiosk-ext.crx crx-v1
blob "$root/chrome" updates.xml upd-v1
seal "$root/chrome"
: >"$FAKE_AWS_LOG"
expect "chrome/：第一次同步" ok "" sync
check "  crx 与 updates.xml 都传了、字节相同" sh -c "cmp -s '$root/chrome/mastersos-kiosk-ext.crx' '$FAKE_AWS_BUCKET/chrome/mastersos-kiosk-ext.crx' && cmp -s '$root/chrome/updates.xml' '$FAKE_AWS_BUCKET/chrome/updates.xml'"
check "  crx 在 updates.xml 之前" before '^s3 cp chrome/mastersos-kiosk-ext\.crx$' '^s3 cp chrome/updates\.xml$'
check "  updates.xml 在 chrome/SHA256SUMS 之前" before '^s3 cp chrome/updates\.xml$' '^s3 cp chrome/SHA256SUMS$'
check "  不查 head-object（不按带版本号的文件对待）" log_hasnt '^s3api head-object chrome/'
check "  max-age=300、类型对" sh -c "[ \"\$(sed -n 's/^cache-control=//p' '$FAKE_AWS_BUCKET/chrome/updates.xml.meta')\" = 'public, max-age=300' ] && [ \"\$(sed -n 's/^content-type=//p' '$FAKE_AWS_BUCKET/chrome/updates.xml.meta')\" = application/xml ] && [ \"\$(sed -n 's/^content-type=//p' '$FAKE_AWS_BUCKET/chrome/mastersos-kiosk-ext.crx.meta')\" = application/x-chrome-extension ]"
check "  失效 /chrome/*" log_has '^cloudfront paths .*/chrome/\* $'
blob "$root/chrome" mastersos-kiosk-ext.crx crx-v2
blob "$root/chrome" updates.xml upd-v2
seal "$root/chrome"
: >"$FAKE_AWS_LOG"
expect "chrome/：新版本（同名、字节不同）照样传" ok "" sync
check "  桶里换成了新的" sh -c "cmp -s '$root/chrome/updates.xml' '$FAKE_AWS_BUCKET/chrome/updates.xml' && cmp -s '$root/chrome/mastersos-kiosk-ext.crx' '$FAKE_AWS_BUCKET/chrome/mastersos-kiosk-ext.crx'"
echo z >"$FAKE_AWS_BUCKET/chrome/old.crx"
expect "chrome/：桶里多出的对象" ok "" sync
check "  删了" bucket_hasnt chrome/old.crx
echo tampered >"$root/chrome/updates.xml"
: >"$FAKE_AWS_LOG"
expect "chrome/：updates.xml 与签过的 SHA256SUMS 对不上" refused "对不上" sync
check "  日志为空" log_empty
blob "$root/chrome" updates.xml upd-v2
blob "$root/chrome" evil.js x
seal "$root/chrome"
expect "chrome/：SHA256SUMS 列着别的文件" refused "chrome/ 里只许" sync
check "  日志为空" log_empty

echo "sync-s3-test: $((t_n - t_fail))/$t_n 通过"
[ "$t_fail" = 0 ]

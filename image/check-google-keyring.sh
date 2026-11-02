#!/bin/bash
# 核对 Google 的 apt 签名 keyring（keys/google-chrome-keyring.gpg）：mkosi.finalize 构建时与 tests/check-tree.sh（CI）都跑。
#   check-google-keyring.sh <keyring>   → 不符就打印原因、退出 1
# gpgv 信任 keyring 里的每一把钥匙（也不看过期与吊销），所以要求：
#   - 恰好一把主钥，指纹等于 Google 在 https://www.google.com/linuxrepositories/ 公布的 Active (Primary)；
#   - 子钥都只能签名（s）。
# 每次发镜像前按 docs/keys.md 重新取这个文件，这里是唯一的自动关卡。
set -euo pipefail
want=EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796
[ $# -eq 1 ] || {
	echo "用法：check-google-keyring.sh <keyring>" >&2
	exit 2
}
command -v gpg >/dev/null || {
	echo "check-google-keyring: 没有 gpg" >&2
	exit 1
}
home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
colons=$(GNUPGHOME=$home gpg --show-keys --with-colons "$1" 2>/dev/null) || {
	echo "check-google-keyring: gpg 读不了 $1" >&2
	exit 1
}
# pub 行之后紧跟的 fpr 是主钥指纹；sub 的第 12 列是用途
verdict=$(printf '%s\n' "$colons" | awk -F: -v want="$want" '
	$1 == "pub" { npub++; after_pub = 1; next }
	$1 == "fpr" && after_pub { fpr = $10; after_pub = 0; next }
	$1 == "sub" && $12 != "s" { badsub = badsub " " $5 "(" $12 ")" }
	{ after_pub = 0 }
	END {
		if (npub != 1) { print "主钥应恰好一把，实际 " npub + 0 " 把"; exit }
		if (fpr != want) { print "主钥指纹是「" fpr "」，不是 Google 公布的 " want; exit }
		if (badsub != "") { print "有不止用于签名的子钥：" badsub; exit }
		print "ok"
	}')
if [ "$verdict" != ok ]; then
	echo "check-google-keyring: ${1}：$verdict" >&2
	exit 1
fi
echo "check-google-keyring: ${1}：主钥 ${want}，子钥都只签名"

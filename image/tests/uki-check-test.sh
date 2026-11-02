#!/bin/bash
# UKI 的 PCR 签名把关（keyset_check_uki → uki-pcrsig-check）的测试，不需要 VM：
#   bash image/tests/uki-check-test.sh
# build.sh（mkosi 之后、写 build-info 之前）、make-installer.sh（放进 U 盘的主 UKI）与 publish/promote 的 check_uki
# 都只经 keyset_check_uki 把关（4b Task 4 复审 I1）。这里直接测它，再把一个四阶段签名的 UKI 喂给真的
# make-installer.sh，看它在出 U 盘之前拒绝（缺 ukify / sbverify / mtools 等工具的机器上跳过这一段）。
# build.sh 要真的 mkosi，不在这里跑；它确实在写 build-info 之前调 keyset_check_uki 由 check-tree.sh 第 13 条核对。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
img=$(cd "$here/.." && pwd)
for t in python3 openssl sha256sum; do
	command -v "$t" >/dev/null || {
		echo "uki-check-test: skip（缺少 ${t}）"
		exit 0
	}
done
# shellcheck source-path=SCRIPTDIR source=../keyset.sh
. "$img/keyset.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

pkfp_of() { openssl rsa -pubin -in "$1" -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
# fake <输出> <PEM> <签名条数> [阶段]
fake() { python3 -I "$here/make-fake-uki.py" "$1" "$2" "$(pkfp_of "$2")" "$3" "${4:-enter-initrd}"; }

# expect <名字> <ok|refused> <refused 时输出里该有的片段> <命令…>
expect() {
	local name=$1 want=$2 frag=$3 out rc=0
	shift 3
	out=$("$@" 2>&1) || rc=$?
	n=$((n + 1))
	if { [ "$want" = ok ] && [ "$rc" = 0 ]; } || { [ "$want" = refused ] && [ "$rc" != 0 ] && grep -qF -- "$frag" <<<"$out"; }; then
		echo "ok   ${name}（rc=${rc}）"
	else
		echo "FAIL ${name}：期望 ${want}，rc=${rc}，输出：" >&2
		printf '%s\n' "$out" | sed 's/^/    /' >&2
		fails=$((fails + 1))
	fi
}

rel=$(keyset_pub release)/tpm2-pcr-public-key.pem
lab=$(keyset_pub lab)/tpm2-pcr-public-key.pem
rel_old=$(keyset_retired release)/tpm2-pcr-public-key-4phase.pem

fake "$tmp/good.efi" "$rel" 1
fake "$tmp/four.efi" "$rel" 4
fake "$tmp/leave.efi" "$rel" 1 enter-initrd:leave-initrd
fake "$tmp/ready.efi" "$rel" 1 enter-initrd:leave-initrd:sysinit:ready
fake "$tmp/retired.efi" "$rel_old" 1
fake "$tmp/labkey.efi" "$lab" 1
fake "$tmp/lab-good.efi" "$lab" 1

expect "一条签名、enter-initrd、当前正式钥匙" ok "" keyset_check_uki "$tmp/good.efi" release
expect "四阶段签名（当前钥匙）" refused "应只有一条 sha256 签名" keyset_check_uki "$tmp/four.efi" release
expect "一条签名、阶段 leave-initrd" refused "不是 enter-initrd 阶段的" keyset_check_uki "$tmp/leave.efi" release
expect "一条签名、阶段 ready" refused "不是 enter-initrd 阶段的" keyset_check_uki "$tmp/ready.efi" release
expect "退役的 PCR 钥匙" refused "退役的 PCR 钥匙" keyset_check_uki "$tmp/retired.efi" release
expect "lab 钥匙签的 UKI 当正式的" refused ".pcrpkey 不符" keyset_check_uki "$tmp/labkey.efi" release
expect "lab 钥匙、lab 组" ok "" keyset_check_uki "$tmp/lab-good.efi" lab
expect "组名不对" refused "lab 或 release" keyset_check_uki "$tmp/good.efi" other

# --- 解析上的边角情形（与 systemd-stub 的读法不一致时一律拒绝，fail closed）-----------------------------
P=$(pkfp_of "$rel")
GOODPOL=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["p"])' <(python3 -I - "$here" "$rel" <<'PY2'
import importlib.machinery, importlib.util, json, os, sys
sys.dont_write_bytecode = True
l = importlib.machinery.SourceFileLoader("c", os.path.join(sys.argv[1], "..", "uki-pcrsig-check"))
sp = importlib.util.spec_from_loader("c", l); c = importlib.util.module_from_spec(sp); l.exec_module(c)
pem = open(sys.argv[2], "rb").read()
print(json.dumps({"p": c.policy_pcr11(c.pcr11_enter_initrd({".linux": b"fake-linux-kernel", ".pcrpkey": pem})).hex()}))
PY2
))
raw() { FAKE_PCRSIG_RAW=$2 fake "$tmp/$1.efi" "$rel" 1; }
E='{"pcrs":[11],"pkfp":"'"$P"'","pol":"'"$GOODPOL"'","sig":"AA=="}'
raw json-ok '{"sha256":['"$E"']}'
expect "手写的合格 .pcrsig" ok "" keyset_check_uki "$tmp/json-ok.efi" release
raw dupkey '{"sha256":['"$E"'],"sha256":['"$E"']}'
expect "JSON 里重复的键（顶层）" refused "重复的键" keyset_check_uki "$tmp/dupkey.efi" release
raw dupkey2 '{"sha256":[{"pcrs":[11],"pkfp":"'"$P"'","pol":"00","pol":"'"$GOODPOL"'","sig":"AA=="}]}'
expect "JSON 里重复的键（条目里，后一个才是对的）" refused "重复的键" keyset_check_uki "$tmp/dupkey2.efi" release
raw sha1 '{"sha256":['"$E"'],"sha1":['"$E"','"$E"','"$E"','"$E"']}'
expect "另带一个 sha1 bank（四条）" refused "只有 sha256 一个 bank" keyset_check_uki "$tmp/sha1.efi" release
raw sha384 '{"sha256":['"$E"'],"sha384":['"$E"']}'
expect "另带一个 sha384 bank" refused "只有 sha256 一个 bank" keyset_check_uki "$tmp/sha384.efi" release
raw extrakey '{"sha256":[{"pcrs":[11],"pkfp":"'"$P"'","pol":"'"$GOODPOL"'","sig":"AA==","phase":"enter-initrd:leave-initrd"}]}'
expect "条目里多一个键（phase 字段）" refused "键应恰好是" keyset_check_uki "$tmp/extrakey.efi" release
raw pcrs '{"sha256":[{"pcrs":[11,15],"pkfp":"'"$P"'","pol":"'"$GOODPOL"'","sig":"AA=="}]}'
expect "签名覆盖 PCR 11 以外的 PCR" refused "只覆盖 PCR 11" keyset_check_uki "$tmp/pcrs.efi" release
raw polcase '{"sha256":[{"pcrs":[11],"pkfp":"'"$P"'","pol":"'"$(tr a-f A-F <<<"$GOODPOL")"'","sig":"AA=="}]}'
expect "pol 大写（不做大小写归一）" refused "不是 enter-initrd 阶段的" keyset_check_uki "$tmp/polcase.efi" release
raw polspace '{"sha256":[{"pcrs":[11],"pkfp":"'"$P"'","pol":" '"$GOODPOL"'","sig":"AA=="}]}'
expect "pol 前面带空格（不做 trim）" refused "不是 enter-initrd 阶段的" keyset_check_uki "$tmp/polspace.efi" release
raw notobj '['"$E"']'
expect ".pcrsig 不是对象" refused "不是 JSON 对象" keyset_check_uki "$tmp/notobj.efi" release
raw broken '{"sha256":['
expect ".pcrsig 是坏的 JSON" refused "不是合格的 JSON" keyset_check_uki "$tmp/broken.efi" release
FAKE_TAIL='\0\0\0\0' raw tailnul '{"sha256":['"$E"']}'
expect "JSON 之后只有 NUL 补齐" ok "" keyset_check_uki "$tmp/tailnul.efi" release
FAKE_TAIL='{"sha256":[]}' raw tailjunk '{"sha256":['"$E"']}'
expect "JSON 之后还有别的数据" refused "不是合格的 JSON" keyset_check_uki "$tmp/tailjunk.efi" release
FAKE_TAIL='\0x' raw midnul '{"sha256":['"$E"']}'
expect ".pcrsig 中间有 NUL" refused "中间有 NUL" keyset_check_uki "$tmp/midnul.efi" release
FAKE_DUP=.pcrsig fake "$tmp/dup-pcrsig.efi" "$rel" 1
expect "两个 .pcrsig 段" refused "2 个 .pcrsig" keyset_check_uki "$tmp/dup-pcrsig.efi" release
FAKE_DUP=.pcrpkey fake "$tmp/dup-pcrpkey.efi" "$rel" 1
expect "两个 .pcrpkey 段" refused "2 个 .pcrpkey" keyset_check_uki "$tmp/dup-pcrpkey.efi" release
FAKE_DUP=.linux fake "$tmp/dup-linux.efi" "$rel" 1
expect "两个 .linux 段" refused "2 个 .linux" keyset_check_uki "$tmp/dup-linux.efi" release
# profile 与基础段（systemd-stub：profile 自己的段盖过基础段，没有就继承）
FAKE_LAYOUT=inherit fake "$tmp/inherit.efi" "$rel" 1
expect "profile 继承基础段的 .pcrsig（enter-initrd，按继承后的段算）" ok "" keyset_check_uki "$tmp/inherit.efi" release
FAKE_LAYOUT=inherit fake "$tmp/inherit-4.efi" "$rel" 4
expect "profile 继承的基础段 .pcrsig 有四条" refused "只有一条 sha256" keyset_check_uki "$tmp/inherit-4.efi" release
FAKE_LAYOUT=inherit fake "$tmp/inherit-leave.efi" "$rel" 1 enter-initrd:leave-initrd
expect "profile 继承的基础段 .pcrsig 签的是 leave-initrd" refused "不是 enter-initrd 阶段的" keyset_check_uki "$tmp/inherit-leave.efi" release
FAKE_LAYOUT=override-bad fake "$tmp/override.efi" "$rel" 1 enter-initrd:leave-initrd
expect "基础段签名对、profile 自己的签名盖过它且签的是 leave-initrd" refused "不是 enter-initrd 阶段的" keyset_check_uki "$tmp/override.efi" release
FAKE_LAYOUT=unused-base fake "$tmp/unused.efi" "$rel" 1
expect "基础段多一份没人用的 .pcrsig" refused "没有 profile 使用" keyset_check_uki "$tmp/unused.efi" release
# 段名截到第一个 NUL（复审 N2，与 systemd-stub 相同）：".linux\0z" 就是 .linux——单独出现时照常量它、通过；
# 再加一个真的 .linux 就是两个 .linux，拒绝
FAKE_LINUX_NAME='.linux\0z' fake "$tmp/nulname.efi" "$rel" 1
expect "段名 .linux\\0z（截到 NUL 就是 .linux）" ok "" keyset_check_uki "$tmp/nulname.efi" release
FAKE_DUP='.linux\0z' FAKE_LINUX_NAME='.linux\0z' fake "$tmp/nulname-dup.efi" "$rel" 1
expect "段名 .linux\\0z 出现两次（都是 .linux）" refused "2 个 .linux" keyset_check_uki "$tmp/nulname-dup.efi" release
printf 'MZ' >"$tmp/trunc.efi"
expect "截断的 PE" refused "check_uki" keyset_check_uki "$tmp/trunc.efi" release

# --- 真构建的样本（复审 N3：不经 make-fake-uki.py，期望的 pol 来自 systemd-measure 当时的真签名）-----------------
# tests/fixtures/uki-v1-measured.json：v1（20261015.4）UKI 每个 profile 实际量的各段 sha256 与那个 profile 的真 .pcrsig。
# 用校验器的 pcr11_from_digests / policy_pcr11 从段摘要算 enter-initrd 的策略，必须等于真签名里的 pol；换成别的阶段就不等。
# .pcrpkey 的摘要与 pkfp 也要对上仓库的 lab 公钥。
n=$((n + 1))
# The sample was signed on 20261015 with the lab key of that day, rotated on 2026-10-31.
lab_v1=$(keyset_retired lab)/tpm2-pcr-public-key-20261015.pem
if out=$(python3 -I - "$here/fixtures/uki-v1-measured.json" "$img/uki-pcrsig-check" "$lab_v1" "$(pkfp_of "$lab_v1")" <<'PY2' 2>&1
import hashlib, importlib.machinery, importlib.util, json, sys
sys.dont_write_bytecode = True
fx, chk_path, pem_path, pkfp = sys.argv[1:5]
l = importlib.machinery.SourceFileLoader("c", chk_path); sp = importlib.util.spec_from_loader("c", l)
c = importlib.util.module_from_spec(sp); l.exec_module(c)
j = json.load(open(fx))
pem = open(pem_path, "rb").read()
assert len(j["profiles"]) == 2, "应有两个 profile（主系统、恢复出厂）"
for i, p in enumerate(j["profiles"]):
    d = {k: bytes.fromhex(v) for k, v in p["measured_sha256"].items()}
    assert d[".pcrpkey"] == hashlib.sha256(pem).digest(), f"profile {i} 的 .pcrpkey 不是签这份样本的 lab 公钥"
    want = c.policy_pcr11(c.pcr11_from_digests(d)).hex()
    for other in ("enter-initrd:leave-initrd", "enter-initrd:leave-initrd:sysinit:ready"):
        assert c.policy_pcr11(c.pcr11_from_digests(d, other)).hex() != want
    c.check_sig(f"profile {i}", p["pcrsig"], pkfp, want)   # 真签名：一条、sha256、pkfp、pol 都对
    print(f"profile {i}: pol {want[:16]}… 等于 systemd-measure 签的那一条")
PY2
); then
	echo "ok   真 v1 UKI 的样本：从段摘要算出的 enter-initrd 策略等于真签名的 pol（两个 profile）"
	printf '%s\n' "$out" | sed 's/^/       /'
else
	echo "FAIL 真 v1 UKI 的样本：$out" >&2
	fails=$((fails + 1))
fi

# --- 真的 make-installer.sh：四阶段签名的主 UKI 不出 U 盘 ------------------------------------------
missing=""
for t in objcopy objdump ukify sbverify sfdisk mformat mcopy mdir mtype mmd mmove jq zstd zip unzip sha256sum; do
	command -v "$t" >/dev/null || missing="$missing $t"
done
if [ -n "$missing" ]; then
	echo "skip make-installer 一段（缺少${missing}；在构建机 VM 161 上跑）"
else
	v=20261012.77
	o=$tmp/out/$v
	mkdir -p "$o" "$tmp/keys/lab"
	: >"$tmp/keys/lab/db.key"
	: >"$tmp/keys/lab/db.crt"
	printf 'version=%s\nprofile=lab\nbroken=\n' "$v" >"$o/build-info.txt"
	: >"$o/MastersOS_${v}_x86-64.raw"
	# 四阶段签名，用的是 lab 组的当前钥匙
	fake "$o/MastersOS_${v}_x86-64.efi" "$lab" 4
	expect "make-installer：四阶段签名的主 UKI" refused "PCR 签名不合格" \
		env MASTERSOS_KEYS="$tmp/keys" MASTERSOS_OUTPUT_DIR="$tmp/out" "$img/make-installer.sh" "$v" --profile lab
	fake "$o/MastersOS_${v}_x86-64.efi" "$lab" 1 enter-initrd:leave-initrd
	expect "make-installer：一条签名但阶段是 leave-initrd" refused "PCR 签名不合格" \
		env MASTERSOS_KEYS="$tmp/keys" MASTERSOS_OUTPUT_DIR="$tmp/out" "$img/make-installer.sh" "$v" --profile lab
fi

echo
if [ "$fails" = 0 ]; then
	echo "uki-check-test: ${n}/${n} 通过"
else
	echo "uki-check-test: $fails 个失败（共 $n）" >&2
	exit 1
fi

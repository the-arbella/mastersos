#!/bin/bash
# kiosk-ext-pack.sh 的测试（计划 9 Task 7），不要 root、不碰网络：
#   bash image/tests/kiosk-ext-pack-test.sh
# 钥匙是现生成的一次性 RSA 2048，放在临时目录、跑完删掉（仓库里不放任何扩展钥匙）。
# 核对：打印的 id 与独立算的一致；crx 是 Cr24 / 3，头能解开、签名用 openssl 验得过、signed_header_data 是这个 id；
# zip 条目排序、时间固定、manifest 带 update_url；updates.xml、宿主清单、kiosk-ext.json 的内容；两次打包字节相同；
# http、带查询串、大写主机名的 base_url 被拒；钥匙解析后在输出目录里（含子目录、符号链接）被拒；扩展目录里除 tests/、
# README.md 与点文件外全打进去，manifest 引用了没打进去的文件被拒；输出目录与日志里没有私钥的片段。
# 要 python3、openssl：没有的机器跳过（MASTERSOS_KIOSK_EXT_TEST_REQUIRE=1 时算失败，CI 这样跑）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
img=$(cd "$here/.." && pwd)
pack=$img/kiosk-ext-pack.sh
for t in python3 openssl sha256sum; do
	command -v "$t" >/dev/null && continue
	# CI 设 MASTERSOS_KIOSK_EXT_TEST_REQUIRE=1：缺工具算失败，不是整套跳过
	if [ "${MASTERSOS_KIOSK_EXT_TEST_REQUIRE:-}" = 1 ]; then
		echo "kiosk-ext-pack-test: FAIL（缺少 $t）" >&2
		exit 1
	fi
	echo "kiosk-ext-pack-test: skip（缺少 $t）"
	exit 0
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
pass() {
	n=$((n + 1))
	echo "ok   $1"
}
fail() {
	n=$((n + 1))
	fails=$((fails + 1))
	echo "FAIL $1" >&2
	[ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/    /' >&2
}

mkdir "$tmp/key"
key=$tmp/key/kiosk-ext.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" 2>/dev/null
openssl pkey -in "$key" -pubout -out "$tmp/key/pub.pem"
openssl pkey -in "$key" -pubout -outform DER -out "$tmp/pub.der"
want_id=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | cut -c1-32 | tr 0-9a-f a-p)
base=https://updates.example.org/mastersos/kiosk-ext

# --- 正常打包 ------------------------------------------------------------------
rc=0
bash "$pack" "$key" "$tmp/out" "$base" >"$tmp/stdout" 2>"$tmp/stderr" || rc=$?
if [ "$rc" = 0 ] && [ "$(cat "$tmp/stdout")" = "$want_id" ] && [ ! -s "$tmp/stderr" ]; then
	pass "打印的 id（只有这一行、stderr 空）与 sha256(公钥 DER) 前 16 字节映射 a–p 一致：$want_id"
else
	fail "打包失败或 id 不对（rc=$rc，期望 $want_id）" "$(cat "$tmp/stdout" "$tmp/stderr")"
fi

got=$(find "$tmp/out" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ')
if [ "$got" = "kiosk-ext.json mastersos-kiosk-ext.crx org.mastersos.kiosk_exit.json org.mastersos.support.json updates.xml " ]; then
	pass "输出目录恰好五个文件"
else
	fail "输出目录的文件不对" "$got"
fi

# crx3 的结构与签名：独立解析（不调 kiosk-ext-pack.py 的代码），签名交给 openssl 验
if out=$(python3 -I - "$tmp/out/mastersos-kiosk-ext.crx" "$tmp" "$want_id" "$img/../kiosk-extension/manifest.json" "$base" <<'PY' 2>&1
import hashlib, io, json, struct, sys, zipfile
crx_path, tmp, want_id, src_manifest, base = sys.argv[1:]
crx = open(crx_path, "rb").read()
assert crx[:4] == b"Cr24", "magic"
version, hlen = struct.unpack("<II", crx[4:12])
assert version == 3, f"version {version}"
header, zbytes = crx[12:12 + hlen], crx[12 + hlen:]

def varint(b, i):
    n = s = 0
    while True:
        c = b[i]; i += 1
        n |= (c & 0x7F) << s; s += 7
        if not c & 0x80:
            return n, i

def fields(b):
    i, out = 0, []
    while i < len(b):
        key, i = varint(b, i)
        assert key & 7 == 2, f"wire type {key & 7}"
        ln, i = varint(b, i)
        out.append((key >> 3, b[i:i + ln])); i += ln
    assert i == len(b), "protobuf 截断"
    return out

top = fields(header)
proofs = [v for f, v in top if f == 2]
shd = [v for f, v in top if f == 10000]
assert len(proofs) == 1 and len(shd) == 1, f"头里的字段 {[f for f, _ in top]}"
p = dict(fields(proofs[0]))
spki, sig = p[1], p[2]
pub_der = open(f"{tmp}/pub.der", "rb").read()
assert spki == pub_der, "头里的公钥不是这把钥匙的"
raw = hashlib.sha256(spki).digest()[:16]
assert "".join(chr(97 + int(c, 16)) for c in raw.hex()) == want_id
assert fields(shd[0]) == [(1, raw)], "signed_header_data 应只有 crx_id = id 的 16 字节"
open(f"{tmp}/sig.bin", "wb").write(sig)
open(f"{tmp}/signed.bin", "wb").write(b"CRX3 SignedData\x00" + struct.pack("<I", len(shd[0])) + shd[0] + zbytes)
open(f"{tmp}/zip.bin", "wb").write(zbytes)

z = zipfile.ZipFile(io.BytesIO(zbytes))
names = [i.filename for i in z.infolist()]
assert names == sorted(names) == ["background.js", "content.js", "manifest.json", "mock/nwea/page.js", "mock/nwea/relay.js", "schema.json"], names
assert all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in z.infolist()), "zip 时间不固定"
m = json.loads(z.read("manifest.json"))
src = json.load(open(src_manifest))
assert m["update_url"] == base + "/updates.xml", m.get("update_url")
assert m["version"] == src["version"] and m["manifest_version"] == 3
assert {k: v for k, v in m.items() if k != "update_url"} == src, "manifest 除 update_url 外应与源码相同"
print(src["version"])
PY
); then
	pass "crx 是 Cr24 / 3，头里是这把钥匙的公钥与 crx_id，zip 条目排序、时间固定、manifest 带 update_url"
	ver=$out
else
	fail "crx 结构不对" "$out"
	ver=
fi
if [ -f "$tmp/sig.bin" ] && out=$(openssl dgst -sha256 -verify "$tmp/key/pub.pem" -signature "$tmp/sig.bin" "$tmp/signed.bin" 2>&1); then
	pass "签名（RSA-PKCS1v15-SHA256，覆盖 CRX3 SignedData 前缀 + signed_header_data + zip）openssl 验得过"
else
	fail "签名验不过" "${out:-没有 sig.bin}"
fi
# 验签真的在看 zip：改一个字节就验不过
if [ -f "$tmp/signed.bin" ]; then
	python3 -I -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[-30]^=1; open(p,"wb").write(b)' "$tmp/signed.bin"
	if openssl dgst -sha256 -verify "$tmp/key/pub.pem" -signature "$tmp/sig.bin" "$tmp/signed.bin" >/dev/null 2>&1; then
		fail "改过一个字节的 zip 也验过了"
	else
		pass "改过一个字节的 zip 验不过"
	fi
fi

if out=$(python3 -I - "$tmp/out" "$want_id" "$base" "$ver" <<'PY' 2>&1
import json, sys
import xml.etree.ElementTree as ET
out, want_id, base, ver = sys.argv[1:]
ns = "{http://www.google.com/update2/response}"
root = ET.parse(f"{out}/updates.xml").getroot()
assert root.tag == ns + "gupdate" and root.get("protocol") == "2.0", root.tag
apps = root.findall(ns + "app")
assert len(apps) == 1 and apps[0].get("appid") == want_id, "appid"
uc = apps[0].findall(ns + "updatecheck")
assert len(uc) == 1, "updatecheck"
assert uc[0].get("codebase") == base + "/mastersos-kiosk-ext.crx", uc[0].get("codebase")
assert ver and uc[0].get("version") == ver, uc[0].get("version")

h = json.load(open(f"{out}/org.mastersos.kiosk_exit.json"))
assert h == {
    "name": "org.mastersos.kiosk_exit",
    "description": h.get("description"),
    "path": "/usr/lib/mastersos/mastersos-kiosk-exit",
    "type": "stdio",
    "allowed_origins": [f"chrome-extension://{want_id}/"],
}, h
assert isinstance(h["description"], str) and h["description"]

s = json.load(open(f"{out}/org.mastersos.support.json"))
assert s == {
    "name": "org.mastersos.support",
    "description": s.get("description"),
    "path": "/usr/lib/mastersos/mastersos-support-host",
    "type": "stdio",
    "allowed_origins": [f"chrome-extension://{want_id}/"],
}, s
assert isinstance(s["description"], str) and s["description"]

e = json.load(open(f"{out}/kiosk-ext.json"))
assert e == {"id": want_id, "update_url": base + "/updates.xml"}, e
PY
); then
	pass "updates.xml（appid、codebase、version）、两份宿主清单（name、path、stdio、allowed_origins）、kiosk-ext.json 都对"
else
	fail "updates.xml / 宿主清单 / kiosk-ext.json 不对" "$out"
fi

# 宿主清单的 name 与 path 跟 bundle 的 EXIT_HOST、镜像里的包装对得上
core=$img/../core
if grep -qF 'pub const EXIT_HOST: &str = "org.mastersos.kiosk_exit";' "$core/mastersos-bundle/src/kiosk.rs" &&
	[ -x "$img/mkosi.extra/usr/lib/mastersos/mastersos-kiosk-exit" ]; then
	pass "宿主名 = mastersos-bundle 的 EXIT_HOST，path 指向镜像里可执行的 mastersos-kiosk-exit"
else
	fail "宿主名或 path 与 EXIT_HOST / mkosi.extra 的包装对不上"
fi
if grep -qF 'pub const SUPPORT_HOST: &str = "org.mastersos.support";' "$core/mastersos-bundle/src/kiosk.rs" &&
	[ -x "$img/mkosi.extra/usr/lib/mastersos/mastersos-support-host" ]; then
	pass "求助宿主名 = mastersos-bundle 的 SUPPORT_HOST，path 指向镜像里可执行的 mastersos-support-host"
else
	fail "求助宿主名或 path 与 SUPPORT_HOST / mkosi.extra 的包装对不上"
fi

# 结尾带 / 的 base_url 一样
rc=0
bash "$pack" "$key" "$tmp/out2" "$base/" >/dev/null 2>&1 || rc=$?
if [ "$rc" = 0 ] && cmp -s "$tmp/out/mastersos-kiosk-ext.crx" "$tmp/out2/mastersos-kiosk-ext.crx" &&
	cmp -s "$tmp/out/updates.xml" "$tmp/out2/updates.xml"; then
	pass "再打一次（base_url 结尾多一个 /）：crx 与 updates.xml 逐字节相同"
else
	fail "两次打包的字节不同（rc=$rc）"
fi

# The image's own directory: the update URL in the crx, kiosk-ext.json and the codebase all point there
local_out=$tmp/local
bash "$pack" "$key" "$local_out" file:///usr/lib/mastersos/kiosk-ext >/dev/null
if grep -qF '"update_url": "file:///usr/lib/mastersos/kiosk-ext/updates.xml"' "$local_out/kiosk-ext.json" &&
	grep -qF 'codebase="file:///usr/lib/mastersos/kiosk-ext/mastersos-kiosk-ext.crx"' "$local_out/updates.xml"; then
	pass "base_url of the image directory: kiosk-ext.json and updates.xml point at it"
else
	fail "base_url of the image directory: kiosk-ext.json or updates.xml wrong"
fi

# --- 拒绝 ----------------------------------------------------------------------
for bad in http://updates.example.org/x "https://updates.example.org/x?v=1" https://Updates.Example.org/x \
	"https://updates.example.org/x'y" https://10.0.0.1/x https://localhost/x ftp://updates.example.org/x "" \
	file:///usr/lib/mastersos/kiosk-ext/ file:///usr/lib/mastersos/other file:///usr/lib/mastersos/kiosk-ext/../x; do
	rc=0
	err=$(bash "$pack" "$key" "$tmp/rej" "$bad" 2>&1 >/dev/null) || rc=$?
	if [ "$rc" != 0 ] && [ -z "$(ls -A "$tmp/rej" 2>/dev/null)" ]; then
		pass "base_url ${bad:-（空）} 被拒，什么都没写：${err%%$'\n'*}"
	else
		fail "base_url ${bad:-（空）} 应被拒（rc=$rc）"
	fi
	rm -rf "$tmp/rej"
done

rc=0
err=$(bash "$pack" "$key" "$tmp/key" "$base" 2>&1 >/dev/null) || rc=$?
if [ "$rc" != 0 ] && [ ! -e "$tmp/key/kiosk-ext.json" ]; then
	pass "钥匙在输出目录里被拒：$err"
else
	fail "钥匙在输出目录里应被拒（rc=$rc）"
fi

# 钥匙在输出目录的子目录里（或经符号链接指进去）也拒
mkdir -p "$tmp/out3/sub"
cp "$key" "$tmp/out3/sub/k.pem"
ln -s "$tmp/out3/sub/k.pem" "$tmp/key/link.pem"
for k in "$tmp/out3/sub/k.pem" "$tmp/key/link.pem"; do
	rc=0
	err=$(bash "$pack" "$k" "$tmp/out3" "$base" 2>&1 >/dev/null) || rc=$?
	if [ "$rc" != 0 ] && [ ! -e "$tmp/out3/kiosk-ext.json" ]; then
		pass "钥匙（${k#"$tmp"/}）解析后在输出目录里：被拒"
	else
		fail "钥匙 ${k#"$tmp"/} 解析后在输出目录里，应被拒（rc=$rc）"
	fi
done
rm -rf "$tmp/out3" "$tmp/key/link.pem"

# 打包的是扩展目录里除 tests/、README.md 与点文件之外的全部文件；manifest 引用了没打进去的文件就拒绝
cp -r "$img/../kiosk-extension" "$tmp/ext"
mkdir -p "$tmp/ext/icons"
printf 'png' >"$tmp/ext/icons/16.png"
printf 'x' >"$tmp/ext/.hidden"
python3 -I - "$tmp/ext/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["icons"] = {"16": "icons/16.png"}
json.dump(m, open(p, "w"), ensure_ascii=False, indent=2)
PY
rc=0
MASTERSOS_KIOSK_EXT_SRC=$tmp/ext bash "$pack" "$key" "$tmp/out4" "$base" >/dev/null 2>&1 || rc=$?
if [ "$rc" = 0 ] && got=$(python3 -I -c 'import sys, zipfile; z = open(sys.argv[1], "rb").read(); i = z.index(b"PK\x03\x04"); import io; print(" ".join(zipfile.ZipFile(io.BytesIO(z[i:])).namelist()))' "$tmp/out4/mastersos-kiosk-ext.crx") &&
	[ "$got" = "background.js content.js icons/16.png manifest.json mock/nwea/page.js mock/nwea/relay.js schema.json" ]; then
	pass "manifest 新加的 icons 跟着打进去，tests/、README.md、点文件不打：$got"
else
	fail "扩展目录的文件没有全打进去（rc=$rc）" "${got:-}"
fi
python3 -I - "$tmp/ext/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["action"] = {"default_popup": "popup.html"}
json.dump(m, open(p, "w"), ensure_ascii=False, indent=2)
PY
rc=0
err=$(MASTERSOS_KIOSK_EXT_SRC=$tmp/ext bash "$pack" "$key" "$tmp/out5" "$base" 2>&1 >/dev/null) || rc=$?
if [ "$rc" != 0 ] && [ ! -e "$tmp/out5/mastersos-kiosk-ext.crx" ] && [[ $err == *popup.html* ]]; then
	pass "manifest 引用了不在扩展目录里的 popup.html：拒绝"
else
	fail "manifest 引用了不存在的文件应被拒（rc=$rc）" "$err"
fi

rc=0
bash "$pack" "$tmp/nope.pem" "$tmp/rej" "$base" >/dev/null 2>&1 || rc=$?
if [ "$rc" != 0 ]; then pass "钥匙文件不在：拒绝"; else fail "钥匙文件不在应被拒"; fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/ec.pem" 2>/dev/null
rc=0
err=$(bash "$pack" "$tmp/ec.pem" "$tmp/rej" "$base" 2>&1 >/dev/null) || rc=$?
if [ "$rc" != 0 ] && [ -z "$(ls -A "$tmp/rej" 2>/dev/null)" ]; then
	pass "不是 RSA 的钥匙被拒：$err"
else
	fail "EC 钥匙应被拒（rc=$rc）"
fi
rm -rf "$tmp/rej"

# --- 输出目录与日志里没有私钥 ----------------------------------------------------
# 私钥 DER 里模数之后的部分（私有指数 d、p、q 等）取几段 32 字节，在输出文件与打包的 stdout / stderr 里找；
# 再找 PEM 的私钥头
if out=$(python3 -I - "$key" "$tmp/out" "$tmp/stdout" "$tmp/stderr" <<'PY' 2>&1
import base64, os, re, subprocess, sys
key, out, *logs = sys.argv[1:]
der = subprocess.run(["openssl", "pkey", "-in", key, "-outform", "DER"], capture_output=True, check=True).stdout
assert len(der) > 1000
frags = [der[o:o + 32] for o in (400, 600, 800, 1000, len(der) - 32)]
pem_head = b"PRIVATE" + b" KEY"  # 拆开写，免得 check-tree 第 1 条命中本文件
b64 = base64.b64encode(der[400:700])
paths = [os.path.join(out, f) for f in os.listdir(out)] + logs
for p in paths:
    data = open(p, "rb").read()
    for i, f in enumerate(frags):
        assert f not in data, f"{p} 含私钥片段 {i}"
    assert pem_head not in data, f"{p} 含 PEM 私钥头"
    assert b64[8:40] not in data, f"{p} 含私钥的 base64"
print(len(paths))
PY
); then
	pass "输出目录的 $((out - 2)) 个文件与打包的 stdout / stderr 里没有私钥片段与 PEM 私钥头"
else
	fail "找到私钥材料" "$out"
fi

echo "kiosk-ext-pack-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]

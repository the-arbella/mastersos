#!/usr/bin/env python3
"""MastersOS 考试扩展的 crx3 打包（计划 9 Task 7），由 kiosk-ext-pack.sh 调用：

    python3 -I kiosk-ext-pack.py <扩展源码目录> <宿主清单模板> <钥匙.pem> <输出目录> <base_url>

只用标准库与 openssl 命令：公钥（DER 的 SubjectPublicKeyInfo）与 RSA-PKCS1v15-SHA256 签名都由 openssl 从
<钥匙.pem> 读私钥算出——私钥只经这个路径交给 openssl，本程序不读它的内容、不复制、不写进输出目录或日志。

扩展 id：sha256(公钥 DER) 的前 16 字节，每个十六进制位 0–f 映射成 a–p。
crx3：b"Cr24" + u32 LE 3 + u32 LE 头长 + CrxFileHeader + zip，其中 CrxFileHeader（protobuf）是
    sha256_with_rsa(2) = AsymmetricKeyProof{public_key(1), signature(2)}
    signed_header_data(10000) = SignedData{crx_id(1) = id 的 16 个原始字节}
签名的是 b"CRX3 SignedData\\x00" + u32 LE len(signed_header_data) + signed_header_data + zip。
zip 里是扩展目录里除 tests/、README.md 与点文件之外的全部文件，manifest.json 加上 update_url；manifest 里像相对文件路径的
字符串（service_worker、content_scripts、icons、default_popup……）都要在其中，否则拒绝。条目排序、时间固定在 1980-01-01，所以同一把钥匙、
同一份源码打出同样的字节。

写出 mastersos-kiosk-ext.crx、updates.xml、org.mastersos.kiosk_exit.json、kiosk-ext.json（先写临时文件再改名），
stdout 只打印 id。出错打印原因、退出 1。
"""

import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from xml.sax.saxutils import quoteattr

CRX = "mastersos-kiosk-ext.crx"
UPDATES = "updates.xml"
HOST = "org.mastersos.kiosk_exit.json"
EXT_JSON = "kiosk-ext.json"
PLACEHOLDER = "__EXAM_EXTENSION_ID__"
RSA_OID = bytes.fromhex("06092a864886f70d010101")  # rsaEncryption
SIGN_PREFIX = b"CRX3 SignedData\x00"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
# https://主机[:端口][/路径]，主机是小写的域名（与 mastersos-bundle 的 https_host 一致：至少两段、顶级域不是纯数字），
# 路径只许不需要在 XML / JSON 里转义的字符，不带查询串与片段
URL_RE = re.compile(
    r"https://(?P<host>[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?"
)
# The one local directory: the image carries the crx and updates.xml there (EXAM_LOCAL_UPDATE_URL in mastersos-bundle).
LOCAL_BASE = "file:///usr/lib/mastersos/kiosk-ext"
VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}")


def die(msg):
    print(f"kiosk-ext-pack: {msg}", file=sys.stderr)
    sys.exit(1)


def openssl(args, data=None):
    """跑 openssl；口令给空的（加了口令的钥匙直接失败，不在终端上问）。失败时只转述 openssl 的 stderr。"""
    try:
        r = subprocess.run(
            ["openssl", *args, "-passin", "pass:"],
            input=data if data is not None else b"",
            capture_output=True,
            check=False,
        )
    except OSError as e:
        die(f"跑不了 openssl：{e}")
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip().splitlines()
        die(f"openssl {args[0]} 失败：{err[0] if err else r.returncode}")
    return r.stdout


def der_len(buf, off):
    """DER 的 TLV：返回 (tag, 内容开始, 内容结束)。"""
    if off + 2 > len(buf):
        raise ValueError("截断")
    tag, n = buf[off], buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or off + k > len(buf):
            raise ValueError("长度")
        n = int.from_bytes(buf[off : off + k], "big")
        off += k
    if off + n > len(buf):
        raise ValueError("截断")
    return tag, off, off + n


def rsa_bits(spki):
    """SubjectPublicKeyInfo 里 RSA 模数的位数；不是 RSA 的抛 ValueError。"""
    tag, s, e = der_len(spki, 0)
    if tag != 0x30 or e != len(spki):
        raise ValueError("不是 SEQUENCE")
    tag, a, b = der_len(spki, s)  # AlgorithmIdentifier
    if tag != 0x30 or not spki[a:b].startswith(RSA_OID):
        raise ValueError("不是 RSA 公钥")
    tag, a, b = der_len(spki, b)  # BIT STRING
    if tag != 0x03 or spki[a] != 0:
        raise ValueError("BIT STRING")
    tag, c, _ = der_len(spki, a + 1)  # RSAPublicKey
    tag, c, d = der_len(spki, c)  # 模数
    if tag != 0x02:
        raise ValueError("模数")
    n = spki[c:d].lstrip(b"\x00")
    return len(n) * 8 - (8 - n[0].bit_length()) if n else 0


def ext_id(spki):
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(spki).hexdigest()[:32])


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb_bytes(field, value):
    """protobuf 的 length-delimited 字段（wire type 2）。"""
    return varint(field << 3 | 2) + varint(len(value)) + value


def safe_rel(p):
    return isinstance(p, str) and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*", p) is not None


# manifest 里像相对文件路径的字符串（有扩展名，不是网址、通配、版本号）：都要在打进去的文件里
FILE_REF = re.compile(r"/?[A-Za-z0-9_-][A-Za-z0-9_./-]*\.[A-Za-z][A-Za-z0-9]*")


def source_files(src):
    """扩展目录里要打包的文件：除顶层的 tests/、README.md 与点开头的文件、目录之外的全部（manifest.json 另算）。"""
    out = []
    for d, dirs, names in os.walk(src):
        rel_d = os.path.relpath(d, src)
        dirs[:] = sorted(x for x in dirs if not x.startswith(".") and not (rel_d == "." and x == "tests"))
        for n in names:
            rel = n if rel_d == "." else f"{rel_d}/{n}".replace(os.sep, "/")
            if n.startswith(".") or rel in ("README.md", "manifest.json"):
                continue
            if not safe_rel(rel) or not os.path.isfile(os.path.join(src, rel)):
                die(f"扩展目录里的 {rel} 不是能打包的普通文件或文件名不合规")
            out.append(rel)
    return sorted(out)


def manifest_refs(v):
    """manifest 里所有像相对文件路径的字符串值。"""
    if isinstance(v, dict):
        for x in v.values():
            yield from manifest_refs(x)
    elif isinstance(v, list):
        for x in v:
            yield from manifest_refs(x)
    elif isinstance(v, str) and FILE_REF.fullmatch(v) and "://" not in v:
        yield v.lstrip("/")


def build_zip(src, manifest_bytes, files):
    buf = io.BytesIO()
    entries = {"manifest.json": manifest_bytes}
    for f in files:
        try:
            with open(os.path.join(src, f), "rb") as fh:
                entries[f] = fh.read()
        except OSError as e:
            die(f"读不了扩展文件 {f}：{e}")
    with zipfile.ZipFile(buf, "w") as z:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, entries[name], compresslevel=9)
    return buf.getvalue()


def write_atomic(outdir, name, data):
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", dir=outdir)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(outdir, name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main():
    if len(sys.argv) != 6:
        die("用法：kiosk-ext-pack.py <扩展源码目录> <宿主清单模板> <钥匙.pem> <输出目录> <base_url>")
    src, tmpl_path, key, outdir, base = sys.argv[1:]

    if base != LOCAL_BASE and (not URL_RE.fullmatch(base) or URL_RE.fullmatch(base).group("host").split(".")[-1].isdigit()):
        die(f"base_url 应是 https://<小写主机名>[:端口][/路径]，不带查询串与片段：{base}")
    base = base.rstrip("/")
    real_out = os.path.realpath(outdir)
    if os.path.commonpath([os.path.realpath(key), real_out]) == real_out:
        die("钥匙（解析符号链接之后）不能在输出目录里，子目录也不行（输出目录的文件要发到网上、装进镜像）")

    # 公钥与 id
    spki = openssl(["pkey", "-in", key, "-pubout", "-outform", "DER"])
    try:
        bits = rsa_bits(spki)
    except (ValueError, IndexError) as e:
        die(f"{key} 不是能用的 RSA 私钥（{e}）")
    if bits < 2048:
        die(f"RSA 钥匙至少 2048 位，这把是 {bits} 位")
    eid = ext_id(spki)
    raw_id = hashlib.sha256(spki).digest()[:16]

    # manifest：版本、引用的文件、加上 update_url
    try:
        with open(os.path.join(src, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as e:
        die(f"读不了 manifest.json：{e}")
    version = manifest.get("version")
    if manifest.get("manifest_version") != 3 or not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        die("manifest.json 应是 manifest_version 3、version 是 1–4 段 0–65535 的数字")
    if any(int(p) > 65535 for p in version.split(".")):
        die(f"manifest 的 version 每段不超过 65535：{version}")
    files = source_files(src)
    missing = sorted(set(manifest_refs(manifest)) - set(files))
    if missing:
        die(f"manifest 引用的文件不在扩展目录里（或在不打包的 tests/、README.md 里）：{', '.join(missing)}")
    update_url = f"{base}/{UPDATES}"
    manifest["update_url"] = update_url
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    zip_bytes = build_zip(src, manifest_bytes, files)

    # crx3
    signed_header_data = pb_bytes(1, raw_id)
    signature = openssl(
        ["dgst", "-sha256", "-sign", key, "-sigopt", "rsa_padding_mode:pkcs1"],
        SIGN_PREFIX + struct.pack("<I", len(signed_header_data)) + signed_header_data + zip_bytes,
    )
    header = pb_bytes(2, pb_bytes(1, spki) + pb_bytes(2, signature)) + pb_bytes(10000, signed_header_data)
    crx = b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes

    # updates.xml
    codebase = f"{base}/{CRX}"
    updates = (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n"
        f"  <app appid={quoteattr(eid)}>\n"
        f"    <updatecheck codebase={quoteattr(codebase)} version={quoteattr(version)} />\n"
        "  </app>\n"
        "</gupdate>\n"
    ).encode()

    # 宿主清单
    try:
        with open(tmpl_path, encoding="utf-8") as fh:
            tmpl = fh.read()
    except OSError as e:
        die(f"读不了宿主清单模板：{e}")
    if tmpl.count(PLACEHOLDER) != 1:
        die(f"宿主清单模板里应恰好有一处 {PLACEHOLDER}")
    host = tmpl.replace(PLACEHOLDER, eid)
    try:
        h = json.loads(host)
    except ValueError as e:
        die(f"填好的宿主清单不是 JSON：{e}")
    if h.get("allowed_origins") != [f"chrome-extension://{eid}/"]:
        die("宿主清单的 allowed_origins 应只有这个扩展")

    ext_json = (json.dumps({"id": eid, "update_url": update_url}, indent=2) + "\n").encode("utf-8")

    for name, data in (
        (CRX, crx),
        (UPDATES, updates),
        (HOST, host.encode("utf-8")),
        (EXT_JSON, ext_json),
    ):
        write_atomic(outdir, name, data)
    print(eid)


if __name__ == "__main__":
    main()

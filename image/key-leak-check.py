#!/usr/bin/env python3
"""签名会话之后在磁盘上找正式私钥的片段（计划 5 Task 4，裁定 9）：

    python3 -I key-leak-check.py <钥匙目录> <要扫的路径…>

<钥匙目录> 是 keys-load.sh 载入的那份（/run/mastersos-release-keys，在 keys-unload.sh 之前跑）或仪式的 tmpfs 目录：
里面的 db.key、pcr.key、kiosk-ext.pem（PEM，PKCS#8 或 PKCS#1 的 RSA）与 gpg/private-keys-v1.d/*.key。

找什么：
  - RSA 私钥：DER 里从私有指数 d 开始到结尾的那一段（前面的模数 n 与 e 是公开的，证书与仓库的公钥里也有，
    不拿来找，否则每份公钥都报）。取开头、中间、结尾三段 32 字节，避开含 0x0a 的位置；再把这一段在三种字节对齐下
    各做 base64，每种取 8 段 24 个字符：PEM 怎么折行、PKCS#8 还是 PKCS#1 都找得到。
  - gpg 私钥（extended key format 或旧的 canonical S 表达式）：私有的那几个值（ecc 的 d；rsa 的 d、p、q、u；带口令的
    取 protected 里最长的那段密文）的原始字节，以及它们在文件里的十六进制写法（大写与小写）。
逐个文件找（不跟随符号链接、只看普通文件，跳过钥匙目录自己）；找到就打印「路径：哪把钥匙」——不打印片段本身——
最后退出 1。钥匙目录读不懂、参数不对退出 2。有读不了的文件（没找到片段时）退出 3——不算干净，在 stderr 列出来；
用 sudo 跑。都扫了、都没找到才退出 0。

找不到的情况：压缩过（zstd 的镜像、日志轮转）、加密过、或只泄露了不到 32 字节。这只是「没有原样落到磁盘上」的检查。
"""

import base64
import os
import re
import stat
import sys

FRAG = 32
B64 = 24  # base64 片段的字符数（18 字节、144 位）
B64_N = 8  # 每种对齐取几段
CHUNK = 16 << 20
BEGIN = re.compile(rb"-----BEGIN ([A-Z ]*)PRIVATE" rb" KEY-----")  # 拆开写，免得 check-tree 第 1 条命中本文件


def die(msg):
    print(f"key-leak-check: {msg}", file=sys.stderr)
    sys.exit(2)


def der_tlv(buf, off):
    """返回 (tag, 值的起点, 值的终点)"""
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4:
            raise ValueError("DER 长度")
        n = int.from_bytes(buf[off : off + k], "big")
        off += k
    if off + n > len(buf):
        raise ValueError("DER 截断")
    return tag, off, off + n


def rsa_private_region(der):
    """DER 里私有指数 d 的 TLV 开始的偏移（PKCS#8 或 PKCS#1），之后到 RSAPrivateKey 的结尾都是私有的"""
    tag, s, e = der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("不是 SEQUENCE")
    # PKCS#8：SEQUENCE { INTEGER 0, SEQUENCE AlgorithmIdentifier, OCTET STRING RSAPrivateKey }
    t1, s1, e1 = der_tlv(der, s)
    t2, s2, e2 = der_tlv(der, e1)
    if t1 == 0x02 and t2 == 0x30:
        t3, s3, e3 = der_tlv(der, e2)
        if t3 != 0x04:
            raise ValueError("PKCS#8 里没有 OCTET STRING")
        tag, s, e = der_tlv(der, s3)
        if tag != 0x30:
            raise ValueError("RSAPrivateKey 不是 SEQUENCE")
    # RSAPrivateKey：SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
    off = s
    for _ in range(3):
        t, _vs, ve = der_tlv(der, off)
        if t != 0x02:
            raise ValueError("RSAPrivateKey 的字段不是 INTEGER")
        off = ve
    t, _vs, _ve = der_tlv(der, off)
    if t != 0x02:
        raise ValueError("没有私有指数 d")
    return off, e


def pick(region):
    """region 里开头、中间、结尾三段 FRAG 字节、不含 0x0a 的片段"""
    out = []
    n = len(region)
    if n < FRAG:
        return out
    for want in (0, (n - FRAG) // 2, n - FRAG):
        # 从 want 往两边找最近一段不含 0x0a 的
        for d in range(n):
            hit = None
            for o in (want - d, want + d):
                if 0 <= o <= n - FRAG and b"\n" not in region[o : o + FRAG]:
                    hit = o
                    break
            if hit is not None:
                frag = bytes(region[hit : hit + FRAG])
                if frag not in out:
                    out.append(frag)
                break
    return out


def pem_patterns(path):
    data = open(path, "rb").read()
    m = BEGIN.search(data)
    if not m:
        die(f"{path} 不是 PEM 私钥")
    end = data.find(b"-----END", m.end())
    if end < 0:
        die(f"{path} 的 PEM 不完整")
    lines = [ln.strip() for ln in data[m.end() : end].splitlines()]
    lines = [ln for ln in lines if ln and b":" not in ln]  # 带口令的旧 PEM 有 Proc-Type 之类的头
    try:
        der = base64.b64decode(b"".join(lines), validate=True)
        priv_start, priv_end = rsa_private_region(der)
    except (ValueError, IndexError) as e:
        die(f"{path} 读不懂（{e}）：只认 RSA 私钥")
    region = der[priv_start:priv_end]
    pats = pick(region)
    # base64：私有区域在三种字节对齐下各编一次（PKCS#8 与 PKCS#1 的 d 起点模 3 不同），取若干段 B64 个字符。
    # 不按行取：重新折行（76 列、不折行）之后整行对不上，而短片段大多落在一行之内；只要命中一段就算
    for a in range(3):
        enc = base64.b64encode(region[a:])[:-4]  # 去掉最后一组（可能有填充、与真实编码不同）
        if len(enc) < B64:
            continue
        step = max(1, (len(enc) - B64) // (B64_N - 1))
        for i in range(B64_N):
            frag = enc[i * step : i * step + B64]
            if len(frag) == B64 and frag not in pats:
                pats.append(frag)
    return pats


SEXP_HEX = re.compile(rb"\((\w+)\s+#([0-9A-Fa-f\s]+)#\s*\)")
SEXP_CANON = re.compile(rb"\((\d+):(\w+)(\d+):")
PRIV_NAMES = {"ecc": {b"d"}, "rsa": {b"d", b"p", b"q", b"u"}, "dsa": {b"x"}, "elg": {b"x"}}


def gpg_patterns(path):
    data = open(path, "rb").read()
    pats = []
    if b"protected-private-key" in data:
        # 带口令：私有部分是 protected 里的密文，取最长的十六进制段
        tail = data[data.find(b"(protected") :] if b"(protected" in data else data
        toks = [re.sub(rb"\s", b"", t) for t in re.findall(rb"#([0-9A-Fa-f\s]+)#", tail)]
        if not toks:
            die(f"{path}：protected-private-key 里没有读得懂的密文")
        toks = [max(toks, key=len)]
        for t in toks:
            pats += [t.upper(), t.lower(), bytes.fromhex(t.decode())]
        return [p for p in pats if len(p) >= FRAG // 2]
    algo = None
    for a in PRIV_NAMES:
        if re.search(rb"\(\s*(?:\d+:)?" + a.encode() + rb"\b", data):
            algo = a
            break
    if algo is None:
        die(f"{path}：不认识的 gpg 私钥算法")
    names = PRIV_NAMES[algo]
    found = False
    for name, hx in SEXP_HEX.findall(data):
        if name in names:
            h = re.sub(rb"\s", b"", hx)
            raw = bytes.fromhex(h.decode())
            pats += [h.upper(), h.lower(), raw]
            # OpenPGP 的 MPI 去掉开头的零字节（gpg --export-secret-keys）
            if raw.lstrip(b"\0") != raw and len(raw.lstrip(b"\0")) >= FRAG - 8:
                pats.append(raw.lstrip(b"\0"))
            found = True
    # 旧的 canonical 格式：(1:d32:<原始字节>)
    for m in re.finditer(rb"\((\d+):", data):
        ln = int(m.group(1))
        s = m.end()
        name = data[s : s + ln]
        if name in names:
            m2 = re.match(rb"(\d+):", data[s + ln :])
            if m2:
                vl = int(m2.group(1))
                vs = s + ln + m2.end()
                pats.append(data[vs : vs + vl])
                found = True
    if not found:
        die(f"{path}：没找到私有的值")
    # 原始字节太短的不要（误报）；ed25519 的 d 正好 32 字节
    return [p for p in pats if len(p) >= FRAG - 8]


def load(keydir):
    keys = []
    for name in ("db.key", "pcr.key", "kiosk-ext.pem"):
        p = os.path.join(keydir, name)
        if not os.path.isfile(p):
            die(f"{keydir} 里没有 {name}")
        keys.append((name, pem_patterns(p)))
    gdir = os.path.join(keydir, "gpg", "private-keys-v1.d")
    gk = sorted(f for f in os.listdir(gdir) if f.endswith(".key")) if os.path.isdir(gdir) else []
    if not gk:
        die(f"{gdir} 里没有 *.key")
    for f in gk:
        # 名字只用 keygrip 的前 8 位（keygrip 由公钥算出，不是秘密；短一点免得像片段）
        keys.append((f"gpg 私钥 {f[:8]}…", gpg_patterns(os.path.join(gdir, f))))
    for name, pats in keys:
        if not pats:
            die(f"{name}：取不出片段")
    return keys


def scan_file(path, keys, maxlen):
    hits = set()
    with open(path, "rb", buffering=0) as fh:
        prev = b""
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            win = prev + buf
            for name, pats in keys:
                if name in hits:
                    continue
                for p in pats:
                    if win.find(p) >= 0:
                        hits.add(name)
                        break
            prev = win[-(maxlen - 1) :]
    return [n for n, _ in keys if n in hits]


def main():
    if len(sys.argv) < 3:
        die("用法：key-leak-check.py <钥匙目录> <要扫的路径…>")
    keydir = os.path.realpath(sys.argv[1])
    keys = load(keydir)
    maxlen = max(len(p) for _, pats in keys for p in pats)
    found = 0
    unread = []
    nfiles = 0

    def visit(p):
        nonlocal found, nfiles
        try:
            st = os.lstat(p)
        except OSError:
            unread.append(p)
            return
        if not stat.S_ISREG(st.st_mode):
            return
        nfiles += 1
        try:
            names = scan_file(p, keys, maxlen)
        except OSError:
            unread.append(p)
            return
        for n in names:
            print(f"{p}：{n}")
            found += 1

    def under_keydir(p):
        rp = os.path.realpath(p)
        return rp == keydir or rp.startswith(keydir + os.sep)

    for top in sys.argv[2:]:
        if under_keydir(top):
            continue
        try:
            st = os.lstat(top)
        except OSError:
            unread.append(top)
            continue
        if stat.S_ISDIR(st.st_mode):
            for root, dirs, files in os.walk(top, followlinks=False, onerror=lambda e: unread.append(e.filename)):
                dirs[:] = [d for d in dirs if not under_keydir(os.path.join(root, d))]
                for f in files:
                    visit(os.path.join(root, f))
        else:
            visit(top)
    for p in unread:
        print(f"key-leak-check: 读不了，没扫：{p}", file=sys.stderr)
    names = ", ".join(n for n, _ in keys)
    if found:
        print(f"key-leak-check: 在磁盘上找到 {found} 处私钥片段（{names} 中的）：上面每行是「路径：哪把钥匙」", file=sys.stderr)
        sys.exit(1)
    if unread:
        print(f"key-leak-check: 扫了 {nfiles} 个文件，没找到片段，但有 {len(unread)} 个读不了（上面列出），不算干净：用 sudo 跑", file=sys.stderr)
        sys.exit(3)
    print(f"key-leak-check: 扫了 {nfiles} 个文件，没有 {names} 的片段")
    sys.exit(0)


if __name__ == "__main__":
    main()

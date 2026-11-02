#!/usr/bin/env python3
# 测试用：做一个最小的「UKI」PE（.linux、.pcrpkey、.pcrsig），publish-test.sh 与 uki-check-test.sh 共用。
#   python3 -I make-fake-uki.py <输出> <PCR 公钥 PEM> <pkfp> <签名条数> [第一条签名的阶段，默认 enter-initrd]
# 第一条签名的 pol 用 uki-pcrsig-check 自己的函数按给定阶段算（真的 PolicyPCR 摘要），其余几条是凑数的值。
import importlib.machinery
import importlib.util
import json
import os
import struct
import sys

# 以模块载入 uki-pcrsig-check 时不在镜像树里留 __pycache__
sys.dont_write_bytecode = True

here = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(here, "..", "uki-pcrsig-check")
loader = importlib.machinery.SourceFileLoader("uki_pcrsig_check", path)
spec = importlib.util.spec_from_loader("uki_pcrsig_check", loader)
chk = importlib.util.module_from_spec(spec)
loader.exec_module(chk)

out, pem_path, pkfp, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
phase = sys.argv[5] if len(sys.argv) > 5 else "enter-initrd"
pem = open(pem_path, "rb").read()
linux = b"fake-linux-kernel"
profile = b"ID=p1\nTITLE=fake profile\n"
# 环境变量（uki-check-test.sh 用来造解析上的边角情形）：
#   FAKE_LAYOUT   plain（默认：.linux .pcrpkey .pcrsig）
#                 inherit      基础段带 .pcrsig，profile 1 只有 .profile、继承基础段的签名（签名按继承后的段算）
#                 override-bad 基础段的签名是对的，但 profile 1 自己的 .pcrsig 签的是 <阶段>（盖过基础段）
#                 unused-base  基础段与 profile 1 各有一份对的 .pcrsig，基础段那份没人用
#   FAKE_PCRSIG_RAW  直接用这段文本当 .pcrsig 的内容（plain 布局）
#   FAKE_DUP         把这个段名再加一份（plain 布局）
#   FAKE_TAIL        追加在 .pcrsig JSON 之后的字节（例如 NUL 补齐或别的垃圾）
#   FAKE_LINUX_NAME  .linux 段的原始段名（plain 布局；测「段名截到第一个 NUL」）


def pol_for(secs, ph):
    return chk.policy_pcr11(chk.pcr11_enter_initrd(secs, ph)).hex()


def sigjson(p, count):
    sig = [{"pcrs": [11], "pkfp": pkfp, "pol": p if i == 0 else f"{i:064x}", "sig": "AA=="} for i in range(count)]
    return json.dumps({"sha256": sig}).encode()


tail = os.environ.get("FAKE_TAIL", "").encode().decode("unicode_escape").encode("latin-1")
layout = os.environ.get("FAKE_LAYOUT", "plain")
base_meas = {".linux": linux, ".pcrpkey": pem}
prof_meas = dict(base_meas, **{".profile": profile})
if layout == "plain":
    body = os.environ.get("FAKE_PCRSIG_RAW")
    body = body.encode() if body is not None else sigjson(pol_for(base_meas, phase), n)
    # FAKE_LINUX_NAME：.linux 段在段表里的原始名字（8 字节以内，可带 NUL，例如 ".linux\\0z"）
    lname = os.environ.get("FAKE_LINUX_NAME", ".linux").encode().decode("unicode_escape").encode("latin-1")
    secs = [(lname, linux), (b".pcrpkey", pem), (b".pcrsig", body + tail)]
    dup = os.environ.get("FAKE_DUP")
    if dup:
        dupb = dup.encode().decode("unicode_escape").encode("latin-1")
        secs += [s_ for s_ in secs if s_[0] == dupb]
elif layout == "inherit":
    secs = [(b".linux", linux), (b".pcrpkey", pem), (b".pcrsig", sigjson(pol_for(prof_meas, phase), n)),
            (b".profile", profile)]
elif layout == "override-bad":
    secs = [(b".linux", linux), (b".pcrpkey", pem), (b".pcrsig", sigjson(pol_for(prof_meas, "enter-initrd"), 1)),
            (b".profile", profile), (b".pcrsig", sigjson(pol_for(prof_meas, phase), n))]
elif layout == "unused-base":
    secs = [(b".linux", linux), (b".pcrpkey", pem), (b".pcrsig", sigjson(pol_for(base_meas, "enter-initrd"), 1)),
            (b".profile", profile), (b".pcrsig", sigjson(pol_for(prof_meas, "enter-initrd"), 1))]
else:
    sys.exit(f"不认识的 FAKE_LAYOUT {layout}")
pe = 0x40
hdr = 24 + 40 * len(secs)
data_off = (pe + hdr + 0x1FF) & ~0x1FF
b = bytearray(b"MZ" + b"\0" * (0x3C - 2) + struct.pack("<I", pe))
b += b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, len(secs), 0, 0, 0, 0, 0)
off, body_ = data_off, b""
for name, data in secs:
    b += name.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", len(data), 0, len(data), off, 0, 0, 0, 0, 0)
    body_ += data
    off += len(data)
b = b.ljust(data_off, b"\0") + body_
open(out, "wb").write(b)

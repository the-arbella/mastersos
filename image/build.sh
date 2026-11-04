#!/bin/bash
# 在构建机（VM 161 mastersos-build）上构建镜像：
#   build.sh <version> [--profile lab] [--broken userspace|initrd|bad-shim]
# version 形如 20261012.1（日期 + 当天序号）。产物在 mkosi.output/<version>/，
# 含 mkosi 的 JSON 清单（MastersOS_<v>_x86-64.manifest）、build-info.txt 与安装 U 盘镜像
# MastersOS-installer_<v>_x86-64.img.zst（make-installer.sh；--broken 的构建不做）。
#
# 环境变量：
#   MASTERSOS_SNAPSHOT     Ubuntu 快照（YYYYMMDDTHHMMSSZ）；默认当天 00:00:00 UTC——同一天的构建用同一组包
#   MASTERSOS_UPDATE_BASE  更新源的根（通道目录 stable/、beta/ 在它下面）。正式镜像默认 https://os.khundavid.com
#                       （Ruling 23），可覆盖，但只收 https://<域名>/…：build.sh 与 finalize 都拒绝 http、IP 与 localhost；
#                       lab 默认是构建机上的 nginx http://192.0.2.99/mastersos
#   MASTERSOS_KEYS         lab 的钥匙目录，默认 ~/mastersos-keys：--profile lab 用 lab/ 下的 db.key/crt（Secure Boot 与 verity）、
#                       pcr.key/crt（PCR 签名）（keyset.sh，Ruling 19）；lab-local/：试验用户的口令哈希与 authorized_keys。
#                       正式构建的同名一套只从 tmpfs 读（keyset_priv release，先 keys-load.sh，见 docs/key-ceremony.md）。钥匙永不入库。
#   MASTERSOS_LAB_SPLASH   1：lab 的截图构建，Plymouth 不管串口、屏幕上出真正的开机画面（提示只能在屏幕上答）；默认 0（串口答提示）
#   MASTERSOS_CORE         core 的位置；默认 ../core（仓库里），其次 ~/mastersos-core（sync.sh 同步的位置）
#   MASTERSOS_KIOSK_EXT_SRC  考试扩展的源码；默认 ../kiosk-extension（仓库里），其次 ~/mastersos-kiosk-extension（sync.sh 同步的位置）
set -euo pipefail

usage() {
	echo "用法：build.sh <version> [--profile lab] [--broken userspace|initrd|bad-shim]" >&2
	exit 2
}
[ $# -ge 1 ] || usage
version=$1
shift
profile="" broken=""
while [ $# -gt 0 ]; do
	case "$1" in
	--profile)
		profile=${2:-}
		shift 2 || usage
		;;
	--broken)
		broken=${2:-}
		shift 2 || usage
		;;
	*) usage ;;
	esac
done
[[ $version =~ ^[0-9]{8}\.[0-9]+$ ]] || {
	echo "build.sh: 版本号应形如 20261012.1，实际：$version" >&2
	exit 2
}
case "$profile" in "" | lab) ;; *)
	echo "build.sh: 未知的 profile：$profile" >&2
	exit 2
	;;
esac
case "$broken" in "" | userspace | initrd | bad-shim) ;; *)
	echo "build.sh: --broken 只能是 userspace、initrd 或 bad-shim" >&2
	exit 2
	;;
esac
if [ -n "$broken" ] && [ "$profile" != lab ]; then
	echo "build.sh: --broken 只给回滚试验做坏版本，只许 --profile lab" >&2
	exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
# shellcheck source-path=SCRIPTDIR source=keyset.sh
. "$here/keyset.sh"
keyset=${profile:-release}
priv=$(keyset_priv "$keyset")
pub=$(keyset_pub "$keyset")
lab_local=$(keyset_lab_local)
if [ -n "${MASTERSOS_CORE:-}" ]; then
	core=$MASTERSOS_CORE
elif [ -f "$here/../core/Cargo.toml" ]; then
	core=$here/../core
else
	core=$HOME/mastersos-core
fi
snapshot=${MASTERSOS_SNAPSHOT:-$(date -u +%Y%m%dT000000Z)}
[[ $snapshot =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
	echo "build.sh: MASTERSOS_SNAPSHOT 应形如 20261012T000000Z，实际：$snapshot" >&2
	exit 2
}
if [ "$profile" = lab ]; then
	base=${MASTERSOS_UPDATE_BASE:-http://192.0.2.99/mastersos}
else
	base=${MASTERSOS_UPDATE_BASE:-https://os.khundavid.com}
	host=${base#https://}
	host=${host%%[:/]*}
	if [[ $base != https://* ]] || [ -z "$host" ] || [[ $host =~ ^[0-9.]+$ ]] || [ "$host" = localhost ]; then
		echo "build.sh: 正式镜像要给 MASTERSOS_UPDATE_BASE=https://<域名>/…（不收 http、IP、localhost），实际：'${base}'" >&2
		exit 2
	fi
fi
base=${base%/}
for k in db.key db.crt pcr.key pcr.crt; do
	[ -r "$priv/$k" ] || {
		echo "build.sh: 缺少 $priv/$k" >&2
		exit 2
	}
done
# Exam extension (plan 9 Task 8). The key is kiosk-ext.pem in this key set's private directory (on the builder's disk for lab, in
# tmpfs via keys-load.sh for release). The image carries the crx and updates.xml, so a fresh Chrome profile installs them from disk
# with no network: without this a locked session starting offline has no Exit button. A release build without the key fails; a lab
# build warns and skips, the image has no kiosk-ext.json and the agent skips web / PWA locked apps; local programs are unaffected.
kext_key=$priv/kiosk-ext.pem
kext_dir=usr/lib/mastersos/kiosk-ext
kext_base=file:///$kext_dir
if [ -n "${MASTERSOS_KIOSK_EXT_SRC:-}" ]; then
	kext_src=$MASTERSOS_KIOSK_EXT_SRC
elif [ -f "$here/../kiosk-extension/manifest.json" ]; then
	kext_src=$here/../kiosk-extension
else
	kext_src=$HOME/mastersos-kiosk-extension
fi
kext_skip=""
if [ ! -r "$kext_key" ]; then
	kext_skip="没有考试扩展的钥匙 $kext_key"
elif [ ! -f "$kext_src/manifest.json" ]; then
	kext_skip="没有考试扩展的源码 $kext_src/manifest.json（lab/sync.sh 同步到 ~/mastersos-kiosk-extension）"
fi
if [ -n "$kext_skip" ] && [ "$profile" != lab ]; then
	echo "build.sh: 正式镜像必须带考试扩展：${kext_skip}（正式钥匙随 keys-load.sh 载入，见 docs/key-ceremony.md）" >&2
	exit 2
fi
if [ "$profile" = lab ] && [ ! -r "$lab_local/usr/lib/mastersos/lab-pw.hash" ]; then
	echo "build.sh: lab profile 要有 $lab_local/usr/lib/mastersos/lab-pw.hash" >&2
	exit 2
fi

out=$here/mkosi.output/$version
log=$here/mkosi.output/build-$version.log
mkdir -p "$here/mkosi.output"
exec > >(tee "$log") 2>&1
echo "build.sh: $version profile=${profile:-正式} broken=${broken:-无} snapshot=$snapshot base=$base 钥匙=$priv"

# --- agent 等二进制（Task 6、10 之前没有的 crate 跳过）-----------------------------
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
extra=$here/build/extra
rm -rf "$here/build"
mkdir -p "$extra/usr/bin"
crates=()
for c in mastersos-agent mastersos-installer; do
	if [ -f "$core/$c/Cargo.toml" ]; then
		crates+=(-p "$c")
	else
		echo "build.sh: 还没有 ${c}，跳过"
	fi
done
if [ ${#crates[@]} -gt 0 ]; then
	(cd "$core" && cargo build --locked --release "${crates[@]}" --message-format=json-render-diagnostics) |
		jq -r 'select(.reason == "compiler-artifact" and .executable != null) | .executable' |
		while IFS= read -r bin; do
			install -m 0755 "$bin" "$extra/usr/bin/"
			echo "build.sh: 放进镜像 /usr/bin/$(basename "$bin")"
		done
fi

# --- 考试扩展（计划 9 Task 8）：打包、装进镜像的两个文件经附加树进去（不写进 git 的树）----------------------
#   kiosk-ext.json                 → /usr/lib/mastersos/kiosk-ext.json（agent 的 kiosk 步骤读 id 与 update_url）
#   org.mastersos.kiosk_exit.json  → /etc/opt/chrome/native-messaging-hosts/（factory；/etc/opt/chrome 是策略表里的 dir，这个子目录
#                                    不在表里，机器上是指回 factory 的链接，跟着镜像走；不在被 pam_namespace 换掉的 policies/managed 下）
#   mastersos-kiosk-ext.crx、updates.xml → 产物目录的 kiosk-ext/，publish.sh <版本> chrome 放进发布根的 chrome/
# 目录一级级显式 0755：finalize 按 factory 里的权限生成 /etc/opt、/etc/opt/chrome 的 d 行，不能让构建用户的 umask 决定它们
kext_out=$here/build/kiosk-ext
kext_tree=$here/build/kiosk-ext-tree
kext_id="" kext_version=""
# 复审 M2：上一次（或手放）的东西不能混进附加树——两个目录先清掉（上面整个 build/ 已删过一次，这里不靠它）
rm -rf "$kext_tree" "$kext_out"
if [ -n "$kext_skip" ]; then
	echo "build.sh: 警告：lab 构建不带考试扩展：${kext_skip}。镜像里没有 kiosk-ext.json，网页 / PWA 锁定应用会被 agent 跳过"
else
	mkdir -p "$kext_out"
	kext_id=$(MASTERSOS_KIOSK_EXT_SRC=$kext_src "$here/kiosk-ext-pack.sh" "$kext_key" "$kext_out" "$kext_base")
	kext_version=$(python3 -I -c 'import sys, xml.etree.ElementTree as E
ns = "{http://www.google.com/update2/response}"
u = E.parse(sys.argv[1]).getroot().find(ns + "app/" + ns + "updatecheck")
print(u.get("version"))' "$kext_out/updates.xml")
	for d in etc etc/opt etc/opt/chrome etc/opt/chrome/native-messaging-hosts usr usr/lib usr/lib/mastersos "$kext_dir"; do
		install -d -m 0755 "$kext_tree/$d"
	done
	install -m 0644 "$kext_out/kiosk-ext.json" "$kext_tree/usr/lib/mastersos/kiosk-ext.json"
	install -m 0644 "$kext_out/mastersos-kiosk-ext.crx" "$kext_tree/$kext_dir/mastersos-kiosk-ext.crx"
	install -m 0644 "$kext_out/updates.xml" "$kext_tree/$kext_dir/updates.xml"
	install -m 0644 "$kext_out/org.mastersos.kiosk_exit.json" "$kext_tree/etc/opt/chrome/native-messaging-hosts/org.mastersos.kiosk_exit.json"
	echo "build.sh: 考试扩展 id=$kext_id version=$kext_version，in the image at /$kext_dir"
fi

# --- ukify 包装：数据盘的 PCR 签名只覆盖 enter-initrd（4b Task 4）------------------
# mkosi v27.1 不给 ukify 传 --phases；它以 `python3 <ukify> build …` 调 ukify，ExtraSearchPaths= 的目录
# 排在 find_binary 搜 PATH 的最前、也 --ro-bind 进 sandbox。放一个名为 ukify 的 Python 包装脚本：build 子命令
# 且参数里有 --pcr-private-key 时注入一条 --phases=enter-initrd（命令行本来没有任何 --phases，不冲突），
# 再 exec 真正的 /usr/lib/systemd/ukify；别的子命令（--version、inspect）原样透传。
# 两个 profile 用同一次 ukify build，注入一致生效。mkosi.conf 的 [Validation] 注释、docs/keys.md 有说明。
ukwrap=$here/build/ukify-wrap
mkdir -p "$ukwrap"
cat >"$ukwrap/ukify" <<'PY'
#!/usr/bin/env python3
# MastersOS build.sh 放的 ukify 包装（4b Task 4）：只给数据盘的 PCR 11 策略签 enter-initrd 一个阶段。
import os
import sys

REAL = "/usr/lib/systemd/ukify"
argv = sys.argv[1:]
# 只在 build 子命令、且确实在签 PCR（有 --pcr-private-key）时注入；注入一条即可（命令行只有一把私钥）。
if argv[:1] == ["build"] and any(
    a == "--pcr-private-key" or a.startswith("--pcr-private-key=") for a in argv
) and not any(a == "--phases" or a.startswith("--phases=") for a in argv):
    argv = [argv[0], "--phases=enter-initrd", *argv[1:]]
os.execv(sys.executable, [sys.executable, REAL, *argv])
PY
chmod 0755 "$ukwrap/ukify"

# --- mkosi ---------------------------------------------------------------------
args=(
	-ff
	--image-version="$version"
	--snapshot="$snapshot"
	--output-directory="$out"
	--extra-search-path="$ukwrap"
	--environment=MASTERSOS_UPDATE_BASE="$base"
	--environment=MASTERSOS_BROKEN="$broken"
	--extra-tree="$extra"
	--secure-boot-key="$priv/db.key"
	--secure-boot-certificate="$priv/db.crt"
	--verity-key="$priv/db.key"
	--verity-certificate="$priv/db.crt"
	--sign-expected-pcr-key="$priv/pcr.key"
	--sign-expected-pcr-certificate="$priv/pcr.crt"
)
if [ "$profile" = lab ]; then
	args+=(--profile=lab --extra-tree="$lab_local")
	# Screenshot build: Plymouth ignores the serial console and shows the real splash on screen; prompts are then answered on the
	# VM's screen (qm sendkey), not over serial (mkosi.profiles/lab.conf)
	if [ "${MASTERSOS_LAB_SPLASH:-0}" = 1 ]; then
		args+=(--kernel-command-line=plymouth.ignore-serial-consoles)
	fi
fi
if [ -n "$kext_id" ]; then
	args+=(--extra-tree="$kext_tree")
fi
# 同一版本重建时 mkosi -ff 不会删掉上一次留下的分区文件（文件名带不同的 UUID，Task 1 实测），
# 留着就会被 publish.sh 的通配一起发出去：先整个清掉
sudo rm -rf "$out"
mkdir -p "$out"
sudo mkosi "${args[@]}" build
sudo chown -R "$(id -u):$(id -g)" "$out"
# 考试扩展的 crx 与 updates.xml 跟着这个版本的产物走（publish.sh <版本> chrome 从这里取）
if [ -n "$kext_id" ]; then
	install -d -m 0755 "$out/kiosk-ext"
	install -m 0644 "$kext_out/mastersos-kiosk-ext.crx" "$kext_out/updates.xml" "$out/kiosk-ext/"
fi

# --- initrd 里要有的东西 --------------------------------------------------------
# tpm-probe（0 = 可用、1 = 确认用不了、255 = 判断不了）缺了命令或 libtss2 只会判断不了，恢复出厂的确认缺了命令就不能恢复出厂
# （lsblk、mount、umount 找并只读挂种子分区，tail 读 LoaderDevicePartUUID，cryptsetup 核对恢复密钥；Ruling 22）：
# 构建时就拦下。查 mkosi 产出的 initrd.cpio.zst（就是 UKI 的 .initrd 段的第一段；段里后面还拼着别的 cpio，
# 中间有对齐补位，zstd 不能从头一口气解完）。mkosi 的默认 initrd 不是我们挑的包。
sect=$(mktemp)
mods=$(mktemp)
trap 'rm -f "$sect" "$mods"' EXIT # also when a step below fails under set -e; cleared after this gate
objcopy -O binary --only-section=.initrd "$out/MastersOS_${version}_x86-64.efi" "$sect" # objcopy 要能 seek 的输出
if ! cmp -s -n "$(stat -c %s "$out/initrd.cpio.zst")" "$out/initrd.cpio.zst" "$sect"; then
	echo "build.sh: UKI 的 .initrd 段不是以 initrd.cpio.zst 开头，下面的检查查不到真正启动的 initrd" >&2
	exit 1
fi
initrd_list=$(zstd -dc "$out/initrd.cpio.zst" | cpio -it --quiet)
missing=()
for f in usr/bin/systemd-analyze usr/bin/systemd-creds usr/bin/udevadm usr/bin/systemd-ask-password \
	usr/lib/systemd/systemd-factory-reset usr/bin/systemctl usr/bin/seq usr/bin/tr usr/bin/sleep \
	usr/sbin/cryptsetup usr/bin/lsblk usr/bin/mount usr/bin/umount usr/bin/tail usr/bin/mkdir \
	usr/lib/mastersos/tpm-probe usr/lib/mastersos/factory-reset-confirm \
	usr/lib/systemd/system/mastersos-factory-reset-confirm.service \
	usr/lib/mastersos/luks-bootstrap-key usr/lib/mastersos/luks-bootstrap-persist \
	usr/lib/systemd/system/mastersos-luks-bootstrap-key.service \
	usr/lib/systemd/system/mastersos-luks-bootstrap-persist.service \
	usr/lib/systemd/system/initrd.target.wants/mastersos-luks-bootstrap-persist.service \
	usr/lib/systemd/system/systemd-repart.service.d/50-mastersos-bootstrap-key.conf; do
	grep -qx -- "$f" <<<"$initrd_list" || missing+=("$f")
done
# 根设备的等待排在恢复出厂的确认之后（Task 5 复审 I1）：名字里有 \x2d，按字面比
for f in 'usr/lib/systemd/system/dev-disk-by\x2ddesignator-root.device.d/50-mastersos.conf' \
	'usr/lib/systemd/system/dev-disk-by\x2ddesignator-root\x2dluks.device.d/50-mastersos-factory-reset.conf'; do
	grep -qxF -- "$f" <<<"$initrd_list" || missing+=("$f")
done
for l in libtss2-esys.so.0 libtss2-rc.so.0 libtss2-mu.so.0 libtss2-tcti-device.so.0; do
	grep -qE "/${l//./\\.}\$" <<<"$initrd_list" || missing+=("$l")
done
# /usr self-repair (usr-self-repair Task 3): every command in golden-lib's INITRD_TOOLS (read from the library, not
# copied here), golden-lib, usr-repair and its unit with the initrd.target.wants/ link
# shellcheck disable=SC2016 # $1 and $INITRD_TOOLS expand in the child bash
INITRD_TOOLS=$(bash -c '. "$1" && echo "$INITRD_TOOLS"' _ "$here/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/golden-lib")
[ -n "$INITRD_TOOLS" ] || {
	echo "build.sh: golden-lib defines no INITRD_TOOLS" >&2
	exit 1
}
for t in $INITRD_TOOLS; do
	grep -qE "^usr/s?bin/${t}\$" <<<"$initrd_list" || missing+=("$t")
done
for f in usr/lib/mastersos/golden-lib usr/lib/mastersos/usr-repair \
	usr/lib/systemd/system/mastersos-usr-repair.service \
	usr/lib/systemd/system/initrd.target.wants/mastersos-usr-repair.service; do
	grep -qx -- "$f" <<<"$initrd_list" || missing+=("$f")
done
# Ventoy installer mount (ventoy-attach, Ventoy installer Task 2): the commands it runs (mkosi's default initrd is not a list we
# chose, so a missing one must stop the build, not the first Ventoy boot), the script and its unit with the wants/ link
for t in stat blkid systemd-dissect; do
	grep -qE "^usr/s?bin/${t}\$" <<<"$initrd_list" || missing+=("$t (ventoy-attach)")
done
for f in 'usr/lib/systemd/system/dev-disk-by\x2dloop\x2dref-mastersos\x2dventoy\x2dpart3.device.d/50-mastersos-ventoy.conf' \
	'usr/lib/systemd/system/dev-disk-by\x2dloop\x2dref-mastersos\x2dventoy\x2dpart4.device.d/50-mastersos-ventoy.conf' \
	'usr/lib/systemd/system/dev-mapper-usr.device.d/50-mastersos-ventoy.conf'; do
	grep -qxF -- "$f" <<<"$initrd_list" || missing+=("$f")
done
for f in usr/lib/mastersos/ventoy-attach usr/lib/systemd/system/mastersos-ventoy-attach.service \
	usr/lib/systemd/system/initrd.target.wants/mastersos-ventoy-attach.service; do
	grep -qx -- "$f" <<<"$initrd_list" || missing+=("$f")
done
# Boot splash (design 2026-11-04 visual identity §5.2): plymouthd with our theme as the default, the two-step module, the text
# plugin and at least one font (without them the recovery key prompt draws nothing), and the ask-password agent that sends
# systemd's password prompts to Plymouth
for f in usr/sbin/plymouthd usr/bin/plymouth usr/share/plymouth/plymouthd.defaults \
	usr/share/plymouth/themes/mastersos/mastersos.plymouth usr/share/plymouth/themes/mastersos/throbber-0001.png \
	usr/lib/systemd/system/systemd-ask-password-plymouth.path \
	usr/lib/systemd/system/sysinit.target.wants/plymouth-start.service \
	usr/lib/systemd/system/initrd-switch-root.target.wants/plymouth-start.service; do
	grep -qx -- "$f" <<<"$initrd_list" || missing+=("$f (boot splash)")
done
for l in two-step.so label-pango.so; do
	grep -qE "/plymouth/${l//./\\.}\$" <<<"$initrd_list" || missing+=("$l (boot splash)")
done
grep -qE '^usr/share/fonts/.+\.(ttf|otf)$' <<<"$initrd_list" || missing+=("a font under usr/share/fonts (boot splash text)")
splash_theme=$(zstd -dc "$out/initrd.cpio.zst" | cpio -i --quiet --to-stdout usr/share/plymouth/plymouthd.defaults 2>/dev/null || true)
grep -qx 'Theme=mastersos' <<<"$splash_theme" || missing+=("Theme=mastersos in the initrd's plymouthd.defaults")
# the initrd's own profile file (mkosi.initrd.conf/mkosi.profiles/lab/): usr-repair's lab-fail-verify hook only works with
# "lab" there, so a release initrd must not have it
initrd_profile=$(zstd -dc "$out/initrd.cpio.zst" | cpio -i --quiet --to-stdout usr/lib/mastersos/profile 2>/dev/null || true)
if [ "$initrd_profile" != "$([ "$profile" = lab ] && echo lab || true)" ]; then
	echo "build.sh: the initrd's usr/lib/mastersos/profile is '${initrd_profile:-absent}' for profile=${profile:-release}" >&2
	exit 1
fi
# usr-repair mounts the ESP (vfat, codepage 437, iocharset iso8859-1). Kernel modules are not in initrd.cpio.zst: mkosi
# appends them as a second zstd cpio after zero padding in the same .initrd section, so list that one; on the Ubuntu kernel
# vfat and nls_cp437 are built in (modules.builtin in that cpio), nls_iso8859-1 is a module file.
# Python (standard library only) finds where that archive starts and runs the zstd CLI on it: the archive is followed by
# alignment zeros that zstd rejects, and a frame may itself end in zero bytes, so it tries the shortest slice without the
# trailing zeros first and then adds them back one at a time. Errors come out as one build.sh: line, not a traceback.
python3 - "$sect" "$(stat -c %s "$out/initrd.cpio.zst")" "$mods" <<'PY'
import subprocess, sys

def fail(msg):
    sys.exit("build.sh: " + msg)

try:
    data = open(sys.argv[1], "rb").read()
    start = int(sys.argv[2])
    while start < len(data) and data[start] == 0:  # alignment padding after initrd.cpio.zst
        start += 1
    if start >= len(data):
        fail("the UKI's .initrd section has nothing after initrd.cpio.zst (no kernel-module archive)")
    if data[start:start + 4] != b"\x28\xb5\x2f\xfd":
        fail("the bytes at offset %d of the .initrd section are not a zstd frame (%s)" % (start, data[start:start + 4].hex()))
    end = len(data)
    while end > start and data[end - 1] == 0:
        end -= 1
    for e in range(end, len(data) + 1):
        r = subprocess.run(["zstd", "-dcq"], input=data[start:e], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if r.returncode == 0:
            open(sys.argv[3], "wb").write(r.stdout)
            break
    else:
        fail("zstd cannot decompress the kernel-module archive at offset %d of the .initrd section" % start)
except OSError as e:
    fail("reading the .initrd section: %s" % e)
PY
mod_list=$(cpio -it --quiet <"$mods")
mod_list+=$'\n'$(cpio -i --quiet --to-stdout 'usr/lib/modules/*/modules.builtin' <"$mods")
rm -f "$sect" "$mods"
trap - EXIT
for m in fat/vfat nls/nls_cp437 nls/nls_iso8859-1 exfat/exfat; do
	grep -qE "/fs/${m}\\.ko" <<<"$mod_list" || missing+=("$m.ko")
done
if [ ${#missing[@]} -gt 0 ]; then
	echo "build.sh: initrd 里缺：${missing[*]}" >&2
	exit 1
fi
echo "build.sh: initrd 里有 TPM 探测与恢复出厂确认要用的命令、libtss2 与我们的单元"
echo "build.sh: initrd has golden-lib's INITRD_TOOLS ($INITRD_TOOLS), usr-repair and its unit, vfat/nls_cp437/nls_iso8859-1, profile file ${initrd_profile:-absent}"

# --- ESP：Secure Boot 的钥匙与 MOK 证书（Task 4）------------------------------------------
# 正式镜像的 ESP 上不能有 loader/keys/auto/、loader.conf 必须是 secure-boot-enroll off：在 setup mode 的
# 真机上 systemd-boot 会把它们当成 PK/KEK/db 导入，替换掉微软的钥匙，显卡、网卡的 Option ROM 就起不来。
# 查的是真正要写进 U 盘的 esp.raw（mtools，不用挂载）。结果记进 build-info，publish.sh 对正式的根再核一次。
esp_raw=$out/MastersOS_${version}_x86-64.esp.raw
if mdir -b -i "$esp_raw" ::/loader/keys/auto >/dev/null 2>&1; then
	esp_keys_auto=present
else
	esp_keys_auto=absent
fi
esp_enroll=$(mtype -i "$esp_raw" ::/loader/loader.conf 2>/dev/null | tr -d '\r' |
	sed -n 's/^[[:space:]]*secure-boot-enroll[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' | tail -n 1)
esp_enroll=${esp_enroll:-unset}
if [ "$profile" != lab ] && { [ "$esp_keys_auto" != absent ] || [ "$esp_enroll" != off ]; }; then
	echo "build.sh: 正式镜像的 ESP 上 loader/keys/auto ${esp_keys_auto}、secure-boot-enroll ${esp_enroll}：应为 absent 与 off" >&2
	exit 1
fi
if ! mtype -i "$esp_raw" ::/mastersos-mok.der | cmp -s - "$pub/mastersos-mok.der"; then
	echo "build.sh: ESP 根目录的 mastersos-mok.der 与 $pub/mastersos-mok.der 不同或没有（MokManager「Enroll key from disk」要选它）" >&2
	exit 1
fi
echo "build.sh: ESP：loader/keys/auto $esp_keys_auto，secure-boot-enroll ${esp_enroll}，根目录有 mastersos-mok.der"
# shim：sha256 与它的 .sbatlevel 段（previous / latest 两套 SbatLevel，按 shim 的默认策略写进 previous）。
# publish.sh / promote.sh 据此拒绝换 shim 的版本，除非 --allow-shim-change（docs/secure-boot.md「引导程序更新与 TPM」）。
# 记的是镜像 /usr/lib/mastersos/esp/BOOTX64.EFI 那份——mastersos-bootloader-update 换到机器 ESP 上的就是它——并放一份副本
# MastersOS_<v>_x86-64.shim.bin 进产物，publish/promote 换 shim 时用它验证书链（4b Task 22）。它必须与 esp.raw 上的相同，
# 只有 --broken bad-shim（/usr 里那份被换成测试 CA 重签的，ESP 不动）例外
shim_usr=$out/MastersOS_${version}_x86-64.shim.bin
# shellcheck disable=SC2024 # 有意：读要 root，写进 $out 的文件归构建用户（上面 chown 过）
sudo systemd-dissect --copy-from "$out/MastersOS_${version}_x86-64.raw" /usr/lib/mastersos/esp/BOOTX64.EFI - >"$shim_usr"
shim_sha=$(sha256sum <"$shim_usr" | cut -d' ' -f1)
shim_esp_sha=$(mtype -i "$esp_raw" ::/EFI/BOOT/BOOTX64.EFI | sha256sum | cut -d' ' -f1)
if [ "$broken" = bad-shim ]; then
	[ "$shim_sha" != "$shim_esp_sha" ] || {
		echo "build.sh: --broken bad-shim 的 /usr/lib/mastersos/esp/BOOTX64.EFI 与 ESP 上的 shim 相同（finalize 没换掉它？）" >&2
		exit 1
	}
	echo "build.sh: --broken bad-shim：/usr 里的 shim（${shim_sha:0:12}）是测试 CA 重签的，ESP 上的（${shim_esp_sha:0:12}）没动"
elif [ "$shim_sha" != "$shim_esp_sha" ]; then
	echo "build.sh: ESP 上的 shim（$shim_esp_sha）与镜像里 /usr/lib/mastersos/esp/BOOTX64.EFI（$shim_sha）不是同一份" >&2
	exit 1
fi
shim_sbatlevel=$(objcopy -O binary --only-section=.sbatlevel "$shim_usr" /dev/stdout 2>/dev/null | tail -c +13 | tr '\n\0' ';|' | tr -cd '[:alnum:],.;|_-')
echo "build.sh: shim sha256=$shim_sha SbatLevel（previous|latest）=${shim_sbatlevel:-无 .sbatlevel 段}"
# 链到哪张微软 CA（只打印；发布闸门在换 shim 时才拦）
for ca in "$here"/keys/microsoft/*.der; do
	rc=0
	keyset_shim_chains "$shim_usr" "$ca" "$here/keys/microsoft/dbx" || rc=$?
	case $rc in
	0) echo "build.sh: shim 链到 keys/microsoft/$(basename "$ca")" ;;
	1) echo "build.sh: shim 链不到 keys/microsoft/$(basename "$ca")" ;;
	3) echo "build.sh: 警告：shim 被 keys/microsoft/dbx/ 吊销" ;;
	*) echo "build.sh: 警告：核对不了 shim 与 keys/microsoft/$(basename "$ca") 的证书链" ;;
	esac
done
# systemd-boot（ESP 上的 EFI/BOOT/grubx64.efi，我们签的那份）：publish.sh / promote.sh 据此拒绝换 systemd-boot 的版本，
# 除非 --allow-bootloader-change（终审 I5：ESP 上它没有 A/B）
sdboot_sha=$(mtype -i "$esp_raw" ::/EFI/BOOT/grubx64.efi | sha256sum | cut -d' ' -f1)
[ "$sdboot_sha" != "$(sha256sum </dev/null | cut -d' ' -f1)" ] || {
	echo "build.sh: ESP 上读不出 EFI/BOOT/grubx64.efi（systemd-boot）" >&2
	exit 1
}
# 4a 终审复审 m7：ESP 上这份与镜像 /usr/lib/mastersos/esp/grubx64.efi（mastersos-bootloader-update 从那里复制到 ESP，
# 发布闸门比较的 sdboot_sha256 就是它）必须是同一份字节，否则闸门比的不是机器上真正会换上的那份。不等就不写 build-info。
usr_sdboot_sha=$(sudo systemd-dissect --copy-from "$out/MastersOS_${version}_x86-64.raw" /usr/lib/mastersos/esp/grubx64.efi - | sha256sum | cut -d' ' -f1)
if [ "$usr_sdboot_sha" != "$sdboot_sha" ]; then
	echo "build.sh: ESP 上的 systemd-boot（$sdboot_sha）与镜像里 /usr/lib/mastersos/esp/grubx64.efi（$usr_sdboot_sha）不是同一份" >&2
	exit 1
fi
echo "build.sh: systemd-boot sha256=$sdboot_sha，与 /usr/lib/mastersos/esp/grubx64.efi 相同"
# 签名里有 PKCS#7 signingTime，每次重签字节都不同：另记去掉签名后的 sha256 与签名证书（DER）的 sha256，
# 发布闸门（check_sdboot）两者都相同时不当成换了 systemd-boot
sdb_tmp=$(mktemp -d)
mtype -i "$esp_raw" ::/EFI/BOOT/grubx64.efi >"$sdb_tmp/signed.efi"
cp "$sdb_tmp/signed.efi" "$sdb_tmp/unsigned.efi"
sbattach --remove "$sdb_tmp/unsigned.efi" >/dev/null
sbattach --detach "$sdb_tmp/sig.p7" "$sdb_tmp/signed.efi" >/dev/null
sdboot_unsigned_sha=$(sha256sum <"$sdb_tmp/unsigned.efi" | cut -d' ' -f1)
sdboot_signer_sha=$(openssl pkcs7 -inform DER -in "$sdb_tmp/sig.p7" -print_certs | openssl x509 -outform DER | sha256sum | cut -d' ' -f1)
rm -rf "$sdb_tmp"
[ "$sdboot_unsigned_sha" != "$sdboot_sha" ] && [ "$sdboot_signer_sha" != "$(sha256sum </dev/null | cut -d' ' -f1)" ] || {
	echo "build.sh: 去不掉 systemd-boot 的签名或读不出签名证书" >&2
	exit 1
}
echo "build.sh: systemd-boot 去掉签名 sha256=$sdboot_unsigned_sha，签名证书 sha256=$sdboot_signer_sha"

# --- UKI 的 PCR 签名（4b Task 4 复审 I1）-------------------------------------------
# 每个 profile 恰好一条 sha256 签名、且是 enter-initrd 阶段的，.pcrpkey 是这一组的当前钥匙。ukify 包装没生效（mkosi 换了
# 调法、ToolsTree 换了 ukify 的路径……）时这里拦下：不写 build-info，publish 与 make-installer 都不会接这个构建。
keyset_check_uki "$out/MastersOS_${version}_x86-64.efi" "$keyset" || {
	# 不合格的构建不能留着能直接用的产物（有人手工 dd 那个 .raw 就绕过了闸门）：全部改名成 *.rejected
	for f in "$out"/*; do
		[ -e "$f" ] || continue
		case "$f" in *.rejected) ;; *) mv -f -- "$f" "$f.rejected" ;; esac
	done
	echo "build.sh: UKI 的 PCR 签名不合格（见上），不写 build-info；$out 里的产物都改名成 *.rejected" >&2
	exit 1
}

# --- authd 的 OIDC broker（4b Task 8）：mkosi.build 写进镜像的构建来源 ---------------------------
authd_oidc_info=$(sudo systemd-dissect --copy-from "$out/MastersOS_${version}_x86-64.raw" /usr/lib/mastersos/authd-oidc.build-info -)
for k in authd_oidc_tag authd_oidc_commit authd_oidc_patches authd_oidc_go authd_oidc_go_sha256 authd_oidc_sha256; do
	grep -q "^$k=." <<<"$authd_oidc_info" || {
		echo "build.sh: 镜像里 /usr/lib/mastersos/authd-oidc.build-info 缺 ${k}（mkosi.build 没跑完？）" >&2
		exit 1
	}
done
# The broker in the image carries exactly the patches in this tree's patches/authd-oidc/ (same names, same bytes, same
# order as mkosi.build applies them)
want_patches=none
for p in "$here"/patches/authd-oidc/*.patch; do
	[ -e "$p" ] || continue
	entry=$(basename "$p"):$(sha256sum "$p" | cut -d' ' -f1)
	if [ "$want_patches" = none ]; then want_patches=$entry; else want_patches="$want_patches $entry"; fi
done
got_patches=$(sed -n 's/^authd_oidc_patches=//p' <<<"$authd_oidc_info")
[ "$got_patches" = "$want_patches" ] || {
	echo "build.sh: the broker in the image carries patches '$got_patches', patches/authd-oidc/ has '$want_patches'" >&2
	exit 1
}

# --- 只认公网信任的证书（Ruling 3）：正式镜像里 /usr/local/share/ca-certificates 必须是空的 ------------------
# （试验 CA 只由 lab profile 的附加树放进来；check-tree 第 16 条管源码树，这里管真正构建出来的镜像）
local_ca=$(sudo systemd-dissect --list "$out/MastersOS_${version}_x86-64.raw" | grep -E '^/?usr/local/share/ca-certificates/.' || true)
if [ "$profile" != lab ] && [ -n "$local_ca" ]; then
	echo "build.sh: 正式镜像的 /usr/local/share/ca-certificates 不是空的：$local_ca" >&2
	exit 1
fi
echo "build.sh: /usr/local/share/ca-certificates：${local_ca:-空}"

# --- golden-fetch (usr self-repair Task 7) runs zstd, curl and gpgv from the image; 20261027.4 shipped without zstd -----------
usr_list=$(sudo systemd-dissect --list "$out/MastersOS_${version}_x86-64.raw")
for t in zstd curl gpgv; do
	grep -qxE "/?usr/bin/$t" <<<"$usr_list" || {
		echo "build.sh: the image has no /usr/bin/$t (golden-fetch needs it; mkosi.conf Packages=)" >&2
		exit 1
	}
done
echo "build.sh: /usr/bin/zstd, curl and gpgv are in the image (golden-fetch)"
# --- Wi-Fi: NetworkManager scans through wpa_supplicant, which it only Recommends; 20261029.1 shipped without it ---------------
grep -qxE "/?usr/s?bin/wpa_supplicant" <<<"$usr_list" || {
	echo "build.sh: the image has no wpa_supplicant (Wi-Fi cannot scan; mkosi.conf Packages= needs wpasupplicant)" >&2
	exit 1
}
echo "build.sh: wpa_supplicant is in the image (Wi-Fi)"

# --- build-info.txt ------------------------------------------------------------
commit=$(cat "$here/.build-commit" 2>/dev/null || git -C "$here" rev-parse HEAD 2>/dev/null || echo unknown)
{
	echo "version=$version"
	echo "profile=${profile:-release}"
	echo "broken=${broken:-}"
	if [ "$profile" = lab ]; then echo "lab_splash=${MASTERSOS_LAB_SPLASH:-0}"; fi
	echo "git_commit=$commit"
	echo "Snapshot=$snapshot"
	echo "mkosi=$(mkosi --version)"
	echo "update_base=$base"
	echo "esp_keys_auto=$esp_keys_auto"
	echo "esp_secure_boot_enroll=$esp_enroll"
	echo "shim_sha256=$shim_sha"
	echo "shim_sbatlevel=$shim_sbatlevel"
	echo "sdboot_sha256=$sdboot_sha"
	echo "sdboot_unsigned_sha256=$sdboot_unsigned_sha"
	echo "sdboot_signer_sha256=$sdboot_signer_sha"
	# 考试扩展（计划 9 Task 8）：publish.sh <版本> chrome 据此核对 crx 与 updates.xml；lab 跳过时只有 kiosk_ext=none
	if [ -n "$kext_id" ]; then
		echo "kiosk_ext_id=$kext_id"
		echo "kiosk_ext_version=$kext_version"
		echo "kiosk_ext_update_url=$kext_base/updates.xml"
		echo "kiosk_ext_crx_sha256=$(sha256sum <"$out/kiosk-ext/mastersos-kiosk-ext.crx" | cut -d' ' -f1)"
		echo "kiosk_ext_updates_sha256=$(sha256sum <"$out/kiosk-ext/updates.xml" | cut -d' ' -f1)"
	else
		echo "kiosk_ext=none"
	fi
	echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "builder=$(hostname)"
	for b in "$extra"/usr/bin/*; do
		[ -e "$b" ] && echo "binary=$(basename "$b") sha256=$(sha256sum "$b" | cut -d' ' -f1)"
	done
	# authd 的 OIDC broker（mkosi.build）：tag、commit、带的补丁、go version 与二进制的 sha256
	echo "$authd_oidc_info"
} >"$out/build-info.txt"
cat "$out/build-info.txt"
manifest=$out/MastersOS_${version}_x86-64.manifest
echo "build.sh: 清单 ${manifest}（$(jq '.packages | length' "$manifest") 个包）"

# --- The login screen's card and shelf patch gnome-shell's private GDM code (mastersos-login@mastersos.org): -----------
# a new upstream version must be retested on a VM, then this pin moved. Ubuntu's security rebuilds of 50.1 pass.
gnome_shell_pin=50.1
got_shell=$(jq -r '.packages[] | select(.name == "gnome-shell") | .version' "$manifest")
case $got_shell in
"$gnome_shell_pin"-*) ;;
*)
	echo "build.sh: gnome-shell is '$got_shell', the login extension was tested on $gnome_shell_pin: retest the sign-in card, then move gnome_shell_pin" >&2
	exit 1
	;;
esac

# --- 安装 U 盘（Task 11）：make-installer.sh 自己再按 build-info 与写好的 ESP 把关 --------------------
if [ -n "$broken" ]; then
	echo "build.sh: --broken 的构建只给回滚试验，不做安装 U 盘"
elif [ "$profile" = lab ]; then
	"$here/make-installer.sh" "$version" --profile lab
else
	"$here/make-installer.sh" "$version"
fi
ls -la "$out"

#!/bin/bash
# 打包 MastersOS 考试扩展（kiosk-extension，计划 9 Task 7）：
#   kiosk-ext-pack.sh <钥匙.pem> <输出目录> <base_url>
# <钥匙.pem> 是扩展的签名钥匙（不加密的 PEM RSA 私钥；lab 是构建机的 ~/mastersos-keys/lab/kiosk-ext.pem），扩展的 id
# 由它的公钥算出。私钥只经这个路径交给 openssl 读：不复制、不写进输出目录、不进日志。
# <base_url> is the directory holding the crx and updates.xml, no trailing slash: exactly file:///usr/lib/mastersos/kiosk-ext
# (the image carries them, so a fresh Chrome profile installs with no network) or an https directory. Writes to the output dir:
#   mastersos-kiosk-ext.crx          crx3，签名的 zip（条目排序、时间固定：同一把钥匙、同一份源码打出同样的字节）
#   updates.xml                      appid = id，codebase = <base_url>/mastersos-kiosk-ext.crx，version 取 manifest
#   org.mastersos.kiosk_exit.json    native messaging 宿主清单：退出（kiosk-ext/ 的模板填上 id）
#   org.mastersos.support.json       native messaging 宿主清单：Get help（同上）
#   kiosk-ext.json                   {"id", "update_url": "<base_url>/updates.xml"}，agent 的 kiosk 步骤读它
# 并在 stdout 打印 id（只有这一行）。前两个放到 <base_url> 下；其余由 build.sh 装进镜像（计划 9 Task 8）：
# 两份宿主清单进 /etc/opt/chrome/native-messaging-hosts/，kiosk-ext.json 进 /usr/lib/mastersos/。
# crx 的拼法与签名在 kiosk-ext-pack.py（只用 python3 标准库与 openssl 命令）。测试：tests/kiosk-ext-pack-test.sh。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
die() {
	echo "kiosk-ext-pack: $*" >&2
	exit 1
}

[ $# -eq 3 ] || die "用法：kiosk-ext-pack.sh <钥匙.pem> <输出目录> <base_url>"
key=$1 out=$2 base=$3
if [ ! -f "$key" ] || [ ! -r "$key" ]; then die "读不了钥匙文件 $key"; fi
case "$base" in
https://?* | file:///usr/lib/mastersos/kiosk-ext) ;;
*) die "base_url must be https://… or file:///usr/lib/mastersos/kiosk-ext: $base" ;;
esac
for t in python3 openssl; do
	command -v "$t" >/dev/null || die "缺少 $t"
done
mkdir -p -- "$out"
if [ ! -d "$out" ] || [ ! -w "$out" ]; then die "输出目录 $out 写不了"; fi

# MASTERSOS_KIOSK_EXT_SRC 换扩展源码目录（测试用）
exec python3 -I "$here/kiosk-ext-pack.py" \
	"${MASTERSOS_KIOSK_EXT_SRC:-$here/../kiosk-extension}" "$here/kiosk-ext" "$key" "$out" "$base"

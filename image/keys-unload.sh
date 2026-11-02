#!/bin/bash
# 签名会话结束：抹掉 keys-load.sh 载入 tmpfs 的正式私钥（计划 5 Task 4，裁定 9）。在 VM 161 上以 mastersos 用户跑：
#   keys-unload.sh
# 先停掉这个 homedir 的 gpg-agent（它在内存里缓存着私钥），再 shred -u 每个文件、rm -rf，最后核对目录已不存在。
# 目录本来就不在也算成功（重复跑不报错）。之前先跑 key-leak-check.py（docs/key-ceremony.md「签名会话」第 5 步）。
# MASTERSOS_RELEASE_KEYS 只给测试（要同时 MASTERSOS_TEST=1）。
set -euo pipefail

if [ -n "${MASTERSOS_RELEASE_KEYS:-}" ] && [ "${MASTERSOS_TEST:-}" != 1 ]; then
	echo "keys-unload.sh: MASTERSOS_RELEASE_KEYS 只给测试用（要同时 MASTERSOS_TEST=1）" >&2
	exit 2
fi
dir=${MASTERSOS_RELEASE_KEYS:-/run/mastersos-release-keys}
as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
	echo "keys-unload.sh: $dir 不存在，没有要抹的"
	exit 0
fi
if [ -L "$dir" ] || [ ! -d "$dir" ]; then
	echo "keys-unload.sh: $dir 不是目录（或是符号链接），不碰它" >&2
	exit 1
fi
case "$(cd "$dir" && pwd -P)" in / | /run | /tmp | /var/tmp | "$HOME" | /home | /root)
	echo "keys-unload.sh: 拒绝抹 $dir" >&2
	exit 2
	;;
esac
if [ -d "$dir/gpg" ]; then
	gpgconf --homedir "$dir/gpg" --kill all >/dev/null 2>&1 || true
fi
find "$dir" -xdev -type f -exec shred -u -- {} +
rm -rf -- "$dir" 2>/dev/null || true
# /run 是 root 的：mastersos 用户删不掉 /run 下面的空目录本身（keys-load.sh 用 sudo 建的它）
[ ! -e "$dir" ] || as_root rmdir -- "$dir" 2>/dev/null || as_root rm -rf -- "$dir"
if [ -e "$dir" ]; then
	echo "keys-unload.sh: $dir 还在，抹掉失败" >&2
	exit 1
fi
echo "keys-unload.sh: 已抹掉 ${dir}（gpg-agent 已停，文件已 shred）"

#!/bin/bash
# 在 Mac 上跑：把 image 同步到构建机的 ~/mastersos-image、core 同步到 ~/mastersos-core、
# kiosk-extension（考试扩展的源码，build.sh 打包它）同步到 ~/mastersos-kiosk-extension，
# 并写下当前提交（build.sh 记进 build-info.txt；工作区有改动时带 -dirty）。
# 构建机：MASTERSOS_BUILD_HOST（默认 mastersos@198.51.100.21，即 lab-pve 的 VM 120；MASTERSOS_JUMP 可加跳板）。
set -euo pipefail
img=$(cd "$(dirname "$0")/.." && pwd)
core=$(cd "$img/../core" && pwd)
kext=$(cd "$img/../kiosk-extension" && pwd)
# The builder is lab-pve VM 120 since 2026-10-30 (reachable directly); MASTERSOS_JUMP=<host> adds an ssh jump.
host=${MASTERSOS_BUILD_HOST:-mastersos@198.51.100.21}
ssh_cmd="ssh${MASTERSOS_JUMP:+ -J $MASTERSOS_JUMP}"

commit=$(git -C "$img" rev-parse HEAD)
if [ -n "$(git -C "$img" status --porcelain -- "$img" "$core" "$kext")" ]; then
	commit=$commit-dirty
fi

rsync -a --delete \
	--exclude /mkosi.cache --exclude /mkosi.output --exclude /mkosi.tools --exclude /build \
	--exclude /lab/results --exclude /.build-commit \
	--exclude mkosi.key --exclude mkosi.crt --exclude mkosi.local.conf --exclude /local \
	-e "$ssh_cmd" "$img/" "$host:mastersos-image/"
# core 不带 -t：Mac 上的修改时间原样带过去时，换了工作副本（并行任务轮流构建）后同步过去的
# 文件可能比 target/ 里上一次的产物还旧，cargo 当成没变、直接复用另一份源码编出的库。
# 按内容比较、不保留时间：内容变了的文件拿到构建机上的当前时间，cargo 一定重编。
rsync -rlp --checksum --delete --exclude /target -e "$ssh_cmd" "$core/" "$host:mastersos-core/"
rsync -rlp --checksum --delete -e "$ssh_cmd" "$kext/" "$host:mastersos-kiosk-extension/"
echo "$commit" | $ssh_cmd "$host" 'cat > ~/mastersos-image/.build-commit'
echo "sync.sh: $commit → $host:~/mastersos-image, ~/mastersos-core, ~/mastersos-kiosk-extension"

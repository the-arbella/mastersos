#!/bin/bash
# 把 beta 里验过的某个版本原样放进 stable（在构建机 VM 161 上跑）：
#   promote.sh <version> [--allow-shim-change [--allow-unchained-shim]] [--allow-bootloader-change]
# 复制的是 beta 里的同一批字节（不重新构建、不重新压缩），复制前按 beta 的 SHA256SUMS（先验 gpg 签名）
# 逐个核对；UKI 再过一次发布闸门。然后 stable 只留最近 3 个版本，重写并重签 stable/SHA256SUMS。
# beta 里没有这个版本、它的 build-info 与这棵根对不上（lab 构建、坏版本、update_base 不同）、或比 stable
# 最新的版本旧（机器不降级，Ruling 5）、shim 与 stable 最新的不同（除非 --allow-shim-change，且新 shim 链到微软 CA 之一，见 check_shim_chain）、systemd-boot 与 stable 最新的不同（除非
# --allow-bootloader-change；stable 最新的没有记录时放行并警告）都失败；stable 里已有同样字节的这个版本时只重签。
# 目录布局与 mastersos-root.conf 见 channel-common.sh。
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=channel-common.sh
. "$(dirname "$0")/channel-common.sh"

parse_allow_flags "$@"
[ ${#args[@]} -eq 1 ] || die "用法：promote.sh <version> [--allow-shim-change [--allow-unchained-shim]] [--allow-bootloader-change]（换 shim 的后果见 docs/secure-boot.md「引导程序更新与 TPM」）"
version=${args[0]}
check_version "$version"

read_root_conf sign
lock_root
beta=$root/beta stable=$root/stable
newest=$(newest_in "$stable")
if [ -n "$newest" ] && older_than "$version" "$newest"; then
	die "$version 比 stable 最新的 $newest 旧：机器不降级，promote 了也装不上"
fi
[ -d "$beta" ] || die "没有 $beta"
mapfile -t files < <(files_of "$beta" "$version" .raw.zst)
[ ${#files[@]} -gt 0 ] || die "beta 里没有 ${version}（beta 现有：$(versions_in "$beta" | tr '\n' ' ')）"
require_complete "$beta" "$version" .raw.zst
[ -f "$beta/MastersOS_${version}_x86-64.build-info.txt" ] || die "beta 里的 $version 没有 build-info（不知道它是怎么构建的，不 promote）"

# beta 的 SHA256SUMS 是签过的、列着这几个文件、哈希对得上
(
	cd "$beta"
	gpgv --keyring "$pubring" SHA256SUMS.gpg SHA256SUMS 2>/dev/null || die "beta/SHA256SUMS 的签名验不过"
	for f in "${files[@]}"; do
		grep -qE "^[0-9a-f]{64}  $f\$" SHA256SUMS || die "beta/SHA256SUMS 里没有 $f"
	done
	grep -E "  ($(printf '%s|' "${files[@]}" | sed 's/[.]/\\./g; s/|$//'))\$" SHA256SUMS | sha256sum --quiet -c - ||
		die "beta 里 $version 的文件与 beta/SHA256SUMS 不符"
)
# build-info 已经按签过的 SHA256SUMS 核对过，再看它与这棵根对不对得上
check_build_info "$beta/MastersOS_${version}_x86-64.build-info.txt"
check_uki "$beta/MastersOS_${version}_x86-64.efi"
# stable 里已有这个版本（只重签）时不再比 shim 与 systemd-boot
if [ -z "$(files_of "$stable" "$version" .raw.zst)" ]; then
	check_shim "$beta/MastersOS_${version}_x86-64.build-info.txt" "$stable" "$allow_shim" "$beta/MastersOS_${version}_x86-64.shim.bin" "$allow_unchained"
	check_sdboot "$beta/MastersOS_${version}_x86-64.build-info.txt" "$stable" "$allow_bootloader"
fi

mkdir -p "$stable"
moved=()
existing=$(files_of "$stable" "$version" .raw.zst)
if [ -n "$existing" ]; then
	for f in "${files[@]}"; do
		cmp -s "$beta/$f" "$stable/$f" || die "stable 里已有 ${version}，但 $f 与 beta 的不同"
	done
	echo "promote.sh: stable 里已有同样字节的 ${version}，只重签"
else
	stage=$(mktemp -d "$stable/.promote-$version.XXXXXX")
	trap 'rm -rf "$stage"' EXIT
	for f in "${files[@]}"; do cp -p "$beta/$f" "$stage/$f"; done
	mapfile -t moved < <(printf '%s\n' "${files[@]}" | sort -r)
	for f in "${moved[@]}"; do mv "$stage/$f" "$stable/$f"; done
fi

seal_rc=0
seal_channel "$stable" || seal_rc=$?
case $seal_rc in
0) ;;
1)
	# 新 SHA256SUMS 没换上：原来的签名、清单与旧版本都没动；撤下刚放进来的文件，重跑不会被当成「已经发过」
	for f in "${moved[@]}"; do rm -f "${stable:?}/$f"; done
	die "签名失败，已撤下刚放进stable 的 ${version}；原来的 SHA256SUMS 与旧版本没有动"
	;;
*) die "${version} 已签进 SHA256SUMS，但收尾出错（见上），要人工检查 ${stable}" ;;
esac
echo "promote.sh: $version beta → stable"
(cd "$stable" && sha256sum "${files[@]}")

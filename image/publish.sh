#!/bin/bash
# 把 build.sh 构建好的某个版本发到某个更新通道（在构建机 VM 161 上跑）：
#   publish.sh <version> <stable|beta> [--allow-shim-change [--allow-unchained-shim]] [--allow-bootloader-change]
#   publish.sh <version> installer      安装 U 盘镜像发到 <根>/installer/（版本须已在 stable，见下面那一段）
#   publish.sh <version> chrome         这个构建打包的考试扩展（crx 与 updates.xml）发到 <根>/chrome/（计划 9 Task 8，见下面那一段）
# 0. 构建与这棵根对得上：build-info 的 update_base 等于 <根>/mastersos-root.conf 的 base；lab=no 的根不收
#    lab profile 与 --broken 的构建（见 channel-common.sh）。build-info 跟着进通道，promote 时再查一次。
# 1. 发布闸门：UKI 的 .pcrpkey 必须与这棵根的 PCR 公钥（lab=no：keys/tpm2-pcr-public-key.pem，lab=yes：
#    keys/lab/ 的那份）逐字节相同，每个 profile 都有用这把钥匙签的 .pcrsig；不符就 exit 1，通道目录一个字节都不动（Ruling 4）。
# 2. 三个分区文件 zstd 压缩、UKI 原样，先写到通道目录里的临时目录，再逐个改名进去；
# 3. 只留最近 3 个版本，重写 SHA256SUMS，用这棵根的 gpg 钥匙分离签名（先用仓库里对应的
#    import-pubring.pgp 验过才换上去；根与钥匙的对应见 channel-common.sh 与 keyset.sh）。
# shim 与通道里最新版本的不同就不发，除非 --allow-shim-change，而且新 shim 要链到 keys/microsoft/ 两张微软 CA 之一
# （check_shim_chain，4b Task 22；lab 根可再加 --allow-unchained-shim 放行坏版本）（channel-common.sh 的 check_shim）；systemd-boot 同样，
# 除非 --allow-bootloader-change（check_sdboot；通道最新的没有记录时放行并警告）。
# 比通道里最新的版本旧的不发（机器不降级）；同一版本不能发两次（已装了这个版本的机器不会再下载，改过的字节到不了它们）：换个版本号重建。
# 先在 beta 验、再用 promote.sh 把同一批字节放进 stable。目录布局与环境变量见 channel-common.sh。
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=channel-common.sh
. "$(dirname "$0")/channel-common.sh"

parse_allow_flags "$@"
[ ${#args[@]} -eq 2 ] || die "用法：publish.sh <version> <stable|beta> [--allow-shim-change [--allow-unchained-shim]] [--allow-bootloader-change] | publish.sh <version> installer | publish.sh <version> chrome（换 shim 的后果见 docs/secure-boot.md「引导程序更新与 TPM」）"
version=${args[0]} channel=${args[1]}
check_version "$version"

# --- 安装 U 盘：publish.sh <version> installer --------------------------------------------
# <根>/installer/ 放 IT 下载的 U 盘镜像 MastersOS-installer_<v>_x86-64.img.zst 和 Ventoy 包 MastersOS-ventoy_<v>_x86-64.zip
# （make-installer.sh 同一次做的，ESP 已由它把关；zip 整个发、不解包，两者进同一份签名的 SHA256SUMS，解开的 img.zst 与 zip 里的系统文件内容不同就拒绝）。
# 只发已经在 stable 里、而且 UKI 与 stable 里那份逐字节相同的版本：U 盘装出来的机器就是 stable 上的这个版本，
# 之后照常跟 stable 更新。build-info 与这棵根对得上（与通道同一道 check_build_info）。留最近 KEEP 个，
# SHA256SUMS 用同一把 gpg 钥匙签、先用仓库里的公钥验过才换上。同一版本再发一次：字节相同只重签，不同就拒绝。
if [ "$channel" = installer ]; then
	out=$outdir/$version
	name=MastersOS-installer_${version}_x86-64.img.zst
	zname=MastersOS-ventoy_${version}_x86-64.zip
	[ -f "$out/$name" ] || die "没有 $out/${name}（build.sh 成功构建时由 make-installer.sh 做出来）"
	[ -f "$out/$zname" ] || die "没有 $out/${zname}（Ventoy 包，make-installer.sh 与 ${name} 一起做出来；构建机要装 zip 与 unzip）"
	# 两个文件必须出自同一次 make-installer.sh（每次跑 U 盘镜像的字节都不同；Ventoy 包里的系统文件就是那一份镜像）。
	# 文件的 mtime 看不出来（zip 在 zstd 压缩 img.zst 之前就做好了），所以比内容：解开的 img.zst 的 sha256
	# 必须等于 zip 里 MastersOS/MastersOS-system_<v>_x86-64.raw 的 sha256（两边都是流，不落盘）
	command -v unzip >/dev/null || die "publish.sh needs unzip to check that $zname and $name come from the same make-installer.sh run"
	sys_member=MastersOS/MastersOS-system_${version}_x86-64.raw
	zip_sys_sha=$(unzip -p "$out/$zname" "$sys_member" | sha256sum | cut -d' ' -f1) ||
		die "cannot read $sys_member from $out/${zname}"
	img_sha=$(zstd -dc "$out/$name" | sha256sum | cut -d' ' -f1) || die "cannot decompress $out/${name}"
	[ "$zip_sys_sha" = "$img_sha" ] ||
		die "$name and $zname come from different make-installer.sh runs ($sys_member in the zip has sha256 $zip_sys_sha, the decompressed image $img_sha): re-run make-installer.sh ${version} and publish the two files it writes together"
	read_root_conf sign
	check_build_info "$out/build-info.txt"
	lock_root
	stable=$root/stable dir=$root/installer
	[ -f "$stable/MastersOS_${version}_x86-64.efi" ] ||
		die "stable 里没有 ${version}：U 盘只发已经在 stable 的版本（先 publish 或 promote 到 stable）"
	cmp -s "$out/MastersOS_${version}_x86-64.efi" "$stable/MastersOS_${version}_x86-64.efi" ||
		die "$out 里的 UKI 与 stable 里的 ${version} 不是同一份字节（重建过？）：U 盘装出来的不会是 stable 上的版本"
	mkdir -p "$dir"
	# 已有的同名文件字节必须相同（一个也不动就拒绝）；zip 作为一个整体发，不解包（里面也有个同名 MastersOS-installer_<v>_x86-64.efi，是 Ventoy 版的）
	for f in "$name" "$zname"; do
		[ ! -f "$dir/$f" ] || cmp -s "$out/$f" "$dir/$f" || die "installer/ 里已有 ${f}，字节不同（同一版本不能发两份 U 盘）"
	done
	stage=$(mktemp -d "$dir/.publish-$version.XXXXXX")
	trap 'rm -rf "$stage"' EXIT
	added=()
	for f in "$name" "$zname"; do
		if [ -f "$dir/$f" ]; then
			echo "publish.sh: installer/ 里已有同样字节的 ${f}，只重签"
		else
			cp "$out/$f" "$stage/$f"
			chmod 0644 "$stage/$f"
			if ! mv "$stage/$f" "$dir/$f"; then
				# no half-published pair: take back what this run already moved in
				for g in "${added[@]}"; do rm -f "${dir:?}/$g"; done
				die "cannot move $f into ${dir}; removed what this run had already added"
			fi
			added+=("$f")
		fi
	done
	mapfile -t all < <(cd "$dir" && find . -maxdepth 1 -name 'MastersOS-installer_*_x86-64.img.zst' -printf '%f\n' | sort -V)
	# ${all[@]: -N} 在不足 N 个时是空的：起点自己算
	start=$((${#all[@]} > KEEP ? ${#all[@]} - KEEP : 0))
	keep=("${all[@]:$start}")
	# 清单：每个留下的版本的 img.zst，加上它的 Ventoy 包（更早发的版本没有就不列）
	listed=()
	for f in "${keep[@]}"; do
		listed+=("$f")
		z=${f/MastersOS-installer_/MastersOS-ventoy_}
		z=${z%.img.zst}.zip
		[ ! -f "$dir/$z" ] || listed+=("$z")
	done
	(cd "$dir" && sha256sum "${listed[@]}") >"$dir/.SHA256SUMS.new"
	if ! gpg --homedir "$gnupghome" --batch --yes --detach-sign --output "$dir/.SHA256SUMS.gpg.new" "$dir/.SHA256SUMS.new" ||
		! gpgv --keyring "$pubring" "$dir/.SHA256SUMS.gpg.new" "$dir/.SHA256SUMS.new" 2>/dev/null; then
		rm -f "$dir/.SHA256SUMS.new" "$dir/.SHA256SUMS.gpg.new"
		for f in "${added[@]}"; do rm -f "${dir:?}/$f"; done
		die "签 installer/SHA256SUMS 失败或用 $pubring 验不过；installer/ 原来的文件没动"
	fi
	mv -f "$dir/.SHA256SUMS.gpg.new" "$dir/SHA256SUMS.gpg"
	mv -f "$dir/.SHA256SUMS.new" "$dir/SHA256SUMS"
	for f in "${all[@]}"; do
		case " ${keep[*]} " in *" $f "*) ;; *)
			z=${f/MastersOS-installer_/MastersOS-ventoy_}
			rm -f "${dir:?}/$f" "${dir:?}/${z%.img.zst}.zip"
			echo "publish.sh: installer/ 只留最近 $KEEP 个，删掉 $f（和它的 Ventoy 包）"
			;;
		esac
	done
	echo "publish.sh: $name、$zname → ${dir}"
	(cd "$dir" && ls -l SHA256SUMS SHA256SUMS.gpg "${listed[@]}")
	exit 0
fi

# --- 考试扩展：publish.sh <version> chrome（计划 9 Task 8）--------------------------------------------
# <根>/chrome/ 放考试扩展的 mastersos-kiosk-ext.crx 与 updates.xml（Chrome 按镜像里 kiosk-ext.json 的 update_url 来取），
# 对外的地址是 <base>/chrome（lab=yes 的根用 mastersos-root.conf 的 chrome_base=，试验网的 base 是 http）。扩展不分通道：
# 每台机器（不论 stable、beta）都按同一个 updates.xml 更新。所以：
#   - 这个版本已经在这棵根的 beta 或 stable 里（UKI 字节相同；复审 M1）；
#   - 构建与这棵根对得上（check_build_info）、build-info 记着扩展（kiosk_ext_*），两个文件的 sha256 与记的相同；
#   - updates.xml 的 appid / version / codebase 与 build-info 和这棵根的 chrome 地址一致；
#   - 根里已有的扩展 id 不同就拒绝（换了扩展钥匙：已装的机器上 kiosk-ext.json 的 id 还是旧的，发了它们就再也装不上扩展）；
#   - 比根里的版本旧就拒绝（Chrome 不降级）；版本相同：字节相同只重签，不同就拒绝（同一版本 Chrome 不会再下载）。
# 先 crx、后 updates.xml 换进去（updates.xml 换上之前机器拿到的仍是旧清单），再重写并签 chrome/SHA256SUMS（sync-s3.sh 据此核对）。
if [ "$channel" = chrome ]; then
	out=$outdir/$version
	info=$out/build-info.txt
	read_root_conf sign
	check_build_info "$info"
	kv() { sed -n "s/^$1=//p" "$info"; }
	# Builds that carry the extension in the image have nothing to put in chrome/.
	case "$(kv kiosk_ext_update_url)" in
	file://*)
		echo "publish.sh: $version carries the exam extension in the image; nothing to publish to chrome/"
		exit 0
		;;
	esac
	[ -n "$root_chrome_base" ] ||
		die "这棵根（lab=yes）没有 chrome_base=：试验网的 base 是 http，考试扩展要一个 https 地址（在 ${root_conf} 里写 chrome_base=https://…/chrome）"
	[ "$(kv kiosk_ext)" != none ] || die "$version 的构建没带考试扩展（build-info 写着 kiosk_ext=none：lab 构建缺钥匙或 https 地址）"
	ext_id=$(kv kiosk_ext_id) ext_ver=$(kv kiosk_ext_version) ext_url=$(kv kiosk_ext_update_url)
	{ [[ $ext_id =~ ^[a-p]{32}$ ]] && [[ $ext_ver =~ ^[0-9]+(\.[0-9]+){0,3}$ ]]; } ||
		die "build-info 里没有像样的 kiosk_ext_id / kiosk_ext_version（$ext_id / $ext_ver）"
	[ "$ext_url" = "$root_chrome_base/updates.xml" ] ||
		die "构建的考试扩展 update_url（${ext_url:-空}）不是这棵根的 $root_chrome_base/updates.xml：装上它的机器会去别处找扩展"
	crx=$out/kiosk-ext/mastersos-kiosk-ext.crx upd=$out/kiosk-ext/updates.xml
	{ [ -f "$crx" ] && [ -f "$upd" ]; } || die "没有 $crx 或 ${upd}（build.sh 打包考试扩展时放的）"
	[ "$(sha256sum <"$crx" | cut -d' ' -f1)" = "$(kv kiosk_ext_crx_sha256)" ] || die "$crx 的 sha256 与 build-info 记的不同（构建之后被改过）"
	[ "$(sha256sum <"$upd" | cut -d' ' -f1)" = "$(kv kiosk_ext_updates_sha256)" ] || die "$upd 的 sha256 与 build-info 记的不同（构建之后被改过）"
	# updates.xml → appid、version、codebase（一行一个）
	upd_fields() {
		python3 -I -c 'import sys, xml.etree.ElementTree as E
ns = "{http://www.google.com/update2/response}"
a = E.parse(sys.argv[1]).getroot().find(ns + "app")
u = a.find(ns + "updatecheck")
print(a.get("appid")); print(u.get("version")); print(u.get("codebase"))' "$1"
	}
	mapfile -t f < <(upd_fields "$upd") || die "读不懂 $upd"
	[ "${f[*]}" = "$ext_id $ext_ver $root_chrome_base/mastersos-kiosk-ext.crx" ] ||
		die "$upd 的 appid / version / codebase（${f[*]}）与 build-info 和这棵根（$ext_id $ext_ver $root_chrome_base/mastersos-kiosk-ext.crx）对不上"
	# 复审 M1：扩展不分通道、发了就到所有机器，只发已经进了这棵根的 beta 或 stable（UKI 字节相同）的构建带的扩展
	in_ch=""
	for c in beta stable; do
		if [ -f "$root/$c/MastersOS_${version}_x86-64.efi" ] && cmp -s "$out/MastersOS_${version}_x86-64.efi" "$root/$c/MastersOS_${version}_x86-64.efi"; then
			in_ch=$c
		fi
	done
	[ -n "$in_ch" ] ||
		die "$version 不在这棵根的 beta 或 stable 里（或 UKI 与那里的不是同一份字节）：考试扩展不分通道，先把这个版本发到 beta 验过"
	lock_root
	dir=$root/chrome
	mkdir -p "$dir"
	same=0
	if [ -f "$dir/updates.xml" ]; then
		mapfile -t g < <(upd_fields "$dir/updates.xml") || die "读不懂根里的 $dir/updates.xml"
		[ "${g[0]:-}" = "$ext_id" ] ||
			die "根里的考试扩展 id 是 ${g[0]:-?}，这个构建是 ${ext_id}（换了扩展钥匙）：已装的机器的 kiosk-ext.json 还是旧 id，发了它们就装不上扩展"
		if [ "${g[1]:-}" = "$ext_ver" ]; then
			{ cmp -s "$crx" "$dir/mastersos-kiosk-ext.crx" && cmp -s "$upd" "$dir/updates.xml"; } ||
				die "根里已有考试扩展 ${ext_ver}，字节不同：同一版本 Chrome 不会再下载（改了扩展要调高 manifest.json 的 version）"
			same=1
			echo "publish.sh: chrome/ 里已是同样字节的考试扩展 ${ext_ver}，只重签"
		elif [ "$(printf '%s\n%s\n' "$ext_ver" "${g[1]:-0}" | sort -V | head -n 1)" = "$ext_ver" ]; then
			die "考试扩展 $ext_ver 比根里的 ${g[1]:-?} 旧：Chrome 不降级"
		fi
	fi
	if [ "$same" = 0 ]; then
		stage=$(mktemp -d "$dir/.publish-chrome.XXXXXX")
		trap 'rm -rf "$stage"' EXIT
		cp "$crx" "$upd" "$stage/"
		chmod 0644 "$stage"/*
		mv -f "$stage/mastersos-kiosk-ext.crx" "$dir/mastersos-kiosk-ext.crx"
		mv -f "$stage/updates.xml" "$dir/updates.xml"
	fi
	(cd "$dir" && sha256sum mastersos-kiosk-ext.crx updates.xml) >"$dir/.SHA256SUMS.new"
	if ! gpg --homedir "$gnupghome" --batch --yes --detach-sign --output "$dir/.SHA256SUMS.gpg.new" "$dir/.SHA256SUMS.new" ||
		! gpgv --keyring "$pubring" "$dir/.SHA256SUMS.gpg.new" "$dir/.SHA256SUMS.new" 2>/dev/null; then
		rm -f "$dir/.SHA256SUMS.new" "$dir/.SHA256SUMS.gpg.new"
		die "签 chrome/SHA256SUMS 失败或用 $pubring 验不过（crx 与 updates.xml 已换上，修好钥匙后重跑同一条命令只重签）"
	fi
	mv -f "$dir/.SHA256SUMS.gpg.new" "$dir/SHA256SUMS.gpg"
	mv -f "$dir/.SHA256SUMS.new" "$dir/SHA256SUMS"
	echo "publish.sh: 考试扩展 $ext_id $ext_ver → ${dir}（$root_chrome_base/updates.xml）"
	(cd "$dir" && ls -l SHA256SUMS SHA256SUMS.gpg mastersos-kiosk-ext.crx updates.xml)
	exit 0
fi
check_channel "$channel"

out=$outdir/$version
[ -d "$out" ] || die "没有 ${out}（先 build.sh ${version}）"
require_complete "$out" "$version" .raw
uki=$out/MastersOS_${version}_x86-64.efi

# --- 0、1. 构建与根对得上、发布闸门（在动任何东西之前）-------------------------------
read_root_conf sign
check_build_info "$out/build-info.txt"
check_uki "$uki"

lock_root
dir=$root/$channel
mkdir -p "$dir"
if [ -n "$(files_of "$dir" "$version" .raw.zst)" ]; then
	die "$channel 里已经有 ${version}（同一版本不能发两次，换个版本号重建）"
fi
newest=$(newest_in "$dir")
if [ -n "$newest" ] && older_than "$version" "$newest"; then
	die "$version 比 $channel 最新的 $newest 旧：机器不会降级，发了也装不上（换个更大的版本号重建）"
fi
check_shim "$out/build-info.txt" "$dir" "$allow_shim" "$out/MastersOS_${version}_x86-64.shim.bin" "$allow_unchained"
check_sdboot "$out/build-info.txt" "$dir" "$allow_bootloader"

# --- 2. 压缩、复制 ---------------------------------------------------------------
stage=$(mktemp -d "$dir/.publish-$version.XXXXXX")
trap 'rm -rf "$stage"' EXIT
for f in $(files_of "$out" "$version" .raw); do
	case "$f" in
	*.efi | *.shim.bin) cp "$out/$f" "$stage/$f" ;;
	*) zstd -q -T0 "$out/$f" -o "$stage/$f.zst" ;;
	esac
done
cp "$out/build-info.txt" "$stage/MastersOS_${version}_x86-64.build-info.txt"
chmod 0644 "$stage"/*
# 分区文件先进、UKI 与 build-info 最后：SHA256SUMS 还没改之前 sysupdate 看不见它们
mapfile -t moved < <(files_of "$stage" "$version" .raw.zst | sort -r)
for f in "${moved[@]}"; do mv "$stage/$f" "$dir/$f"; done

# --- 3. 保留、SHA256SUMS、签名（失败就把刚放进去的文件拿走，免得重跑时被当成「已经发过」）------
seal_rc=0
seal_channel "$dir" || seal_rc=$?
case $seal_rc in
0) ;;
1)
	# 新 SHA256SUMS 没换上：原来的签名、清单与旧版本都没动；撤下刚放进来的文件，重跑不会被当成「已经发过」
	for f in "${moved[@]}"; do rm -f "${dir:?}/$f"; done
	die "签名失败，已撤下刚放进通道的 ${version}；原来的 SHA256SUMS 与旧版本没有动"
	;;
*) die "${version} 已签进 SHA256SUMS，但收尾出错（见上），要人工检查 ${dir}" ;;
esac
echo "publish.sh: $version → ${channel}（${dir}）"
# shellcheck disable=SC2046 # 文件名是 MastersOS_<v>_… 加 UUID，没有空白
(cd "$dir" && ls -l SHA256SUMS SHA256SUMS.gpg $(files_of . "$version" .raw.zst))

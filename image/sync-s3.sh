#!/bin/bash
# 把签好的本地发布根镜像到 S3（CloudFront 的源站），在构建机 VM 161 上跑：
#   sync-s3.sh [--dry-run]
# 本地根（MASTERSOS_PUBLISH_ROOT，正式的是 /srv/mastersos/release）是唯一的真相，S3 只是它的镜像（计划 5 裁定 5）；
# 根的 mastersos-root.conf 要有 lab=no、mirror_s3=s3://<桶>、mirror_cdn=<DistributionId>。publish.sh / promote.sh 不碰网络，
# 发布 = 先它们、再本脚本；同步中断就重跑（每一步都可以重来）。
#
# 顺序保证 CDN 上任何时刻都没有指向不存在文件的清单（裁定 4）：
#   1 本地自检  stable、beta、installer、chrome 中存在的每个目录：SHA256SUMS 的签名用这棵根的公钥验得过、列着的每个文件都在且
#               sha256 对得上；任何一项不过就退出，桶一个字节都不动。传的 = 各目录 SHA256SUMS 列着的文件 + SHA256SUMS +
#               SHA256SUMS.gpg，别的（mastersos-root.conf、.lock、临时目录）一概不传
#   2 带版本号的文件  桶里没有才传（Cache-Control 一年 immutable，metadata sha256）；已有且 sha256 相同就跳过；
#               已有而不同就拒绝（边缘节点上一年的缓存会留着旧字节，换版本号重建）。先把所有对象都查完、没有一个冲突，才开始传
#   2b 考试扩展 chrome/ 的 mastersos-kiosk-ext.crx 与 updates.xml（计划 9 Task 8）名字不带版本、每次发布都换字节（Chrome 按 updates.xml
#               的固定地址来取），不走第 2 步的「同名不同字节就拒绝」：先 crx、后 updates.xml，max-age=300，每次都传
#   3 清单      每个目录先 SHA256SUMS、后 SHA256SUMS.gpg（max-age=60）
#   4 失效      /<目录>/SHA256SUMS*（chrome/ 是整个 /chrome/*）失效并等它完成；失败就退出，不删任何东西
#   5 删除      四个前缀里不在第 1 步集合的对象。本地没有的目录，桶里对应的前缀不碰
# 环境变量：MASTERSOS_PUBLISH_ROOT（同 publish.sh）、MASTERSOS_SYNC_SETTLE（删除前多等几秒，默认 60 = 清单的 max-age，只给测试设 0）、MASTERSOS_AWS_PROFILE（默认 mastersos-publish；只写这一个桶、只能给这一个分发做失效）。
# --dry-run 只打印第 2–5 步要做的事，只调 head-object 与 list-objects-v2。
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=channel-common.sh
. "$(dirname "$0")/channel-common.sh"

DIRS="stable beta installer chrome"
# chrome/ 里只许这两个文件（publish.sh <版本> chrome 写的），名字固定、内容可变
CHROME_FILES="mastersos-kiosk-ext.crx updates.xml"
dry=0
case "${1:-}" in
"") ;;
--dry-run) dry=1 ;;
*) die "用法：sync-s3.sh [--dry-run]" ;;
esac
[ $# -le 1 ] || die "用法：sync-s3.sh [--dry-run]"

read_root_conf verify # 只核对签过的清单，不要私钥（正式私钥不用为同步载入 tmpfs）
[ "$root_lab" = no ] || die "$root 是 lab=yes 的根，不镜像到 S3"
[ -n "$root_mirror_s3" ] || die "${root_conf} 没有 mirror_s3= / mirror_cdn=（这棵根没声明镜像到哪里）"
lock_root
export AWS_PROFILE=${MASTERSOS_AWS_PROFILE:-mastersos-publish}
bucket=${root_mirror_s3#s3://}
for t in aws gpgv sha256sum; do
	command -v "$t" >/dev/null || die "没有 ${t}"
done

# want_sha[<目录>/<文件>]=sha256；in_set 是第 1 步的整个集合（含清单），versioned 是带版本号的对象键
declare -A want_sha=() in_set=()
dirs_present=() versioned=() mutable=()

# 第 1 步：本地自检（还没碰过 aws）
for d in $DIRS; do
	dir=$root/$d
	[ -d "$dir" ] || continue
	if [ ! -f "$dir/SHA256SUMS" ] || [ ! -f "$dir/SHA256SUMS.gpg" ]; then
		die "$dir 缺 SHA256SUMS 或 SHA256SUMS.gpg：这个通道没签过，不同步"
	fi
	gpgv --keyring "$pubring" "$dir/SHA256SUMS.gpg" "$dir/SHA256SUMS" 2>/dev/null ||
		die "$dir/SHA256SUMS 的签名用 ${pubring} 验不过：本地树不可信，不同步（桶没动）"
	n=0
	while read -r h f; do
		[[ $h =~ ^[0-9a-f]{64}$ ]] || die "$dir/SHA256SUMS 里有看不懂的行：'$h $f'"
		[[ $f =~ ^[A-Za-z0-9._+-]+$ ]] || die "$dir/SHA256SUMS 里有看不懂的行：'$h $f'"
		[ -f "$dir/$f" ] || die "$dir/SHA256SUMS 列着 $f，但文件不在：本地树不完整，不同步"
		want_sha["$d/$f"]=$h
		if [ "$d" = chrome ]; then
			case " $CHROME_FILES " in *" $f "*) ;; *) die "$dir/SHA256SUMS 列着 ${f}：chrome/ 里只许 ${CHROME_FILES}" ;; esac
			mutable+=("$d/$f")
		else
			versioned+=("$d/$f")
		fi
		in_set["$d/$f"]=1
		n=$((n + 1))
	done <"$dir/SHA256SUMS"
	[ "$n" -gt 0 ] || die "$dir/SHA256SUMS 是空的：同步它会清空桶里的 $d/，不做"
	(cd "$dir" && sha256sum --quiet -c SHA256SUMS) >/dev/null 2>&1 || die "$dir 里的文件与 SHA256SUMS 对不上：本地树坏了，不同步（桶没动）"
	in_set["$d/SHA256SUMS"]=1
	in_set["$d/SHA256SUMS.gpg"]=1
	dirs_present+=("$d")
done
[ ${#dirs_present[@]} -gt 0 ] || die "$root 下没有 stable、beta、installer、chrome 中的任何一个目录"
if [ ${#mutable[@]} -gt 0 ] && [ ${#mutable[@]} != 2 ]; then
	die "$root/chrome/SHA256SUMS 应恰好列着 ${CHROME_FILES}"
fi
# crx 在前、updates.xml 在后：桶里的 updates.xml 换上之前，新的 crx 已经在了
mapfile -t mutable < <(printf '%s\n' "${mutable[@]}" | sed '/^$/d' | LC_ALL=C sort)
say() { echo "$(basename "$0"): $*"; }
say "根 ${root} → ${root_mirror_s3}（CloudFront ${root_mirror_cdn}，profile ${AWS_PROFILE}），目录：${dirs_present[*]}$([ "$dry" = 1 ] && echo '；--dry-run')"
if [ "$dry" = 0 ]; then
	aws sts get-caller-identity --query Arn --output text >/dev/null || die "aws 凭据不可用（profile ${AWS_PROFILE}）"
fi

# 第 2 步：先把所有带版本号的对象都查完——有一个字节不同就拒绝，此时还没传过任何东西
declare -A n_up=() n_skip=() n_del=()
todo=()
errf=$(mktemp)
trap 'rm -f "$errf"' EXIT
for d in "${dirs_present[@]}"; do n_up[$d]=0 n_skip[$d]=0 n_del[$d]=0; done
for k in "${versioned[@]}"; do
	d=${k%%/*}
	rc=0
	out=$(aws s3api head-object --bucket "$bucket" --key "$k" --query Metadata.sha256 --output text 2>"$errf") || rc=$?
	if [ "$rc" != 0 ]; then
		err=$(cat "$errf")
		case "$err" in
		*"(404)"* | *"Not Found"*)
			todo+=("$k")
			n_up[$d]=$((n_up[$d] + 1))
			;;
		*) die "查不了 s3://$bucket/${k}：$err" ;;
		esac
	elif [ "$out" = "${want_sha[$k]}" ]; then
		n_skip[$d]=$((n_skip[$d] + 1))
	else
		die "s3://$bucket/$k 已存在，但 sha256（${out}）与本地的 ${want_sha[$k]} 不同：同名对象字节不同，边缘节点上一年的缓存会留着旧字节，换版本号重建（没传任何东西）"
	fi
done

# 要删的：三个前缀里不在集合里的对象（只管本地有的目录）
to_delete=()
for d in "${dirs_present[@]}"; do
	out=$(aws s3api list-objects-v2 --bucket "$bucket" --prefix "$d/" --query 'Contents[].[Key]' --output text) || die "列不出 s3://$bucket/$d/"
	while IFS= read -r k; do
		if [ -z "$k" ] || [ "$k" = None ]; then continue; fi
		[[ $k == "$d/"* ]] || die "list-objects-v2 回了前缀之外的键 '$k'"
		[ -z "${in_set[$k]:-}" ] || continue
		to_delete+=("$k")
		n_del[$d]=$((n_del[$d] + 1))
	done <<<"$out"
done

if [ "$dry" = 1 ]; then
	for k in "${todo[@]}"; do say "[dry-run] 传 $k"; done
	for k in "${mutable[@]}"; do say "[dry-run] 传 ${k}（max-age=300，每次都传）"; done
	for d in "${dirs_present[@]}"; do say "[dry-run] 传 $d/SHA256SUMS、$d/SHA256SUMS.gpg"; done
	say "[dry-run] 失效 /<目录>/SHA256SUMS*（${dirs_present[*]}），等完成"
	for k in "${to_delete[@]}"; do say "[dry-run] 删 $k"; done
else
	# 第 2 步：带版本号的文件，一年不变
	for k in "${todo[@]}"; do
		aws s3 cp "$root/$k" "s3://$bucket/$k" --only-show-errors --cache-control 'public, max-age=31536000, immutable' \
			--content-type application/octet-stream --metadata "sha256=${want_sha[$k]}" || die "传 $k 失败（清单还是上一次同步的，重跑即可）"
	done
	# 第 2b 步：考试扩展（名字固定、内容可变），crx 先、updates.xml 后
	for k in "${mutable[@]}"; do
		case "$k" in *.crx) ct=application/x-chrome-extension ;; *) ct=application/xml ;; esac
		aws s3 cp "$root/$k" "s3://$bucket/$k" --only-show-errors --cache-control 'public, max-age=300' \
			--content-type "$ct" --metadata "sha256=${want_sha[$k]}" || die "传 $k 失败（重跑即可）"
		n_up[chrome]=$((n_up[chrome] + 1))
	done
	# 第 3 步：清单，先 SHA256SUMS、后 .gpg
	for d in "${dirs_present[@]}"; do
		aws s3 cp "$root/$d/SHA256SUMS" "s3://$bucket/$d/SHA256SUMS" --only-show-errors --cache-control 'public, max-age=60' \
			--content-type text/plain || die "传 $d/SHA256SUMS 失败（重跑即可）"
		aws s3 cp "$root/$d/SHA256SUMS.gpg" "s3://$bucket/$d/SHA256SUMS.gpg" --only-show-errors --cache-control 'public, max-age=60' \
			--content-type application/pgp-signature || die "传 $d/SHA256SUMS.gpg 失败：桶里的清单与签名对不上，重跑即可"
	done
	# 第 4 步：失效并等完成；之后才删
	paths=()
	for d in "${dirs_present[@]}"; do
		if [ "$d" = chrome ]; then paths+=("/chrome/*"); else paths+=("/$d/SHA256SUMS*"); fi
	done
	inv=$(aws cloudfront create-invalidation --distribution-id "$root_mirror_cdn" --paths "${paths[@]}" --query Invalidation.Id --output text) ||
		die "CloudFront 失效失败：没删任何东西，重跑即可"
	aws cloudfront wait invalidation-completed --distribution-id "$root_mirror_cdn" --id "$inv" ||
		die "等不到失效 ${inv} 完成：没删任何东西，重跑即可"
	# 第 5 步：删。先等旧清单在边缘节点和客户端的 max-age=60 过去（失效之外的保险），MASTERSOS_SYNC_SETTLE 秒，默认 60，只给测试改
	sleep "${MASTERSOS_SYNC_SETTLE:-60}"
	for k in "${to_delete[@]}"; do
		aws s3 rm "s3://$bucket/$k" --only-show-errors || die "删 $k 失败（重跑即可）"
	done
fi

# 第 6 步
for d in "${dirs_present[@]}"; do
	say "$d：传 ${n_up[$d]} 个、跳过 ${n_skip[$d]} 个、删 ${n_del[$d]} 个（另有 SHA256SUMS 与 SHA256SUMS.gpg）"
done
say "$([ "$dry" = 1 ] && echo '--dry-run 结束，桶没动' || echo '同步完成')"

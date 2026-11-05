#!/bin/bash
# Publish a release build to the update source from GitHub Actions. The release root (docs/update-channels.md) only
# exists for the length of a job: this script rebuilds the part of it that the step changes from the S3 mirror, checks
# it against the signed manifests, then runs the same publish.sh / promote.sh / sync-s3.sh as a build host would.
#   ci-publish.sh beta <version>                  after build.sh in the image workflow: the build goes into beta/
#   ci-publish.sh promote <version> [--allow-…]   the promote workflow: beta → stable, then the installer of that version
#                                                 (from the version's GitHub Release) into installer/
# The --allow-shim-change / --allow-unchained-shim / --allow-bootloader-change flags are passed to promote.sh unchanged.
# Environment:
#   MASTERSOS_OS_BUCKET     the S3 bucket behind the update source (a secret of the release environment)
#   MASTERSOS_OS_CDN        its CloudFront distribution id (a secret too)
#   MASTERSOS_UPDATE_BASE   the update source, default https://os.khundavid.com (build.sh's release default)
#   MASTERSOS_PUBLISH_ROOT  where the temporary root goes, default $RUNNER_TEMP/mastersos-release
#   AWS credentials in the environment (configure-aws-credentials with the publish role); the release keys loaded
#   (keys-load.sh, through ci-load-release-keys.py). For promote also GH_TOKEN and GITHUB_REPOSITORY (gh release).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
die() {
	echo "ci-publish.sh: $*" >&2
	exit 1
}
say() { echo "ci-publish.sh: $*"; }

[ $# -ge 2 ] || die "usage: ci-publish.sh beta <version> | ci-publish.sh promote <version> [--allow-…]"
step=$1 version=$2
shift 2
[[ $version =~ ^[0-9]{8}\.[0-9]+$ ]] || die "bad version '$version'"
case "$step" in
beta) [ $# -eq 0 ] || die "beta takes no flags" ;;
promote)
	for a in "$@"; do
		case "$a" in --allow-shim-change | --allow-unchained-shim | --allow-bootloader-change) ;; *) die "unknown flag $a" ;; esac
	done
	;;
*) die "unknown step '$step'" ;;
esac

bucket=${MASTERSOS_OS_BUCKET:?MASTERSOS_OS_BUCKET is empty}
cdn=${MASTERSOS_OS_CDN:?MASTERSOS_OS_CDN is empty}
base=${MASTERSOS_UPDATE_BASE:-https://os.khundavid.com}
export MASTERSOS_PUBLISH_ROOT=${MASTERSOS_PUBLISH_ROOT:-${RUNNER_TEMP:?}/mastersos-release}
# sync-s3.sh: an empty profile means the credentials in the environment
export MASTERSOS_AWS_PROFILE=
root=$MASTERSOS_PUBLISH_ROOT

[ ! -e "$root" ] || die "$root already exists: one root per job"
mkdir -p "$root"
printf 'base=%s\nlab=no\nmirror_s3=s3://%s\nmirror_cdn=%s\n' "$base" "$bucket" "$cdn" >"$root/mastersos-root.conf"

# The public key this root signs with (read_root_conf in channel-common.sh, without the private side). channel-common.sh
# sets root and here to the same values as above and brings its own die.
# shellcheck source-path=SCRIPTDIR source=channel-common.sh
. "$here/channel-common.sh"
read_root_conf verify
[ -f "$pubring" ] || die "no public keyring for this root (${pubring:-none})"

# restore <dir>: copy <bucket>/<dir>/ into the root and check it. publish.sh and promote.sh re-sign whatever they find in a
# channel, so a file that is not exactly what the last signed manifest lists must never get that far: the signature
# must verify with the repository's key, every listed file must match, and nothing else may be there.
restore() {
	local d=$1 dir=$root/$1 listed extra
	mkdir -p "$dir"
	aws s3 sync "s3://$bucket/$d/" "$dir/" --only-show-errors || die "cannot copy $d/ from the bucket"
	if [ -z "$(ls -A "$dir")" ]; then
		say "$d/ is empty in the bucket"
		return 0
	fi
	[ -f "$dir/SHA256SUMS" ] && [ -f "$dir/SHA256SUMS.gpg" ] || die "$d/ in the bucket has files but no signed SHA256SUMS"
	gpgv --keyring "$pubring" "$dir/SHA256SUMS.gpg" "$dir/SHA256SUMS" 2>/dev/null || die "$d/SHA256SUMS in the bucket does not verify"
	(cd "$dir" && sha256sum --quiet --strict -c SHA256SUMS) || die "$d/ in the bucket does not match its SHA256SUMS"
	listed=$(awk '{ print $2 } END { print "SHA256SUMS"; print "SHA256SUMS.gpg" }' "$dir/SHA256SUMS" | LC_ALL=C sort)
	extra=$(cd "$dir" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | comm -23 - <(echo "$listed"))
	[ -z "$extra" ] || die "$d/ in the bucket has files its SHA256SUMS does not list: $extra"
	say "$d/: $(awk 'END { print NR }' "$dir/SHA256SUMS") files, signature and hashes good"
}

case "$step" in
beta)
	restore beta
	"$here/publish.sh" "$version" beta
	"$here/sync-s3.sh"
	;;
promote)
	restore beta
	restore stable
	restore installer
	[ -f "$root/beta/MastersOS_${version}_x86-64.efi" ] || die "$version is not in beta"
	"$here/promote.sh" "$version" "$@"

	# The installer of this version, from the GitHub Release the image workflow made. publish.sh installer checks that the
	# image and the Ventoy package come from one make-installer.sh run; the build-info must be the one beta signed, so the
	# release is this build and no other.
	out=${MASTERSOS_OUTPUT_DIR:-$here/mkosi.output}/$version
	[ ! -e "$out" ] || die "$out already exists"
	mkdir -p "$out"
	tag=image-release-$version
	gh release download "$tag" --repo "${GITHUB_REPOSITORY:?}" --dir "$out" || die "cannot download the assets of release $tag"
	(cd "$out" && sha256sum --quiet --strict -c SHA256SUMS) || die "the assets of $tag do not match its SHA256SUMS"
	cmp -s "$out/build-info.txt" "$root/beta/MastersOS_${version}_x86-64.build-info.txt" ||
		die "the build-info of release $tag is not the one beta has for $version"
	for f in "$out"/*.part-00; do
		[ -e "$f" ] || continue
		whole=${f%.part-00}
		cat "$whole".part-* >"$whole"
		rm -f "$whole".part-*
	done
	cp "$root/stable/MastersOS_${version}_x86-64.efi" "$out/"
	"$here/publish.sh" "$version" installer

	"$here/sync-s3.sh"
	;;
esac
say "$step $version done"

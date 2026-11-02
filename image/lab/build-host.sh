#!/bin/bash
# Check or set up an image build host. Run it on the build host:
#   bash build-host.sh check             reports every prerequisite, changes nothing; exit 1 if any is missing
#   bash build-host.sh packages          installs the missing packages and mkosi only (also used by ci-runner-setup.sh)
#   bash build-host.sh setup             same, and creates the release root
#   bash build-host.sh restore-release   pulls the release root from S3 (needs the mastersos-publish profile)
# Private keys are never handled here: lab keys come from `lab/keys.sh`, release keys from `keys-load.sh --age`.
set -euo pipefail

release_root=${MASTERSOS_RELEASE_ROOT:-/srv/mastersos/release}
bucket=${MASTERSOS_RELEASE_BUCKET:-mastersos-os-111122223333}
profile=${MASTERSOS_PUBLISH_PROFILE:-mastersos-publish}
packages=(systemd-boot-tools systemd-repart tpm2-tools jq zip unzip zstd age sbsigntool mtools dosfstools awscli git rustup rsync python3-pefile)
mkosi_tag=v27.1
mkosi_commit=ecf7f5702bb2052b7a69cab3fe7d37bc3b9ad77b # tags can move; this host handles signing keys
commands=(mkosi systemd-repart tpm2_getcap sbsign jq zip unzip zstd age aws)
PATH=$PATH:$HOME/.cargo/bin

missing=0
report() { # report <ok|MISSING> <what>
	echo "$1  $2"
	if [ "$1" != ok ]; then missing=$((missing + 1)); fi
}

check() {
	local c
	for c in "${commands[@]}"; do
		if command -v "$c" >/dev/null; then report ok "command $c"; else report MISSING "command $c"; fi
	done
	if [ "$(git -C "$HOME/mkosi" rev-parse HEAD 2>/dev/null)" = "$mkosi_commit" ]; then report ok "mkosi at $mkosi_tag"; else report MISSING "$HOME/mkosi at $mkosi_commit"; fi
	if command -v rustup >/dev/null; then report ok "command rustup"; else report MISSING "command rustup"; fi
	if [ -x /usr/lib/systemd/systemd-measure ]; then report ok "systemd-measure"; else report MISSING "/usr/lib/systemd/systemd-measure"; fi
	if [ -d "$HOME/mastersos-keys/lab" ]; then report ok "lab keys directory"; else report MISSING "lab keys directory ~/mastersos-keys/lab"; fi
	if [ -d "$release_root" ]; then report ok "release root $release_root"; else report MISSING "release root $release_root"; fi
	if [ -z "$(swapon --noheadings 2>/dev/null)" ]; then report ok "no swap (keys-load.sh requires it)"; else report MISSING "swap must be off for release keys"; fi
	if aws configure list-profiles 2>/dev/null | grep -qxF "$profile"; then report ok "AWS profile $profile"; else report MISSING "AWS profile $profile"; fi
	echo "build-host: $missing missing"
	[ "$missing" -eq 0 ]
}

packages() {
	sudo apt-get update -qq
	sudo apt-get install -y -qq "${packages[@]}"
	if [ ! -d "$HOME/mkosi" ]; then
		git clone --depth 1 --branch "$mkosi_tag" https://github.com/systemd/mkosi "$HOME/mkosi"
	fi
	if [ "$(git -C "$HOME/mkosi" rev-parse HEAD)" != "$mkosi_commit" ]; then
		echo "build-host: $HOME/mkosi is not $mkosi_tag ($mkosi_commit)" >&2
		exit 1
	fi
	sudo ln -sf "$HOME/mkosi/bin/mkosi" /usr/local/bin/mkosi
}

setup() {
	packages
	sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0755 "$release_root"
	check
}

restore_release() {
	[ -d "$release_root" ] || {
		echo "build-host: run setup first" >&2
		exit 1
	}
	AWS_PROFILE=$profile aws s3 sync "s3://$bucket/" "$release_root/" --only-show-errors
	du -sh "$release_root"
}

case "${1:-check}" in
check) check ;;
packages) packages ;;
setup) setup ;;
restore-release) restore_release ;;
*)
	echo "usage: build-host.sh check|packages|setup|restore-release" >&2
	exit 2
	;;
esac

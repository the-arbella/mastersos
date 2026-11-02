#!/bin/bash
# Prepare a GitHub-hosted runner for build.sh: frees disk, turns swap off (keys-load.sh requires it), installs the packages
# and mkosi, and restores the key set the build needs. Run it only from .github/workflows/mastersos-image.yml.
#   ci-runner-setup.sh lab       needs MASTERSOS_LAB_KEYS_B64: base64 of a tar with lab/ and lab-local/
#   ci-runner-setup.sh release   installs tools only; the keys come from ci-load-release-keys.py
set -euo pipefail

profile=${1:?usage: ci-runner-setup.sh lab|release}
here=$(cd "$(dirname "$0")" && pwd)

df -h / | tail -n 1
sudo rm -rf /usr/local/lib/android /usr/local/.ghcup /usr/share/dotnet /opt/ghc /opt/hostedtoolcache /usr/share/swift
df -h / | tail -n 1
sudo swapoff -a
sudo sed -i '/\sswap\s/d' /etc/fstab

bash "$here/lab/build-host.sh" packages
sudo apt-get install -y -qq bubblewrap cpio cryptsetup-bin e2fsprogs erofs-utils mtools squashfs-tools \
	systemd-container systemd-ukify debian-archive-keyring ubuntu-keyring

mkosi --version

if [ "$profile" = lab ]; then
	[ -n "${MASTERSOS_LAB_KEYS_B64:-}" ] || {
		echo "ci-runner-setup.sh: MASTERSOS_LAB_KEYS_B64 is empty" >&2
		exit 1
	}
	install -d -m 0700 "$HOME/mastersos-keys"
	base64 -d <<<"$MASTERSOS_LAB_KEYS_B64" | tar -C "$HOME/mastersos-keys" --no-same-owner -xzf -
fi

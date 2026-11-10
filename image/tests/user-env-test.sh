#!/bin/bash
# The session environment comes from the system only (locked-session hardening, 2026-11-10): the image's user environment
# generators drop the user's ~/.config/environment.d (a DCONF_PROFILE there switches every dconf lock off) and Flatpak's
# per-user export dir (a user-writable XDG_DATA_DIRS entry, where gnome-shell would load a look-alike extension as a system
# one). Runs the image's two generators against a fake home; the first needs systemd's own generator, the second a fake
# flatpak on PATH that prints its arguments. Linux only (CI image-lint, or a ubuntu:24.04 container as non-root):
#   bash image/tests/user-env-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
gens=$here/../mkosi.extra/usr/local/lib/systemd/user-environment-generators
sysd=/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
check() { # check <name> <want> <got>
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		printf 'FAIL %s: want %q, got %q\n' "$1" "$2" "$3" >&2
		fails=$((fails + 1))
	fi
}

[ -x "$sysd" ] || {
	echo "user-env-test: $sysd is missing (systemd not installed)" >&2
	exit 1
}
home=$tmp/home
mkdir -p "$home/.config/environment.d"
printf 'DCONF_PROFILE=%s/evil\nGSETTINGS_BACKEND=memory\n' "$home" >"$home/.config/environment.d/50-x.conf"
run() { env -i HOME="$home" PATH=/usr/bin:/bin "$@"; }

# The setup is real: systemd's own generator reads the user's file
check "systemd's generator reads ~/.config/environment.d (setup)" yes \
	"$(run "$sysd" | grep -qx "DCONF_PROFILE=$home/evil" && echo yes || echo no)"
out=$(run "$gens/30-systemd-environment-d-generator")
check "the image's generator leaves DCONF_PROFILE out" no "$(grep -q '^DCONF_PROFILE=' <<<"$out" && echo yes || echo no)"
check "the image's generator leaves GSETTINGS_BACKEND out" no "$(grep -q '^GSETTINGS_BACKEND=' <<<"$out" && echo yes || echo no)"
check "the image's generator sets no XDG_CONFIG_HOME of its own" no "$(grep -q '^XDG_CONFIG_HOME=' <<<"$out" && echo yes || echo no)"
# An XDG_CONFIG_HOME already in the manager's environment does not bring the user's files back either
mkdir -p "$home/cfg/environment.d"
cp "$home/.config/environment.d/50-x.conf" "$home/cfg/environment.d/"
out=$(run XDG_CONFIG_HOME="$home/cfg" "$gens/30-systemd-environment-d-generator")
check "an inherited XDG_CONFIG_HOME is ignored too" no "$(grep -q '^DCONF_PROFILE=' <<<"$out" && echo yes || echo no)"

# Flatpak: system installation only
mkdir -p "$tmp/bin"
# shellcheck disable=SC2016 # the fake flatpak expands these itself
printf '#!/bin/sh\necho "GIO_USE_VFS=$GIO_USE_VFS ARGS=$*"\n' >"$tmp/bin/flatpak"
chmod +x "$tmp/bin/flatpak"
out=$(env -i HOME="$home" PATH="$tmp/bin:/usr/bin:/bin" "$gens/60-flatpak")
check "60-flatpak asks for the system installation only" "GIO_USE_VFS=local ARGS=--print-updated-env --print-system-only" "$out"

echo "user-env-test: $((n - fails))/$n"
[ "$fails" = 0 ]

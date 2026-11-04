#!/bin/sh
# Installs the MastersOS command line (mastersos, mastersos-sign) for the current user on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/the-arbella/mastersos/master/tools/install/install.sh | sh
#   curl -fsSL …/install.sh | sh -s -- --version cli-0123456789ab
#
# Downloads the release asset for this computer and SHA256SUMS from the GitHub release, checks the SHA-256 before
# anything is installed, and installs into ~/.local/bin. No sudo, no administrator rights.
#
# Environment (for tests and mirrors):
#   MASTERSOS_VERSION        the release to install, like --version
#   MASTERSOS_RELEASE_BASE   download base; assets are read from <base>/<version>/<asset>
#   MASTERSOS_RELEASES_API   the release list (GitHub API JSON) used to find the newest cli-* release
set -eu

repo=the-arbella/mastersos
base=${MASTERSOS_RELEASE_BASE:-https://github.com/$repo/releases/download}
api=${MASTERSOS_RELEASES_API:-https://api.github.com/repos/$repo/releases?per_page=100}
version=${MASTERSOS_VERSION:-}

say() { printf '%s\n' "$*"; }
die() { printf 'mastersos install: %s\n' "$*" >&2; exit 1; }

usage() {
  say "Usage: install.sh [--version cli-<commit>]"
  say "Installs mastersos and mastersos-sign into ~/.local/bin. Without --version: the newest cli-* release."
}

while [ $# -gt 0 ]; do
  case $1 in
    --version)
      [ $# -ge 2 ] || die "--version needs a value, for example --version cli-0123456789ab"
      version=$2
      shift 2
      ;;
    --version=*)
      version=${1#--version=}
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

case ${HOME:-} in
  /*) ;;
  *) die "HOME is not set to an absolute path" ;;
esac
bindir=$HOME/.local/bin

# HTTPS only (redirects too); plain http only for a release served by a test (MASTERSOS_RELEASE_BASE set)
if [ -n "${MASTERSOS_RELEASE_BASE:-}" ]; then
  curl_tls=
  wget_tls=
else
  curl_tls="--proto =https --proto-redir =https --tlsv1.2"
  # GNU wget; BusyBox wget has no such option (it is never asked for anything but the https URLs above)
  wget_tls=
  if wget --help 2>&1 | grep -q -- --https-only; then wget_tls=--https-only; fi
  for url in "$base" "$api"; do
    case $url in
      https://*) ;;
      *) die "only https:// addresses are used, not: $url" ;;
    esac
  done
fi

# fetch <url> <file>
fetch() {
  if command -v curl >/dev/null 2>&1; then
    # shellcheck disable=SC2086 # $curl_tls is a list of options
    curl -fsSL --retry 3 $curl_tls -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    # shellcheck disable=SC2086 # $wget_tls is a list of options
    wget -q $wget_tls -O "$2" "$1"
  else
    die "needs curl or wget"
  fi
}

# sha256 <file>: the lowercase hex digest
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    die "needs sha256sum or shasum to check the download"
  fi
}

os=$(uname -s)
arch=$(uname -m)
case $os in
  Darwin)
    # A shell under Rosetta reports x86_64 on Apple silicon; the native build is the right one there
    if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
      arch=arm64
    fi
    case $arch in
      arm64 | aarch64) target=aarch64-apple-darwin ;;
      x86_64) target=x86_64-apple-darwin ;;
      *) die "no build for macOS on $arch" ;;
    esac
    ;;
  Linux)
    case $arch in
      x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
      aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
      *) die "no build for Linux on $arch" ;;
    esac
    ;;
  *)
    die "this script is for macOS and Linux; on Windows use install.ps1"
    ;;
esac
asset=mastersos-$target.tar.gz

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t mastersos-install)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

if [ -z "$version" ]; then
  # The list is newest first, 100 to a page; the first cli-* tag is the newest command line release. Image
  # releases come in between, so read further pages until one has a cli-* tag or the list ends.
  case $api in
    *\?*) sep='&' ;;
    *) sep='?' ;;
  esac
  page=1
  while [ -z "$version" ] && [ "$page" -le 30 ]; do
    fetch "$api${sep}page=$page" "$tmp/releases.json" \
      || die "could not read the list of releases from $api. GitHub limits anonymous lookups; try again later or pass --version cli-<commit>"
    grep -q '"tag_name"' "$tmp/releases.json" || break
    version=$(tr ',' '\n' <"$tmp/releases.json" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(cli-[0-9a-z]*\)".*/\1/p' | head -n 1)
    page=$((page + 1))
  done
  [ -n "$version" ] || die "no cli-* release found at $api"
fi
# A pattern on the whole value: a line-based grep would let "cli-x<newline>anything" through
case $version in
  cli- | cli-*[!0-9a-z]*) die "the version must look like cli-0123456789ab (a release tag), not: $version" ;;
  cli-*) ;;
  *) die "the version must look like cli-0123456789ab (a release tag), not: $version" ;;
esac

say "Installing MastersOS command line $version for $target"
fetch "$base/$version/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $base/$version/SHA256SUMS"
fetch "$base/$version/$asset" "$tmp/$asset" || die "could not download $base/$version/$asset"

expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print tolower($1); exit }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "SHA256SUMS has no line for $asset: nothing installed"
actual=$(sha256 "$tmp/$asset")
[ "$expected" = "$actual" ] \
  || die "the SHA-256 of $asset does not match SHA256SUMS (expected $expected, got $actual): nothing installed"

mkdir "$tmp/x"
tar -xzf "$tmp/$asset" -C "$tmp/x"
for name in mastersos mastersos-sign; do
  if [ ! -f "$tmp/x/$name" ] || [ -L "$tmp/x/$name" ]; then
    die "$asset has no $name: nothing installed"
  fi
done

mkdir -p "$bindir"
# Copy next to the target, then rename: a running copy is never half written
for name in mastersos mastersos-sign; do
  cp "$tmp/x/$name" "$bindir/.$name.new"
  chmod 755 "$bindir/.$name.new"
done
for name in mastersos mastersos-sign; do
  mv -f "$bindir/.$name.new" "$bindir/$name"
done

installed=$("$bindir/mastersos" --version) || die "installed $bindir/mastersos, but it does not run on this computer"
say "Installed $bindir/mastersos"
say "Installed $bindir/mastersos-sign"
say "$installed"

case ":${PATH:-}:" in
  *":$bindir:"*) ;;
  *)
    case ${SHELL:-} in
      */zsh) rc=$HOME/.zshrc ;;
      */bash) rc=$HOME/.bashrc ;;
      *) rc=$HOME/.profile ;;
    esac
    say ""
    say "$bindir is not on your PATH yet. Add it, then open a new terminal:"
    say "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> $rc"
    ;;
esac
say ""
say "Next: mastersos connect <your school's admin address>"

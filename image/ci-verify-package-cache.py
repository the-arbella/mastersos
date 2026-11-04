#!/usr/bin/env python3
"""Keep only trustworthy packages in a restored package cache before a release build.

Usage: ci-verify-package-cache.py <cache_dir> <snapshot> <release> [--lists DIR] [--keyring FILE]

The CI keeps mkosi's downloaded .deb files between runs (actions/cache), because snapshot.ubuntu.com is often down. apt takes
a cached .deb whose size matches without checking its hash, so a planted file could reach a signed release image. This fetches
the snapshot's InRelease for <release>, -updates and -security, verifies it with gpgv against the Ubuntu archive keyring,
checks each binary-amd64 Packages index against the SHA256 in it, and deletes every cached .deb whose SHA256 is not the one the
index gives for that file name. When any index cannot be fetched or verified, every cached .deb is deleted: the build then
downloads everything itself, as without a cache. --lists reads the files from an apt lists directory instead (tests).
"""
import argparse
import gzip
import hashlib
import lzma
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HOST = "https://snapshot.ubuntu.com/ubuntu"
COMPONENTS = ("main", "restricted", "universe", "multiverse")


class Untrusted(Exception):
    pass


def fetch(url):
    last = None
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return r.read()
        except Exception as e:  # 5xx, 401, timeouts: try again, then give up
            last = e
            time.sleep(10 * (attempt + 1))
    raise Untrusted(f"cannot fetch {url}: {last}")


def verify_inrelease(data, keyring):
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "InRelease")
        with open(src, "wb") as f:
            f.write(data)
        r = subprocess.run(["gpgv", "--keyring", keyring, "--output", "-", src], capture_output=True)
        if r.returncode != 0:
            raise Untrusted("InRelease signature does not verify: " + r.stderr.decode(errors="replace").strip())
        return r.stdout.decode()


def sha256_section(release):
    out, inside = {}, False
    for line in release.splitlines():
        if line.startswith("SHA256:"):
            inside = True
            continue
        if inside:
            if not line.startswith(" "):
                break
            digest, _size, path = line.split()
            out[path] = digest
    return out


def deb_name(stanza):
    # apt's file name in archives/: name_version_arch.deb with the epoch colon quoted as %3a
    return f"{stanza['Package']}_{stanza['Version'].replace(':', '%3a')}_{stanza['Architecture']}.deb"


def parse_packages(text, wanted):
    for block in text.split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ":" in line:
                k, v = line.split(":", 1)
                fields[k] = v.strip()
        if {"Package", "Version", "Architecture", "SHA256"} <= fields.keys():
            name = deb_name(fields)
            if wanted.get(name, fields["SHA256"]) != fields["SHA256"]:
                raise Untrusted(f"{name} has two different hashes in the index")
            wanted[name] = fields["SHA256"]


def index(snapshot, release, lists, keyring):
    wanted = {}
    for suite in (release, f"{release}-updates", f"{release}-security"):
        prefix = f"snapshot.ubuntu.com_ubuntu_{snapshot}_dists_{suite}_"
        if lists:
            with open(os.path.join(lists, prefix + "InRelease"), "rb") as f:
                raw = f.read()
        else:
            raw = fetch(f"{HOST}/{snapshot}/dists/{suite}/InRelease")
        hashes = sha256_section(verify_inrelease(raw, keyring))
        for comp in COMPONENTS:
            path = f"{comp}/binary-amd64/Packages"
            if lists:
                p = os.path.join(lists, prefix + f"{comp}_binary-amd64_Packages")
                if not os.path.exists(p):
                    continue
                with open(p, "rb") as f:
                    data = f.read()
            else:
                for ext, unpack in ((".xz", lzma.decompress), (".gz", gzip.decompress)):
                    if path + ext in hashes:
                        packed = fetch(f"{HOST}/{snapshot}/dists/{suite}/{path}{ext}")
                        if hashlib.sha256(packed).hexdigest() != hashes[path + ext]:
                            raise Untrusted(f"{suite} {path}{ext} does not match InRelease")
                        data = unpack(packed)
                        break
                else:
                    continue
            if hashes.get(path) != hashlib.sha256(data).hexdigest():
                raise Untrusted(f"{suite} {path} does not match InRelease")
            parse_packages(data.decode(), wanted)
    return wanted


def debs(cache):
    for root, _dirs, files in os.walk(cache):
        for f in files:
            if f.endswith(".deb"):
                yield os.path.join(root, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cache")
    ap.add_argument("snapshot")
    ap.add_argument("release")
    ap.add_argument("--lists")
    ap.add_argument("--keyring", default="/usr/share/keyrings/ubuntu-archive-keyring.gpg")
    a = ap.parse_args()
    if not os.path.isdir(a.cache):
        print("verify-package-cache: no cache restored")
        return 0
    try:
        wanted = index(a.snapshot, a.release, a.lists, a.keyring)
    except (Untrusted, OSError) as e:
        n = 0
        for p in debs(a.cache):
            os.remove(p)
            n += 1
        print(f"verify-package-cache: {e}; deleted all {n} cached packages", file=sys.stderr)
        return 0
    kept = dropped = 0
    for p in debs(a.cache):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if wanted.get(os.path.basename(p)) == h.hexdigest():
            kept += 1
        else:
            os.remove(p)
            dropped += 1
    print(f"verify-package-cache: kept {kept}, deleted {dropped} (not in the signed index of snapshot {a.snapshot})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

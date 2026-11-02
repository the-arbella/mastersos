#!/usr/bin/env python3
"""Refuse private strings in the tree: hosts, account ids and the like.

The patterns are themselves private, so they come from MASTERSOS_DENYLIST (one regex per line) in CI and from
~/.config/mastersos/denylist.txt on a maintainer's machine. Without either this passes with a notice, so outside
contributors are not blocked; gitleaks still runs for them.
"""
import os
import pathlib
import re
import subprocess
import sys

SKIP = (".po", "pnpm-lock.yaml", "Cargo.lock")
SKIP_DIRS = ("image/tests/fixtures/", "core/mastersos-bundle/testdata/", "image/patches/")


def main():
    text = os.environ.get("MASTERSOS_DENYLIST", "")
    local = pathlib.Path.home() / ".config/mastersos/denylist.txt"
    if not text and local.exists():
        text = local.read_text()
    if not text.strip():
        print("check-private: no denylist here, skipped")
        return
    deny = [re.compile(l, re.IGNORECASE) for l in text.split("\n") if l.strip()]
    root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    bad = 0
    for rel in subprocess.check_output(["git", "ls-files"], cwd=root, text=True).split("\n"):
        if not rel or rel.endswith(SKIP) or rel.startswith(SKIP_DIRS):
            continue
        try:
            data = pathlib.Path(root, rel).read_text(errors="replace")
        except OSError:
            continue
        for n, d in enumerate(deny):
            if d.search(data):
                print(f"{rel}: denylist entry {n + 1}")  # the pattern itself is not printed: logs are public
                bad += 1
    if bad:
        sys.exit("check-private: private strings found")
    print("check-private: clean")


if __name__ == "__main__":
    main()

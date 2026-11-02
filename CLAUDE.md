# MastersOS

Open source education laptop OS (Ubuntu + mkosi). This repository is the only home of the system source; commits are public as soon as they land and cannot be taken back.

## Rules

- Nothing private here: no hosts, account ids, school data or keys. `python3 -I tools/check-private.py` and gitleaks run in CI; run the first before committing.
- Fix high-severity security issues through a GitHub Security Advisory private fork, not a public commit.
- The cloud lives elsewhere and pins a commit of this repository. Nothing here may depend on it.
- Comments, errors and script output are in English. End-user text goes through i18n, English first. File system paths are always English.
- `image/patches/authd-oidc/*.patch` are checked byte for byte: do not edit their contents.
- Private keys never enter the tree (`image/tests/check-tree.sh` refuses them).

## Commands

```bash
cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
bash image/tests/check-tree.sh
```

Shell tests need GNU tools: run them in an `ubuntu:24.04` amd64 container on a Mac.
Release images are built by `.github/workflows/mastersos-image.yml`, approved through the `release` environment.

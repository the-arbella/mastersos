# MastersOS

MastersOS is an operating system for school laptops: an immutable Ubuntu image built with mkosi, with the device
agent, installer and signing tools. A device applies only settings bundles signed by the school's own keys.
The cloud service that manages devices is not open source and is not in this repository.

**School IT:** installing the command line on macOS, Linux or Windows and setting up a school is in English in
[README.md, "Getting started for school IT"](README.md#getting-started-for-school-it-macos-linux-windows); the words
are in [docs/glossary.md](docs/glossary.md).
If the school network filters outbound traffic, allow the diagnostics upload domain shown on the admin site's Install page.

The rest of the main documentation is in Chinese ([README.md](README.md), [image/README.md](image/README.md)). This
page is a short guide for English readers. Design documents and acceptance records are kept private, so some documents mention
paths that are not in this repository.

## Layout

| Path | What it is |
|---|---|
| `core/` | Rust workspace, see below |
| `image/` | System image: mkosi tree, build and publish scripts, A/B update, Secure Boot and TPM |
| `image/docs/` | Installation, hardware, keys, Secure Boot and update channels |
| `kiosk-extension/` | Browser extension for locked exam apps |
| `skills/` | Agent skill for changing a school's settings through the command line |
| `tools/install/` | Installers for the command line (`install.sh` for macOS and Linux, `install.ps1` for Windows) and their tests |

## Rust crates

- `mastersos-bundle`: settings bundle manifest, packing, signing and verification (Ed25519; old WebAuthn
  signatures are still verified, never made), the monthly check-in (heartbeat), pre-publish lint. Shared by the
  agent and `mastersos-sign`.
- `mastersos-agent`: runs on each device. It fetches, verifies and applies settings.
- `mastersos-mcp`: the `mastersos` command line for people and AI assistants (`mastersos mcp` is a stdio MCP server).
  People edit a local settings folder and publish it with a school key; an AI assistant can read, check and diff,
  but cannot publish.
- `mastersos-sign`: command line for school keys: make one, register it, approve an upload on another computer,
  read a computer's disk recovery code.
- `mastersos-installer`: USB installer and first-boot user setup for unmanaged devices.

## Trust model in brief

A device applies only a bundle approved with one of the school's trusted keys. The **school key** (a small file plus
a printed copy) is the one key type: IT approves with it from any computer that has the file
(`mastersos publish --school-key <file>`). The trusted keys come only from school key files
IT holds (`mastersos init`, `mastersos keys add|remove`), never from the server. The cloud stores and delivers
bundles but cannot forge one, and an AI assistant can prepare a change but a person has to approve it.

## Build and test

```bash
# Rust (toolchain pinned in core/rust-toolchain.toml)
cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cd core && cargo test --workspace

# Static checks for the image tree (no image build)
bash image/tests/check-tree.sh

# The installers, against a fake release served on this computer
bash tools/install/test-install.sh
```

## License

MIT, see [LICENSE](LICENSE). The patches in `image/patches/authd-oidc/` are GPL-3.0, see [NOTICE](NOTICE).

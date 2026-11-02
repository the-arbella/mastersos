# MastersOS

MastersOS is an operating system for school laptops: an immutable Ubuntu image built with mkosi, with the device
agent, installer and signing tools. A device applies only settings bundles signed by the school's own keys.
The cloud service that manages devices is not open source and is not in this repository.

The main documentation is in Chinese ([README.md](README.md), [image/README.md](image/README.md)). This page is a
short guide for English readers. Design documents and acceptance records are kept private, so some documents mention
paths that are not in this repository.

## Layout

| Path | What it is |
|---|---|
| `core/` | Rust workspace, see below |
| `image/` | System image: mkosi tree, build and publish scripts, A/B update, Secure Boot and TPM |
| `image/docs/` | Installation, hardware, keys, Secure Boot and update channels |
| `kiosk-extension/` | Browser extension for locked exam apps |
| `skills/` | Agent skill for changing a school's settings through the command line |

## Rust crates

- `mastersos-bundle`: settings bundle manifest, packing, signing and verification (Ed25519 and passkey WebAuthn
  assertions), heartbeat, pre-publish lint. Shared by the agent and `mastersos-sign`.
- `mastersos-agent`: runs on each device. It fetches, verifies and applies settings.
- `mastersos-mcp`: the `mastersos` command line for people and AI assistants (`mastersos mcp` is a stdio MCP server).
  It can query, edit drafts and request a publish. It cannot publish.
- `mastersos-sign`: command line for a school's recovery key. Changes to trust can only be signed through it.
- `mastersos-installer`: USB installer and first-boot user setup for unmanaged devices.

## Trust model in brief

A device applies only a bundle signed by the school's keys: a passkey for daily publishing, an offline recovery key
for changes to trust. The cloud stores and delivers bundles but cannot forge one, and an AI assistant can prepare a
change but a person has to sign it.

## Build and test

```bash
# Rust (toolchain pinned in core/rust-toolchain.toml)
cd core && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cd core && cargo test --workspace

# Static checks for the image tree (no image build)
bash image/tests/check-tree.sh
```

## License

MIT, see [LICENSE](LICENSE). The patches in `image/patches/authd-oidc/` are GPL-3.0, see [NOTICE](NOTICE).

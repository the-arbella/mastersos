//! Remote diagnostics (docs/specs/2026-11-05-remote-diagnostics-and-help-design.md, design 2):
//! the whitelist collector that builds the `tar.zst` archive with its `manifest.json`, the
//! redaction applied to every text file in it, and the three-step upload.

pub mod collect;
pub mod redact;
pub mod upload;

pub use collect::{collect, CollectOpts, Collected};
pub use redact::redact;

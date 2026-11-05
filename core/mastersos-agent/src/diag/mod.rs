//! Remote diagnostics (docs/specs/2026-11-05-remote-diagnostics-and-help-design.md, design 2):
//! the whitelist collector that builds the `tar.zst` archive with its `manifest.json`, and the
//! redaction applied to every text file in it.

pub mod collect;
pub mod redact;

pub use collect::{collect, CollectOpts, Collected};
pub use redact::redact;

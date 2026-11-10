//! 设置包：清单类型与校验（后续任务加上打包、签名与解包）。
#![forbid(unsafe_code)]

pub mod archive;
pub mod check;
pub mod checks;
pub mod deb;
pub mod diag;
pub mod escrow;
pub mod heartbeat;
pub mod keyid;
pub mod kiosk;
pub mod kit;
pub mod lint;
pub mod manifest;
pub mod push;
pub mod secret_ref;
pub mod seed;
pub mod select;
pub mod sign;
pub mod spec;
pub mod stamp;
pub mod status;
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;
pub mod webauthn;

/// 长轮询最多挂住的秒数；server 与 agent 共用。
pub const LONG_POLL_SECS: u64 = 60;

pub use archive::*;
pub use diag::*;
pub use escrow::*;
pub use heartbeat::*;
pub use lint::*;
pub use manifest::*;
pub use push::*;
pub use seed::*;
pub use select::*;
pub use sign::*;
pub use stamp::*;
pub use status::*;

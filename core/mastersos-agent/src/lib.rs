//! mastersos-agent：以 root 运行在每台笔记本上，拉取、验证并应用设置包。
#![forbid(unsafe_code)]

pub mod apply;
pub mod apply_worker;
pub mod backoff;
pub mod chrome_sysext;
pub mod config;
pub mod diag;
pub mod fetch;
pub mod homes;
pub mod hw;
pub mod ident;
pub mod inbox;
pub mod integrity;
pub mod jobs;
pub mod kiosk_session;
pub mod login_queue;
pub mod luks;
pub mod push;
pub mod report;
pub mod reset;
pub mod run;
pub mod runner;
pub mod safefs;
pub mod scripts;
pub mod secureboot;
pub mod seedpart;
pub mod shim_predict;
pub mod signin_handoff;
pub mod state;
pub mod status;
pub mod system;
pub mod token;
pub mod tpm;
pub mod upload;

pub use apply::{Applier, ApplyContext, NullApplier, Phase, RecordingApplier};
pub use config::AgentConfig;
pub use fetch::{FetchOutcome, Fetcher};
pub use run::{apply_local, apply_local_with, once, run, run_with_wake};
pub use state::State;

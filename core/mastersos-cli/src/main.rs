//! `mastersos`: the MastersOS admin command line.
#![forbid(unsafe_code)]

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    mastersos_cli::cli::main().await
}

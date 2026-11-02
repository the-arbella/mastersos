//! `mastersos`: the MastersOS admin command line, and `mastersos mcp`, the same operations as an
//! MCP server over stdio.
#![forbid(unsafe_code)]

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    mastersos_mcp::cli::main().await
}

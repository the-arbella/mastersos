//! The command-line surface: what is gone must stay gone.

use std::process::{Command, Output};

fn mastersos(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .output()
        .expect("run mastersos")
}

#[test]
fn mcp_and_setup_are_unknown_commands() {
    for cmd in ["mcp", "setup"] {
        let out = mastersos(&[cmd]);
        assert_eq!(out.status.code(), Some(2), "{cmd}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("unrecognized subcommand"), "{cmd}: {err}");
    }
}

#[test]
fn ai_token_option_is_gone() {
    let out = mastersos(&["--ai-token-file", "x", "check"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unexpected argument"), "{err}");
}

#[test]
fn help_mentions_no_mcp_or_ai_token() {
    let mut texts = vec![mastersos(&["--help"])];
    for sub in ["connect", "init", "pull", "publish", "keys", "devices"] {
        texts.push(mastersos(&[sub, "--help"]));
    }
    for out in texts {
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        for word in ["mcp", "MCP", "AI token", "ai-token", "ai_token"] {
            assert!(!text.contains(word), "{word} in:\n{text}");
        }
    }
}

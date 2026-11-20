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
    for sub in ["init", "pull", "publish", "key", "devices", "spec"] {
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

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// `mastersos` with `home` as the home folder (nothing configured there).
fn mastersos_in(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        .current_dir(home)
        .output()
        .expect("run mastersos")
}

#[test]
fn old_names_are_unknown() {
    for cmd in [
        "school-key",
        "keygen",
        "restore-from-paper",
        "escrow-read",
        "seed-check",
        "register",
        "sign",
        "keys",
    ] {
        let out = mastersos(&[cmd]);
        assert_eq!(out.status.code(), Some(2), "{cmd}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("unrecognized subcommand"), "{cmd}: {err}");
    }
    for flag in ["--school-key", "--kit", "--key"] {
        let out = mastersos(&["publish", flag, "x"]);
        assert_eq!(out.status.code(), Some(2), "{flag}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("unexpected argument"), "{flag}: {err}");
    }
}

#[test]
fn key_new_names_file_in_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out = mastersos(&[
        "key",
        "new",
        "--out",
        dir.path().to_str().unwrap(),
        "--school-name",
        "Alpha",
    ]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    let n = &names[0];
    assert!(
        n.starts_with("alpha-school-key-") && n.ends_with(".kit"),
        "{n}"
    );
    let code8 = &n["alpha-school-key-".len()..n.len() - 4];
    assert_eq!(code8.len(), 8);
    assert!(
        t.contains(&format!("key code:    {}-{}", &code8[..4], &code8[4..])),
        "{t}"
    );
    assert!(t.contains(n.as_str()), "{t}");
    assert!(!t.contains("recipient") && !t.contains("kit file"), "{t}");
    assert!(
        t.contains("mastersos key register --key-file <file>"),
        "{t}"
    );
}

#[test]
fn key_new_prints_an_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(["key", "new", "--out", "own.kit"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let line = t.lines().find(|l| l.starts_with("school key:")).unwrap();
    let shown = std::path::Path::new(line["school key:".len()..].trim());
    assert!(shown.is_absolute(), "{line}");
    assert!(shown.ends_with("own.kit") && dir.path().join("own.kit").is_file());
}

#[test]
fn publish_without_key_file_says_so() {
    let home = tempfile::tempdir().unwrap();
    let out = mastersos_in(home.path(), &["publish"]);
    // A usage error, before anything else.
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--key-file"), "{err}");
}

/// A 0600 file in `dir` holding `text`.
fn private_file(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}

#[test]
fn pkcs8_file_is_refused_as_key_file() {
    let home = tempfile::tempdir().unwrap();
    // Split so that secret scanners do not take the test for a key.
    let pem = concat!(
        "-----BEGIN ",
        "PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END ",
        "PRIVATE KEY-----\n"
    );
    let p = private_file(home.path(), "old.pem", pem);
    let shown = p.to_str().unwrap();
    for args in [
        vec!["publish", "--key-file", shown],
        vec!["heartbeat", "--key-file", shown],
        vec!["init", "dir", "--key-file", shown],
        vec!["key", "add", shown],
    ] {
        let out = mastersos_in(home.path(), &args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {err}");
        assert!(
            err.contains(&format!(
                "{shown} is a PEM key, not a school key file; school keys are made with mastersos key new"
            )),
            "{args:?}: {err}"
        );
    }
}

#[test]
fn pem_text_on_stdin_is_refused_as_key_file() {
    use std::io::Write;
    use std::process::Stdio;
    let home = tempfile::tempdir().unwrap();
    let pem = concat!(
        "-----BEGIN ",
        "PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END ",
        "PRIVATE KEY-----\n"
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mastersos"));
    cmd.env("HOME", home.path())
        .env("APPDATA", home.path())
        .current_dir(home.path())
        .args(["publish", "--key-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(pem.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("is a PEM key, not a school key file"), "{err}");
}

/// Spec §5.3: a school key file others can read (a FAT32 or exFAT USB stick) still loads, with a
/// note.
#[cfg(unix)]
#[test]
fn loose_key_file_loads_with_a_note() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let kit = home.path().join("school.kit");
    let made = mastersos_in(home.path(), &["key", "new", "--out", kit.to_str().unwrap()]);
    assert!(made.status.success(), "{}", text(&made));
    std::fs::set_permissions(&kit, std::fs::Permissions::from_mode(0o777)).unwrap();
    // Loaded with the note; then it stops because nobody can confirm (stdin is not a terminal).
    let out = mastersos_in(
        home.path(),
        &["heartbeat", "--key-file", kit.to_str().unwrap()],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Make sure no other user can read this school key file"),
        "{err}"
    );
    assert!(err.contains("pass --yes"), "{err}");
}

/// A private file that is not a school key is refused before anything else.
#[test]
fn private_non_kit_file_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let junk = private_file(home.path(), "junk", "hello\n");
    let out = mastersos_in(
        home.path(),
        &["heartbeat", "--key-file", junk.to_str().unwrap()],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("cannot read the school key"), "{err}");
    assert!(!err.contains("No server address"), "{err}");
}

#[test]
fn seed_check_reads_its_file_before_the_network() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("missing-seed.toml");
    let out = mastersos_in(
        home.path(),
        &[
            "--server",
            "http://127.0.0.1:9",
            "seed",
            "check",
            missing.to_str().unwrap(),
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains(missing.to_str().unwrap()), "{err}");
    for word in ["whoami", "reach", "connect"] {
        assert!(!err.contains(word), "{word}: {err}");
    }
}

#[test]
fn recovery_read_takes_the_device_as_argument() {
    let out = mastersos(&["recovery", "read", "--help"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("<DEVICE>"), "{t}");
    assert!(t.contains("--key-file"), "{t}");
}

#[test]
fn network_commands_take_the_global_options() {
    for cmd in [
        &["key", "register"][..],
        &["key", "list"],
        &["key", "add"],
        &["key", "remove"],
        &["verify"],
        &["heartbeat"],
        &["recovery", "read"],
        &["seed", "check"],
        &["publish"],
        &["init"],
    ] {
        let mut args = cmd.to_vec();
        args.push("--help");
        let out = mastersos(&args);
        let t = text(&out);
        assert!(out.status.success(), "{cmd:?}: {t}");
        for flag in ["--server", "--school", "--pin-dir", "--yes", "--json"] {
            assert!(t.contains(flag), "{flag} missing for {cmd:?}:\n{t}");
        }
        for word in ["key token", "recovery token", "Tokens page"] {
            assert!(!t.contains(word), "{word} in {cmd:?}:\n{t}");
        }
    }
}

#[test]
fn help_is_english() {
    let mut texts = vec![mastersos(&["--help"])];
    for cmd in [
        &["key"][..],
        &["key", "new"],
        &["verify"],
        &["heartbeat"],
        &["recovery"],
        &["seed"],
    ] {
        let mut args = cmd.to_vec();
        args.push("--help");
        texts.push(mastersos(&args));
    }
    for out in texts {
        let t = text(&out);
        assert!(out.status.success(), "{t}");
        assert!(
            !t.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
            "{t}"
        );
        for word in [
            "keygen",
            "restore-from-paper",
            "PKCS",
            "passkey",
            "--school-key",
        ] {
            assert!(!t.contains(word), "{word} in:\n{t}");
        }
    }
}

/// `mastersos` with `home` as the home folder and nothing on PATH (no `arbella`).
fn bare(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        .env("PATH", home)
        .current_dir(home)
        .output()
        .expect("run mastersos")
}

#[test]
fn help_lists_exactly_the_commands() {
    let out = mastersos(&["--help"]);
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    let mut names: Vec<&str> = help
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| *n != "help")
        .collect();
    names.sort_unstable();
    let mut want = vec![
        "init",
        "pull",
        "check",
        "diff",
        "publish",
        "key",
        "heartbeat",
        "verify",
        "recovery",
        "seed",
        "spec",
        "login",
        "logout",
        "explain",
        "migrate",
        "hash-password",
        "devices",
    ];
    want.sort_unstable();
    assert_eq!(names, want, "{help}");
}

#[test]
fn connect_logo_and_token_file_are_gone() {
    for cmd in [
        &["connect", "https://server.example"][..],
        &["logo", "upload"],
        &["whoami"],
    ] {
        let out = mastersos(cmd);
        assert_eq!(out.status.code(), Some(2), "{cmd:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("unrecognized subcommand"), "{cmd:?}: {err}");
    }
    let out = mastersos(&["--token-file", "x", "check"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unexpected argument"), "{err}");
}

#[test]
fn spec_works_offline() {
    let home = tempfile::tempdir().unwrap();
    // No server, no credentials, nothing on PATH.
    let out = bare(home.path(), &["spec", "school.oidc"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("### `[school.oidc]`"), "{stdout}");
    assert_eq!(
        stdout.trim_end(),
        mastersos_bundle::spec::section("school.oidc").unwrap()
    );
    // The short version without a section; the whole reference with --full.
    let short = bare(home.path(), &["spec"]);
    assert!(short.status.success());
    assert_eq!(
        String::from_utf8_lossy(&short.stdout).trim_end(),
        mastersos_bundle::spec::prompt_spec().trim_end()
    );
    let full = bare(home.path(), &["spec", "--full"]);
    assert!(full.status.success());
    assert_eq!(
        String::from_utf8_lossy(&full.stdout).trim_end(),
        mastersos_bundle::spec::MANIFEST_SPEC.trim_end()
    );
    // A section and --full together, and an unknown section, are usage errors.
    let out = bare(home.path(), &["spec", "x", "--full"]);
    assert_eq!(out.status.code(), Some(2));
    let out = bare(home.path(), &["--json", "spec", "no.such.section"]);
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["problems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "school.oidc"));
}

#[test]
fn json_error_for_not_logged_in() {
    let home = tempfile::tempdir().unwrap();
    let out = bare(
        home.path(),
        &[
            "--json",
            "--server",
            "https://server.example",
            "--school",
            "0192f3a4-5b6c-7d8e-9f00-112233445566",
            "devices",
            "list",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON value");
    assert_eq!(v["error"]["code"], "not_logged_in");
    assert!(v["error"]["message"].is_string());
    assert!(v["error"]["problems"].is_array());
}

#[test]
fn json_errors_have_one_shape_for_every_command() {
    let home = tempfile::tempdir().unwrap();
    // A clap usage error, a local check refusal and a failure of a local command.
    for (args, code, exit) in [
        (&["--json", "--bogus"][..], "usage", 2),
        (&["--json", "nosuchcommand"], "usage", 2),
        (&["--json", "check", "no-such-dir"], "local_file", 1),
        (
            &["--json", "explain", "device", "SN", "--dir", "no-such-dir"],
            "local_file",
            1,
        ),
    ] {
        let out = bare(home.path(), args);
        assert_eq!(out.status.code(), Some(exit), "{args:?}: {}", text(&out));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("{args:?}: stdout {}", text(&out)));
        assert_eq!(v["error"]["code"], code, "{args:?}: {v}");
        assert!(v["error"]["message"].is_string(), "{args:?}");
        assert!(v["error"]["problems"].is_array(), "{args:?}");
        assert_eq!(v.as_object().unwrap().len(), 1, "{args:?}");
    }
    // Help and version are not errors, with or without --json.
    for args in [&["--json", "--help"][..], &["--json", "--version"]] {
        let out = bare(home.path(), args);
        assert!(out.status.success(), "{args:?}");
        assert!(!out.stdout.is_empty());
    }
}

/// The global --school is the school's UUID for every command; `key new` names the file with
/// --school-name.
#[test]
fn school_is_the_uuid_everywhere() {
    let home = tempfile::tempdir().unwrap();
    let help = bare(home.path(), &["key", "new", "--help"]);
    let h = String::from_utf8_lossy(&help.stdout);
    assert!(
        h.contains("--school-name <NAME>") && h.matches("--school <UUID>").count() == 1,
        "{h}"
    );
    for cmd in [
        &["pull"][..],
        &["verify"],
        &["devices", "list"],
        &["seed", "make"],
    ] {
        let mut args = cmd.to_vec();
        args.push("--help");
        let o = bare(home.path(), &args);
        let h = String::from_utf8_lossy(&o.stdout).into_owned();
        assert_eq!(h.matches("--school <UUID>").count(), 1, "{cmd:?}: {h}");
    }
}

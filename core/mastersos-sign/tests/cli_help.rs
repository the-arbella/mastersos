//! The `mastersos-sign` command line as IT sees it: English help, the `--school-key` flag with
//! `--kit` as a hidden alias, old commands hidden.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos-sign"))
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn help_is_english_and_hides_old_commands() {
    let out = run(&["--help"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(
        !t.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
        "{t}"
    );
    assert!(
        !t.contains("keygen") && !t.contains("restore-from-paper"),
        "{t}"
    );
    assert!(
        t.contains(
            "Monthly check-in: confirm to every computer that the latest settings are current"
        ),
        "{t}"
    );
    // They still parse.
    for hidden in ["keygen", "restore-from-paper"] {
        assert!(run(&[hidden, "--help"]).status.success());
    }
}

#[test]
fn sign_help_shows_school_key_not_kit_or_mode() {
    let t = text(&run(&["sign", "--help"]));
    assert!(t.contains("--school-key"), "{t}");
    assert!(
        !t.contains("--kit") && !t.contains("0600") && !t.contains("--key "),
        "{t}"
    );
    assert!(
        t.contains("keep it on a USB stick; only you should be able to read it"),
        "{t}"
    );
}

#[test]
fn kit_alias_still_parses() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none.kit");
    let token = dir.path().join("token");
    for flag in ["--kit", "--school-key"] {
        let out = run(&[
            "sign",
            "--server",
            "https://school.example",
            "--token-file",
            token.to_str().unwrap(),
            "--pending",
            "p",
            flag,
            missing.to_str().unwrap(),
        ]);
        let t = text(&out);
        assert!(!out.status.success());
        assert!(!t.contains("unexpected argument"), "{flag}: {t}");
        assert!(t.starts_with("Error: "), "{flag}: {t}");
    }
}

#[test]
fn kit_new_names_file_in_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(&[
        "kit",
        "new",
        "--out",
        dir.path().to_str().unwrap(),
        "--school",
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
}

#[test]
fn sign_without_a_school_key_says_so() {
    let out = run(&[
        "sign",
        "--server",
        "https://school.example",
        "--token-file",
        "t",
        "--pending",
        "p",
    ]);
    let t = text(&out);
    assert!(!out.status.success());
    assert!(t.contains("--school-key"), "{t}");
}

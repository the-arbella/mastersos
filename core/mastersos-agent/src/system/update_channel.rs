//! Update channel (Ruling 5) and school cache (plan 5 Task 12).
//!
//! The image's `/usr/lib/sysupdate.d/` is stable and points at the official update source. When the manifest
//! picks `beta` or sets `update_mirror`, the templates in `/usr/lib/mastersos/sysupdate.d.in/` get the channel
//! (`@CHANNEL@`) filled in, optionally with the `[Source]` root replaced by the school cache, and are written
//! as same-named files under `/etc/sysupdate.d/`, which override the originals. With neither, the overrides
//! are removed. Any other channel value is treated as `stable` and reported as a failure (the pre-publish
//! lint already rejects it; this is a backstop). Going from beta back to stable does not downgrade: the
//! machine stays on the beta version until stable has a higher one.
//!
//! The cache is not trusted: `Verify=yes`, `SHA256SUMS.gpg`, per-file sha256, dm-verity and the signed UKI are
//! all unchanged, so a cache cannot alter or downgrade content. It can still serve a stale listing and so
//! delay updates; `update-run` detects that (the official source offers something newer for over 12 hours),
//! updates from the official source, and the record it leaves is reported as a failed `update:mirror`.
//! An override differs from the original only in the root of the `[Source]` `Path=` line
//! (`with_mirror` touches that one line; everything else is byte-identical).
//!
//! Fallback when the cache is unreachable: with a cache set, a second copy of the transfers (channel filled in,
//! root NOT replaced) is written to `<var_dir>/sysupdate-fallback.d/`. `/usr/lib/mastersos/update-run`, which
//! `mastersos-update.service` runs, first updates using the `/etc` overrides (the cache); on failure it retries
//! once with `--definitions=` pointing at the fallback directory and writes the outcome to
//! `<var_dir>/update-mirror-failed`. This step reads that record and reports `update:mirror`. The next round
//! tries the cache first again; the round in which the cache works makes `update-run` delete the record.

use std::path::Path;

use anyhow::{bail, Context, Result};
use mastersos_bundle::{checks, ItemResult};

use super::{failed, ok, var_dir, Env, Step, SysPaths};
use crate::apply::{is_not_found, ApplyContext};
use crate::safefs;

pub const ITEM: &str = "system:update-channel";
/// Report item for the school cache: one per round when a cache is set; a failure when the last update round
/// fell back to the official source.
pub const MIRROR_ITEM: &str = "update:mirror";
const TEMPLATES: &str = "usr/lib/mastersos/sysupdate.d.in";
const TARGET: &str = "etc/sysupdate.d";
/// Fallback directory under `<var_dir>` (`update-run` hard-codes the same name).
pub const FALLBACK_DIR: &str = "sysupdate-fallback.d";
/// Record under `<var_dir>` that `update-run` writes when the cache was not used (`update-run` hard-codes the
/// same name).
pub const MIRROR_STATUS: &str = "update-mirror-failed";
const PLACEHOLDER: &str = "@CHANNEL@";

pub fn step() -> Step {
    Step {
        name: "update_channel",
        fast: true,
        run,
        without_bundle: None,
    }
}

/// 把模板里的 `@CHANNEL@` 换成 `channel`。
pub fn render(template: &str, channel: &str) -> String {
    template.replace(PLACEHOLDER, channel)
}

/// Replaces the `[Source]` `Path=<root>/@CHANNEL@/` line of a template with `Path=<mirror>/@CHANNEL@/`;
/// everything else is byte-identical. The template must have exactly one such `Path=` line (the `[Target]`
/// `Path=auto` is not one).
pub fn with_mirror(template: &str, mirror: &str) -> Result<String> {
    let suffix = format!("/{PLACEHOLDER}/");
    let mut hit = 0;
    let mut out = String::with_capacity(template.len() + mirror.len());
    for line in template.split_inclusive('\n') {
        if line.starts_with("Path=") && line.trim_end().ends_with(&suffix) {
            hit += 1;
            let nl = &line[line.trim_end().len()..];
            out.push_str(&format!(
                "Path={}{suffix}{nl}",
                mirror.trim_end_matches('/')
            ));
        } else {
            out.push_str(line);
        }
    }
    if hit != 1 {
        bail!("template should have exactly one Path=<root>{suffix} line, found {hit}");
    }
    Ok(out)
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let channel = ctx.school.update_channel.as_str();
    let root = &env.paths.root;
    let beta = channel == "beta";
    let eff_channel = if beta { "beta" } else { "stable" };
    let mut out = Vec::new();
    // Invalid cache address: do not use it, report a failure (lint already rejects it; this is a backstop).
    let mirror = match ctx.school.update_mirror.as_deref() {
        Some(m) => match checks::update_mirror(m) {
            Ok(()) => Some(m),
            Err(e) => {
                out.push(failed(MIRROR_ITEM, e));
                None
            }
        },
        None => None,
    };
    let r = if beta || mirror.is_some() {
        write_overrides(root, eff_channel, mirror)
    } else {
        remove_overrides(root)
    };
    // 覆盖文件在不在，以这一次实际做成的为准；失败时保持原记录。
    if r.is_ok() {
        env.sys.channel_override = beta || mirror.is_some();
    }
    let r = r.and_then(|()| match channel {
        "beta" | "stable" => Ok(()),
        other => bail!("unknown update channel {other}; treating it as stable"),
    });
    out.push(match r {
        Ok(()) => ok(ITEM),
        Err(e) => failed(ITEM, format!("{e:#}")),
    });
    // Fallback directory and the "cache not used" record.
    match mirror {
        Some(_) => out.extend(mirror_report(root, env.paths, eff_channel)),
        None => {
            if let Err(e) = clear_fallback(env.paths) {
                out.push(failed(MIRROR_ITEM, format!("{e:#}")));
            }
        }
    }
    out
}

/// 模板目录里的 `*.transfer`：(文件名, 内容)。
fn templates(root: &Path) -> Result<Vec<(String, String)>> {
    let dir = safefs::open_dir(root, Path::new(TEMPLATES), false)
        .with_context(|| format!("open /{TEMPLATES}"))?;
    let mut out = Vec::new();
    for name in safefs::list_at(&dir)? {
        if !name.ends_with(".transfer") {
            continue;
        }
        let bytes = safefs::read_at(&dir, &name)?
            .with_context(|| format!("/{TEMPLATES}/{name} disappeared"))?;
        let text = String::from_utf8(bytes).with_context(|| format!("{name} is not UTF-8"))?;
        out.push((name, text));
    }
    if out.is_empty() {
        bail!("no .transfer templates in /{TEMPLATES}");
    }
    Ok(out)
}

fn write_overrides(root: &Path, channel: &str, mirror: Option<&str>) -> Result<()> {
    let tpl = templates(root)?;
    // Compute everything before touching the disk, so a bad template leaves no half-written override set.
    let mut files = Vec::new();
    for (name, text) in tpl {
        let text = match mirror {
            Some(m) => with_mirror(&text, m).with_context(|| name.clone())?,
            None => text,
        };
        files.push((name, render(&text, channel)));
    }
    let dir = safefs::open_dir(root, Path::new(TARGET), true)?;
    for (name, text) in files {
        safefs::write_at(&dir, &name, text.as_bytes(), 0o644)
            .with_context(|| format!("write /{TARGET}/{name}"))?;
    }
    Ok(())
}

fn remove_overrides(root: &Path) -> Result<()> {
    let tpl = templates(root)?;
    let dir = match safefs::open_dir(root, Path::new(TARGET), false) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    for (name, _) in tpl {
        safefs::remove_at(&dir, &name).with_context(|| format!("delete /{TARGET}/{name}"))?;
    }
    Ok(())
}

/// Cache set: write the fallback directory (originals with only the channel filled in), read the record
/// `update-run` left behind, and yield one `update:mirror` item.
fn mirror_report(root: &Path, paths: &SysPaths, channel: &str) -> Vec<ItemResult> {
    let r = (|| -> Result<Option<String>> {
        let tpl = templates(root)?;
        let var = var_dir(paths)?;
        let fb = safefs::open_dir_at(&var, Path::new(FALLBACK_DIR), true)?;
        for (name, text) in tpl {
            safefs::write_at(&fb, &name, render(&text, channel).as_bytes(), 0o644)
                .with_context(|| format!("writing {FALLBACK_DIR}/{name}"))?;
        }
        let status = safefs::read_at(&var, MIRROR_STATUS)?;
        Ok(status.map(|b| {
            let t = String::from_utf8_lossy(&b);
            t.lines().next().unwrap_or("").chars().take(300).collect()
        }))
    })();
    vec![match r {
        Ok(None) => ok(MIRROR_ITEM),
        Ok(Some(why)) => failed(MIRROR_ITEM, why),
        Err(e) => failed(MIRROR_ITEM, format!("{e:#}")),
    }]
}

/// No cache: delete the transfers in the fallback directory and the record (the empty directory stays).
fn clear_fallback(paths: &SysPaths) -> Result<()> {
    let var = match safefs::open_abs_dir(&paths.var_dir, false) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    safefs::remove_at(&var, MIRROR_STATUS)?;
    if let Some(fb) = safefs::open_child_dir(&var, FALLBACK_DIR)? {
        for name in safefs::list_at(&fb)? {
            if name.ends_with(".transfer") {
                safefs::remove_at(&fb, &name)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{paths, tmp_root, with_ctx};
    use super::super::{steps, SysState};
    use super::*;
    use crate::apply::Phase;
    use crate::runner::FakeRunner;
    use mastersos_bundle::School;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    const NAMES: [&str; 4] = [
        "10-usr-verity-sig.transfer",
        "11-usr-verity.transfer",
        "12-usr.transfer",
        "20-uki.transfer",
    ];

    /// 临时根，模板取自镜像树里的真文件。
    fn root_with_templates() -> tempfile::TempDir {
        let root = tmp_root();
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../image/mkosi.extra")
            .join(TEMPLATES);
        let dst = root.path().join(TEMPLATES);
        fs::create_dir_all(&dst).unwrap();
        for n in NAMES {
            fs::copy(src.join(n), dst.join(n)).unwrap();
        }
        root
    }

    fn apply_channel(root: &Path, channel: &str, sys: &mut SysState) -> Vec<ItemResult> {
        apply_with(root, channel, None, sys)
    }

    fn apply_with(
        root: &Path,
        channel: &str,
        mirror: Option<&str>,
        sys: &mut SysState,
    ) -> Vec<ItemResult> {
        let p = paths(root);
        let runner = FakeRunner::new();
        let school = School {
            update_channel: channel.into(),
            update_mirror: mirror.map(String::from),
            ..School::default()
        };
        let flag = AtomicBool::new(false);
        with_ctx(&school, Phase::Boot, &flag, |ctx| {
            run(
                ctx,
                &mut Env {
                    paths: &p,
                    runner: &runner,
                    sys,
                },
            )
        })
    }

    fn etc(root: &Path) -> std::path::PathBuf {
        root.join(TARGET)
    }

    #[test]
    fn beta_writes_four_transfers_with_channel() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        let r = apply_channel(root.path(), "beta", &mut sys);
        assert_eq!(r, vec![ok(ITEM)]);
        assert!(sys.channel_override);
        let mut found: Vec<String> = fs::read_dir(etc(root.path()))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        found.sort();
        assert_eq!(found, NAMES);
        for n in NAMES {
            let p = etc(root.path()).join(n);
            let text = fs::read_to_string(&p).unwrap();
            assert!(!text.contains(PLACEHOLDER), "{n}");
            let path = text
                .lines()
                .find(|l| l.starts_with("Path=@BASE@"))
                .unwrap_or_else(|| panic!("{n} 没有源 Path="));
            assert!(path.ends_with("/beta/"), "{n}: {path}");
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
                0o644
            );
        }
    }

    #[test]
    fn back_to_stable_removes_overrides() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        apply_channel(root.path(), "beta", &mut sys);
        // 别人放的文件不动。
        fs::write(etc(root.path()).join("99-other.transfer"), b"x").unwrap();
        let r = apply_channel(root.path(), "stable", &mut sys);
        assert_eq!(r, vec![ok(ITEM)]);
        assert!(!sys.channel_override);
        for n in NAMES {
            assert!(!etc(root.path()).join(n).exists(), "{n}");
        }
        assert!(etc(root.path()).join("99-other.transfer").exists());
        // 本来就没有覆盖（目录都没有）：也是成功。
        let fresh = root_with_templates();
        assert_eq!(
            apply_channel(fresh.path(), "stable", &mut SysState::default()),
            vec![ok(ITEM)]
        );
        assert!(!etc(fresh.path()).exists());
    }

    #[test]
    fn unknown_channel_falls_back_to_stable_and_reports() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        apply_channel(root.path(), "beta", &mut sys);
        let r = apply_channel(root.path(), "nightly", &mut sys);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].item, ITEM);
        assert!(!r[0].ok);
        assert_eq!(
            r[0].detail.as_deref(),
            Some("unknown update channel nightly; treating it as stable")
        );
        for n in NAMES {
            assert!(!etc(root.path()).join(n).exists(), "{n}");
        }
        assert!(!sys.channel_override);
    }

    #[test]
    fn update_channel_is_fast_step() {
        let all = steps();
        let s = all.iter().find(|s| s.name == "update_channel").unwrap();
        assert!(s.fast);
    }

    #[test]
    fn render_replaces_every_placeholder() {
        assert_eq!(render("a/@CHANNEL@/b/@CHANNEL@", "beta"), "a/beta/b/beta");
    }

    const MIRROR: &str = "https://cache.school.ac.th/mastersos";

    fn read(p: &Path) -> String {
        fs::read_to_string(p).unwrap()
    }

    fn fallback(root: &Path) -> std::path::PathBuf {
        root.join("var/lib/mastersos-system").join(FALLBACK_DIR)
    }

    fn template(root: &Path, n: &str) -> String {
        read(&root.join(TEMPLATES).join(n))
    }

    /// Compare line by line and return the differing lines as (original, new).
    fn diff_lines(a: &str, b: &str) -> Vec<(String, String)> {
        assert_eq!(a.lines().count(), b.lines().count());
        a.lines()
            .zip(b.lines())
            .filter(|(x, y)| x != y)
            .map(|(x, y)| (x.to_string(), y.to_string()))
            .collect()
    }

    #[test]
    fn with_mirror_only_changes_source_root() {
        let t = "[Transfer]\nVerify=yes\n\n[Source]\nPath=https://os.khundavid.com/@CHANNEL@/\nMatchPattern=x\n\n[Target]\nPath=auto\n";
        let out = with_mirror(t, "http://10.0.0.5:8080/os/").unwrap();
        assert_eq!(
            diff_lines(t, &out),
            vec![(
                "Path=https://os.khundavid.com/@CHANNEL@/".to_string(),
                "Path=http://10.0.0.5:8080/os/@CHANNEL@/".to_string()
            )]
        );
        assert!(out.ends_with("Path=auto\n"));
        // No source Path= line, or more than one: refused.
        assert!(with_mirror("[Target]\nPath=auto\n", MIRROR).is_err());
        let two = "Path=a/@CHANNEL@/\nPath=b/@CHANNEL@/\n";
        assert!(with_mirror(two, MIRROR).is_err());
    }

    #[test]
    fn mirror_writes_overrides_differing_only_in_source_root() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        let r = apply_with(root.path(), "stable", Some(MIRROR), &mut sys);
        assert_eq!(r, vec![ok(ITEM), ok(MIRROR_ITEM)]);
        assert!(sys.channel_override);
        for n in NAMES {
            let orig = render(&template(root.path(), n), "stable");
            let over = read(&etc(root.path()).join(n));
            let d = diff_lines(&orig, &over);
            assert_eq!(d.len(), 1, "{n}: {d:?}");
            assert_eq!(d[0].0, "Path=@BASE@/stable/");
            assert_eq!(d[0].1, format!("Path={MIRROR}/stable/"));
            // Verification settings and target are unchanged.
            assert_eq!(
                orig.contains("Verify=yes"),
                over.contains("Verify=yes"),
                "{n}"
            );
            assert_eq!(
                fs::metadata(etc(root.path()).join(n))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o644
            );
        }
    }

    #[test]
    fn mirror_with_beta_uses_beta_dir_and_trailing_slash_is_normalised() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        apply_with(root.path(), "beta", Some("http://10.0.0.5/os/"), &mut sys);
        for n in NAMES {
            let text = read(&etc(root.path()).join(n));
            assert!(text.contains("\nPath=http://10.0.0.5/os/beta/\n"), "{n}");
        }
    }

    #[test]
    fn changing_and_removing_mirror_rewrites_then_deletes() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        apply_with(root.path(), "stable", Some(MIRROR), &mut sys);
        apply_with(root.path(), "stable", Some("http://10.1.1.1/x"), &mut sys);
        for n in NAMES {
            let text = read(&etc(root.path()).join(n));
            assert!(text.contains("Path=http://10.1.1.1/x/stable/"), "{n}");
            assert!(!text.contains("cache.school.ac.th"), "{n}");
        }
        // Cache removed, channel stable: overrides deleted, and so are the fallback transfers.
        let r = apply_with(root.path(), "stable", None, &mut sys);
        assert_eq!(r, vec![ok(ITEM)]);
        assert!(!sys.channel_override);
        for n in NAMES {
            assert!(!etc(root.path()).join(n).exists(), "{n}");
            assert!(!fallback(root.path()).join(n).exists(), "{n}");
        }
        // Beta with the cache removed: the beta override stays, the root goes back to the original.
        apply_with(root.path(), "beta", Some(MIRROR), &mut sys);
        apply_with(root.path(), "beta", None, &mut sys);
        for n in NAMES {
            let text = read(&etc(root.path()).join(n));
            assert!(text.contains("Path=@BASE@/beta/"), "{n}");
        }
        assert!(sys.channel_override);
    }

    #[test]
    fn mirror_writes_fallback_equal_to_original_for_channel() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        apply_with(root.path(), "beta", Some(MIRROR), &mut sys);
        for n in NAMES {
            let fb = read(&fallback(root.path()).join(n));
            assert_eq!(fb, render(&template(root.path(), n), "beta"), "{n}");
        }
    }

    #[test]
    fn invalid_mirror_is_refused_and_reported() {
        for bad in [
            "file:///srv/os",
            "https://cache.lan/os?x=1",
            "https://user:pw@cache.lan/os",
        ] {
            let root = root_with_templates();
            let mut sys = SysState::default();
            let r = apply_with(root.path(), "stable", Some(bad), &mut sys);
            assert_eq!(r.len(), 2, "{bad}: {r:?}");
            assert_eq!(r[0].item, MIRROR_ITEM);
            assert!(!r[0].ok, "{bad}");
            assert_eq!(r[1], ok(ITEM));
            assert!(!etc(root.path()).exists(), "{bad}");
            assert!(!fallback(root.path()).exists(), "{bad}");
            assert!(!sys.channel_override);
        }
    }

    #[test]
    fn mirror_failure_record_is_reported_until_update_run_clears_it() {
        let root = root_with_templates();
        let mut sys = SysState::default();
        apply_with(root.path(), "stable", Some(MIRROR), &mut sys);
        let status = root
            .path()
            .join("var/lib/mastersos-system")
            .join(MIRROR_STATUS);
        fs::write(
            &status,
            "2026-10-19T15:00:00Z school cache not used: sysupdate exit code 1; this round updated from the official source\n",
        )
        .unwrap();
        let r = apply_with(root.path(), "stable", Some(MIRROR), &mut sys);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].item, MIRROR_ITEM);
        assert!(!r[1].ok);
        assert!(r[1]
            .detail
            .as_deref()
            .unwrap()
            .contains("school cache not used"));
        // Next round the cache works (update-run deletes the record): back to ok.
        fs::remove_file(&status).unwrap();
        let r = apply_with(root.path(), "stable", Some(MIRROR), &mut sys);
        assert_eq!(r[1], ok(MIRROR_ITEM));
        // When the cache is removed, a leftover record is deleted and no longer reported.
        fs::write(&status, "stale record\n").unwrap();
        let r = apply_with(root.path(), "stable", None, &mut sys);
        assert_eq!(r, vec![ok(ITEM)]);
        assert!(!status.exists());
    }

    #[test]
    fn template_without_source_path_leaves_no_half_override() {
        let root = root_with_templates();
        fs::write(
            root.path().join(TEMPLATES).join("20-uki.transfer"),
            "[Target]\nPath=auto\n",
        )
        .unwrap();
        let mut sys = SysState::default();
        let r = apply_with(root.path(), "stable", Some(MIRROR), &mut sys);
        assert!(r.iter().any(|i| i.item == ITEM && !i.ok), "{r:?}");
        assert!(!etc(root.path()).exists());
    }
}

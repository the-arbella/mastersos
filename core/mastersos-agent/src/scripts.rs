//! `when = "apply"` 的脚本：以 agent 的身份（root）运行，同一份内容只成功跑一次（spec §5.5）。
//! `when = "login"` 的脚本不在这里跑：由 [`crate::login_queue`] 在用户登录时以该用户的身份运行。

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use mastersos_bundle::{Config, ItemResult, When, MAX_SCRIPT_TIMEOUT_SECS};

use crate::apply::sha256_hex;
use crate::config::DEFAULT_SCRIPT_TIMEOUT_SECS;
use crate::runner::{capture, last_lines, wait_group, Waited};
use crate::state::State;

/// 回报里带的输出行数。
const TAIL_LINES: usize = 20;
/// 输出只留最后这么多字节来取尾部。
const TAIL_BYTES: usize = 16 * 1024;

/// 运行分组里所有 `when = "apply"` 的脚本。脚本内容的 sha256 与 `state.script_hashes`
/// 里记录的一致就跳过；只有退出码为 0 才记录哈希，失败的下次还会再跑。
///
/// 记下的哈希就是实际执行的字节：脚本从包目录读出一次、算哈希，再把**同一份字节**写到
/// `work_dir`（root 0700 的私有目录）里执行，工作目录仍是 `bundle_dir`。
pub fn run_apply(
    config: &Config,
    bundle_dir: &Path,
    work_dir: &Path,
    state: &mut State,
) -> Vec<ItemResult> {
    let mut results = Vec::new();
    for s in config.scripts.iter().filter(|s| s.when == When::Apply) {
        let path = bundle_dir.join(&s.path);
        let (bytes, hash) = match fs::read(&path) {
            Ok(b) => {
                let h = sha256_hex(&b);
                (b, h)
            }
            Err(_) => {
                results.push(ItemResult {
                    item: s.path.clone(),
                    ok: false,
                    detail: Some("包里没有这个脚本".into()),
                });
                continue;
            }
        };
        if state.script_hashes.get(&s.path) == Some(&hash) {
            results.push(ItemResult {
                item: s.path.clone(),
                ok: true,
                detail: None,
            });
            continue;
        }
        // validate 已拒收超过上限的值；这里再夹一次，计算截止时间不会溢出。
        let secs = s
            .timeout_secs
            .unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS)
            .min(MAX_SCRIPT_TIMEOUT_SECS);
        let timeout = Duration::from_secs(secs);
        let (ok, detail) = match run_copy(&bytes, work_dir, bundle_dir, timeout) {
            Ok(Outcome::Exited(st, tail)) if st.success() => (true, tail),
            Ok(Outcome::Exited(st, tail)) => (false, Some(join(&describe(st), tail))),
            Ok(Outcome::TimedOut(tail)) => (
                false,
                Some(join(
                    &format!("timeout：{} 秒内没有结束，已终止", timeout.as_secs()),
                    tail,
                )),
            ),
            Err(e) => (false, Some(format!("无法运行：{e}"))),
        };
        if ok {
            state.script_hashes.insert(s.path.clone(), hash);
        }
        results.push(ItemResult {
            item: s.path.clone(),
            ok,
            detail,
        });
    }
    results
}

fn join(head: &str, tail: Option<String>) -> String {
    match tail {
        Some(t) => format!("{head}\n{t}"),
        None => head.to_string(),
    }
}

fn describe(st: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (st.code(), st.signal()) {
        (Some(c), _) => format!("退出码 {c}"),
        (None, Some(sig)) => format!("被信号 {sig} 终止"),
        _ => "异常退出".into(),
    }
}

enum Outcome {
    Exited(ExitStatus, Option<String>),
    TimedOut(Option<String>),
}

/// 把脚本字节写进 `work_dir` 的一个新文件（0700）执行，跑完删掉。
fn run_copy(
    bytes: &[u8],
    work_dir: &Path,
    cwd: &Path,
    timeout: Duration,
) -> std::io::Result<Outcome> {
    let name = format!("{}.script", uuid::Uuid::new_v4());
    let dir =
        crate::safefs::open_dir(work_dir, Path::new(""), false).map_err(std::io::Error::other)?;
    crate::safefs::write_at(&dir, &name, bytes, 0o700).map_err(std::io::Error::other)?;
    let exe = work_dir.join(&name);
    let r = run_one(&exe, cwd, timeout);
    let _ = crate::safefs::remove_at(&dir, &name);
    r
}

/// 脚本自成一个进程组，超时时整组先 SIGTERM、`TERM_GRACE` 后 SIGKILL（见 [`wait_group`]），
/// 连同它拉起的子进程一起收掉。stdout 与 stderr 接到同一个管道（读进内存，不落盘），回报取
/// 最后 20 行。
fn run_one(path: &Path, cwd: &Path, timeout: Duration) -> std::io::Result<Outcome> {
    let (r, w) = std::io::pipe()?;
    let mut child = {
        let mut c = Command::new(path);
        c.current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(w.try_clone()?)
            .stderr(w)
            .process_group(0);
        // 刚写好的文件可能正被别的线程 fork 出来、还没 exec 的子进程拿着写句柄（ETXTBSY）。
        let mut tries = 0;
        loop {
            match c.spawn() {
                Err(e) if e.raw_os_error() == Some(nix::libc::ETXTBSY) && tries < 10 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                r => break r?,
            }
        }
    };
    let out = capture(r, TAIL_BYTES);
    let tail = |out: crate::runner::Capture| {
        let t = last_lines(&out.finish(), TAIL_LINES);
        (!t.is_empty()).then_some(t)
    };
    Ok(match wait_group(&mut child, timeout)? {
        Waited::Exited(st) => Outcome::Exited(st, tail(out)),
        Waited::TimedOut => Outcome::TimedOut(tail(out)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::TERM_GRACE;
    use mastersos_bundle::Manifest;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    /// 每个 (path, when, timeout) 生成一条 `[[group.scripts]]`。
    fn config(scripts: &[(&str, &str, Option<u64>)]) -> Config {
        let mut s = String::from("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n");
        for (p, when, t) in scripts {
            s += &format!("[[group.scripts]]\npath = \"{p}\"\nwhen = \"{when}\"\n");
            if let Some(t) = t {
                s += &format!("timeout_secs = {t}\n");
            }
        }
        let m = Manifest::parse(&s).unwrap();
        mastersos_bundle::effective_config(&m, &m.configs[0])
    }

    fn write_script(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn script_runs_once_per_content() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("log");
        write_script(
            d.path(),
            "scripts/a.sh",
            &format!("echo ran >> {}", log.display()),
        );
        let g = config(&[("scripts/a.sh", "apply", None)]);
        let mut st = State::default();
        for _ in 0..2 {
            let r = run_apply(&g, d.path(), d.path(), &mut st);
            assert_eq!(r.len(), 1);
            assert!(r[0].ok, "{r:?}");
        }
        assert_eq!(fs::read_to_string(&log).unwrap(), "ran\n");
        assert!(st.script_hashes.contains_key("scripts/a.sh"));

        // 内容变了就再跑一次。
        write_script(
            d.path(),
            "scripts/a.sh",
            &format!("echo ran2 >> {}", log.display()),
        );
        run_apply(&g, d.path(), d.path(), &mut st);
        assert_eq!(fs::read_to_string(&log).unwrap(), "ran\nran2\n");
    }

    #[test]
    fn failed_script_is_retried() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("log");
        write_script(
            d.path(),
            "scripts/f.sh",
            &format!("echo try >> {}\necho 打印机没连上\nexit 1", log.display()),
        );
        let g = config(&[("scripts/f.sh", "apply", None)]);
        let mut st = State::default();
        let r = run_apply(&g, d.path(), d.path(), &mut st);
        assert!(!r[0].ok);
        let detail = r[0].detail.as_deref().unwrap();
        assert!(detail.contains("退出码 1"), "{detail}");
        assert!(detail.contains("打印机没连上"), "{detail}");
        assert!(st.script_hashes.is_empty());
        run_apply(&g, d.path(), d.path(), &mut st);
        assert_eq!(fs::read_to_string(&log).unwrap(), "try\ntry\n");
    }

    #[test]
    fn huge_timeout_does_not_panic() {
        // 没经过 validate 的清单（比如旧版 agent 收下的）也不会让计算截止时间溢出。
        let d = tempfile::tempdir().unwrap();
        write_script(d.path(), "scripts/ok.sh", "exit 0");
        let g = config(&[("scripts/ok.sh", "apply", Some(i64::MAX as u64))]);
        let mut st = State::default();
        let r = run_apply(&g, d.path(), d.path(), &mut st);
        assert!(r[0].ok, "{r:?}");
    }

    #[test]
    fn script_timeout_is_reported() {
        let d = tempfile::tempdir().unwrap();
        write_script(d.path(), "scripts/slow.sh", "echo start\nsleep 30");
        let g = config(&[("scripts/slow.sh", "apply", Some(1))]);
        let mut st = State::default();
        let t0 = Instant::now();
        let r = run_apply(&g, d.path(), d.path(), &mut st);
        // The script sleeps 30 s; anything well short of that proves the 1 s timeout fired (slack for loaded CI hosts)
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        assert!(!r[0].ok);
        let detail = r[0].detail.as_deref().unwrap();
        assert!(detail.contains("timeout"), "{detail}");
        assert!(detail.contains("start"), "{detail}");
        assert!(st.script_hashes.is_empty());
    }

    #[test]
    fn script_ignoring_sigterm_is_killed_after_grace() {
        let d = tempfile::tempdir().unwrap();
        write_script(d.path(), "scripts/stubborn.sh", "trap '' TERM\nsleep 30");
        let g = config(&[("scripts/stubborn.sh", "apply", Some(1))]);
        let t0 = Instant::now();
        let r = run_apply(&g, d.path(), d.path(), &mut State::default());
        let took = t0.elapsed();
        assert!(!r[0].ok);
        assert!(r[0].detail.as_deref().unwrap().contains("timeout"));
        assert!(took >= TERM_GRACE, "{took:?}");
        assert!(took < TERM_GRACE + Duration::from_secs(10), "{took:?}");
    }

    /// 记下的哈希是实际执行的那份字节：执行期间包里的脚本被换掉，记录仍是旧内容的哈希，
    /// 下一次（内容不同）照样再跑。
    #[test]
    fn recorded_hash_is_of_executed_bytes() {
        let d = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let log = d.path().join("log");
        let path = d.path().join("scripts/a.sh");
        let old = format!(
            "#!/bin/sh\necho old >> {}\nprintf '#!/bin/sh\\necho new >> {}\\n' > {}\n",
            log.display(),
            log.display(),
            path.display()
        );
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &old).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let g = config(&[("scripts/a.sh", "apply", None)]);
        let mut st = State::default();
        run_apply(&g, d.path(), work.path(), &mut st);
        assert_eq!(fs::read_to_string(&log).unwrap(), "old\n");
        assert_eq!(
            st.script_hashes.get("scripts/a.sh"),
            Some(&sha256_hex(old.as_bytes())),
            "记录的是执行的那份"
        );
        run_apply(&g, d.path(), work.path(), &mut st);
        assert_eq!(fs::read_to_string(&log).unwrap(), "old\nnew\n");
        assert!(
            fs::read_dir(work.path()).unwrap().next().is_none(),
            "执行用的副本删掉了"
        );
    }

    #[test]
    fn login_scripts_not_run_by_agent() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("log");
        write_script(
            d.path(),
            "scripts/login.sh",
            &format!("echo ran >> {}", log.display()),
        );
        let g = config(&[("scripts/login.sh", "login", None)]);
        let mut st = State::default();
        assert!(run_apply(&g, d.path(), d.path(), &mut st).is_empty());
        assert!(!log.exists());
        assert!(st.script_hashes.is_empty());
    }

    #[test]
    fn detail_keeps_last_20_lines() {
        let d = tempfile::tempdir().unwrap();
        write_script(
            d.path(),
            "scripts/many.sh",
            "i=1; while [ $i -le 50 ]; do echo line$i; i=$((i+1)); done",
        );
        let g = config(&[("scripts/many.sh", "apply", None)]);
        let r = run_apply(&g, d.path(), d.path(), &mut State::default());
        let detail = r[0].detail.as_deref().unwrap();
        let lines: Vec<&str> = detail.lines().collect();
        assert_eq!(lines.len(), 20, "{detail}");
        assert_eq!(lines[0], "line31");
        assert_eq!(lines[19], "line50");
    }
}

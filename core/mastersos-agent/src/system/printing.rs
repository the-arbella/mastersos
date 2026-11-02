//! 打印与扫描：分组的 `printers` 经 CUPS 的 `lpadmin -m everywhere`（IPP Everywhere，免驱动）加成系统队列，
//! `scanners` 写进 sane-airscan 的 `/etc/sane.d/airscan.d/mastersos.conf`。
//!
//! - 队列名就是打印机名称，CUPS 不收的字符换成 `_`、截到 127 字节（`checks::printer_queue`）：打印对话框里显示的是
//!   队列名，用户看到的就是 IT 起的名字。名称原样也放在 `-D`。CUPS 的队列名不分大小写（ASCII），比较一律
//!   `eq_ignore_ascii_case`；整理之后相同的两项，后一项回报失败、不加。
//! - **归属只看 `SysState::printers`**：只改、只删记在那里的队列。本机已有同名而不是我们记下的队列（IT 加的、CUPS 自动
//!   发现的），不动它，那一台回报失败。
//! - 每台在 `lpadmin -p` 之前先记进 `SysState::printers` 并立即存盘：`-E` 让 lpadmin 在取打印机能力之前就建好队列，打印机连不上或
//!   超时会留下半个队列；记录在，下一轮就重试，清单里去掉了就删。
//! - `printers` 不是 fast 步骤：`lpadmin -m everywhere` 要连上打印机取能力（每台限时 60 秒）。每台之前看 `superseded`，
//!   已置位就停下（Ruling 17：挂失锁定不排在一串打印机后面）。
//! - `lpstat -v` 读不了（cupsd 起不来）就整步不动：不知道现状，既不加也不删，每台回报「未能确认」。
//!   `system-state.json` 这一轮读不了时同样整步不动（不知道哪些是我们的），只回报一条。
//! - 不合格的项（`checks::printer_uri` / `scanner_uri` / `device_name`）跳过并回报；它上一轮加的队列、写的那一行保留不删
//!   （与 `wifi` 一样，清单改坏了不撤掉已生效的设置）。
//! - CUPS 的命令一律在 `LC_ALL=C.UTF-8` 下跑：消息不翻译（按「device for」解析），队列名里的泰文等照 UTF-8 原样进出。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use mastersos_bundle::{checks, ItemResult, NetDevice};

use super::{failed, ok, Env, Step, SysState};
use crate::apply::{is_not_found, ApplyContext};
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;

/// 每次 `lpadmin` 的时限（`-m everywhere` 要连打印机）。
pub const LPADMIN_TIMEOUT: Duration = Duration::from_secs(60);
/// CUPS 命令的语言环境：英文消息、UTF-8 字符集。
pub const CUPS_LOCALE: &str = "LC_ALL=C.UTF-8";
/// sane-airscan 的附加配置目录（相对系统根）与我们的文件名。
pub const AIRSCAN_DIR: &str = "etc/sane.d/airscan.d";
pub const AIRSCAN_FILE: &str = "mastersos.conf";
/// 步骤层面的失败（`lpstat` 读不了、删队列、设默认失败；airscan 目录打不开）用这些回报项。
pub const PRINTERS_ITEM: &str = "printers";
pub const SCANNERS_ITEM: &str = "scanners";

pub fn printers_step() -> Step {
    Step {
        name: "printers",
        fast: false,
        run: run_printers,
        without_bundle: None,
    }
}

pub fn scanners_step() -> Step {
    Step {
        name: "scanners",
        fast: true,
        run: run_scanners,
        without_bundle: None,
    }
}

/// 打印机名称对应的 CUPS 队列名（`checks::printer_queue`）。
pub fn queue_name(display: &str) -> String {
    checks::printer_queue(display)
}

fn printer_item(name: &str) -> String {
    format!("printer:{name}")
}

fn scanner_item(name: &str) -> String {
    format!("scanner:{name}")
}

fn run_printers(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    apply_printers(env, &ctx.config.printers, ctx.superseded)
}

fn run_scanners(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let root = env.paths.root.clone();
    apply_scanners(&root, env.sys, &ctx.config.scanners)
}

/// `env LC_ALL=C.UTF-8 <args>`。
fn cups(args: &[&str]) -> Cmd {
    let mut a = vec![CUPS_LOCALE];
    a.extend_from_slice(args);
    Cmd::new("env", &a)
}

fn lpadmin(args: &[&str]) -> Cmd {
    let mut a = vec!["lpadmin"];
    a.extend_from_slice(args);
    cups(&a).timeout(LPADMIN_TIMEOUT)
}

/// `lpstat -v`：队列 → 设备 URI。没有任何队列时 CUPS 报「No destinations added.」，当作空。
fn lpstat_devices(r: &dyn Runner) -> Result<BTreeMap<String, String>> {
    let out = r.run(&cups(&["lpstat", "-v"]))?;
    if out.code != 0 {
        if out.stderr.contains("No destinations added") {
            return Ok(BTreeMap::new());
        }
        anyhow::bail!(
            "lpstat -v 退出码 {}：{}",
            out.code,
            crate::runner::last_lines(&out.stderr, 20)
        );
    }
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("device for "))
        .filter_map(|l| l.split_once(": "))
        .map(|(q, u)| (q.to_string(), u.trim().to_string()))
        .collect())
}

/// `lpstat -d` 的系统默认队列；没有默认或读不了为 `None`。
fn lpstat_default(r: &dyn Runner) -> Option<String> {
    let out = run_ok(r, cups(&["lpstat", "-d"])).ok()?;
    out.lines()
        .find_map(|l| l.strip_prefix("system default destination: "))
        .map(|q| q.trim().to_string())
}

/// 表里与 `q` 只差大小写（含相同）的那一项。
fn find_ci<'a, V>(m: &'a BTreeMap<String, V>, q: &str) -> Option<(&'a String, &'a V)> {
    m.iter().find(|(k, _)| k.eq_ignore_ascii_case(q))
}

fn apply_printers(env: &mut Env, list: &[NetDevice], superseded: &AtomicBool) -> Vec<ItemResult> {
    if env.sys.load_failed {
        return vec![failed(
            PRINTERS_ITEM,
            "system-state.json 这一轮读不了，不知道哪些打印机队列是 MastersOS 加的，这一轮不改打印机"
                .into(),
        )];
    }
    let mut out = Vec::new();
    // 合格的：(队列, 名称, URI)，按清单顺序。不合格项的队列（小写）只进 `keep`。
    let mut want: Vec<(String, &str, &str)> = Vec::new();
    let mut keep = BTreeSet::new();
    for d in list {
        let q = queue_name(&d.name);
        if let Err(e) = checks::device_name(&d.name).and_then(|_| checks::printer_uri(&d.uri)) {
            out.push(failed(&printer_item(&d.name), e));
            keep.insert(q.to_ascii_lowercase());
            continue;
        }
        if let Some((_, first, _)) = want.iter().find(|(w, _, _)| w.eq_ignore_ascii_case(&q)) {
            out.push(failed(
                &printer_item(&d.name),
                format!(
                    "打印机 {:?} 的队列名 {q:?} 与前面的 {first:?} 相同（CUPS 不收的字符换成 _、不分大小写之后），只用前面那台",
                    d.name
                ),
            ));
            continue;
        }
        want.push((q, &d.name, &d.uri));
    }

    // 现状读不了就什么都不动：不知道哪些队列在、URI 对不对。
    let current = match lpstat_devices(env.runner) {
        Ok(c) => c,
        Err(e) => {
            out.push(failed(PRINTERS_ITEM, format!("{e:#}")));
            out.extend(want.iter().map(|(_, name, _)| {
                failed(
                    &printer_item(name),
                    "CUPS 的队列读不了（lpstat -v 失败），这一轮未能确认".into(),
                )
            }));
            return out;
        }
    };

    // 这一轮在 CUPS 里、URI 对的我们的队列（按清单顺序）。
    let mut present: Vec<String> = Vec::new();
    for (q, name, uri) in &want {
        if superseded.load(Ordering::SeqCst) {
            log::info!("有更新的应用请求，停在打印机 {q} 之前");
            return out;
        }
        let item = printer_item(name);
        // 我们记下的名字（大小写以记录为准）；没有就是新的。
        let ours = find_ci(&env.sys.printers, q).map(|(k, _)| k.clone());
        match (find_ci(&current, q), &ours) {
            (Some((cq, _)), None) => {
                out.push(failed(
                    &item,
                    format!("本机已有同名的打印机队列 {cq:?}，不是 MastersOS 加的，不动它"),
                ));
                continue;
            }
            (Some((cq, cu)), Some(_)) if cu == uri => {
                present.push(cq.clone());
                out.push(ok(&item));
                continue;
            }
            _ => {}
        }
        // 先记下、**落盘**再加：lpadmin 失败、超时，或 agent 在它跑到一半时被杀（关机、断电）留下的半个队列也归我们
        // （下一轮重试或删除）。一轮结束时的那次保存赶不上中途被杀的情形。存不下就不加这一台。
        let key = ours.unwrap_or_else(|| q.clone());
        let prev = env.sys.printers.insert(key.clone(), uri.to_string());
        if let Err(e) = env.sys.save(env.paths) {
            match prev {
                Some(u) => env.sys.printers.insert(key.clone(), u),
                None => env.sys.printers.remove(&key),
            };
            out.push(failed(
                &item,
                format!("记录这台打印机失败（{e:#}），这一轮不加"),
            ));
            continue;
        }
        match run_ok(
            env.runner,
            lpadmin(&[
                "-p",
                &key,
                "-E",
                "-v",
                uri,
                "-m",
                "everywhere",
                "-D",
                name,
                "-o",
                "printer-is-shared=false",
            ]),
        ) {
            Ok(_) => {
                present.push(key);
                out.push(ok(&item));
            }
            Err(e) => out.push(failed(&item, format!("{e:#}"))),
        }
    }

    let wanted: BTreeSet<String> = want
        .iter()
        .map(|(q, _, _)| q.to_ascii_lowercase())
        .collect();
    // 不在清单里、CUPS 里也已经没有的：记录作废。
    env.sys
        .printers
        .retain(|q, _| wanted.contains(&q.to_ascii_lowercase()) || find_ci(&current, q).is_some());

    // 第一台（在 CUPS 里的）设为系统默认；已经是就不动。
    if let Some(first) = present.first() {
        let is_default = lpstat_default(env.runner).is_some_and(|d| d.eq_ignore_ascii_case(first));
        if !is_default {
            if let Err(e) = run_ok(env.runner, lpadmin(&["-d", first])) {
                out.push(failed(PRINTERS_ITEM, format!("设默认打印机：{e:#}")));
            }
        }
    }

    // 清单里去掉的：只删我们记下的，一台删不掉照删下一台，删不掉的一直记着。
    let stale: Vec<String> = env
        .sys
        .printers
        .keys()
        .filter(|q| {
            let l = q.to_ascii_lowercase();
            !wanted.contains(&l) && !keep.contains(&l)
        })
        .cloned()
        .collect();
    for q in stale {
        match run_ok(env.runner, lpadmin(&["-x", &q])) {
            Ok(_) => {
                env.sys.printers.remove(&q);
            }
            Err(e) => out.push(failed(PRINTERS_ITEM, format!("删除队列 {q}：{e:#}"))),
        }
    }
    out
}

/// sane-airscan 配置里的引号字符串：`\` 与 `"` 前加 `\`（它的解析器在引号里把 `\x` 当成 x，`\n` 等是控制字符；
/// 设备名不含控制字符，`checks::device_name` 已挡）。
fn airscan_quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q
}

/// `[devices]` 段：每行 `"<名称>" = "<uri>", eSCL`。URI 也加引号：不加引号时 sane-airscan 把 `;` 与 `#` 当注释开头、
/// `,` 当分隔符，URI 里有这些字符就被截断。调用者先过检查。
pub fn render_airscan(scanners: &[NetDevice]) -> String {
    let mut t = String::from("# 由 mastersos-agent 按设置文件生成，本机改动会被覆盖\n[devices]\n");
    for s in scanners {
        t.push_str(&format!(
            "{} = {}, eSCL\n",
            airscan_quote(&s.name),
            airscan_quote(&s.uri)
        ));
    }
    t
}

fn apply_scanners(root: &Path, sys: &mut SysState, list: &[NetDevice]) -> Vec<ItemResult> {
    let mut out = Vec::new();
    // 要写的行：合格的，加上不合格但上次写过的（照旧那一行）。
    let mut lines: Vec<NetDevice> = Vec::new();
    let mut items = Vec::new();
    for d in list {
        if let Err(e) = checks::device_name(&d.name).and_then(|_| checks::scanner_uri(&d.uri)) {
            out.push(failed(&scanner_item(&d.name), e));
            if let Some(uri) = sys.scanners.get(&d.name) {
                if !lines.iter().any(|l| l.name == d.name) {
                    lines.push(NetDevice {
                        name: d.name.clone(),
                        uri: uri.clone(),
                    });
                }
            }
            continue;
        }
        if lines.iter().any(|g| g.name == d.name) {
            out.push(failed(
                &scanner_item(&d.name),
                format!("扫描仪名称 {:?} 重复，只用第一项", d.name),
            ));
            continue;
        }
        lines.push(d.clone());
        items.push(scanner_item(&d.name));
    }

    if lines.is_empty() {
        match safefs::open_dir(root, Path::new(AIRSCAN_DIR), false) {
            Ok(dir) => match safefs::remove_at(&dir, AIRSCAN_FILE) {
                Ok(()) => sys.scanners.clear(),
                Err(e) => out.push(failed(
                    SCANNERS_ITEM,
                    format!(
                        "{:#}",
                        e.context(format!("删除 /{AIRSCAN_DIR}/{AIRSCAN_FILE}"))
                    ),
                )),
            },
            Err(e) if is_not_found(&e) => sys.scanners.clear(),
            Err(e) => out.push(failed(
                SCANNERS_ITEM,
                format!("{:#}", e.context(format!("打开 /{AIRSCAN_DIR}"))),
            )),
        }
        return out;
    }

    let res = safefs::open_dir(root, Path::new(AIRSCAN_DIR), true)
        .with_context(|| format!("打开 /{AIRSCAN_DIR}"))
        .and_then(|dir| {
            safefs::write_at(&dir, AIRSCAN_FILE, render_airscan(&lines).as_bytes(), 0o644)
                .with_context(|| format!("写入 /{AIRSCAN_DIR}/{AIRSCAN_FILE}"))
        });
    match res {
        Ok(_) => {
            sys.scanners = lines.into_iter().map(|l| (l.name, l.uri)).collect();
            out.extend(items.iter().map(|i| ok(i)));
        }
        Err(e) => out.extend(items.iter().map(|i| failed(i, format!("{e:#}")))),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::tests::{paths, tmp_root};
    use super::super::SysPaths;
    use super::*;
    use crate::runner::{FakeRunner, Output};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    fn dev(name: &str, uri: &str) -> NetDevice {
        NetDevice {
            name: name.into(),
            uri: uri.into(),
        }
    }

    const LPSTAT_V: &str = "env LC_ALL=C.UTF-8 lpstat -v";
    const LPSTAT_D: &str = "env LC_ALL=C.UTF-8 lpstat -d";
    const LPADMIN: &str = "env LC_ALL=C.UTF-8 lpadmin";

    /// 记下每次调用的参数数组（`Cmd::line` 用空格连接，看不出参数边界）；第一次 `lpadmin -p` 返回后可置位 `superseded`。
    struct Rec {
        inner: FakeRunner,
        args: Mutex<Vec<Vec<String>>>,
        supersede: Option<Arc<AtomicBool>>,
    }

    impl Rec {
        fn new() -> Rec {
            Rec {
                inner: FakeRunner::new(),
                args: Mutex::new(Vec::new()),
                supersede: None,
            }
        }
        fn lines(&self) -> Vec<String> {
            self.inner.calls()
        }
        fn with(&self, prefix: &str) -> Vec<String> {
            self.lines()
                .into_iter()
                .filter(|l| l.starts_with(prefix))
                .collect()
        }
        fn adds(&self) -> Vec<String> {
            self.with(&format!("{LPADMIN} -p"))
        }
        fn args(&self) -> Vec<Vec<String>> {
            self.args.lock().unwrap().clone()
        }
    }

    impl Runner for Rec {
        fn run(&self, cmd: &Cmd) -> Result<Output> {
            let mut a = vec![cmd.program.clone()];
            a.extend(cmd.args.iter().cloned());
            self.args.lock().unwrap().push(a);
            let o = self.inner.run(cmd);
            if let Some(f) = &self.supersede {
                if cmd.line().starts_with(&format!("{LPADMIN} -p")) {
                    f.store(true, Ordering::SeqCst);
                }
            }
            o
        }
    }

    fn run_with(
        r: &dyn Runner,
        sys: &mut SysState,
        list: &[NetDevice],
        flag: &AtomicBool,
    ) -> Vec<ItemResult> {
        let root = tmp_root();
        let p = paths(root.path());
        let mut env = Env {
            paths: &p,
            runner: r,
            sys,
        };
        apply_printers(&mut env, list, flag)
    }

    fn add_line(name: &str, uri: &str) -> String {
        format!(
            "{LPADMIN} -p {} -E -v {uri} -m everywhere -D {name} -o printer-is-shared=false",
            queue_name(name)
        )
    }

    fn lpstat(r: &Rec, lines: &[(&str, &str)]) {
        let t: String = lines
            .iter()
            .map(|(q, u)| format!("device for {q}: {u}\n"))
            .collect();
        r.inner.respond(LPSTAT_V, Output::ok(&t));
    }

    fn recorded(pairs: &[(&str, &str)]) -> SysState {
        SysState {
            printers: pairs
                .iter()
                .map(|(q, u)| (q.to_string(), u.to_string()))
                .collect(),
            ..SysState::default()
        }
    }

    /// Review Focus 1：队列名是名称本身（CUPS 不收的字符换成 _），`-D` 是原名、作为**一个**参数传给 lpadmin。
    #[test]
    fn printer_display_name_keeps_unicode() {
        let name = "ห้อง 3/ชั้น #2 \"A\"";
        let q = queue_name(name);
        assert_eq!(q, "ห้อง_3_ชั้น__2__A_");
        let r = Rec::new();
        let mut sys = SysState::default();
        let out = run_with(
            &r,
            &mut sys,
            &[dev(name, "ipp://10.0.0.5/ipp/print")],
            &AtomicBool::new(false),
        );
        assert_eq!(out, vec![ok(&format!("printer:{name}"))]);
        let adds: Vec<Vec<String>> = r
            .args()
            .into_iter()
            .filter(|a| a.get(2).map(String::as_str) == Some("lpadmin") && a[3] == "-p")
            .collect();
        assert_eq!(
            adds,
            vec![vec![
                "env",
                "LC_ALL=C.UTF-8",
                "lpadmin",
                "-p",
                q.as_str(),
                "-E",
                "-v",
                "ipp://10.0.0.5/ipp/print",
                "-m",
                "everywhere",
                "-D",
                name,
                "-o",
                "printer-is-shared=false",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()]
        );
        assert_eq!(
            sys.printers,
            BTreeMap::from([(q, "ipp://10.0.0.5/ipp/print".to_string())])
        );
    }

    /// 复审 N-I1：记录在 `lpadmin -p` 跑起来之前就已经落盘——agent 在 lpadmin 中途被杀（关机、断电、abort），半个队列
    /// 照样是我们的。这里的 runner 在看到 `lpadmin -p` 时从盘上读 state（等于那一刻进程死掉，后面的保存都没发生）。
    #[test]
    fn pending_record_is_on_disk_before_lpadmin() {
        struct DiskPeek {
            inner: FakeRunner,
            paths: SysPaths,
            seen: Mutex<Vec<BTreeMap<String, String>>>,
        }
        impl Runner for DiskPeek {
            fn run(&self, cmd: &Cmd) -> Result<Output> {
                if cmd.line().starts_with(&format!("{LPADMIN} -p")) {
                    let on_disk = SysState::load(&self.paths).unwrap();
                    self.seen.lock().unwrap().push(on_disk.printers);
                }
                self.inner.run(cmd)
            }
        }
        let root = tmp_root();
        let p = paths(root.path());
        let r = DiskPeek {
            inner: FakeRunner::new(),
            paths: p.clone(),
            seen: Mutex::new(Vec::new()),
        };
        let mut sys = SysState::default();
        let mut env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        apply_printers(
            &mut env,
            &[dev("A", "ipp://a/ipp/print"), dev("B", "ipp://b/ipp/print")],
            &AtomicBool::new(false),
        );
        let seen = r.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0],
            BTreeMap::from([("A".to_string(), "ipp://a/ipp/print".to_string())]),
            "A 的 lpadmin 开始时盘上已有 A"
        );
        assert!(seen[1].contains_key("A") && seen[1].contains_key("B"));
    }

    /// 存不下记录（var_dir 是个普通文件）：这一台不跑 lpadmin、回报失败，记录也不留在内存里。
    #[test]
    fn unsaved_record_skips_lpadmin() {
        let root = tmp_root();
        let p = paths(root.path());
        std::fs::write(&p.var_dir, b"not a dir").unwrap();
        let r = Rec::new();
        let mut sys = SysState::default();
        let mut env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        let out = apply_printers(
            &mut env,
            &[dev("A", "ipp://a/ipp/print")],
            &AtomicBool::new(false),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(!out[0].ok && out[0].item == "printer:A");
        assert!(r.adds().is_empty(), "{:?}", r.lines());
        assert!(sys.printers.is_empty());
    }

    #[test]
    fn readds_when_uri_changes() {
        let r = Rec::new();
        let mut sys = SysState::default();
        let flag = AtomicBool::new(false);
        run_with(&r, &mut sys, &[dev("Office", "ipp://a/ipp/print")], &flag);
        assert_eq!(r.adds().len(), 1);
        // CUPS 里已经是这个 URI：不再 lpadmin。
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        let out = run_with(&r, &mut sys, &[dev("Office", "ipp://a/ipp/print")], &flag);
        assert_eq!(out, vec![ok("printer:Office")]);
        assert_eq!(r.adds().len(), 1, "{:?}", r.lines());
        // URI 变了：重新加。
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        run_with(&r, &mut sys, &[dev("Office", "ipps://b/ipp/print")], &flag);
        assert_eq!(r.adds().len(), 2);
        assert_eq!(r.adds()[1], add_line("Office", "ipps://b/ipp/print"));
        assert_eq!(sys.printers["Office"], "ipps://b/ipp/print");
    }

    /// Review Focus 2：只删我们记下的队列；IT 加的、没记的（哪怕名字像我们的）都不动。
    #[test]
    fn removes_only_managed_queues() {
        let r = Rec::new();
        let mut sys = recorded(&[("Office", "ipp://a/ipp/print")]);
        lpstat(
            &r,
            &[
                ("Office", "ipp://a/ipp/print"),
                ("HP_LaserJet", "ipp://10.0.0.9/ipp/print"),
                ("Library", "ipp://c/ipp/print"),
            ],
        );
        let out = run_with(&r, &mut sys, &[], &AtomicBool::new(false));
        assert_eq!(out, vec![]);
        assert_eq!(
            r.with(&format!("{LPADMIN} -x")),
            vec![format!("{LPADMIN} -x Office")]
        );
        assert!(sys.printers.is_empty());
        // 删不掉：回报，记录留着，下一轮再删。
        let mut sys = recorded(&[("Office", "ipp://a/ipp/print")]);
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        r.inner
            .respond(&format!("{LPADMIN} -x"), Output::fail(1, "lpadmin: busy"));
        let out = run_with(&r, &mut sys, &[], &AtomicBool::new(false));
        assert!(
            out.iter().any(|i| i.item == PRINTERS_ITEM && !i.ok),
            "{out:?}"
        );
        assert!(sys.printers.contains_key("Office"));
    }

    /// 复审 I1：lpadmin 失败或超时也先记下（-E 已经建了半个队列）；下一轮看到这个同名队列（device 是 file:///dev/null）
    /// 照样是我们的、重试，而不是当成「本机已有的同名队列」。
    #[test]
    fn failed_lpadmin_is_retried_next_time() {
        let r = Rec::new();
        let mut sys = SysState::default();
        let flag = AtomicBool::new(false);
        r.inner.respond(
            &format!("{LPADMIN} -p"),
            Output::fail(1, "lpadmin: Unable to connect to printer"),
        );
        let out = run_with(&r, &mut sys, &[dev("Office", "ipp://a/ipp/print")], &flag);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].item, "printer:Office");
        assert!(!out[0].ok);
        assert_eq!(
            sys.printers,
            BTreeMap::from([("Office".to_string(), "ipp://a/ipp/print".to_string())]),
            "失败也记着"
        );
        assert!(
            r.with(&format!("{LPADMIN} -d")).is_empty(),
            "没有队列就不设默认：{:?}",
            r.lines()
        );
        lpstat(&r, &[("Office", "file:///dev/null")]);
        let out = run_with(&r, &mut sys, &[dev("Office", "ipp://a/ipp/print")], &flag);
        assert_eq!(out, vec![ok("printer:Office")]);
        assert_eq!(r.adds().len(), 2);
        // 半个队列在、清单里去掉了：删掉。
        lpstat(&r, &[("Office", "file:///dev/null")]);
        run_with(&r, &mut sys, &[], &flag);
        assert_eq!(
            r.with(&format!("{LPADMIN} -x")),
            vec![format!("{LPADMIN} -x Office")]
        );
        assert!(sys.printers.is_empty());
    }

    /// URI 变了而重新加失败：记录换成新 URI、留着，清单再去掉它时照样删得掉。
    #[test]
    fn failed_readd_keeps_queue_owned() {
        let r = Rec::new();
        let mut sys = recorded(&[("Office", "ipp://a/ipp/print")]);
        let flag = AtomicBool::new(false);
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        r.inner
            .respond(&format!("{LPADMIN} -p"), Output::fail(1, "timeout"));
        let out = run_with(&r, &mut sys, &[dev("Office", "ipp://b/ipp/print")], &flag);
        assert!(!out[0].ok);
        assert!(sys.printers.contains_key("Office"));
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        run_with(&r, &mut sys, &[], &flag);
        assert_eq!(
            r.with(&format!("{LPADMIN} -x")),
            vec![format!("{LPADMIN} -x Office")]
        );
    }

    /// 裁定：本机已有同名（不分大小写）而不是我们记下的队列，不动它，这一台回报失败、不记。
    #[test]
    fn existing_foreign_queue_is_not_touched() {
        let r = Rec::new();
        let mut sys = SysState::default();
        lpstat(&r, &[("office", "ipp://it/ipp/print")]);
        let out = run_with(
            &r,
            &mut sys,
            &[dev("Office", "ipp://a/ipp/print")],
            &AtomicBool::new(false),
        );
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok && out[0].item == "printer:Office", "{out:?}");
        assert!(
            r.with(LPADMIN).is_empty(),
            "不 lpadmin（-p、-d、-x 都没有）：{:?}",
            r.lines()
        );
        assert!(sys.printers.is_empty());
        // URI 恰好相同也一样：不收养。
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        let out = run_with(
            &r,
            &mut sys,
            &[dev("Office", "ipp://a/ipp/print")],
            &AtomicBool::new(false),
        );
        assert!(!out[0].ok);
        assert!(sys.printers.is_empty());
    }

    /// 整理之后相同（或只差大小写）的两台：后一台回报失败、不加。
    #[test]
    fn colliding_queue_names_keep_first() {
        let r = Rec::new();
        let mut sys = SysState::default();
        let out = run_with(
            &r,
            &mut sys,
            &[
                dev("A/B", "ipp://a/ipp/print"),
                dev("A#B", "ipp://b/ipp/print"),
                dev("office", "ipp://c/ipp/print"),
                dev("Office", "ipp://d/ipp/print"),
            ],
            &AtomicBool::new(false),
        );
        assert!(!out[0].ok && out[0].item == "printer:A#B", "{out:?}");
        assert!(out[0].detail.as_deref().unwrap().contains("A_B"));
        assert!(!out[1].ok && out[1].item == "printer:Office", "{out:?}");
        assert_eq!(
            r.adds(),
            vec![
                add_line("A/B", "ipp://a/ipp/print"),
                add_line("office", "ipp://c/ipp/print")
            ]
        );
    }

    #[test]
    fn first_printer_is_default() {
        let r = Rec::new();
        let mut sys = SysState::default();
        let flag = AtomicBool::new(false);
        let list = [dev("A", "ipp://a/ipp/print"), dev("B", "ipp://b/ipp/print")];
        run_with(&r, &mut sys, &list, &flag);
        assert_eq!(
            r.with(&format!("{LPADMIN} -d")),
            vec![format!("{LPADMIN} -d A")]
        );
        // 已经是默认：不再设。
        r.inner
            .respond(LPSTAT_D, Output::ok("system default destination: A\n"));
        lpstat(
            &r,
            &[("A", "ipp://a/ipp/print"), ("B", "ipp://b/ipp/print")],
        );
        run_with(&r, &mut sys, &list, &flag);
        assert_eq!(r.with(&format!("{LPADMIN} -d")).len(), 1, "{:?}", r.lines());
        // lpstat -d 读不了：照样设。
        r.inner.respond(LPSTAT_D, Output::fail(1, "lpstat: boom"));
        lpstat(
            &r,
            &[("A", "ipp://a/ipp/print"), ("B", "ipp://b/ipp/print")],
        );
        run_with(&r, &mut sys, &list, &flag);
        assert_eq!(r.with(&format!("{LPADMIN} -d")).len(), 2, "{:?}", r.lines());
    }

    /// 第一台的 lpadmin 返回后置位 superseded：第二台没有 lpadmin，之后也不设默认、不删。
    #[test]
    fn superseded_stops_between_printers() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut r = Rec::new();
        r.supersede = Some(flag.clone());
        let mut sys = recorded(&[("Old", "ipp://o/ipp/print")]);
        lpstat(&r, &[("Old", "ipp://o/ipp/print")]);
        run_with(
            &r,
            &mut sys,
            &[dev("A", "ipp://a/ipp/print"), dev("B", "ipp://b/ipp/print")],
            &flag,
        );
        assert_eq!(r.adds(), vec![add_line("A", "ipp://a/ipp/print")]);
        assert!(
            r.with(&format!("{LPADMIN} -d")).is_empty(),
            "{:?}",
            r.lines()
        );
        assert!(
            r.with(&format!("{LPADMIN} -x")).is_empty(),
            "{:?}",
            r.lines()
        );
        assert_eq!(
            sys.printers.keys().cloned().collect::<Vec<_>>(),
            vec!["A".to_string(), "Old".to_string()],
            "已经加上的照记，没删的也还记着"
        );
    }

    #[test]
    fn bad_printer_is_skipped_and_its_queue_kept() {
        let r = Rec::new();
        let mut sys = recorded(&[("Office", "ipp://a/ipp/print")]);
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        let out = run_with(
            &r,
            &mut sys,
            &[dev("Office", "file:///dev/null"), dev("", "ipp://x")],
            &AtomicBool::new(false),
        );
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|i| !i.ok));
        assert!(r.with(LPADMIN).is_empty(), "{:?}", r.lines());
        assert!(sys.printers.contains_key("Office"));
    }

    /// 复审 M3：lpstat -v 读不了（cupsd 起不来）：整步不动，每台回报未能确认，不 lpadmin、不删、不改记录。
    #[test]
    fn lpstat_failure_changes_nothing() {
        let r = Rec::new();
        let mut sys = recorded(&[
            ("Office", "ipp://a/ipp/print"),
            ("Gone", "ipp://g/ipp/print"),
        ]);
        let before = sys.clone();
        r.inner
            .respond(LPSTAT_V, Output::fail(1, "lpstat: Bad file descriptor"));
        let out = run_with(
            &r,
            &mut sys,
            &[
                dev("Office", "ipp://a/ipp/print"),
                dev("New", "ipp://n/ipp/print"),
            ],
            &AtomicBool::new(false),
        );
        assert_eq!(out.len(), 3, "{out:?}");
        assert_eq!(out[0].item, PRINTERS_ITEM);
        assert!(out.iter().all(|i| !i.ok));
        assert!(r.with(LPADMIN).is_empty(), "{:?}", r.lines());
        assert_eq!(sys, before);
    }

    /// 裁定 5：system-state.json 读不了时只回报一条、什么命令都不跑（不把每台都报成「本机已有的同名队列」）。
    #[test]
    fn state_load_failure_is_one_failure() {
        let r = Rec::new();
        let mut sys = SysState {
            load_failed: true,
            ..SysState::default()
        };
        lpstat(&r, &[("Office", "ipp://a/ipp/print")]);
        let out = run_with(
            &r,
            &mut sys,
            &[
                dev("Office", "ipp://a/ipp/print"),
                dev("B", "ipp://b/ipp/print"),
            ],
            &AtomicBool::new(false),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].item, PRINTERS_ITEM);
        assert!(r.lines().is_empty(), "{:?}", r.lines());
    }

    /// 记录里有、CUPS 里没了：不在清单里的记录作废（不 -x），还在清单里的重新加。
    #[test]
    fn missing_recorded_queue_is_pruned_or_readded() {
        let r = Rec::new();
        let mut sys = recorded(&[
            ("Office", "ipp://a/ipp/print"),
            ("Gone", "ipp://g/ipp/print"),
        ]);
        lpstat(&r, &[]);
        let out = run_with(
            &r,
            &mut sys,
            &[dev("Office", "ipp://a/ipp/print")],
            &AtomicBool::new(false),
        );
        assert_eq!(out, vec![ok("printer:Office")]);
        assert_eq!(r.adds(), vec![add_line("Office", "ipp://a/ipp/print")]);
        assert!(r.with(&format!("{LPADMIN} -x")).is_empty());
        assert_eq!(
            sys.printers.keys().cloned().collect::<Vec<_>>(),
            vec!["Office".to_string()]
        );
    }

    #[test]
    fn airscan_conf_lists_escl_devices() {
        let text = render_airscan(&[
            dev("ห้องสมุด", "http://10.0.0.6/eSCL"),
            dev("Lab \"2\" \\ #1;x", "https://s.lan:443/eSCL#a;b,c"),
        ]);
        assert_eq!(
            text,
            "# 由 mastersos-agent 按设置文件生成，本机改动会被覆盖\n[devices]\n\
             \"ห้องสมุด\" = \"http://10.0.0.6/eSCL\", eSCL\n\
             \"Lab \\\"2\\\" \\\\ #1;x\" = \"https://s.lan:443/eSCL#a;b,c\", eSCL\n"
        );
        // 写进 airscan.d（0644）；不合格与重复的回报并跳过；列表空了删掉文件。
        let root = tmp_root();
        let mut sys = SysState::default();
        let out = apply_scanners(
            root.path(),
            &mut sys,
            &[
                dev("S", "http://10.0.0.6/eSCL"),
                dev("S", "http://10.0.0.7/eSCL"),
                dev("Bad", "ipp://x"),
            ],
        );
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(out.contains(&ok("scanner:S")));
        let f = root.path().join(AIRSCAN_DIR).join(AIRSCAN_FILE);
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644);
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            render_airscan(&[dev("S", "http://10.0.0.6/eSCL")])
        );
        assert_eq!(apply_scanners(root.path(), &mut sys, &[]), vec![]);
        assert!(!f.exists());
        assert!(sys.scanners.is_empty());
        // 没有 airscan.d：不建、不报错。
        let root2 = tmp_root();
        assert_eq!(
            apply_scanners(root2.path(), &mut SysState::default(), &[]),
            vec![]
        );
        assert!(!root2.path().join(AIRSCAN_DIR).exists());
    }

    /// 裁定 6：上一轮写过的扫描仪这一轮改坏了：回报失败，原来那一行照旧留着。
    #[test]
    fn bad_scanner_keeps_its_old_line() {
        let root = tmp_root();
        let mut sys = SysState::default();
        let f = root.path().join(AIRSCAN_DIR).join(AIRSCAN_FILE);
        apply_scanners(
            root.path(),
            &mut sys,
            &[dev("A", "http://a/eSCL"), dev("B", "http://b/eSCL")],
        );
        let out = apply_scanners(
            root.path(),
            &mut sys,
            &[dev("A", "ipp://broken"), dev("B", "http://b2/eSCL")],
        );
        assert_eq!(out.len(), 2);
        assert!(!out[0].ok && out[0].item == "scanner:A");
        assert_eq!(out[1], ok("scanner:B"));
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            render_airscan(&[dev("A", "http://a/eSCL"), dev("B", "http://b2/eSCL")])
        );
        // 只剩改坏的那一项：文件只留它原来那一行，不删。
        let out = apply_scanners(root.path(), &mut sys, &[dev("A", "ipp://broken")]);
        assert!(!out[0].ok);
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            render_airscan(&[dev("A", "http://a/eSCL")])
        );
        // 从没写过的不合格项：没有可保留的行。
        let out = apply_scanners(root.path(), &mut sys, &[dev("C", "ipp://x")]);
        assert!(!out[0].ok);
        assert!(!f.exists());
    }

    #[test]
    fn printers_step_is_not_fast() {
        assert!(!printers_step().fast);
        assert!(printers_step().without_bundle.is_none());
        assert!(scanners_step().fast);
        let names: Vec<&str> = super::super::steps().iter().map(|s| s.name).collect();
        assert!(names.contains(&"printers") && names.contains(&"scanners"));
        assert!(super::super::WRITE_ROOTS.contains(&"/etc/sane.d/airscan.d"));
    }

    #[test]
    fn lpstat_without_destinations_is_empty() {
        let r = FakeRunner::new();
        r.respond(
            LPSTAT_V,
            Output::fail(1, "lpstat: No destinations added.\n"),
        );
        assert_eq!(lpstat_devices(&r).unwrap(), BTreeMap::new());
        r.respond(LPSTAT_V, Output::fail(1, "lpstat: Bad file descriptor\n"));
        assert!(lpstat_devices(&r).is_err());
        r.respond(
            LPSTAT_V,
            Output::ok("device for ห้อง_3: ipp://h/ipp/print\ndevice for B: ipp://b:631/x\n"),
        );
        assert_eq!(
            lpstat_devices(&r).unwrap(),
            BTreeMap::from([
                ("ห้อง_3".to_string(), "ipp://h/ipp/print".to_string()),
                ("B".to_string(), "ipp://b:631/x".to_string())
            ])
        );
    }
}

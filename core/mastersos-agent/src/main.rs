#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mastersos_agent::runner::RealRunner;
use mastersos_agent::system::{SysPaths, SystemApplier};
use mastersos_agent::AgentConfig;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "mastersos-agent", version)]
struct Cli {
    /// 状态目录（种子的副本、state.json、当前设置包都在这里；加密的根分区上）。
    #[arg(long, global = true, default_value = "/var/lib/mastersos")]
    state_dir: PathBuf,
    /// 种子分区的挂载点：只在状态目录里没有状态时读。
    #[arg(long, global = true, default_value = mastersos_agent::seedpart::SEED_PART_DIR)]
    seed_dir: PathBuf,
    /// DMI 信息目录（序列号、型号）。
    #[arg(long, global = true, default_value = "/sys/class/dmi/id")]
    dmi_dir: PathBuf,
    /// 系统版本从这里读。
    #[arg(long, global = true, default_value = "/etc/os-release")]
    os_release: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Resident: syncs settings at startup, on MQTT doorbells and on SIGUSR1, and applies them.
    Run,
    /// 拉取并应用一次后退出。
    Once,
    /// 开机在 GDM 之前：只跑快速步骤；还没有包时先试拉一次（合计不超过 45 秒）。
    ApplyLocal,
    /// 更新一次 Chrome sysext 后退出（mastersos-chrome.timer 驱动；有没有种子都跑）。失败时退出码 1。
    Chrome {
        /// 由定时器触发（mastersos-chrome.service 带上）：没设更新时段时，上一次查源不到 6 小时就不联网。
        /// IT 在 shell 里手动跑时不带它，照常查。
        #[arg(long)]
        scheduled: bool,
    },
}

/// 日志写到 stderr，交给 journald。
struct StderrLog;

impl log::Log for StderrLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::max_level()
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!("{} {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}

/// The log level from `MASTERSOS_LOG_LEVEL`: `debug` or `trace` (exactly), anything else is `info`. Nothing in the image sets it
/// today (the USB diagnostics switch that did was removed); kept for a debug drop-in and the planned remote `diag-verbose`.
fn level_from_env(v: Option<&str>) -> log::LevelFilter {
    match v {
        Some("debug") => log::LevelFilter::Debug,
        Some("trace") => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    }
}

fn env_level() -> log::LevelFilter {
    level_from_env(std::env::var("MASTERSOS_LOG_LEVEL").ok().as_deref())
}

/// PAM 调用的子命令（`pam-check`、`pam-session`）、临时账号的清理（`ephemeral-cleanup`、`guest-cleanup`）与锁定会话的
/// `kiosk` 在设日志、解析参数、
/// 建 tokio 运行时**之前**按 `argv[1]` 分出去：它们要在 10 ms 级完成、不能往 stderr 打日志、
/// 出错时按各自规定的方向失败而不是被 clap 的退出码 2 带偏。其余子命令照旧。
fn main() -> ExitCode {
    let sub = std::env::args_os().nth(1);
    if sub.as_deref() == Some(OsStr::new("pam-check")) {
        return mastersos_agent::system::login::pam_check_main(std::env::args_os().skip(2));
    }
    // pam-session 不收参数（PAM 以固定的 argv 调它，参数照样不看）；guest-cleanup、ephemeral-cleanup 同样是同步的，不要运行时
    if sub.as_deref() == Some(OsStr::new("pam-session")) {
        return mastersos_agent::system::guest::pam_session_main();
    }
    if sub.as_deref() == Some(OsStr::new("guest-cleanup")) {
        return mastersos_agent::system::guest::guest_cleanup_main();
    }
    // 临时账号的清理（`mastersos-ephemeral-cleanup@<user>.service`）：与 guest-cleanup 同一条路，账号名是第二个参数
    if sub.as_deref() == Some(OsStr::new("ephemeral-cleanup")) {
        return mastersos_agent::system::ephemeral::cleanup_main(
            std::env::args_os().nth(2).as_deref(),
        );
    }
    // 锁定会话里的 `mastersos-kiosk run / exit-host / enter`（计划 9 Task 6）：以会话的用户身份跑，同步；exit-host 的
    // stdout 是 native messaging 的通道，不能有别的输出
    if sub.as_deref() == Some(OsStr::new("kiosk")) {
        return mastersos_agent::kiosk_session::main(std::env::args_os().skip(2));
    }
    // The sign-in handoff (docs/specs/2026-11-05-browser-signin-handoff-design.md): the card unit's ExecStartPre/ExecStopPost
    // as root, and the user unit as the user; synchronous, quick, their own exit codes
    if sub.as_deref() == Some(OsStr::new("signin-handoff")) {
        return mastersos_agent::signin_handoff::handoff_main(std::env::args_os().skip(2));
    }
    if sub.as_deref() == Some(OsStr::new("signin-import")) {
        return mastersos_agent::signin_handoff::import_main();
    }
    // Get help (plan 2026-11-05 Task 5): `support host` behind mastersos-support.socket (root; its log lines go to stderr
    // and the journal) and `support native-host` for the kiosk extension (as the kiosk account; stdout is the message
    // channel). Synchronous entry points with their own runtime and exit codes
    if sub.as_deref() == Some(OsStr::new("support")) {
        let _ = log::set_logger(&StderrLog).map(|()| log::set_max_level(env_level()));
        return mastersos_agent::support::main(std::env::args_os().skip(2));
    }
    // systemd-sysext.service 合并或刷新之后（镜像里的 drop-in）：按记下的模式重挂浏览器模式的桩，同步的
    if sub.as_deref() == Some(OsStr::new("exec-block")) {
        return mastersos_agent::system::exec_block::sync_main();
    }
    // bootloader-update 换 shim 之前：新 shim 能不能链到这台的活动 db（4b Task 22）；同步的，退出码 0 / 1 / 2 有约定
    if sub.as_deref() == Some(OsStr::new("shim-check")) {
        return mastersos_agent::secureboot::shim_check_main(std::env::args_os().skip(2));
    }
    // bootloader-update, after shim-check and before any write: add the new shim's SbatLevel to the pcrlock policy
    // (plan 5 Task 8); synchronous, exit 0 = prepared or not needed, 1 = failed (the shim is replaced anyway)
    if sub.as_deref() == Some(OsStr::new("shim-prepare")) {
        // its log lines (e.g. removing the PIN credential failed) go to stderr, which bootloader-update captures
        let _ = log::set_logger(&StderrLog).map(|()| log::set_max_level(env_level()));
        return mastersos_agent::shim_predict::shim_prepare_main(std::env::args_os().skip(2));
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: failed to build the tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    // 建好运行时就先装上 SIGUSR1 的处理（复审 M8）：登录（pam-session）与网络连上（NM dispatcher）随时会发 SIGUSR1，
    // 默认动作是终止进程；装上之后、`run` 自己的接收端起来之前收到的只是被吞掉——登录队列在盘上，`run` 启动时会取走。
    // tokio 装的处理在进程里一直有效（丢掉这个接收端也不卸），剩下的窗口只有 exec 到这里的几毫秒
    let _usr1 = rt.block_on(async { signal(SignalKind::user_defined1()).ok() });
    let r = rt.block_on(agent_main());
    // 有意对所有阻塞线程都只等 5 秒（复审 M7）：Flatpak 装到一半（限时 15 分钟）、超过 SHUTDOWN_APPLY_GRACE 还没停下的
    // 应用任务、LuksJob 的 systemd-cryptenroll 都一样不等。它们的命令在自己的进程组里；systemctl stop 时 systemd 收掉
    // 整个 cgroup，自己退出（出错返回）时由 Restart=on-failure 重新拉起、下一轮重做（Flatpak 靠 pending 补记）
    rt.shutdown_timeout(std::time::Duration::from_secs(5));
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

async fn agent_main() -> anyhow::Result<()> {
    let _ = log::set_logger(&StderrLog).map(|()| log::set_max_level(env_level()));
    let cli = Cli::parse();
    let cfg = AgentConfig {
        state_dir: cli.state_dir,
        seed_dir: cli.seed_dir,
        dmi_dir: cli.dmi_dir,
        os_release: cli.os_release,
        ..AgentConfig::default()
    };
    let paths = SysPaths {
        state_dir: cfg.state_dir.clone(),
        ..SysPaths::default()
    };
    let applier = Arc::new(SystemApplier::new(paths.clone(), Arc::new(RealRunner)));
    match cli.cmd {
        Cmd::Once => mastersos_agent::once(cfg, applier).await,
        Cmd::ApplyLocal => {
            // 先按盘上的模式挂好浏览器模式的桩，再等网络、拉包（复审 T13 发现 4：后面失败或超时，GDM 之前照样挂着）
            let p = paths.clone();
            match tokio::task::spawn_blocking(move || {
                mastersos_agent::system::exec_block::sync(&p, &RealRunner)
            })
            .await
            {
                Ok(Err(e)) => log::warn!("exec-block: {e:#}"),
                Err(e) => log::warn!("exec-block: {e}"),
                Ok(Ok(_)) => {}
            }
            mastersos_agent::apply_local(cfg, applier).await
        }
        Cmd::Chrome { scheduled } => {
            let job = mastersos_agent::chrome_sysext::ChromeJob::new(Arc::new(RealRunner))
                .scheduled(scheduled);
            if !job.update_once().await.ok {
                std::process::exit(1);
            }
            Ok(())
        }
        Cmd::Run => {
            let shutdown = CancellationToken::new();
            let mut term = signal(SignalKind::terminate())?;
            let mut int = signal(SignalKind::interrupt())?;
            let s = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
                s.cancel();
            });
            // 后台任务：恢复密钥托管与 pcrlock（Task 8）；Chrome（Task 9）只回报——更新由 mastersos-chrome.timer 跑
            // `mastersos-agent chrome`，有没有种子都跑，这里不再更新，免得两个更新者；Flatpak 的装卸与每日更新（4b Task 16）；
            // 共用机磁盘紧张时清 SSO 用户的家目录（4b Task 19）
            let jobs: Vec<Arc<dyn mastersos_agent::jobs::Job>> = vec![
                Arc::new(mastersos_agent::luks::LuksJob::new(Arc::new(RealRunner))),
                Arc::new(mastersos_agent::chrome_sysext::ChromeStatus::new(
                    mastersos_agent::chrome_sysext::WORK_DIR.into(),
                )),
                // Device status for the login screen and the locked session (offline, no settings, no browser yet).
                Arc::new(mastersos_agent::status::StatusJob::new(
                    mastersos_agent::chrome_sysext::ChromeStatus::new(
                        mastersos_agent::chrome_sysext::WORK_DIR.into(),
                    ),
                    mastersos_agent::system::desktop::CHROME_BIN.into(),
                )),
                Arc::new(mastersos_agent::system::flatpak::FlatpakJob::new(Arc::new(
                    RealRunner,
                ))),
                Arc::new(mastersos_agent::system::flatpak::FlatpakUpdateJob::new(
                    Arc::new(RealRunner),
                )),
                Arc::new(mastersos_agent::homes::HomeCleanupJob::new(Arc::new(
                    RealRunner,
                ))),
            ];
            mastersos_agent::run(cfg, applier, jobs, shutdown).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::level_from_env;
    use log::LevelFilter;

    #[test]
    fn level_from_env_values() {
        assert_eq!(level_from_env(None), LevelFilter::Info);
        assert_eq!(level_from_env(Some("")), LevelFilter::Info);
        assert_eq!(level_from_env(Some("debug")), LevelFilter::Debug);
        assert_eq!(level_from_env(Some("trace")), LevelFilter::Trace);
        assert_eq!(level_from_env(Some("verbose")), LevelFilter::Info);
        assert_eq!(level_from_env(Some("DEBUG")), LevelFilter::Info);
    }
}

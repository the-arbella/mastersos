//! agent 的路径与退避参数；字段都能在测试里指到临时目录。

use std::path::PathBuf;
use std::time::Duration;

/// The cap of the backoff after a failed fetch (spec §6.6), and the status report interval.
pub const FALLBACK_SECS: u64 = 15 * 60;
/// 这么多天没有拉取成功、或没有签名证据说明设置是最新的，回报里标为过期（spec §6.6、§4.2）。
/// 与服务端算概览里的设置有效期用同一个数。
pub use mastersos_bundle::STALE_WARN_DAYS;
/// The signed heartbeat's own timer: one check every this many seconds.
pub const HEARTBEAT_POLL_SECS: u64 = 3600;
/// `apply` 脚本没写 `timeout_secs` 时的超时（spec §5.5）。
pub const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub state_dir: PathBuf,
    /// 种子分区的挂载点（Ruling 10）：只在 `state_dir` 里没有状态时读，之后只写缓存。
    pub seed_dir: PathBuf,
    /// 往种子分区写之前要求它是挂载点（生产为 true；测试的临时目录不是挂载点）。
    pub seed_requires_mount: bool,
    pub dmi_dir: PathBuf,
    pub os_release: PathBuf,
    /// 系统根；测试里指向临时目录，生产为 "/"。
    pub root: PathBuf,
    /// The first wait after a failed fetch; doubled per consecutive failure up to `backoff_max`,
    /// each wait multiplied by a factor in [0.8, 1.2] from `jitter` (ruling 59, [`crate::backoff`]).
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    /// The random source of the backoff's factor; tests inject a fixed one.
    pub jitter: crate::backoff::Jitter,
    /// 包被拒收（验签失败、版本回退……）后，下一次拉取前等多久。
    pub reject_wait: Duration,
    /// 没有别的事件时，至少隔这么久回报一次状态。
    pub report_every: Duration,
    /// The heartbeat timer: a check this long after the previous one; a settings sync also checks
    /// when the last check (by the wall clock) is at least this old.
    pub heartbeat_every: Duration,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            state_dir: "/var/lib/mastersos".into(),
            seed_dir: crate::seedpart::SEED_PART_DIR.into(),
            seed_requires_mount: true,
            dmi_dir: "/sys/class/dmi/id".into(),
            os_release: "/etc/os-release".into(),
            root: "/".into(),
            backoff_start: Duration::from_secs(5),
            backoff_max: Duration::from_secs(FALLBACK_SECS),
            jitter: crate::backoff::Jitter::system(),
            reject_wait: Duration::from_secs(60),
            report_every: Duration::from_secs(FALLBACK_SECS),
            heartbeat_every: Duration::from_secs(HEARTBEAT_POLL_SECS),
        }
    }
}

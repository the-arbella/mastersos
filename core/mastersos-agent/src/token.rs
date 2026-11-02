//! 拉取令牌（`fetch_token`）从哪来、换领到的新令牌存哪（计划 4b Task 2，Ruling 20）。
//!
//! 来源按优先级：`/var/lib/mastersos/fetch-token` → 种子分区的 `fetch-token` → `seed.toml` 的
//! `fetch_token`。换领到的新令牌两处都写（0600）：种子分区那份让恢复出厂之后仍用新令牌。
//! 令牌本身从不进日志、错误信息与回报。

use std::path::Path;
use std::time::{Duration, Instant};

use mastersos_bundle::Seed;

/// 令牌文件名（`state_dir` 与种子分区里都叫这个）。
pub const TOKEN_FILE: &str = "fetch-token";
/// 令牌文件的大小上限。
pub const MAX_TOKEN_BYTES: usize = 256;
/// 同一台机器最多每这么久换领一次。
pub const RENEW_EVERY: Duration = Duration::from_secs(3600);

/// 种子分区没写成（没挂上或写不进）：新令牌只在 `state_dir` 里，恢复出厂之后会退回旧令牌。
#[derive(Debug)]
pub struct SeedNotWritten(pub String);

impl std::fmt::Display for SeedNotWritten {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SeedNotWritten {}

/// 令牌合格：不空、不超过 [`MAX_TOKEN_BYTES`] 字节、只有可打印的 ASCII（没有空白与控制字符）。
/// 与服务端加载配置时对 `fetch_token` 的要求（`mastersos_server::config::is_fetch_token_format`）相同。
pub fn is_valid(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|b| b.is_ascii_graphic())
}

/// 读一个目录里的令牌文件：不在、读不了、不合格都是 None（后两种记一行警告，不写内容）。
fn read_file(dir: &Path, what: &str) -> Option<String> {
    let fd = match crate::safefs::open_abs_dir(dir, false) {
        Ok(fd) => fd,
        Err(e) if crate::apply::is_not_found(&e) => return None,
        Err(e) => {
            log::warn!("打开{what}失败，不读其中的 {TOKEN_FILE}：{e:#}");
            return None;
        }
    };
    let bytes = match crate::safefs::read_at(&fd, TOKEN_FILE) {
        Ok(Some(b)) => b,
        Ok(None) => return None,
        Err(e) => {
            log::warn!("读取{what}的 {TOKEN_FILE} 失败：{e:#}");
            return None;
        }
    };
    let ok = bytes.len() <= MAX_TOKEN_BYTES;
    match String::from_utf8(bytes) {
        Ok(t) if ok && is_valid(&t) => Some(t),
        _ => {
            log::warn!(
                "{what}的 {TOKEN_FILE} 不合格（空、超过 {MAX_TOKEN_BYTES} 字节或含不可打印字符），当作没有"
            );
            None
        }
    }
}

/// 全部来源，按优先级：state 里的、种子分区里的、`seed.toml` 的（不合格的已去掉）。
pub fn sources(state_dir: &Path, seed_dir: &Path, seed: &Seed) -> Vec<String> {
    [
        read_file(state_dir, "状态目录"),
        read_file(seed_dir, "种子分区"),
        seed.fetch_token.clone().filter(|t| {
            let ok = is_valid(t);
            if !ok {
                log::warn!("seed.toml 的 fetch_token 不合格（空、超过 {MAX_TOKEN_BYTES} 字节或含不可打印字符），当作没有");
            }
            ok
        }),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// 这台机器眼下该用的令牌：state 里的 > 种子分区里的 > `seed.toml` 的。
/// 文件为空、全空白、超过 256 字节或含不可打印字符就当作没有（记一行警告，不写内容）。
pub fn effective(state_dir: &Path, seed_dir: &Path, seed: &Seed) -> Option<String> {
    sources(state_dir, seed_dir, seed).into_iter().next()
}

/// 换领到的新令牌写进 `state_dir` 与种子分区（都经 `safefs`、0600）。种子分区必须是挂载点。
///
/// - 令牌不合格、写 `state_dir` 失败：返回错误，种子分区不动。
/// - 种子分区没挂上（不是挂载点：写下去会落在根分区上、恢复出厂就丢）或写不进：只写了 state，
///   返回 [`SeedNotWritten`]（调用方回报 `fetch-token` 成功，`detail` 说明恢复出厂会退回旧令牌）。
pub fn save(state_dir: &Path, seed_dir: &Path, token: &str) -> anyhow::Result<()> {
    save_with(state_dir, seed_dir, token, true)
}

/// 同 [`save`]；`require_mount` 为 false 时不要求种子分区是挂载点（测试的临时目录，
/// 对应 `AgentConfig::seed_requires_mount`）。
pub fn save_with(
    state_dir: &Path,
    seed_dir: &Path,
    token: &str,
    require_mount: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;
    if !is_valid(token) {
        anyhow::bail!(
            "服务端给的新令牌不合格（空、超过 {MAX_TOKEN_BYTES} 字节或含不可打印字符），不保存"
        );
    }
    let state = crate::safefs::open_abs_dir(state_dir, false).context("打开状态目录")?;
    crate::safefs::write_at(&state, TOKEN_FILE, token.as_bytes(), 0o600)
        .with_context(|| format!("写状态目录的 {TOKEN_FILE}"))?;
    let unmounted = || {
        anyhow::Error::new(SeedNotWritten(
            "种子分区没挂上，恢复出厂之后会退回旧令牌".into(),
        ))
    };
    if require_mount {
        match crate::seedpart::is_mount_point(seed_dir) {
            Ok(true) => {}
            Ok(false) => return Err(unmounted()),
            Err(e) => {
                log::warn!("检查种子分区失败：{e:#}");
                return Err(unmounted());
            }
        }
    }
    let written = crate::safefs::open_abs_dir(seed_dir, false).and_then(|fd| {
        crate::safefs::write_at(&fd, TOKEN_FILE, token.as_bytes(), 0o600).map(|_| ())
    });
    if let Err(e) = written {
        log::warn!("写种子分区的 {TOKEN_FILE} 失败：{e:#}");
        return Err(anyhow::Error::new(SeedNotWritten(
            "种子分区写不进，恢复出厂之后会退回旧令牌".into(),
        )));
    }
    Ok(())
}

/// 该不该换领：见到了旧令牌标记、有托管凭据、距上次换领满一小时（或从没换过）。纯函数，时间由调用方给。
pub fn renew_due(
    stale: bool,
    has_identity: bool,
    last_renew: Option<Instant>,
    now: Instant,
) -> bool {
    stale
        && has_identity
        && last_renew.is_none_or(|t| {
            now.checked_duration_since(t)
                .is_some_and(|d| d >= RENEW_EVERY)
        })
}

#[cfg(test)]
mod tests;

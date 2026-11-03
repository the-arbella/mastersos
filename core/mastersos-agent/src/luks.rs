//! 数据分区（根分区的 LUKS2）：登记恢复密钥 → 托管到服务端并得到确认 → 才把 TPM 槽换成
//! 「签名的 PCR 11 + pcrlock（只锁 PCR 7）」（Ruling 7；`image/docs/keys.md`）。
//!
//! 后台任务 [`LuksJob`] 每小时（以及网络连上时）按 [`next_step`] 一步步把分区推到期望的状态：
//!
//! 1. **登记恢复密钥**：`systemd-cryptenroll --recovery-key`。密钥只出现在命令的 stdout 里（经管道
//!    读进内存，不落 /tmp），先用 `cryptsetup open --test-passphrase` 经 stdin 核对它真能解开分区，
//!    **再**写进加密根分区上 0600 的 `escrow-pending.json`，然后才去托管：服务器暂时连不上时下一轮
//!    （或 agent 重启后）拿同一把重试，不会再登记一把新的、把服务端没收到的留在盘上。
//! 2. **托管**：`POST /v1/escrow`。成功（204）才在 `luks-state.json` 记下这个分区已托管，删掉待托管文件。
//!    Sealed only (plan 6 design §6.2, rulings 26, 27): nothing is enrolled or sent before the
//!    first accepted bundle names `[school].escrow_recipients` ([`escrow_mode`]); the key is
//!    sealed with age to every recipient once, the armor kept in `escrow-pending.json`
//!    ([`Pending::sealed`]) and resent unchanged until the server takes it. The plaintext key
//!    never leaves the machine. `escrow-done.json` ([`EscrowDone`]) records the recipients'
//!    fingerprint and the partition, not the server address: a new address of the same cloud
//!    does not escrow again. When the bundle's recipients change ([`redo`]) a new recovery key
//!    is enrolled (unlocking with the held one), escrowed sealed to the new recipients, and only
//!    then the old slot is wiped and the new key held ([`Need::Rotate`]). A 4b lab machine
//!    escrowed without a held key cannot rotate (`luks:recovery` reports the missing local key
//!    every round, ahead of pcrlock): it needs a factory reset.
//!    403（凭据不符）、429（超上限）与连不上一样：回报 `luks:escrow` 失败（带状态码与服务端的说明），
//!    不往下走，下一轮再试。种子的 `server_url` 不是 `https://` 时（lab 镜像与本机回环除外）恢复密钥与托管凭据
//!    一个字节也不发：连第 1 步都不做，已有的待托管密钥留着，同样回报 `luks:escrow` 失败（「托管被拒（本机）」）。
//! 3. **补 pcrlock**：只有托管确认之后。用 agent 自己的 PIN（`/var/lib/mastersos/pcrlock-pin`，0600）
//!    重建 pcrlock 策略（`remove-policy` → 经凭据目录 `make-policy --pcr=7 --recovery-pin=query`），
//!    再 `systemd-cryptenroll` 换成两者同时满足的 TPM 槽、去掉首次开机只绑 PCR 11 的槽。
//!
//! 之后每一轮：`systemd-pcrlock-make-policy` 失败了（db/dbx 变过、shim 更新改了 SbatLevel，这次开机
//! 是用恢复密钥进来的）就用同一个 PIN 改写策略，下次开机恢复无感。
//!
//! 第 3 步与 PIN 改写都只在本轮 `bootctl status` 说 Secure Boot 开着时做：否则会把「Secure Boot 关着」
//! 的 PCR 7 授权进策略，正是 pcrlock 要拦的攻击（Ruling 7）。两个状态文件读不出（不是不存在）时整轮
//! 不动分区。换恢复密钥一律是「先登记新的 → 托管成功 → 再按编号去掉旧的（用新的那把经 stdin 解锁）」，
//! 不论分区绑没绑 pcrlock，任何时刻服务端都有一把能用的。不属于任何 token 的口令槽（IT 手工
//! `luksAddKey` 的口令、换 TPM 槽半路断电留下的），在托管与 pcrlock 都好了之后去掉，在那之前 `luks:tpm` 报失败。
//!
//! 每一步都按「现在的状态」（`cryptsetup luksDump` 与两个状态文件）决定，被打断就从头判断。
//! 恢复密钥只经 stdin 与 0600 文件传给外部命令，不进命令行、日志、错误信息与回报；
//! 所有 `systemd-cryptenroll` 都经 [`run_ok_redacted`]（失败时它可能把密钥打在 stderr 上）。
//!
//! TPM 2.0 是前提（Ruling 17）：安装器拒装没有可用 TPM 的机器，数据分区一定有 TPM2 槽。分区没有 TPM2 槽
//! （不是按现在的安装器装的）时只回报 `luks:tpm` 失败、请重装，什么都不动。
//!
//! 状态文件 `<var_dir>/luks-state.json` 只由本任务读写，不放进 `SysState`：`SystemApplier` 每次应用
//! 整份读写 `SysState`，两边并发会丢掉对方的更新；丢了 `escrowed_luks_uuid` 就会重新登记、抹掉已托管的槽。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use mastersos_bundle::{is_luks_uuid, is_recovery_key, EscrowRequest, ItemResult};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fetch::escrow_transport_ok;
use crate::jobs::{CurrentGroup, Job, JobCtx};
use crate::runner::{run_ok, run_ok_redacted, Cmd, Output, Runner};
use crate::safefs;

/// 启动盘上的根分区（LUKS）。systemd ≥ 254 为 gpt-auto 的根分区建这个链接，只指向启动盘上的那一个；
/// 不按分区标签找（别的盘、U 盘可以带同名标签）。
pub const ROOT_LUKS_DEV: &str = "/dev/gpt-auto-root-luks";
/// 镜像里签 PCR 11 策略的公钥（与 UKI 的 `.pcrpkey` 相同）。
pub const TPM2_PUBKEY: &str = "/usr/lib/systemd/tpm2-pcr-public-key.pem";
/// 构建时写下的镜像 profile（`lab` / `release`），在签名的 `/usr` 里。
pub const IMAGE_PROFILE: &str = "/usr/lib/mastersos/profile";
/// `systemd-pcrlock make-policy` 写下的策略。
pub const PCRLOCK_POLICY: &str = "/var/lib/systemd/pcrlock.json";
/// `systemd-pcrlock` 不在 PATH 里。
pub const PCRLOCK_BIN: &str = "/usr/lib/systemd/systemd-pcrlock";
/// 镜像里生成 pcrlock 策略的单元（drop-in 把它限成 `--location=770 --pcr=7`）。
pub const PCRLOCK_UNIT: &str = "systemd-pcrlock-make-policy";
/// `make-policy` 的参数，与镜像里那个单元的 drop-in 一致（`50-mastersos.conf`）：它每次开机按同样的参数
/// 预测，结果相同就跳过、不动我们用 PIN 建的策略。
const MAKE_POLICY_ARGS: &[&str] = &["make-policy", "--location=770", "--pcr=7"];

/// `state_dir` 里的 pcrlock PIN（hex 文本，0600）。PIN 加上能碰到机器等于恢复密钥（docs/keys.md）。
pub const PCRLOCK_PIN: &str = "pcrlock-pin";
/// `var_dir` 里的待托管文件（0600）：已登记、还没托管成功的恢复密钥。
pub const PENDING_FILE: &str = "escrow-pending.json";
/// `var_dir` 里本任务的状态（0600）。
pub const LUKS_STATE_FILE: &str = "luks-state.json";
/// `var_dir` 里最近一次托管成功的记录（0600，[`EscrowDone`]）。
pub const ESCROW_DONE_FILE: &str = "escrow-done.json";

/// [`EscrowMode::Wait`] before any bundle was accepted (ruling 27).
pub const WAIT_FIRST_BUNDLE: &str = "waiting for the first bundle";
/// [`EscrowMode::Wait`] while the accepted bundle names no `escrow_recipients`.
pub const WAIT_RECIPIENTS: &str = "waiting for escrow recipients";
/// [`EscrowMode::Wait`] when the accepted bundle's recipients do not hold up on this side.
pub const WAIT_BAD_RECIPIENTS: &str =
    "the bundle's escrow recipients are invalid (not 1 to 8 distinct age X25519 recipients); \
waiting for escrow recipients";
/// `var_dir` 里首次开机 / 恢复出厂时 initrd 放下的临时钥匙（32 字节，0600）。agent 用它（不靠 TPM）
/// 登记恢复密钥、换 TPM 槽，托管与 pcrlock 都好了之后去掉这个钥匙槽与这个文件（4b Task 4）。
pub const BOOTSTRAP_KEY_FILE: &str = "luks-bootstrap-key";
/// `var_dir` 里 agent 自己保管的那把恢复密钥（0600）：托管成功后写下，之后动 LUKS（换 TPM 槽、去旧槽、
/// 去临时钥匙槽）都用它解锁——数据盘离开 initrd 后 TPM 不再放行（spec §6.12 (a)）。
pub const HELD_KEY_FILE: &str = "luks-recovery-key.json";
/// 传 PIN 的凭据目录（相对系统根；`/run` 是 tmpfs），里面的文件名是 systemd 规定的凭据名。
const CRED_DIR: &str = "run/mastersos-agent/pcrlock-cred";
const CRED_NAME: &str = "pcrlock.recovery-pin";

/// luksDump JSON 里 TPM2 token 的字面 PCR 字段（拆开写：`check-tree.sh` 第 2 条查的就是这个词后面跟的值）。
const LITERAL_PCRS_KEY: &str = concat!("tpm2", "-pcrs");

const NO_SB_BIND: &str = "Secure Boot is off: not binding pcrlock (a policy built from the current PCR 7 would authorize \"Secure Boot off\", \
and with Secure Boot off an edited kernel command line could unlock the data partition through the TPM); \
the data partition is protected only by the signed PCR 11 for now, and pcrlock is added once Secure Boot is on";
/// 分区没有 TPM2 槽时 `luks:tpm` 的说明；另三项用 [`NO_TPM_SLOT_SHORT`]。
const NO_TPM_SLOT: &str = "数据分区没有 TPM2 槽：这台不是按现在的安装器装的（没有 TPM 已不再支持），请重装 / The data partition has no TPM2 slot; reinstall";
const NO_TPM_SLOT_SHORT: &str = "数据分区没有 TPM2 槽，请重装 / No TPM2 slot; reinstall";
const NO_SB_REPAIR: &str =
    "Secure Boot is off: not rewriting the pcrlock policy (it would authorize \"Secure Boot off\"); \
every boot needs the recovery key until Secure Boot is on";
/// 本机没有能解开数据分区的钥匙：首次开机的临时钥匙丢了，或这台在这项修正之前装好。用户态不再用 TPM 解锁。
const NO_LOCAL_KEY: &str = "本机没有能解开数据分区的钥匙（首次开机的临时钥匙丢了，或这台在这项修正之前装好）；\
用户态不再用 TPM 解锁，请恢复出厂或重装 / No local key to unlock the data partition; factory reset or reinstall";
/// TPM 槽绑的不是这个镜像的 PCR 公钥（换过签名钥匙，slot 绑着退役的那把）：这次开机多半用了恢复密钥。
const WRONG_PUBKEY: &str =
    "the TPM slot is bound to a different PCR public key (the signing key was rotated); this boot most likely used the recovery key; the slot is replaced once escrow succeeds";
/// 已托管、但本机没有 HeldKey（这项修正之前托管的）：`luks:escrow` 的 detail 后面接这句。
const NO_HELD_KEY: &str =
    "; no recovery key held on this device, so the next PCR key rotation needs a factory reset";
/// 多余的槽只有首次开机的临时钥匙那一个（本机还留着那把钥匙文件）：无害，托管与 pcrlock 都好了之后去掉。
const BOOTSTRAP_SLOT_LEFT: &str = "the first-boot temporary key slot is still present; it is removed once escrow and pcrlock are done";

/// 用经 stdin 送进来的钥匙解锁（`cryptsetup` 的 `--key-file=-` 在 cryptenroll 里写作 /dev/stdin）。
const KEY_STDIN_UNLOCK: &str = "--unlock-key-file=/dev/stdin";
/// A well-formed recovery key that unlocks nothing: sealed once before enrolling, to know that
/// sealing works before a slot is added.
const PROBE_KEY: &str = "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc";
/// 盘上恢复槽的上限：到了就不再登记（连续登记失败攒下的孤儿不会占满 32 个 keyslot）。
const MAX_RECOVERY_SLOTS: usize = 4;

/// 托管失败、等待重试的间隔就是任务的间隔：每小时一次（429 时不能高频重发）。
const EVERY: Duration = Duration::from_secs(3600);
/// 一轮里最多走这么多步（正常最多四步：登记、托管、补 pcrlock，再判断一次）。
const MAX_STEPS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuksInfo {
    pub uuid: String,
    pub tpm2: Option<Tpm2Token>,
    pub has_recovery: bool,
    /// `systemd-recovery` token 引用的 keyslot。
    pub recovery_slots: Vec<u32>,
    /// 有任何一个 TPM2 token 带 pcrlock（`tpm2` 只给出最差的那个）。
    pub any_pcrlock: bool,
    /// 不属于任何 token 的 keyslot（口令槽）。我们的分区不该有：IT 手工 `luksAddKey` 的口令、
    /// 换 TPM 槽的 cryptenroll 半路断电，都会留下一个。
    pub stray_slots: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2Token {
    /// 签名策略绑的 PCR（`tpm2_pubkey_pcrs`）。
    pub pubkey_pcrs: Vec<u32>,
    /// `tpm2_pcrlock`。
    pub pcrlock: bool,
    /// 字面绑定的 PCR；我们的分区上永远是空的（Global Constraints）。
    pub literal_pcrs: Vec<u32>,
    /// luksDump 的 `tpm2_pubkey`（base64 的 PEM 文本）；没有就是 None。
    pub pubkey: Option<String>,
    /// `pubkey` 等于这个镜像的 PCR 公钥（`/usr/lib/systemd/tpm2-pcr-public-key.pem`）。换过签名钥匙之后，
    /// 旧机器的 TPM 槽绑的是退役的那把，这里为假——算「要补」，agent 用 HeldKey 换成这个镜像的新钥匙。
    pub pubkey_is_image: bool,
}

impl Tpm2Token {
    /// 期望的样子：签名 PCR 11 + pcrlock、字面 PCR 为空，且绑的是这个镜像的 PCR 公钥。
    pub fn sealed(&self) -> bool {
        self.pubkey_pcrs == [11]
            && self.pcrlock
            && self.literal_pcrs.is_empty()
            && self.pubkey_is_image
    }
}

fn pcr_list(v: Option<&Value>) -> Result<Vec<u32>> {
    let Some(v) = v else { return Ok(vec![]) };
    v.as_array()
        .ok_or_else(|| anyhow!("the PCR list is not an array"))?
        .iter()
        .map(|p| {
            p.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| anyhow!("a PCR is not an integer"))
        })
        .collect()
}

/// 解析 `cryptsetup luksDump --dump-json-metadata` 的输出（token 类型 `systemd-tpm2` 与
/// `systemd-recovery`）。JSON 元数据里没有 UUID，由调用方用 `cryptsetup luksUUID` 取来传入
/// （小写的 8-4-4-4-12，否则报错）。
///
/// 有不止一个 TPM2 token 时取「最不像期望状态」的那个：只要有一个不是签名 PCR 11 + pcrlock（且绑的是
/// 这个镜像的公钥），就要补（补的那一步 `--wipe-slot=tpm2` 会把它们全换掉）。
///
/// `image_pubkey`：这个镜像的 PCR 公钥，base64 的 PEM 文本（与 luksDump 的 `tpm2_pubkey` 同一种编码，
/// VM 实测，见 `lab/results/2026-10-15-4b/t4-initrd-only.txt` Step 1.3）。token 的 `tpm2_pubkey` 等于它
/// 才算 `pubkey_is_image`。None（读不到镜像的公钥）时一律当作不是本镜像的（保守：会走换槽）。
pub fn parse_luks_dump(json: &str, uuid: &str, image_pubkey: Option<&str>) -> Result<LuksInfo> {
    let uuid = uuid.trim().to_ascii_lowercase();
    if !is_luks_uuid(&uuid) {
        bail!("malformed LUKS UUID");
    }
    let v: Value = serde_json::from_str(json).context("parsing the luksDump JSON failed")?;
    let tokens = v
        .get("tokens")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the luksDump JSON has no tokens"))?;
    let keyslots = v
        .get("keyslots")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the luksDump JSON has no keyslots"))?;
    let mut tpm2: Vec<Tpm2Token> = vec![];
    let mut has_recovery = false;
    let mut recovery_slots: Vec<u32> = vec![];
    let mut referenced: Vec<u32> = vec![];
    for t in tokens.values() {
        let slots = slot_list(t.get("keyslots")).context("keyslots of a token")?;
        referenced.extend(&slots);
        if t.get("type").and_then(Value::as_str) == Some("systemd-recovery") {
            recovery_slots.extend(&slots);
        }
        match t.get("type").and_then(Value::as_str) {
            Some("systemd-tpm2") => {
                let pubkey = t
                    .get("tpm2_pubkey")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let pubkey_is_image =
                    matches!((&pubkey, image_pubkey), (Some(p), Some(img)) if p == img);
                tpm2.push(Tpm2Token {
                    pubkey_pcrs: pcr_list(t.get("tpm2_pubkey_pcrs")).context("tpm2_pubkey_pcrs")?,
                    pcrlock: t
                        .get("tpm2_pcrlock")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    literal_pcrs: pcr_list(t.get(LITERAL_PCRS_KEY)).context("literal PCRs")?,
                    pubkey,
                    pubkey_is_image,
                });
            }
            Some("systemd-recovery") => has_recovery = true,
            _ => {}
        }
    }
    let any_pcrlock = tpm2.iter().any(|t| t.pcrlock);
    let tpm2 = tpm2.iter().find(|t| !t.sealed()).or(tpm2.first()).cloned();
    let mut stray_slots = keyslots
        .keys()
        .map(|k| {
            k.parse::<u32>()
                .map_err(|_| anyhow!("a keyslot number is not an integer"))
        })
        .collect::<Result<Vec<u32>>>()?;
    stray_slots.retain(|k| !referenced.contains(k));
    stray_slots.sort_unstable();
    recovery_slots.sort_unstable();
    Ok(LuksInfo {
        uuid,
        tpm2,
        has_recovery,
        recovery_slots,
        any_pcrlock,
        stray_slots,
    })
}

/// token 的 `keyslots`：字符串形式的编号数组。
fn slot_list(v: Option<&Value>) -> Result<Vec<u32>> {
    let Some(v) = v else { return Ok(vec![]) };
    v.as_array()
        .ok_or_else(|| anyhow!("keyslots is not an array"))?
        .iter()
        .map(|s| {
            s.as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| anyhow!("bad keyslot number"))
        })
        .collect()
}

/// How the recovery key may be escrowed now (plan 6 design §6.2, ruling 27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowMode {
    /// Nothing is enrolled or sent; `luks:escrow` reports this text.
    Wait(&'static str),
    /// Seal with age to every one of `recipients`; `fp` is their [`mastersos_bundle::recipients_fp`].
    Sealed { recipients: Vec<String>, fp: String },
}

/// The escrow mode for `current` (what the main loop published from the accepted bundle). The
/// recipients are checked again here (each an age X25519 recipient in canonical form, none twice,
/// 1 to 8): a bundle that slipped past the server's checks never gets a key sealed to garbage.
pub fn escrow_mode(current: Option<&CurrentGroup>) -> EscrowMode {
    let Some(c) = current else {
        return EscrowMode::Wait(WAIT_FIRST_BUNDLE);
    };
    if c.escrow_recipients.is_empty() {
        return EscrowMode::Wait(WAIT_RECIPIENTS);
    }
    if let Some(e) = recipients_problem(Some(c)) {
        log::error!("bundle v{}: {e}; not escrowing", c.version);
        return EscrowMode::Wait(WAIT_BAD_RECIPIENTS);
    }
    EscrowMode::Sealed {
        recipients: c.escrow_recipients.clone(),
        fp: mastersos_bundle::recipients_fp(&c.escrow_recipients),
    }
}

/// What is wrong with `current`'s escrow recipients (a non-empty list that fails
/// `checks::escrow_recipients`); None when there is nothing to report. The text names the
/// recipient, which is public.
fn recipients_problem(current: Option<&CurrentGroup>) -> Option<String> {
    let c = current?;
    if c.escrow_recipients.is_empty() {
        return None;
    }
    mastersos_bundle::checks::escrow_recipients(&c.escrow_recipients).err()
}

/// What `luks:escrow` says while waiting in `mode`: the wait text, and for invalid recipients
/// also what is wrong with them.
fn wait_detail(mode: &EscrowMode, current: Option<&CurrentGroup>) -> Option<String> {
    match mode {
        EscrowMode::Sealed { .. } => None,
        EscrowMode::Wait(w) if *w == WAIT_BAD_RECIPIENTS => {
            Some(match recipients_problem(current) {
                Some(e) => format!("{w}: {e}"),
                None => (*w).to_owned(),
            })
        }
        EscrowMode::Wait(w) => Some((*w).to_owned()),
    }
}

/// `<var_dir>/escrow-done.json` (0600): the last escrow the server took. No server address: a
/// new address of the same cloud has the ciphertext already (review M7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowDone {
    pub recipients_fp: String,
    pub luks_uuid: String,
}

/// Whether an escrowed partition must escrow again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redo {
    None,
    /// The recipients changed since (or the escrow predates sealing): enroll a new recovery key,
    /// escrow it sealed, then wipe the old slot (ruling 26).
    Rotate,
}

/// [`Redo::Rotate`] when the current recipients' fingerprint or the partition differ from the
/// last escrow, or there is no record of one; never while waiting (nothing to seal to).
pub fn redo(done: Option<&EscrowDone>, mode: &EscrowMode, luks_uuid: &str) -> Redo {
    match (mode, done) {
        (EscrowMode::Wait(_), _) => Redo::None,
        (EscrowMode::Sealed { fp, .. }, Some(d))
            if d.recipients_fp == *fp && d.luks_uuid == luks_uuid =>
        {
            Redo::None
        }
        (EscrowMode::Sealed { .. }, _) => Redo::Rotate,
    }
}

/// 从 `systemd-cryptenroll --recovery-key` 的 stdout 里取出恢复密钥（8 组 × 8 个 modhex，`-` 连接）。
/// 实测 systemd 259 的 stdout 只有密钥本身一行（说明文字在 stderr）；这里也容忍前后有别的字、
/// 终端颜色码与表情符号。找不到、或找到两把不同的都返回 None。
pub fn extract_recovery_key(stdout: &str) -> Option<String> {
    let mut found: Option<&str> = None;
    for word in stdout.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        // ANSI 颜色码（ESC [ … m）被上面的分隔切开后，残片可能粘在密钥前面，例如 "1m"。
        let word = word.trim_start_matches(|c: char| c.is_ascii_digit() || c == 'm');
        if is_recovery_key(word) {
            match found {
                Some(f) if f != word => return None,
                _ => found = Some(word),
            }
        }
    }
    found.map(str::to_string)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Nothing,
    /// 分区没有 TPM2 槽（或只有不属于任何 token 的口令槽）：只回报，不动分区（Ruling 17）。
    NoTpmSlot,
    AddPcrlock,
    EnrollRecovery,
    Escrow,
    /// 去掉不属于任何 token 的 keyslot（`LuksInfo::stray_slots`）；只在恢复密钥已托管、
    /// pcrlock 的 TPM 槽已在之后。
    WipeStray,
    /// The escrow recipients changed ([`Redo::Rotate`]): enroll a new recovery key; the escrow
    /// step then sends it sealed and wipes the old slot.
    Rotate,
}

/// 已登记、还没托管成功的恢复密钥，存在 `<var_dir>/escrow-pending.json`（0600，加密的根分区上）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub luks_uuid: String,
    pub recovery_key: String,
    /// 登记这把时已在盘上的恢复槽（一律不先去掉）：这把托管成功之后才按编号去掉。
    #[serde(default)]
    pub replaces_slots: Vec<u32>,
    /// The key sealed to the escrow recipients, made once and resent unchanged until the server
    /// takes it. None in a pending file written before sealing (sealed on the next attempt).
    #[serde(default)]
    pub sealed: Option<SealedKey>,
}

/// A recovery key sealed with age: the armor and the fingerprint of the recipients.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    pub recovery_key_age: String,
    pub recipients_fp: String,
}

/// Only the length of the armor.
impl std::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKey")
            .field(
                "recovery_key_age",
                &format_args!("<{} bytes>", self.recovery_key_age.len()),
            )
            .field("recipients_fp", &self.recipients_fp)
            .finish()
    }
}

/// 不打印恢复密钥。
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("luks_uuid", &self.luks_uuid)
            .field("recovery_key", &"<redacted>")
            .field("replaces_slots", &self.replaces_slots)
            .field("sealed", &self.sealed)
            .finish()
    }
}

/// agent 自己保管的那把恢复密钥（托管成功之后写 `<var_dir>/luks-recovery-key.json`，0600）：换 TPM 槽、
/// 去旧槽、去临时钥匙槽都用它解锁（数据盘离开 initrd 后 TPM 不放行）。恢复出厂换了分区就对不上，从登记重来。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldKey {
    pub luks_uuid: String,
    pub recovery_key: String,
}

/// 不打印恢复密钥。
impl std::fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldKey")
            .field("luks_uuid", &self.luks_uuid)
            .field("recovery_key", &"<redacted>")
            .finish()
    }
}

/// 解锁这个分区用哪把钥匙。用户态不再用 TPM 解锁（数据盘的 TPM 签名只覆盖 enter-initrd）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockKey {
    /// agent 保管的恢复密钥（`HeldKey`，托管成功之后）。
    Held,
    /// 这一轮刚登记、还没托管成功的恢复密钥（`escrow-pending.json`）。
    Pending,
    /// 首次开机 / 恢复出厂时 initrd 放下的 32 字节临时钥匙（`luks-bootstrap-key`）。
    Bootstrap,
}

/// 挑一把能解开这个分区的钥匙（经 stdin 送给 `systemd-cryptenroll --unlock-key-file=/dev/stdin`）：
/// 先 `HeldKey`（UUID 对得上）、再这个分区的待托管密钥、再 32 字节的临时钥匙，都没有就 None。
/// 文件读不出（不是「不存在」）报错——整轮不动分区（4a 的规则）。
fn unlock_key(
    paths: &crate::system::SysPaths,
    info: &LuksInfo,
    pending: Option<&Pending>,
) -> Result<Option<(UnlockKey, Vec<u8>)>> {
    if let Some(h) = load_held(paths)? {
        if h.luks_uuid == info.uuid {
            return Ok(Some((UnlockKey::Held, h.recovery_key.into_bytes())));
        }
    }
    if let Some(p) = pending {
        if p.luks_uuid == info.uuid {
            return Ok(Some((
                UnlockKey::Pending,
                p.recovery_key.clone().into_bytes(),
            )));
        }
    }
    if let Some(b) = load_bootstrap_key(paths)? {
        return Ok(Some((UnlockKey::Bootstrap, b)));
    }
    Ok(None)
}

/// `<var_dir>/luks-state.json`（0600），只由 [`LuksJob`] 读写。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuksState {
    /// 恢复密钥已托管成功的分区（LUKS UUID）。恢复出厂换了分区就对不上，从登记重来。
    #[serde(default)]
    pub escrowed_luks_uuid: Option<String>,
}

/// 下一步做什么（纯函数；规则按序，Ruling 7：恢复密钥 → 托管确认 → pcrlock）：
///
/// 1. 没有 TPM2 槽 → `NoTpmSlot`；
/// 2. 有这个分区的待托管密钥 → `Escrow`；
/// 3. 这个分区没托管过，或者恢复槽没了 → `EnrollRecovery`；
/// 4. the escrow recipients changed since ([`redo`]) → `Rotate` (ahead of pcrlock: the copy the
///    server has may be readable with the replaced kit);
/// 5. TPM 槽不是「签名 PCR 11 + pcrlock、字面 PCR 为空」→ `AddPcrlock`；
/// 6. 还有不属于任何 token 的 keyslot → `WipeStray`；
/// 7. 否则 `Nothing`。
///
/// 任何「这个分区没托管成功」的输入都到不了 `AddPcrlock`（Review Focus 7）。
pub fn next_step(
    info: &LuksInfo,
    pending: Option<&Pending>,
    escrowed: Option<&str>,
    redo: Redo,
) -> Need {
    if info.tpm2.is_none() {
        return Need::NoTpmSlot;
    }
    if pending.is_some_and(|p| p.luks_uuid == info.uuid) {
        return Need::Escrow;
    }
    if !(escrowed == Some(info.uuid.as_str()) && info.has_recovery) {
        return Need::EnrollRecovery;
    }
    if redo == Redo::Rotate {
        return Need::Rotate;
    }
    match &info.tpm2 {
        // 签名 PCR 11 + pcrlock、字面 PCR 为空、且绑的是这个镜像的公钥（退役钥匙的槽不算，走 AddPcrlock 换槽）。
        Some(t) if t.sealed() => {
            if info.stray_slots.is_empty() {
                Need::Nothing
            } else {
                Need::WipeStray
            }
        }
        _ => Need::AddPcrlock,
    }
}

/// 恢复密钥登记、托管、补 pcrlock 的后台任务。
pub struct LuksJob {
    runner: Arc<dyn Runner>,
}

impl LuksJob {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        LuksJob { runner }
    }
}

impl Job for LuksJob {
    fn name(&self) -> &'static str {
        "luks"
    }

    fn every(&self) -> Duration {
        EVERY
    }

    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(Round::new(self.runner.clone(), cx).run())
    }

    /// 第一次托管排在第一份状态回报之前（progress.md Carry → T8）。
    fn gates_first_report(&self) -> bool {
        true
    }

    /// The escrow waits for the first bundle and its recipients, and rotates when they change.
    fn wake_on_new_bundle(&self) -> bool {
        true
    }
}

fn ok(item: &str, detail: Option<String>) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: true,
        detail,
    }
}

fn fail(item: &str, detail: impl Into<String>) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: false,
        detail: Some(detail.into()),
    }
}

/// 一步失败：落在哪个回报项上、说明（不含恢复密钥与 PIN）。
struct StepError {
    item: &'static str,
    detail: String,
}

fn step_err(item: &'static str, e: anyhow::Error) -> StepError {
    StepError {
        item,
        detail: format!("{e:#}"),
    }
}

/// 一轮。
struct Round<'a> {
    runner: Arc<dyn Runner>,
    cx: &'a JobCtx,
    /// 本轮里补 pcrlock 那一步是否因为「还没有策略」跳过了。
    waiting_policy: bool,
    /// 本轮 `bootctl status` 说 Secure Boot 开着。没开时不绑 pcrlock、也不改写策略：那会把
    /// 「Secure Boot 关着」的 PCR 7 授权进策略，正是 pcrlock 要拦的攻击（Ruling 7，矩阵第 5 行）。
    secure_boot: bool,
    /// 这个镜像的 PCR 公钥，base64 的 PEM 文本（读 `/usr/lib/systemd/tpm2-pcr-public-key.pem`）：
    /// 判断 TPM 槽绑的是不是本镜像的公钥（换过签名钥匙的旧机器为否）。读不到为 None。
    image_pubkey: Option<String>,
    /// 多余的槽只有一个、本机有临时钥匙文件，且**用临时钥匙对那个槽号试口令成功**（不是只看文件在不在）：
    /// 只有这时 `luks:tpm` 才把那个多余槽当成首次开机的临时钥匙槽、照样报成功。
    bootstrap_slot_verified: bool,
    /// What the shim-update follow-up found this round (plan 5 Task 8).
    shim: Option<crate::shim_predict::Followup>,
    /// From the bundle published when the round started ([`escrow_mode`]).
    mode: EscrowMode,
    /// `luks:escrow`'s detail while `mode` waits ([`wait_detail`]).
    wait_detail: Option<String>,
}

impl<'a> Round<'a> {
    fn new(runner: Arc<dyn Runner>, cx: &'a JobCtx) -> Self {
        let (mode, wait_detail) = {
            let cur = cx.current.borrow();
            let mode = escrow_mode(cur.as_deref());
            let detail = wait_detail(&mode, cur.as_deref());
            (mode, detail)
        };
        Round {
            runner,
            cx,
            waiting_policy: false,
            secure_boot: false,
            image_pubkey: image_pubkey_b64(&cx.paths.root),
            bootstrap_slot_verified: false,
            shim: None,
            mode,
            wait_detail,
        }
    }

    /// 在阻塞线程里跑一条命令（Runner 是同步的，命令可能跑到 2 分钟）。
    async fn exec(&self, cmd: Cmd) -> Result<Output> {
        let r = self.runner.clone();
        let program = cmd.program.clone();
        tokio::task::spawn_blocking(move || r.run(&cmd))
            .await
            .map_err(|e| anyhow!("{program} exited abnormally: {e}"))?
    }

    async fn exec_ok(&self, cmd: Cmd) -> Result<String> {
        let r = self.runner.clone();
        let program = cmd.program.clone();
        tokio::task::spawn_blocking(move || run_ok(r.as_ref(), cmd))
            .await
            .map_err(|e| anyhow!("{program} exited abnormally: {e}"))?
    }

    /// 输出可能带恢复密钥的命令：错误里只有退出码。
    async fn exec_redacted(&self, cmd: Cmd) -> Result<String> {
        let r = self.runner.clone();
        let program = cmd.program.clone();
        tokio::task::spawn_blocking(move || run_ok_redacted(r.as_ref(), cmd))
            .await
            .map_err(|e| anyhow!("{program} exited abnormally: {e}"))?
    }

    async fn run(mut self) -> Vec<ItemResult> {
        let sb = self.secure_boot().await;
        self.secure_boot = sb.ok;
        // 与 system:secureboot 同一处回报：bootloader-update 换不换得了 shim（4b Task 22）
        let mut results = vec![
            sb,
            crate::secureboot::shim_ca_item(&self.cx.paths.var_dir),
            // The /usr integrity checker's state (integrity.json), same var dir as the shim-ca status.
            crate::integrity::integrity_item(&self.cx.paths.var_dir),
        ];
        // 上一次被杀在半路时可能留下的 PIN 凭据。
        remove_stale_credential(&self.cx.paths);
        // initrd 的持久化单元没跑成时（例如切根前失败），/run 里那份临时钥匙会带进用户态：删掉。
        remove_run_bootstrap_copy(&self.cx.paths);
        let mut err: Option<StepError> = None;
        let mut info: Option<LuksInfo> = None;
        for _ in 0..MAX_STEPS {
            let cur = match self.read_info().await {
                Ok(i) => i,
                Err(e) => {
                    err = Some(step_err(
                        "luks:tpm",
                        e.context("cannot read the LUKS header of the data partition"),
                    ));
                    break;
                }
            };
            // 两个状态文件读不出（不是「不存在」）就整轮不动分区：把读错当成「没托管过」会重新登记，
            // 而重新登记会动已托管的恢复槽。
            // HeldKey 也一样：读不出就整轮不动（之后换槽、去临时钥匙槽都靠它解锁）。
            let (pending, escrowed, done) = match load_pending(&self.cx.paths)
                .and_then(|p| {
                    Ok((
                        p,
                        load_luks_state(&self.cx.paths)?.escrowed_luks_uuid,
                        load_done(&self.cx.paths)?,
                    ))
                })
                .and_then(|v| {
                    // 恢复出厂换了分区（UUID 变了）留下的旧 HeldKey 解不开现在的分区：删掉，不长期留着密钥。
                    if load_held(&self.cx.paths)?.is_some_and(|h| h.luks_uuid != cur.uuid) {
                        remove_held(&self.cx.paths)?;
                    }
                    Ok(v)
                }) {
                Ok(v) => v,
                Err(e) => {
                    info = Some(cur);
                    err = Some(step_err(
                        "luks:escrow",
                        e.context("reading the local escrow state failed; not touching the data partition this round"),
                    ));
                    break;
                }
            };
            let need = next_step(
                &cur,
                pending.as_ref(),
                escrowed.as_deref(),
                redo(done.as_ref(), &self.mode, &cur.uuid),
            );
            if matches!(need, Need::EnrollRecovery | Need::Escrow | Need::Rotate) {
                // 托管只走 https（终审 I4）：送不出去就连恢复密钥也不登记，已有的待托管密钥留着不发。
                let lab = image_is_lab(&self.cx.paths.root);
                if let Err(why) = escrow_transport_ok(self.cx.fetcher.base(), lab) {
                    info = Some(cur);
                    err = Some(StepError {
                        item: "luks:escrow",
                        detail: format!("escrow refused (locally): {why}"),
                    });
                    break;
                }
                // Ruling 27: no key is enrolled or sent before the first bundle names recipients.
                if let Some(why) = &self.wait_detail {
                    info = Some(cur);
                    err = Some(StepError {
                        item: "luks:escrow",
                        detail: why.clone(),
                    });
                    break;
                }
            }
            let r = match need {
                Need::Nothing | Need::NoTpmSlot => {
                    info = Some(cur);
                    break;
                }
                Need::EnrollRecovery => self.enroll_recovery(&cur, pending.as_ref()).await,
                Need::Rotate => {
                    log::info!(
                        "escrow recipients changed: rotating the recovery key of {}",
                        cur.uuid
                    );
                    self.enroll_recovery(&cur, pending.as_ref()).await
                }
                Need::Escrow => match pending {
                    Some(p) => self.escrow(&cur, p).await,
                    None => Err(StepError {
                        item: "luks:escrow",
                        detail: "the key waiting for escrow is missing".into(),
                    }),
                },
                Need::AddPcrlock if !self.secure_boot => Err(StepError {
                    item: "luks:pcrlock",
                    detail: NO_SB_BIND.into(),
                }),
                Need::AddPcrlock => match self.shim_lock().await {
                    // same lock as shim-prepare: it runs make-policy too
                    Ok(_g) => self.add_pcrlock(&cur, pending.as_ref()).await,
                    Err(e) => Err(e),
                },
                Need::WipeStray => self.wipe_stray(&cur, pending.as_ref()).await,
            };
            info = Some(cur);
            if let Err(e) = r {
                err = Some(e);
                break;
            }
            if self.waiting_policy {
                break;
            }
        }
        // 绑好之后：策略服务失败了（db/dbx 或 shim 的 SbatLevel 变过）就用 PIN 改写策略。恢复密钥那边
        // （登记、托管、去掉旧槽）的失败不挡它：改写只碰 TPM 的 NV 策略，不碰 LUKS 槽。
        let mut repaired = None;
        let mut errs: Vec<StepError> = err.into_iter().collect();
        let repair_ok = errs
            .iter()
            .all(|e| matches!(e.item, "luks:recovery" | "luks:escrow"));
        if repair_ok && info.as_ref().is_some_and(is_sealed) {
            if !self.secure_boot {
                errs.push(StepError {
                    item: "luks:pcrlock",
                    detail: NO_SB_REPAIR.into(),
                });
            } else {
                // The policy repair and the shim follow-up run under shim-prepare's lock, so `mastersos-agent shim-prepare`
                // (mastersos-bootloader-update, same boot) never interleaves its make-policy with ours.
                let guard = self.shim_lock().await;
                // Did the policy service fail in this boot (repaired now, or the repair failed)? Then this boot did not
                // unlock with the TPM, whatever the SbatLevel says.
                let policy_failed = match self.repair_policy_if_failed().await {
                    Ok(r) => {
                        repaired = r;
                        repaired.is_some()
                    }
                    Err(e) => {
                        errs.push(e);
                        true
                    }
                };
                // Runs even when the repair failed: a Failed record from an earlier boot is cleared after the reboot
                // either way (the repair's own error stays on luks:pcrlock).
                match guard {
                    Ok(_g) => match self.shim_followup(policy_failed).await {
                        Ok(f) => self.shim = Some(f),
                        Err(e) => errs.push(e),
                    },
                    Err(e) => errs.push(e),
                }
            }
        }
        // 没有 TPM2 槽的分区只回报、什么都不碰（Ruling 17），连试口令也不做。
        if let Some(i) = info.as_ref().filter(|i| i.tpm2.is_some()) {
            self.check_bootstrap_slot(i, &mut errs).await;
        }
        results.extend(self.summarize(info.as_ref(), errs, repaired));
        results
    }

    /// 读当前状态：`cryptsetup luksUUID` 与 `luksDump --dump-json-metadata`。
    async fn read_info(&self) -> Result<LuksInfo> {
        let uuid = self
            .exec_ok(Cmd::new("cryptsetup", &["luksUUID", ROOT_LUKS_DEV]))
            .await?;
        let json = self
            .exec_ok(Cmd::new(
                "cryptsetup",
                &["luksDump", "--dump-json-metadata", ROOT_LUKS_DEV],
            ))
            .await?;
        parse_luks_dump(&json, &uuid, self.image_pubkey.as_deref())
    }

    async fn secure_boot(&self) -> ItemResult {
        const ITEM: &str = "system:secureboot";
        let out = match self.exec(Cmd::new("bootctl", &["status"])).await {
            Ok(o) => o,
            Err(e) => return fail(ITEM, format!("{e:#}")),
        };
        let state = out.stdout.lines().find_map(|l| {
            l.trim()
                .strip_prefix("Secure Boot:")
                .map(|v| v.trim().to_string())
        });
        match state {
            Some(s) if s.starts_with("enabled") => ok(ITEM, Some(s)),
            Some(s) => fail(ITEM, format!("Secure Boot is off: {s}")),
            None => fail(
                ITEM,
                format!(
                    "bootctl status has no Secure Boot line (exit code {})",
                    out.code
                ),
            ),
        }
    }

    /// 登记一把新的恢复密钥；取出、核对之后先写待托管文件。盘上已有的恢复槽**一律不先动**：
    /// 它可能就是服务端手里的那一把（`luks-state.json` 丢了；Secure Boot 关着的机器上分区会一直
    /// 不绑 pcrlock，从「绑没绑」也看不出托管过没有），也可能是没托管成功的孤儿——编号都记进待托管
    /// 文件，新的这把托管成功之后才按编号去掉（`escrow`）。孤儿留在盘上无害（服务端没有它，也没人知道它）。
    /// 连续登记失败会一把把攒下孤儿：盘上已有 [`MAX_RECOVERY_SLOTS`] 个恢复槽时不再登记，回报失败。
    async fn enroll_recovery(
        &self,
        info: &LuksInfo,
        pending: Option<&Pending>,
    ) -> std::result::Result<(), StepError> {
        if info.recovery_slots.len() >= MAX_RECOVERY_SLOTS {
            return Err(StepError {
                item: "luks:recovery",
                detail: format!(
                    "the disk already has {} recovery slots (this device cannot tell which one is escrowed); not enrolling another (to avoid filling the keyslots); IT should check",
                    info.recovery_slots.len()
                ),
            });
        }
        // Sealing must work before a slot is added: a failure after cryptenroll would leave an
        // orphan slot each round. Probe with a throwaway key (the real one does not exist yet).
        self.seal(PROBE_KEY)?;
        // 用首次开机的临时钥匙（或已保管的恢复密钥）解锁来登记新的恢复密钥；都没有就什么都不动。
        let key = unlock_key(&self.cx.paths, info, pending)
            .map_err(|e| {
                step_err(
                    "luks:recovery",
                    e.context("reading the local unlock key failed"),
                )
            })?
            .ok_or_else(|| StepError {
                item: "luks:recovery",
                detail: NO_LOCAL_KEY.into(),
            })?
            .1;
        let out = self
            .exec_redacted(
                Cmd::new(
                    "systemd-cryptenroll",
                    &[KEY_STDIN_UNLOCK, "--recovery-key", ROOT_LUKS_DEV],
                )
                .stdin(key),
            )
            .await
            .map_err(|e| {
                step_err(
                    "luks:recovery",
                    e.context("enrolling the recovery key failed"),
                )
            })?;
        let key = extract_recovery_key(&out).ok_or_else(|| StepError {
            item: "luks:recovery",
            detail:
                "enrolled a recovery key but could not extract it from the output (another is enrolled next round; this slot is removed after a later successful escrow)"
                    .into(),
        })?;
        drop(out);
        // 核对：这把密钥真能解开分区（不用 token，只试口令）。经 stdin，不带换行。
        self.exec_redacted(
            Cmd::new(
                "cryptsetup",
                &[
                    "open",
                    "--test-passphrase",
                    "--disable-external-tokens",
                    "--key-file=-",
                    ROOT_LUKS_DEV,
                ],
            )
            .stdin(key.clone().into_bytes()),
        )
        .await
        .map_err(|e| {
            step_err(
                "luks:recovery",
                e.context("the extracted recovery key does not unlock the data partition (not escrowing; another is enrolled next round)"),
            )
        })?;
        // Sealed once here and kept with the key: every attempt sends this same ciphertext. The
        // key is written to the pending file even if sealing fails after all (the probe passed):
        // the next round then seals it in the escrow step instead of enrolling another slot.
        let sealed = self.seal(&key);
        save_pending(
            &self.cx.paths,
            &Pending {
                luks_uuid: info.uuid.clone(),
                recovery_key: key,
                replaces_slots: info.recovery_slots.clone(),
                sealed: sealed.as_ref().ok().cloned(),
            },
        )
        .map_err(|e| {
            step_err(
                "luks:recovery",
                e.context("writing the pending escrow file failed"),
            )
        })?;
        sealed.map(|_| ())
    }

    /// Seal `key` to this round's recipients. Errors never carry the key.
    fn seal(&self, key: &str) -> std::result::Result<SealedKey, StepError> {
        let EscrowMode::Sealed { recipients, fp } = &self.mode else {
            return Err(StepError {
                item: "luks:escrow",
                detail: WAIT_RECIPIENTS.into(),
            });
        };
        let recovery_key_age = mastersos_bundle::seal(key, recipients).map_err(|e| StepError {
            item: "luks:escrow",
            detail: format!("sealing the recovery key failed: {e}"),
        })?;
        Ok(SealedKey {
            recovery_key_age,
            recipients_fp: fp.clone(),
        })
    }

    async fn escrow(&self, info: &LuksInfo, p: Pending) -> std::result::Result<(), StepError> {
        let escrow_err = |detail: String| StepError {
            item: "luks:escrow",
            detail,
        };
        let Some(id) = &self.cx.identity else {
            return Err(escrow_err(
                "the seed partition has no identity.json (escrow credentials), so escrow is not possible; the recovery key waits on this device".into(),
            ));
        };
        if !is_recovery_key(&p.recovery_key) {
            return Err(escrow_err(
                "invalid escrow request: malformed recovery key".into(),
            ));
        }
        let current_fp = match &self.mode {
            EscrowMode::Sealed { fp, .. } => fp,
            EscrowMode::Wait(why) => return Err(escrow_err((*why).into())),
        };
        let sealed = match &p.sealed {
            Some(s) if s.recipients_fp == *current_fp => s.clone(),
            // Sealed to recipients that were replaced before the server took it: that copy may
            // be readable with the replaced kit, so it is not sent. Enroll a fresh key instead
            // (it replaces every recovery slot on the disk, this one too, once escrowed).
            Some(_) => {
                log::info!(
                    "the pending recovery key of {} was sealed to replaced recipients: enrolling a new one",
                    info.uuid
                );
                return self.enroll_recovery(info, Some(&p)).await;
            }
            // Written before sealing: seal now and keep it, so retries resend the same.
            None => {
                let s = self.seal(&p.recovery_key)?;
                let mut q = p.clone();
                q.sealed = Some(s.clone());
                save_pending(&self.cx.paths, &q).map_err(|e| {
                    step_err(
                        "luks:escrow",
                        e.context("writing the pending escrow file failed"),
                    )
                })?;
                s
            }
        };
        let req = EscrowRequest {
            device_id: self.cx.ident.device_id.clone(),
            serial: self.cx.ident.serial.clone(),
            luks_uuid: info.uuid.clone(),
            recovery_key_age: sealed.recovery_key_age.clone(),
            recipients_fp: sealed.recipients_fp.clone(),
            escrow_secret: id.escrow_secret.clone(),
        };
        // The bundle's errors name the field, never its value.
        if let Err(e) = req.validate() {
            return Err(escrow_err(format!("invalid escrow request: {e}")));
        }
        if let Err(e) = self
            .cx
            .fetcher
            .escrow(&req, image_is_lab(&self.cx.paths.root))
            .await
        {
            // 服务端的说明原样带上；万一里面出现了密钥，抹掉。
            let msg = format!("{e:#}").replace(&p.recovery_key, "<redacted>");
            return Err(escrow_err(msg));
        }
        save_luks_state(
            &self.cx.paths,
            &LuksState {
                escrowed_luks_uuid: Some(info.uuid.clone()),
            },
        )
        .map_err(|e| {
            step_err(
                "luks:escrow",
                e.context("escrow succeeded, but writing luks-state.json failed"),
            )
        })?;
        save_done(
            &self.cx.paths,
            &EscrowDone {
                recipients_fp: sealed.recipients_fp.clone(),
                luks_uuid: info.uuid.clone(),
            },
        )
        .map_err(|e| {
            step_err(
                "luks:escrow",
                e.context("escrowed, but writing escrow-done.json failed"),
            )
        })?;
        // 把这把写成 HeldKey（0600）：之后换 TPM 槽、去旧槽、去临时钥匙槽都用它解锁（用户态不用 TPM）。
        save_held(
            &self.cx.paths,
            &HeldKey {
                luks_uuid: info.uuid.clone(),
                recovery_key: p.recovery_key.clone(),
            },
        )
        .map_err(|e| {
            step_err(
                "luks:escrow",
                e.context("escrow succeeded, but writing luks-recovery-key.json failed"),
            )
        })?;
        // 新的这把已在服务端、也已保管：现在才去掉它要替换的旧恢复槽（只去掉还在、且仍是恢复槽的编号）。
        let old: Vec<String> = p
            .replaces_slots
            .iter()
            .filter(|n| info.recovery_slots.contains(n))
            .map(u32::to_string)
            .collect();
        if !old.is_empty() {
            let wipe = format!("--wipe-slot={}", old.join(","));
            // 用刚托管、登记时已核对过的这把解锁（经 stdin）：不依赖 TPM——pcrlock 策略这会儿可能正坏着
            // （db/dbx、shim 变过，这次开机用恢复密钥进来）。
            self.exec_redacted(
                Cmd::new(
                    "systemd-cryptenroll",
                    &[KEY_STDIN_UNLOCK, &wipe, ROOT_LUKS_DEV],
                )
                .stdin(p.recovery_key.clone().into_bytes()),
            )
            .await
            .map_err(|e| {
                step_err(
                    "luks:recovery",
                    e.context("the new recovery key is escrowed, but removing the old recovery slot failed (retrying next round)"),
                )
            })?;
        }
        remove_pending(&self.cx.paths).map_err(|e| {
            step_err(
                "luks:escrow",
                e.context("escrow succeeded, but removing the pending escrow file failed"),
            )
        })?;
        log::info!(
            "the recovery key of data partition {} is escrowed (sealed to recipients {})",
            info.uuid,
            sealed.recipients_fp
        );
        Ok(())
    }

    /// 托管确认之后：用新 PIN 重建 pcrlock 策略，再把 TPM 槽换成签名 PCR 11 + pcrlock。
    async fn add_pcrlock(
        &mut self,
        info: &LuksInfo,
        pending: Option<&Pending>,
    ) -> std::result::Result<(), StepError> {
        let item = "luks:pcrlock";
        let policy = self
            .cx
            .paths
            .root
            .join(PCRLOCK_POLICY.trim_start_matches('/'));
        if !policy.exists() {
            // 镜像里的 make-policy 单元每次开机生成它；还没有（这次开机它失败了、或 TPM 刚能用）就等。
            self.waiting_policy = true;
            return Ok(());
        }
        let already_pcrlock = info.tpm2.as_ref().is_some_and(|t| t.pcrlock);
        if !already_pcrlock {
            // 现在的 TPM 槽只绑 PCR 11：删掉 make-policy 单元建的 NV 策略（它的 PIN 是随机的、只封在 TPM 里，
            // db/dbx 变了就解不出来）不影响解锁；换成我们掌握 PIN 的策略。新槽配新 PIN。
            let pin = new_pin().map_err(|e| step_err(item, e))?;
            write_pin(&self.cx.paths, &pin)
                .map_err(|e| step_err(item, e.context("writing the PIN failed")))?;
            self.exec_ok(Cmd::new(PCRLOCK_BIN, &["remove-policy"]))
                .await
                .map_err(|e| step_err(item, e))?;
            self.make_policy_with_pin(&pin)
                .await
                .map_err(|e| step_err(item, e))?;
        }
        // 已经带 pcrlock、只是签名 PCR 不对（或绑的是退役的公钥）：不动策略（删了它，现在的槽就解不开）。
        // 解锁用 agent 保管 / 首次开机的钥匙（经 stdin），不靠 TPM——数据盘离开 initrd 后 TPM 不放行。
        let key = unlock_key(&self.cx.paths, info, pending)
            .map_err(|e| step_err(item, e.context("reading the local unlock key failed")))?
            .ok_or_else(|| StepError {
                item,
                detail: NO_LOCAL_KEY.into(),
            })?
            .1;
        let tpm2_pubkey = format!("--tpm2-public-key={TPM2_PUBKEY}");
        let pcrlock = format!("--tpm2-pcrlock={PCRLOCK_POLICY}");
        self.exec_redacted(
            Cmd::new(
                "systemd-cryptenroll",
                &[
                    KEY_STDIN_UNLOCK,
                    "--wipe-slot=tpm2",
                    "--tpm2-device=auto",
                    &tpm2_pubkey,
                    "--tpm2-public-key-pcrs=11",
                    "--tpm2-pcrs=",
                    &pcrlock,
                    ROOT_LUKS_DEV,
                ],
            )
            .stdin(key),
        )
        .await
        .map_err(|e| step_err(item, e.context("replacing the TPM slot failed")))?;
        log::info!(
            "the TPM slot of data partition {} is now signed PCR 11 + pcrlock",
            info.uuid
        );
        Ok(())
    }

    /// 恢复密钥已托管、pcrlock 槽已在：去掉不属于任何 token 的 keyslot（首次开机的临时钥匙、手工加的口令、
    /// 换 TPM 槽半路断电留下的）。去完之后，首次开机的临时钥匙文件（`BOOTSTRAP_KEY_FILE`）还在就删掉。
    ///
    /// 解锁：agent 保管的恢复密钥 / 待托管的 / 首次开机的临时钥匙，经 stdin，不靠 TPM。都没有就失败、下一轮再试。
    async fn wipe_stray(
        &self,
        info: &LuksInfo,
        pending: Option<&Pending>,
    ) -> std::result::Result<(), StepError> {
        let slots: Vec<String> = info.stray_slots.iter().map(u32::to_string).collect();
        let wipe = format!("--wipe-slot={}", slots.join(","));
        let key = unlock_key(&self.cx.paths, info, pending)
            .map_err(|e| step_err("luks:tpm", e.context("reading the local unlock key failed")))?
            .ok_or_else(|| StepError {
                item: "luks:tpm",
                detail: NO_LOCAL_KEY.into(),
            })?
            .1;
        let cmd = Cmd::new(
            "systemd-cryptenroll",
            &[KEY_STDIN_UNLOCK, &wipe, ROOT_LUKS_DEV],
        )
        .stdin(key);
        self.exec_redacted(cmd).await.map_err(|e| {
            step_err(
                "luks:tpm",
                e.context("removing the extra passphrase slot failed"),
            )
        })?;
        // 多余的槽（含首次开机的临时钥匙槽）已去掉：临时钥匙文件不再需要，删掉它（之后不再用临时钥匙解锁）。
        remove_bootstrap_key(&self.cx.paths).map_err(|e| {
            step_err(
                "luks:tpm",
                e.context("removing the first-boot temporary key file failed"),
            )
        })?;
        log::info!(
            "data partition {}: removed the extra passphrase slot {}",
            info.uuid,
            slots.join(",")
        );
        Ok(())
    }

    /// 经凭据目录把 PIN 交给 `make-policy --recovery-pin=query`（不进命令行、不进环境变量）。
    async fn make_policy_with_pin(&self, pin: &str) -> Result<()> {
        let r = self.runner.clone();
        let paths = self.cx.paths.clone();
        let pin = pin.to_string();
        tokio::task::spawn_blocking(move || {
            make_policy_with_pin_blocking(r.as_ref(), &paths, CRED_DIR, &pin)
        })
        .await
        .map_err(|e| anyhow!("make-policy panicked: {e}"))?
    }

    /// shim-prepare's lock (`<var_dir>/shim-prepare.lock`), held while the returned fd lives.
    async fn shim_lock(&self) -> std::result::Result<std::os::fd::OwnedFd, StepError> {
        let paths = self.cx.paths.clone();
        tokio::task::spawn_blocking(move || crate::shim_predict::lock(&paths))
            .await
            .map_err(|e| anyhow!("locking panicked: {e}"))
            .and_then(|r| r)
            .map_err(|e| step_err("luks:pcrlock", e))
    }

    /// Finish a shim update prepared by `mastersos-agent shim-prepare` (plan 5 Task 8, [`crate::shim_predict::followup`]).
    /// The caller holds [`Self::shim_lock`].
    async fn shim_followup(
        &self,
        policy_failed: bool,
    ) -> std::result::Result<crate::shim_predict::Followup, StepError> {
        let r = self.runner.clone();
        let paths = self.cx.paths.clone();
        tokio::task::spawn_blocking(move || {
            crate::shim_predict::followup(
                &paths.root.join("sys"),
                &paths,
                r.as_ref(),
                policy_failed,
            )
        })
        .await
        .map_err(|e| anyhow!("shim follow-up panicked: {e}"))
        .and_then(|r| r)
        .map_err(|e| step_err("luks:pcrlock", e.context("finishing the shim update")))
    }

    /// `systemd-pcrlock-make-policy` 失败了就用 PIN 改写策略；改写了返回 Some(())。
    async fn repair_policy_if_failed(&self) -> std::result::Result<Option<()>, StepError> {
        let item = "luks:pcrlock";
        let out = self
            .exec(Cmd::new("systemctl", &["is-failed", PCRLOCK_UNIT]))
            .await
            .map_err(|e| step_err(item, e))?;
        if out.stdout.trim() != "failed" {
            return Ok(None);
        }
        let pin = read_pin(&self.cx.paths)
            .map_err(|e| step_err(item, e))?
            .ok_or_else(|| StepError {
                item,
                detail: "the pcrlock policy service failed and this device has no PIN, so the policy cannot be rewritten; the next boot needs the recovery key".into(),
            })?;
        self.make_policy_with_pin(&pin).await.map_err(|e| {
            step_err(
                item,
                e.context("the pcrlock policy service failed (this boot most likely used the recovery key)"),
            )
        })?;
        if let Err(e) = self
            .exec_ok(Cmd::new("systemctl", &["reset-failed", PCRLOCK_UNIT]))
            .await
        {
            log::warn!("reset-failed {PCRLOCK_UNIT} failed: {e:#}");
        }
        log::info!("the pcrlock policy service had failed; the policy was rewritten with the PIN");
        Ok(Some(()))
    }

    /// 一轮结束时看临时钥匙：
    /// - 没有多余的槽、临时钥匙文件还在（wipe_stray 去了槽但没来得及删文件）→ 删掉文件；
    /// - 恰好一个多余槽、有临时钥匙文件 → 用它对那个槽号试口令（经 stdin，不用 token），对上才算「临时钥匙槽」。
    ///   对不上、读不出就不算（`luks:tpm` 按普通的多余口令槽报失败），不靠「文件在不在」下结论。
    async fn check_bootstrap_slot(&mut self, info: &LuksInfo, errs: &mut Vec<StepError>) {
        if info.stray_slots.is_empty() {
            if let Err(e) = remove_bootstrap_key(&self.cx.paths) {
                errs.push(step_err(
                    "luks:tpm",
                    e.context("removing the first-boot temporary key file failed"),
                ));
            }
            return;
        }
        if info.stray_slots.len() != 1 {
            return;
        }
        let key = match load_bootstrap_key(&self.cx.paths) {
            Ok(Some(k)) => k,
            Ok(None) => return,
            Err(e) => {
                errs.push(step_err(
                    "luks:tpm",
                    e.context("reading the first-boot temporary key failed"),
                ));
                return;
            }
        };
        let slot = format!("--key-slot={}", info.stray_slots[0]);
        let r = self
            .exec_redacted(
                Cmd::new(
                    "cryptsetup",
                    &[
                        "open",
                        "--test-passphrase",
                        "--disable-external-tokens",
                        &slot,
                        "--key-file=-",
                        ROOT_LUKS_DEV,
                    ],
                )
                .stdin(key),
            )
            .await;
        self.bootstrap_slot_verified = r.is_ok();
    }

    /// 四个回报项：`luks:tpm`、`luks:recovery`、`luks:escrow`、`luks:pcrlock`。
    fn summarize(
        &self,
        info: Option<&LuksInfo>,
        errs: Vec<StepError>,
        repaired: Option<()>,
    ) -> Vec<ItemResult> {
        // 读不出时当作没托管（只影响回报的措辞；读错本身已作为 luks:escrow 的失败报上去）。
        let escrowed = load_luks_state(&self.cx.paths)
            .ok()
            .and_then(|s| s.escrowed_luks_uuid);
        let mut items: Vec<ItemResult> = match info {
            None => ["luks:recovery", "luks:escrow", "luks:pcrlock"]
                .iter()
                .map(|i| fail(i, "cannot read the state of the data partition"))
                .collect(),
            Some(info) => {
                let is_escrowed = escrowed.as_deref() == Some(info.uuid.as_str());
                // 首次开机的临时钥匙文件还在吗（多余的槽只有它那一个时 luks:tpm 照样算好）。
                let tpm = match &info.tpm2 {
                    // TPM 槽绑的不是本镜像的公钥（换过签名钥匙，slot 绑着退役的那把）：要换槽。
                    Some(t) if !t.pubkey_is_image => fail("luks:tpm", WRONG_PUBKEY),
                    // 多余的槽只有首次开机的临时钥匙那一个、且本机还留着那把文件：无害，之后去掉。
                    Some(_) if info.stray_slots.len() == 1 && self.bootstrap_slot_verified => {
                        ok("luks:tpm", Some(BOOTSTRAP_SLOT_LEFT.to_string()))
                    }
                    Some(_) if !info.stray_slots.is_empty() => fail(
                        "luks:tpm",
                        format!(
                            "there are passphrase slots not bound to any token ({}): their passphrase unlocks the data partition; they are removed once escrow and pcrlock are done",
                            info.stray_slots
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    ),
                    Some(_) => ok("luks:tpm", None),
                    None => fail("luks:tpm", NO_TPM_SLOT),
                };
                let no_tpm = info.tpm2.is_none();
                let recovery = if no_tpm {
                    fail("luks:recovery", NO_TPM_SLOT_SHORT)
                } else if info.has_recovery {
                    ok("luks:recovery", None)
                } else {
                    fail("luks:recovery", "no recovery key slot yet")
                };
                let escrow = if no_tpm {
                    fail("luks:escrow", NO_TPM_SLOT_SHORT)
                } else if is_escrowed
                    && info.has_recovery
                    && self.mode == EscrowMode::Wait(WAIT_BAD_RECIPIENTS)
                {
                    // Escrowed earlier, but the accepted bundle's recipients are invalid: a kit
                    // change cannot be followed until they are fixed — say so, not ok.
                    fail("luks:escrow", self.wait_detail.clone().unwrap_or_default())
                } else if is_escrowed && info.has_recovery {
                    // 这项修正之前托管的机器没有 HeldKey（复审 M8）：托管本身是好的，但本机没有不靠 TPM 的钥匙，
                    // 下次换 PCR 签名钥匙时换不了槽——在 detail 里说清楚，不当成普通的「好」。
                    let held = load_held(&self.cx.paths)
                        .ok()
                        .flatten()
                        .is_some_and(|h| h.luks_uuid == info.uuid);
                    let mut d = format!("luks {}", info.uuid);
                    if !held {
                        d.push_str(NO_HELD_KEY);
                    }
                    ok("luks:escrow", Some(d))
                } else {
                    fail("luks:escrow", "the recovery key is not escrowed yet")
                };
                let pcrlock = match &info.tpm2 {
                    Some(t) if t.sealed() && !self.secure_boot => {
                        fail("luks:pcrlock", NO_SB_REPAIR)
                    }
                    Some(t) if t.sealed() => match &self.shim {
                        Some(crate::shim_predict::Followup::PrepareFailed(why)) => {
                            fail("luks:pcrlock", crate::shim_predict::failed_detail(why))
                        }
                        Some(crate::shim_predict::Followup::Mispredicted) => {
                            fail("luks:pcrlock", crate::shim_predict::MISPREDICTED_DETAIL)
                        }
                        // never instead of a PIN repair in this round (the repair's detail must stay visible)
                        Some(crate::shim_predict::Followup::Completed) if repaired.is_none() => ok(
                            "luks:pcrlock",
                            Some(crate::shim_predict::DONE_DETAIL.to_string()),
                        ),
                        _ => ok(
                            "luks:pcrlock",
                            repaired.map(|()| "the policy service had failed; the policy was rewritten with the PIN".to_string()),
                        ),
                    },
                    None => fail("luks:pcrlock", NO_TPM_SLOT_SHORT),
                    _ if self.waiting_policy => fail(
                        "luks:pcrlock",
                        format!("waiting for the pcrlock policy: {PCRLOCK_POLICY} does not exist yet (generated at boot)"),
                    ),
                    Some(_) if is_escrowed && !self.secure_boot => fail("luks:pcrlock", NO_SB_BIND),
                    Some(_) if !is_escrowed => fail(
                        "luks:pcrlock",
                        "pcrlock is not bound until escrow of the recovery key is confirmed: the data partition is protected only by the signed PCR 11 for now",
                    ),
                    Some(_) => fail("luks:pcrlock", "the TPM slot is not signed PCR 11 + pcrlock yet"),
                };
                vec![tpm, recovery, escrow, pcrlock]
            }
        };
        for e in errs {
            match items.iter_mut().find(|r| r.item == e.item) {
                Some(r) => *r = fail(e.item, e.detail),
                None => items.insert(0, fail(e.item, e.detail)),
            }
        }
        items
    }
}

/// TPM 槽已是期望的样子（签名 PCR 11 + pcrlock）：pcrlock 策略坏了会让它解不开，值得修。
fn is_sealed(info: &LuksInfo) -> bool {
    info.tpm2.as_ref().is_some_and(Tpm2Token::sealed)
}

fn var_dir(paths: &crate::system::SysPaths) -> Result<std::os::fd::OwnedFd> {
    let dir = safefs::open_abs_dir(&paths.var_dir, true)?;
    safefs::set_mode(&dir, 0o700)?;
    Ok(dir)
}

fn state_dir(paths: &crate::system::SysPaths) -> Result<std::os::fd::OwnedFd> {
    let dir = safefs::open_abs_dir(&paths.state_dir, true)?;
    safefs::set_mode(&dir, 0o700)?;
    Ok(dir)
}

/// 只有「不存在」是 None；目录打不开、读不了、解析不了都报错（调用方整轮不动分区）。
fn load_pending(paths: &crate::system::SysPaths) -> Result<Option<Pending>> {
    let Some(bytes) = safefs::read_at(&var_dir(paths)?, PENDING_FILE)
        .with_context(|| format!("reading {PENDING_FILE}"))?
    else {
        return Ok(None);
    };
    // serde 的错误信息可能带字段的值（恢复密钥），只报行号。
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("parsing {PENDING_FILE} failed (line {})", e.line()))
}

fn save_pending(paths: &crate::system::SysPaths, p: &Pending) -> Result<()> {
    let dir = var_dir(paths)?;
    safefs::write_at(&dir, PENDING_FILE, &serde_json::to_vec(p)?, 0o600)?;
    Ok(())
}

/// [`EscrowDone`]: only "does not exist" is None; unreadable or unparsable is an error (the
/// round leaves the partition alone, as with the other state files).
fn load_done(paths: &crate::system::SysPaths) -> Result<Option<EscrowDone>> {
    let Some(bytes) = safefs::read_at(&var_dir(paths)?, ESCROW_DONE_FILE)
        .with_context(|| format!("reading {ESCROW_DONE_FILE}"))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("parsing {ESCROW_DONE_FILE} failed"))
}

fn save_done(paths: &crate::system::SysPaths, d: &EscrowDone) -> Result<()> {
    let dir = var_dir(paths)?;
    safefs::write_at(&dir, ESCROW_DONE_FILE, &serde_json::to_vec(d)?, 0o600)?;
    Ok(())
}

fn remove_pending(paths: &crate::system::SysPaths) -> Result<()> {
    safefs::remove_at(&var_dir(paths)?, PENDING_FILE)
}

/// agent 保管的那把恢复密钥（`HeldKey`）。只有「不存在」是 None；读不了、解析不了都报错
/// （调用方整轮不动分区，同 `load_pending`）。serde 的错误可能带密钥，只报行号。
fn load_held(paths: &crate::system::SysPaths) -> Result<Option<HeldKey>> {
    let Some(bytes) = safefs::read_at(&var_dir(paths)?, HELD_KEY_FILE)
        .with_context(|| format!("reading {HELD_KEY_FILE}"))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("parsing {HELD_KEY_FILE} failed (line {})", e.line()))
}

fn save_held(paths: &crate::system::SysPaths, h: &HeldKey) -> Result<()> {
    let dir = var_dir(paths)?;
    safefs::write_at(&dir, HELD_KEY_FILE, &serde_json::to_vec(h)?, 0o600)?;
    Ok(())
}

/// 首次开机 / 恢复出厂时 initrd 放下的 32 字节临时钥匙。存在且恰好 32 字节才返回；长度不对当作没有
/// （不报错）；读不出（不是「不存在」）报错——整轮不动分区。
fn load_bootstrap_key(paths: &crate::system::SysPaths) -> Result<Option<Vec<u8>>> {
    let Some(b) = safefs::read_at(&var_dir(paths)?, BOOTSTRAP_KEY_FILE)
        .with_context(|| format!("reading {BOOTSTRAP_KEY_FILE}"))?
    else {
        return Ok(None);
    };
    Ok((b.len() == 32).then_some(b))
}

fn remove_bootstrap_key(paths: &crate::system::SysPaths) -> Result<()> {
    safefs::remove_at(&var_dir(paths)?, BOOTSTRAP_KEY_FILE)
}

fn remove_held(paths: &crate::system::SysPaths) -> Result<()> {
    safefs::remove_at(&var_dir(paths)?, HELD_KEY_FILE)
}

/// initrd 的 `/run/mastersos/luks-bootstrap-key`（相对系统根）。持久化单元每条路径都删它；万一它没跑成，
/// 这份会随 /run 带进用户态——agent 每轮开始删掉（目录不在就什么都不做）。
const RUN_BOOTSTRAP_DIR: &str = "run/mastersos";

fn remove_run_bootstrap_copy(paths: &crate::system::SysPaths) {
    match safefs::open_dir(&paths.root, std::path::Path::new(RUN_BOOTSTRAP_DIR), false) {
        Ok(d) => {
            if let Err(e) = safefs::remove_at(&d, BOOTSTRAP_KEY_FILE) {
                log::error!("removing the leftover temporary key in /run failed: {e:#}");
            }
        }
        Err(e) if crate::apply::is_not_found(&e) => {}
        Err(e) => log::error!("opening /run/mastersos failed: {e:#}"),
    }
}

/// 这个镜像的 PCR 公钥，base64 的 PEM 文本（与 luksDump 的 `tpm2_pubkey` 同编码）。读不到为 None。
fn image_pubkey_b64(root: &std::path::Path) -> Option<String> {
    std::fs::read(root.join(TPM2_PUBKEY.trim_start_matches('/')))
        .ok()
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
}

/// 不存在为默认值（没托管过）；目录打不开（含收紧权限失败）、读不了、解析不了都报错——把它们当成
/// 「没托管过」会让下一步重新登记、动已托管的恢复槽。
pub fn load_luks_state(paths: &crate::system::SysPaths) -> Result<LuksState> {
    match safefs::read_at(&var_dir(paths)?, LUKS_STATE_FILE)
        .with_context(|| format!("reading {LUKS_STATE_FILE}"))?
    {
        None => Ok(LuksState::default()),
        Some(b) => {
            serde_json::from_slice(&b).with_context(|| format!("parsing {LUKS_STATE_FILE} failed"))
        }
    }
}

/// 删掉上一次被杀在半路时可能留在凭据目录里的 PIN（目录不在就什么都不做）。
fn remove_stale_credential(paths: &crate::system::SysPaths) {
    match safefs::open_dir(&paths.root, std::path::Path::new(CRED_DIR), false) {
        Ok(d) => {
            if let Err(e) = safefs::remove_at(&d, CRED_NAME) {
                log::error!("removing the leftover PIN credential failed: {e:#}");
            }
        }
        Err(e) if crate::apply::is_not_found(&e) => {}
        Err(e) => log::error!("opening the credential directory failed: {e:#}"),
    }
}

fn save_luks_state(paths: &crate::system::SysPaths, s: &LuksState) -> Result<()> {
    let dir = var_dir(paths)?;
    safefs::write_at(&dir, LUKS_STATE_FILE, &serde_json::to_vec_pretty(s)?, 0o600)?;
    Ok(())
}

/// 32 字节随机数的 hex（PIN 经 ask-password 的凭据读入，是一行文本）。
fn new_pin() -> Result<String> {
    let mut b = [0u8; 32];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| anyhow!("getting random bytes failed"))?;
    Ok(crate::apply::hex(&b))
}

fn write_pin(paths: &crate::system::SysPaths, pin: &str) -> Result<()> {
    safefs::write_at(&state_dir(paths)?, PCRLOCK_PIN, pin.as_bytes(), 0o600)?;
    Ok(())
}

pub(crate) fn read_pin(paths: &crate::system::SysPaths) -> Result<Option<String>> {
    let Some(b) = safefs::read_at(&state_dir(paths)?, PCRLOCK_PIN)? else {
        return Ok(None);
    };
    let pin = String::from_utf8(b).map_err(|_| anyhow!("the PIN file is not text"))?;
    let pin = pin.trim().to_string();
    if pin.is_empty() {
        return Ok(None);
    }
    Ok(Some(pin))
}

/// `make-policy --location=770 --pcr=7 --recovery-pin=query` with the PIN passed through the credentials directory
/// `<root>/<cred_rel>` (never on the command line or in the environment). The credential is removed either way.
pub(crate) fn make_policy_with_pin_blocking(
    r: &dyn Runner,
    paths: &crate::system::SysPaths,
    cred_rel: &str,
    pin: &str,
) -> Result<()> {
    let cred = safefs::open_dir(&paths.root, std::path::Path::new(cred_rel), true)
        .context("creating the credentials directory")?;
    safefs::set_mode(&cred, 0o700)?;
    safefs::remove_at(&cred, CRED_NAME).context("removing an old PIN credential")?;
    safefs::write_at(&cred, CRED_NAME, pin.as_bytes(), 0o600)
        .context("writing the PIN credential")?;
    let dir = paths.root.join(cred_rel);
    let env = format!("CREDENTIALS_DIRECTORY={}", dir.display());
    let mut args = vec![env.as_str(), PCRLOCK_BIN];
    args.extend_from_slice(MAKE_POLICY_ARGS);
    args.push("--recovery-pin=query");
    let res = run_ok_redacted(r, Cmd::new("env", &args));
    if let Err(e) = safefs::remove_at(&cred, CRED_NAME) {
        log::error!("removing the PIN credential: {e:#}");
    }
    res.map(|_| ())
        .context("making the pcrlock policy with the PIN failed")
}

/// 这个镜像是不是 lab profile：看签名的 `/usr` 里构建时写下的 `/usr/lib/mastersos/profile`（`mkosi.finalize`
/// 写 `lab` 或 `release`，安装器也读它）。读不到或内容不是 `lab` 一律按正式镜像。
pub fn image_is_lab(root: &std::path::Path) -> bool {
    std::fs::read_to_string(root.join(IMAGE_PROFILE.trim_start_matches('/')))
        .is_ok_and(|s| s.trim() == "lab")
}

#[cfg(test)]
mod tests;

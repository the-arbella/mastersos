use super::*;
use crate::fetch::Fetcher;
use crate::jobs::CurrentGroup;
use crate::runner::FakeRunner;
use crate::seedpart::Identity;
use crate::system::tests::{paths, tmp_root};
use crate::system::SysPaths;
use mastersos_bundle::{DeviceIdent, Seed};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// VM 168（镜像 20261013.13）上抓的真实 luksDump：首次开机（TPM 槽只绑签名的 PCR 11）、登记恢复密钥
/// 之后、补上 pcrlock 之后。恢复密钥本身不在里面（luksDump 只有盐与摘要）。4b 起 repart 用
/// Encrypt=key-file+tpm2 建分区，首次开机还多一个不属于任何 token 的临时钥匙槽（下面 `with_bootstrap`）。
const FIRST_BOOT: &str = include_str!("../../tests/fixtures/luksdump-first-boot.json");
const RECOVERY: &str = include_str!("../../tests/fixtures/luksdump-recovery.json");
const SEALED: &str = include_str!("../../tests/fixtures/luksdump-sealed.json");
/// 没有 TPM2 槽的分区（4a 在没有 TPM 的机器上建的空口令 LUKS2；4b 起安装器拒装这种机器，不会再有）。
const EMPTY: &str = include_str!("../../tests/fixtures/luksdump-empty-passphrase.json");
const EMPTY_REC: &str =
    include_str!("../../tests/fixtures/luksdump-empty-passphrase-recovery.json");

const UUID: &str = "f9fd9985-7280-4c3d-bab4-f132ac2336f2";
const OLD_UUID: &str = "0b0b0b0b-1111-4222-8333-444455556666";
const KEY: &str = "fhkebvrd-cgvhkfrb-jinlnrtu-vbcdefgh-ijklnrtu-vbcdefgh-ijklnrtu-vbcdefgh";
const DEV: &str = "/dev/gpt-auto-root-luks";
/// 首次开机的 32 字节临时钥匙（测试用固定值）。
const BOOT: [u8; 32] = [7u8; 32];
/// 用户态不再用 TPM 解锁：所有 cryptenroll 都经 stdin 送钥匙。
const ENROLL: &str =
    "systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key /dev/gpt-auto-root-luks";
const BIND: &str = "systemd-cryptenroll --unlock-key-file=/dev/stdin --wipe-slot=tpm2 \
--tpm2-device=auto --tpm2-public-key=/usr/lib/systemd/tpm2-pcr-public-key.pem \
--tpm2-public-key-pcrs=11 --tpm2-pcrs= --tpm2-pcrlock=/var/lib/systemd/pcrlock.json \
/dev/gpt-auto-root-luks";

/// 这些 fixture 的 TPM 槽用的 PCR 公钥（base64 的 PEM）：把它当成「这个镜像的公钥」，fixture 就是本镜像签的。
fn img_pubkey_b64() -> String {
    let v: Value = serde_json::from_str(FIRST_BOOT).unwrap();
    v["tokens"]["0"]["tpm2_pubkey"]
        .as_str()
        .unwrap()
        .to_string()
}

fn info(dump: &str) -> LuksInfo {
    parse_luks_dump(dump, UUID, Some(&img_pubkey_b64())).unwrap()
}

/// 在某个 dump 上加一个不属于任何 token 的 keyslot（首次开机 repart 用临时钥匙加的那个），编号 `n`。
fn add_stray(base: &str, n: &str) -> String {
    let mut v: Value = serde_json::from_str(base).unwrap();
    let ks = v["keyslots"].as_object().unwrap();
    let any = ks.values().next().unwrap().clone();
    v["keyslots"][n] = any;
    v.to_string()
}

#[test]
fn parses_first_boot_dump() {
    let i = info(FIRST_BOOT);
    assert_eq!(i.uuid, UUID);
    let t = i.tpm2.as_ref().unwrap();
    assert_eq!(t.pubkey_pcrs, vec![11]);
    assert!(!t.pcrlock);
    assert!(t.literal_pcrs.is_empty());
    assert!(t.pubkey_is_image, "fixture 的公钥当成本镜像的");
    assert!(!i.has_recovery);
}

#[test]
fn parses_sealed_dump() {
    let i = info(SEALED);
    let t = i.tpm2.as_ref().unwrap();
    assert!(t.pcrlock && i.has_recovery);
    assert_eq!(t.pubkey_pcrs, vec![11]);
    assert!(t.sealed());
    let r = info(RECOVERY);
    assert!(r.has_recovery && !r.tpm2.unwrap().pcrlock);
}

#[test]
fn parses_dump_without_tpm2_slot() {
    let i = info(EMPTY);
    assert!(i.tpm2.is_none() && !i.has_recovery);
    let r = info(EMPTY_REC);
    assert!(r.tpm2.is_none() && r.has_recovery);
}

/// TPM 槽绑的不是这个镜像的公钥（换过签名钥匙，slot 绑着退役的那把）：pubkey_is_image 为假、sealed() 为假。
#[test]
fn retired_pubkey_is_not_sealed() {
    // image_pubkey = None（读不到镜像公钥）：任何 TPM 槽都不算本镜像的
    let i = parse_luks_dump(SEALED, UUID, None).unwrap();
    let t = i.tpm2.as_ref().unwrap();
    assert!(!t.pubkey_is_image && !t.sealed());
    // image_pubkey 与 dump 里的不同：同样不是本镜像的
    let i = parse_luks_dump(SEALED, UUID, Some("some-other-key")).unwrap();
    assert!(!i.tpm2.unwrap().pubkey_is_image);
}

#[test]
fn never_literal_pcr7() {
    for d in [FIRST_BOOT, RECOVERY, SEALED] {
        let t = info(d).tpm2.unwrap();
        assert!(!t.literal_pcrs.contains(&7), "{t:?}");
        assert!(t.literal_pcrs.is_empty(), "{t:?}");
    }
}

#[test]
fn parse_rejects_bad_uuid_and_bad_json() {
    assert!(parse_luks_dump(FIRST_BOOT, "not-a-uuid", None).is_err());
    assert!(parse_luks_dump("{", UUID, None).is_err());
    assert!(parse_luks_dump("{}", UUID, None).is_err());
    let i = parse_luks_dump(FIRST_BOOT, &format!("{}\n", UUID.to_uppercase()), None).unwrap();
    assert_eq!(i.uuid, UUID);
}

/// 多个 TPM2 token 时看「最差」的那个：有一个不是 pcrlock 就要补。
#[test]
fn worst_tpm2_token_wins() {
    let mut v: Value = serde_json::from_str(SEALED).unwrap();
    let toks = v["tokens"].as_object_mut().unwrap();
    let mut old = toks["2"].clone();
    old["tpm2_pcrlock"] = Value::Bool(false);
    toks.insert("9".into(), old);
    let i = parse_luks_dump(&v.to_string(), UUID, Some(&img_pubkey_b64())).unwrap();
    assert!(!i.tpm2.unwrap().pcrlock);
}

#[test]
fn extracts_recovery_key_from_cryptenroll_output() {
    assert_eq!(
        extract_recovery_key(&format!("{KEY}\n")).as_deref(),
        Some(KEY)
    );
    let chatty = format!(
        "A secret recovery key has been generated for this volume:\n\n    🔐 \x1b[0;1;39m{KEY}\x1b[0m\n\nPlease save this secret recovery key at a secure location.\n"
    );
    assert_eq!(extract_recovery_key(&chatty).as_deref(), Some(KEY));
    assert_eq!(
        extract_recovery_key("New recovery key enrolled as key slot 1.\n"),
        None
    );
    assert_eq!(extract_recovery_key(""), None);
    assert_eq!(extract_recovery_key(&KEY[..62]), None);
    assert_eq!(extract_recovery_key(&KEY.replace('f', "a")), None);
    let other = KEY.replace("fhkebvrd", "ccccdddd");
    assert_eq!(extract_recovery_key(&format!("{KEY}\n{other}\n")), None);
}

fn pending(uuid: &str) -> Pending {
    Pending {
        luks_uuid: uuid.into(),
        recovery_key: KEY.into(),
        replaces_slots: vec![],
        sealed: None,
    }
}

#[test]
fn next_step_table() {
    let first = info(FIRST_BOOT);
    let rec = info(RECOVERY);
    let sealed = info(SEALED);
    let empty = info(EMPTY);
    let p = pending(UUID);
    // 1. 没有 TPM2 槽
    assert_eq!(next_step(&empty, None, None, Redo::None), Need::NoTpmSlot);
    assert_eq!(
        next_step(&info(EMPTY_REC), Some(&p), Some(UUID), Redo::None),
        Need::NoTpmSlot
    );
    // 2. 这个分区有待托管的密钥
    assert_eq!(next_step(&rec, Some(&p), None, Redo::None), Need::Escrow);
    assert_eq!(
        next_step(&sealed, Some(&p), Some(UUID), Redo::None),
        Need::Escrow
    );
    assert_eq!(
        next_step(&rec, Some(&pending(OLD_UUID)), None, Redo::None),
        Need::EnrollRecovery
    );
    // 3. 没托管过 / 托管的是别的分区 / 恢复槽没了
    assert_eq!(
        next_step(&first, None, None, Redo::None),
        Need::EnrollRecovery
    );
    assert_eq!(
        next_step(&rec, None, None, Redo::None),
        Need::EnrollRecovery
    );
    assert_eq!(
        next_step(&rec, None, Some(OLD_UUID), Redo::None),
        Need::EnrollRecovery
    );
    assert_eq!(
        next_step(&first, None, Some(UUID), Redo::None),
        Need::EnrollRecovery
    );
    // 4. 托管过、TPM 槽还不是签名 PCR 11 + pcrlock
    assert_eq!(
        next_step(&rec, None, Some(UUID), Redo::None),
        Need::AddPcrlock
    );
    let mut wrong = sealed.clone();
    wrong.tpm2.as_mut().unwrap().pubkey_pcrs = vec![7, 11];
    assert_eq!(
        next_step(&wrong, None, Some(UUID), Redo::None),
        Need::AddPcrlock
    );
    // 4b. 托管过、TPM 槽绑的是退役的公钥（换过签名钥匙）→ 也要补（换槽）
    let retired = parse_luks_dump(SEALED, UUID, Some("other")).unwrap();
    assert_eq!(
        next_step(&retired, None, Some(UUID), Redo::None),
        Need::AddPcrlock
    );
    // 5. 都好了
    assert_eq!(
        next_step(&sealed, None, Some(UUID), Redo::None),
        Need::Nothing
    );
    // Recipients changed since the escrow: rotate, ahead of pcrlock and stray slots; a pending
    //    key or a partition not yet escrowed comes first.
    assert_eq!(
        next_step(&sealed, None, Some(UUID), Redo::Rotate),
        Need::Rotate
    );
    assert_eq!(
        next_step(&rec, None, Some(UUID), Redo::Rotate),
        Need::Rotate
    );
    assert_eq!(
        next_step(&sealed, Some(&p), Some(UUID), Redo::Rotate),
        Need::Escrow
    );
    assert_eq!(
        next_step(&rec, None, None, Redo::Rotate),
        Need::EnrollRecovery
    );
    assert_eq!(
        next_step(&empty, None, Some(UUID), Redo::Rotate),
        Need::NoTpmSlot
    );
}

#[test]
fn pcrlock_is_never_added_before_escrow() {
    let first = info(FIRST_BOOT);
    assert_eq!(
        next_step(&first, None, None, Redo::None),
        Need::EnrollRecovery
    );
    assert_eq!(
        next_step(&info(RECOVERY), Some(&pending(UUID)), None, Redo::None),
        Need::Escrow
    );
    let dumps = [FIRST_BOOT, RECOVERY, SEALED, EMPTY, EMPTY_REC];
    let pendings = [None, Some(pending(UUID)), Some(pending(OLD_UUID))];
    for d in dumps {
        let i = info(d);
        for p in &pendings {
            for e in [None, Some(OLD_UUID)] {
                for r in [Redo::None, Redo::Rotate] {
                    assert_ne!(
                        next_step(&i, p.as_ref(), e, r),
                        Need::AddPcrlock,
                        "{i:?} {p:?} {e:?} {r:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn luks_device_is_gpt_auto_not_partlabel() {
    assert_eq!(ROOT_LUKS_DEV, "/dev/gpt-auto-root-luks");
}

#[test]
fn pending_and_held_debug_hide_key() {
    assert!(!format!("{:?}", pending(UUID)).contains(KEY));
    let h = HeldKey {
        luks_uuid: UUID.into(),
        recovery_key: KEY.into(),
    };
    assert!(!format!("{h:?}").contains(KEY));
}

#[test]
fn unlock_key_prefers_held_then_pending_then_bootstrap() {
    let dir = tmp_root();
    let p = paths(dir.path());
    let first = info(FIRST_BOOT);
    // 都没有 → None
    assert!(unlock_key(&p, &first, None).unwrap().is_none());
    // 只有临时钥匙 → Bootstrap
    std::fs::create_dir_all(&p.var_dir).unwrap();
    std::fs::write(p.var_dir.join(BOOTSTRAP_KEY_FILE), BOOT).unwrap();
    let (k, b) = unlock_key(&p, &first, None).unwrap().unwrap();
    assert_eq!(k, UnlockKey::Bootstrap);
    assert_eq!(b, BOOT.to_vec());
    // 临时钥匙长度不对 → 当作没有
    std::fs::write(p.var_dir.join(BOOTSTRAP_KEY_FILE), b"short").unwrap();
    assert!(unlock_key(&p, &first, None).unwrap().is_none());
    std::fs::write(p.var_dir.join(BOOTSTRAP_KEY_FILE), BOOT).unwrap();
    // 有这个分区的待托管密钥 → Pending（优先于 Bootstrap）
    let (k, b) = unlock_key(&p, &first, Some(&pending(UUID)))
        .unwrap()
        .unwrap();
    assert_eq!(k, UnlockKey::Pending);
    assert_eq!(b, KEY.as_bytes());
    // 别的分区的待托管不算
    let (k, _) = unlock_key(&p, &first, Some(&pending(OLD_UUID)))
        .unwrap()
        .unwrap();
    assert_eq!(k, UnlockKey::Bootstrap);
    // HeldKey（UUID 对得上）优先于一切
    save_held(
        &p,
        &HeldKey {
            luks_uuid: UUID.into(),
            recovery_key: KEY.into(),
        },
    )
    .unwrap();
    let (k, b) = unlock_key(&p, &first, Some(&pending(UUID)))
        .unwrap()
        .unwrap();
    assert_eq!(k, UnlockKey::Held);
    assert_eq!(b, KEY.as_bytes());
    // HeldKey 是别的分区的 → 不用它
    save_held(
        &p,
        &HeldKey {
            luks_uuid: OLD_UUID.into(),
            recovery_key: KEY.into(),
        },
    )
    .unwrap();
    let (k, _) = unlock_key(&p, &first, None).unwrap().unwrap();
    assert_eq!(k, UnlockKey::Bootstrap);
}

// ---------- 任务（FakeRunner + wiremock 当托管服务端） ----------

struct Lab {
    _dir: tempfile::TempDir,
    paths: SysPaths,
    fake: Arc<FakeRunner>,
    cx: JobCtx,
    srv: MockServer,
    /// What the main loop publishes: by default a bundle with [`lab_recipients`].
    cur_tx: tokio::sync::watch::Sender<Option<Arc<CurrentGroup>>>,
}

/// An age X25519 escrow recipient of a test kit.
fn recipient(b: u8) -> String {
    mastersos_bundle::kit::Kit::from_master(&[b; 32]).escrow_recipient()
}

/// The escrow recipients of the bundle a [`lab`] starts with.
fn lab_recipients() -> Vec<String> {
    vec![recipient(1), recipient(2)]
}

fn lab_fp() -> String {
    mastersos_bundle::recipients_fp(&lab_recipients())
}

fn current(recipients: Vec<String>) -> Arc<CurrentGroup> {
    let mut m =
        mastersos_bundle::Manifest::parse("version = 1\n[[group]]\nid = \"a\"\nname = \"a\"\n")
            .unwrap();
    Arc::new(CurrentGroup {
        version: 1,
        group: m.groups.remove(0),
        config: mastersos_bundle::effective_config(&m, &m.configs[0]),
        escrow_recipients: recipients,
    })
}

async fn lab() -> Lab {
    let dir = tmp_root();
    let paths = paths(dir.path());
    mark_lab(&paths.root);
    write_image_pubkey(&paths.root);
    let srv = MockServer::start().await;
    let fake = Arc::new(FakeRunner::new());
    let (cur_tx, cur_rx) = tokio::sync::watch::channel(Some(current(lab_recipients())));
    let seed = Seed {
        server_url: srv.uri(),
        trust: vec![],
        fetch_token: Some("tok".into()),
        group: None,
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    };
    let cx = JobCtx {
        fetcher: Fetcher::from_seed(&seed),
        ident: DeviceIdent {
            serial: Some("PF-1".into()),
            device_id: "dev-1".into(),
        },
        paths: paths.clone(),
        runner: fake.clone(),
        identity: Some(Identity {
            device_id: "dev-1".into(),
            escrow_secret: "A".repeat(43),
        }),
        current: cur_rx,
        reapply: Default::default(),
        fetch_error: tokio::sync::watch::channel(None).1,
    };
    Lab {
        _dir: dir,
        paths,
        fake,
        cx,
        srv,
        cur_tx,
    }
}

fn mark_lab(root: &Path) {
    let p = root.join(IMAGE_PROFILE.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, "lab\n").unwrap();
}

/// 把 fixture 的 PCR 公钥写成镜像里的 `/usr/lib/systemd/tpm2-pcr-public-key.pem`，让 Round 算出的
/// image_pubkey 与 fixture 的 tpm2_pubkey 相同（fixture 就是「本镜像」签的）。
fn write_image_pubkey(root: &Path) {
    let pem = base64::engine::general_purpose::STANDARD
        .decode(img_pubkey_b64())
        .unwrap();
    let p = root.join(TPM2_PUBKEY.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, pem).unwrap();
}

impl Lab {
    fn release(&self) {
        std::fs::remove_file(self.paths.root.join(IMAGE_PROFILE.trim_start_matches('/'))).unwrap();
    }

    /// 放下首次开机的临时钥匙（32 字节，var_dir）。
    fn bootstrap(&self) {
        std::fs::create_dir_all(&self.paths.var_dir).unwrap();
        std::fs::write(self.paths.var_dir.join(BOOTSTRAP_KEY_FILE), BOOT).unwrap();
    }

    fn dumps(&self, uuid: &str, dumps: &[&str]) {
        for d in dumps {
            self.fake
                .respond("cryptsetup luksUUID", Output::ok(&format!("{uuid}\n")));
            self.fake.respond("cryptsetup luksDump", Output::ok(d));
        }
    }

    fn escrow_status(&self, code: u16) -> Mock {
        let mut r = ResponseTemplate::new(code);
        if code == 403 {
            r = r.set_body_json(serde_json::json!({"error": {"code": "forbidden",
                "message": "这台机器的托管凭据与登记的不同；IT 可在面板上重置"}}));
        }
        if code == 429 {
            r = r.set_body_json(serde_json::json!({"error": {"code": "too_many_keys",
                "message": "这台机器托管的恢复密钥已到上限"}}));
        }
        Mock::given(method("POST"))
            .and(path("/v1/escrow"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(r)
    }

    fn policy_exists(&self) {
        let p = self.paths.root.join("var/lib/systemd/pcrlock.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "{}").unwrap();
    }

    async fn round(&self) -> Vec<ItemResult> {
        self.fake.respond(
            "bootctl status",
            Output::ok("    Secure Boot: enabled (user)\n"),
        );
        LuksJob::new(self.fake.clone()).run(&self.cx).await
    }

    async fn round_sb_off(&self) -> Vec<ItemResult> {
        self.fake.respond(
            "bootctl status",
            Output::ok("    Secure Boot: disabled (setup)\n"),
        );
        LuksJob::new(self.fake.clone()).run(&self.cx).await
    }

    /// Escrowed: luks-state names this partition and escrow-done the lab's recipients.
    fn escrowed(&self) {
        save_luks_state(
            &self.paths,
            &LuksState {
                escrowed_luks_uuid: Some(UUID.into()),
            },
        )
        .unwrap();
        self.done(&lab_fp());
    }

    fn done(&self, fp: &str) {
        save_done(
            &self.paths,
            &EscrowDone {
                recipients_fp: fp.into(),
                luks_uuid: UUID.into(),
            },
        )
        .unwrap();
    }

    fn set_current(&self, c: Option<Arc<CurrentGroup>>) {
        self.cur_tx.send_replace(c);
    }

    fn done_path(&self) -> std::path::PathBuf {
        self.paths.var_dir.join(ESCROW_DONE_FILE)
    }

    fn load_pending(&self) -> Pending {
        serde_json::from_slice(&std::fs::read(self.pending_path()).unwrap()).unwrap()
    }

    /// The JSON bodies of every escrow request this lab's server received.
    async fn escrow_bodies(&self) -> Vec<Vec<u8>> {
        self.srv
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/v1/escrow")
            .map(|r| r.body)
            .collect()
    }

    /// 已托管：luks-state 记下 UUID，并保管这把恢复密钥（HeldKey）。
    fn held(&self) {
        self.escrowed();
        save_held(
            &self.paths,
            &HeldKey {
                luks_uuid: UUID.into(),
                recovery_key: KEY.into(),
            },
        )
        .unwrap();
    }

    fn pending_path(&self) -> std::path::PathBuf {
        self.paths.var_dir.join(PENDING_FILE)
    }

    fn held_path(&self) -> std::path::PathBuf {
        self.paths.var_dir.join(HELD_KEY_FILE)
    }

    fn bootstrap_path(&self) -> std::path::PathBuf {
        self.paths.var_dir.join(BOOTSTRAP_KEY_FILE)
    }

    fn calls_with(&self, needle: &str) -> Vec<String> {
        self.fake
            .calls()
            .into_iter()
            .filter(|c| c.contains(needle))
            .collect()
    }
}

fn item<'a>(r: &'a [ItemResult], name: &str) -> &'a ItemResult {
    r.iter()
        .find(|i| i.item == name)
        .unwrap_or_else(|| panic!("没有 {name}：{r:?}"))
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

/// 首次开机：只有 TPM 槽 + 临时钥匙槽、var_dir 有 luks-bootstrap-key → 用临时钥匙解锁登记恢复密钥；
/// 所有 cryptenroll 都经 stdin 送钥匙解锁（不靠 TPM），stdin 是那 32 字节临时钥匙。
#[tokio::test]
async fn first_enroll_unlocks_with_bootstrap_key() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(500).expect(1).mount(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    // 登记用临时钥匙解锁：stdin 是那 32 字节
    assert_eq!(l.fake.stdin_of(ENROLL).as_deref(), Some(BOOT.as_slice()));
    // 待托管文件在、0600、就是这把密钥
    let p: Pending = serde_json::from_slice(&std::fs::read(l.pending_path()).unwrap()).unwrap();
    assert_eq!((p.luks_uuid.as_str(), p.recovery_key.as_str()), (UUID, KEY));
    assert_eq!(mode(&l.pending_path()), 0o600);
    // 用 stdin 送钥匙解锁（不靠 TPM）
    for c in l.calls_with("systemd-cryptenroll") {
        assert!(c.contains("--unlock-key-file=/dev/stdin"), "{c}");
    }
    assert!(!item(&r, "luks:escrow").ok);
}

/// 托管成功之后：保管成 HeldKey（0600）、删掉待托管文件；去掉旧恢复槽用的是这把（经 stdin）。
#[tokio::test]
async fn escrow_keeps_key_as_held_then_removes_pending() {
    let l = lab().await;
    // 已有一个旧恢复槽（槽 1），登记新的（槽 3）后托管，再按编号去掉旧的
    save_pending(
        &l.paths,
        &Pending {
            luks_uuid: UUID.into(),
            recovery_key: KEY.into(),
            replaces_slots: vec![1],
            sealed: None,
        },
    )
    .unwrap();
    l.escrow_status(204).expect(1).mount(&l.srv).await;
    let two = add_stray(RECOVERY, "3"); // 槽 1 旧恢复 + 槽 3（这里用 stray 占位，escrow 只看 recovery_slots）
                                        // escrow 读当前 dump：recovery_slots 要含 1
    l.dumps(UUID, &[RECOVERY, &two]);
    let r = l.round().await;
    // HeldKey 在、0600、就是这把
    let h: HeldKey = serde_json::from_slice(&std::fs::read(l.held_path()).unwrap()).unwrap();
    assert_eq!((h.luks_uuid.as_str(), h.recovery_key.as_str()), (UUID, KEY));
    assert_eq!(mode(&l.held_path()), 0o600);
    // 待托管文件没了
    assert!(!l.pending_path().exists());
    // 去旧槽用这把（经 stdin），不靠 TPM
    let wipe = format!("systemd-cryptenroll --unlock-key-file=/dev/stdin --wipe-slot=1 {DEV}");
    assert_eq!(l.fake.stdin_of(&wipe).as_deref(), Some(KEY.as_bytes()));
    assert!(item(&r, "luks:escrow").ok, "{r:?}");
}

/// 补 pcrlock 用 HeldKey 解锁（托管之后本机保管的那把），命令行逐字核对；换槽经 stdin 是这把。
#[tokio::test]
async fn add_pcrlock_unlocks_with_held_key() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    l.dumps(UUID, &[RECOVERY, SEALED]);
    let r = l.round().await;
    let calls = l.fake.calls();
    assert!(calls.contains(&BIND.to_string()), "{calls:?}");
    assert_eq!(l.fake.stdin_of(BIND).as_deref(), Some(KEY.as_bytes()));
    for c in l.calls_with("systemd-cryptenroll") {
        assert!(c.contains("--unlock-key-file=/dev/stdin"), "{c}");
    }
    assert!(item(&r, "luks:pcrlock").ok, "{r:?}");
}

/// 多余的槽（含首次开机的临时钥匙槽）去掉之后，临时钥匙文件也删掉。
#[tokio::test]
async fn wipe_stray_removes_bootstrap_file_after_slot_gone() {
    let l = lab().await;
    l.held();
    l.bootstrap();
    // 已 sealed（新钥匙）+ 一个临时钥匙 stray 槽（槽 9）→ WipeStray
    let with_stray = add_stray(SEALED, "9");
    l.dumps(UUID, &[&with_stray, SEALED]);
    let r = l.round().await;
    let wipe = format!("systemd-cryptenroll --unlock-key-file=/dev/stdin --wipe-slot=9 {DEV}");
    assert!(l.fake.calls().contains(&wipe), "{:?}", l.fake.calls());
    assert_eq!(l.fake.stdin_of(&wipe).as_deref(), Some(KEY.as_bytes()));
    // 临时钥匙文件删掉了
    assert!(!l.bootstrap_path().exists());
    assert!(item(&r, "luks:tpm").ok, "{r:?}");
}

/// 三样钥匙都没有：luks:recovery 失败、说清楚、FakeRunner 没收到 systemd-cryptenroll。
#[tokio::test]
async fn no_unlock_key_reports_and_touches_nothing() {
    let l = lab().await;
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    // 首次开机的 dump（要登记），但 var_dir 没有任何钥匙
    l.dumps(UUID, &[FIRST_BOOT]);
    let r = l.round().await;
    assert!(
        l.calls_with("systemd-cryptenroll").is_empty(),
        "{:?}",
        l.fake.calls()
    );
    let rec = item(&r, "luks:recovery");
    assert!(
        !rec.ok && rec.detail.as_deref().unwrap().contains("请恢复出厂或重装"),
        "{rec:?}"
    );
    assert!(!l.pending_path().exists());
}

/// 换过签名钥匙：TPM 槽绑的是退役的公钥、已托管 → AddPcrlock，用 HeldKey 解锁换槽；luks:tpm 说明原因。
#[tokio::test]
async fn tpm_slot_bound_to_retired_pubkey_is_rebound() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    // SEALED 但 tpm2_pubkey 换成别的（退役的那把）：pubkey_is_image 为假
    let mut v: Value = serde_json::from_str(SEALED).unwrap();
    v["tokens"]["2"]["tpm2_pubkey"] = Value::String("retired-4phase-key".into());
    let retired = v.to_string();
    l.dumps(UUID, &[&retired, SEALED]);
    let r = l.round().await;
    // 已带 pcrlock、只是公钥不对：不动策略，直接换槽（BIND）、用 HeldKey
    let calls = l.fake.calls();
    assert!(calls.contains(&BIND.to_string()), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("remove-policy")));
    assert_eq!(l.fake.stdin_of(BIND).as_deref(), Some(KEY.as_bytes()));
    assert!(item(&r, "luks:tpm").ok, "换槽之后读到干净的分区：{r:?}");
}

/// 换过钥匙、还没换槽那一轮：luks:tpm 报「绑的是别的 PCR 公钥」。
#[tokio::test]
async fn retired_pubkey_reports_wrong_pubkey() {
    let l = lab().await;
    l.held();
    // 换槽失败（cryptenroll 报错），这一轮 summarize 看到的还是退役公钥的 dump
    let mut v: Value = serde_json::from_str(SEALED).unwrap();
    v["tokens"]["2"]["tpm2_pubkey"] = Value::String("retired".into());
    let retired = v.to_string();
    l.policy_exists();
    l.dumps(UUID, &[&retired, &retired]);
    l.fake
        .respond("systemd-cryptenroll", Output::fail(1, "nope"));
    let r = l.round().await;
    let t = item(&r, "luks:tpm");
    assert!(
        !t.ok && t.detail.as_deref().unwrap().contains("别的 PCR 公钥"),
        "{t:?}"
    );
}

/// 多余的槽只有首次开机的临时钥匙那一个（本机还留着钥匙文件）：luks:tpm 成功，detail 说临时钥匙槽还在。
/// 用首次开机那一轮（托管还没成功、临时钥匙槽还在）：luks:escrow 失败不影响 luks:tpm。
#[tokio::test]
async fn bootstrap_slot_reports_tpm_ok() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(500).mount(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    let t = item(&r, "luks:tpm");
    assert!(
        t.ok && t.detail.as_deref().unwrap().contains("临时钥匙槽还在"),
        "{t:?}"
    );
    assert!(!item(&r, "luks:escrow").ok);
}

/// HeldKey / 临时钥匙 / 恢复密钥都不进命令行、回报与日志（成功、托管失败几种）。
#[tokio::test]
async fn held_key_never_in_results_or_logs() {
    for escrow in [204u16, 403, 429, 500] {
        let l = lab().await;
        l.bootstrap();
        l.escrow_status(escrow).mount(&l.srv).await;
        l.policy_exists();
        let first = add_stray(FIRST_BOOT, "7");
        let rec = add_stray(RECOVERY, "7");
        let sealed_stray = add_stray(SEALED, "7");
        l.dumps(UUID, &[&first, &rec, &rec, &sealed_stray, SEALED]);
        l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
        let r = l.round().await;
        for i in &r {
            assert!(!i.detail.as_deref().unwrap_or("").contains(KEY), "{i:?}");
            assert!(!format!("{i:?}").contains(KEY));
        }
        for c in l.fake.calls() {
            assert!(!c.contains(KEY), "{c}");
        }
        // 临时钥匙的原始字节也不在命令行里（只经 stdin）
        let boot_hex = crate::apply::hex(&BOOT);
        for c in l.fake.calls() {
            assert!(!c.contains(&boot_hex), "{c}");
        }
    }
}

/// 不带 TPM 解锁：所有 cryptenroll 都带 --unlock-key-file=/dev/stdin。
#[tokio::test]
async fn all_cryptenroll_unlock_via_stdin() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(500).mount(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    l.round().await;
    let enroll = l.calls_with("systemd-cryptenroll");
    assert!(!enroll.is_empty());
    for c in enroll {
        assert!(c.contains("--unlock-key-file=/dev/stdin"), "{c}");
    }
}

/// 待托管密钥在托管失败后重试、不再登记第二把；托管成功后 HeldKey 在、pcrlock 补上。
#[tokio::test]
async fn pending_key_is_retried_not_reenrolled() {
    let l = lab().await;
    l.bootstrap();
    let failing = l.escrow_status(500).mount_as_scoped(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    l.round().await;
    drop(failing);
    assert_eq!(l.calls_with("--recovery-key").len(), 1);

    l.escrow_status(204).expect(1).mount(&l.srv).await;
    l.policy_exists();
    let sealed_stray = add_stray(SEALED, "7");
    l.dumps(UUID, &[&rec, &rec, &sealed_stray, SEALED]);
    let r = l.round().await;
    assert_eq!(l.calls_with("--recovery-key").len(), 1, "不再登记第二把");
    assert!(!l.pending_path().exists());
    assert_eq!(
        load_luks_state(&l.paths)
            .unwrap()
            .escrowed_luks_uuid
            .as_deref(),
        Some(UUID)
    );
    let h: HeldKey = serde_json::from_slice(&std::fs::read(l.held_path()).unwrap()).unwrap();
    assert_eq!(h.recovery_key, KEY);
    let reqs = l.srv.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
    // Sealed only: no plaintext field, the key itself nowhere in the body.
    assert!(body.get("recovery_key").is_none(), "{body}");
    assert!(!String::from_utf8_lossy(&reqs.last().unwrap().body).contains(KEY));
    assert!(mastersos_bundle::is_sealed(
        body["recovery_key_age"].as_str().unwrap()
    ));
    assert_eq!(body["recipients_fp"], lab_fp());
    assert_eq!(body["luks_uuid"], UUID);
    // 先换 PIN 重建策略，再换 TPM 槽（命令行逐字核对）
    let calls = l.fake.calls();
    let i_remove = calls
        .iter()
        .position(|c| c == "/usr/lib/systemd/systemd-pcrlock remove-policy")
        .unwrap();
    let cred = l.paths.root.join("run/mastersos-agent/pcrlock-cred");
    let make = format!(
        "env CREDENTIALS_DIRECTORY={} /usr/lib/systemd/systemd-pcrlock make-policy --location=770 --pcr=7 --recovery-pin=query",
        cred.display()
    );
    let i_make = calls.iter().position(|c| *c == make).unwrap();
    let i_bind = calls.iter().position(|c| c == BIND).unwrap();
    assert!(i_remove < i_make && i_make < i_bind, "{calls:?}");
    let pin = std::fs::read_to_string(l.paths.state_dir.join(PCRLOCK_PIN)).unwrap();
    assert_eq!(pin.len(), 64);
    assert!(calls.iter().all(|c| !c.contains(&pin)));
    // 临时钥匙槽（stray 7）在最后一轮去掉、文件删掉
    assert!(!l.bootstrap_path().exists());
    for i in ["luks:tpm", "luks:recovery", "luks:escrow", "luks:pcrlock"] {
        assert!(item(&r, i).ok, "{r:?}");
    }
}

#[tokio::test]
async fn cryptenroll_stderr_never_in_results() {
    let l = lab().await;
    l.bootstrap();
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    l.fake.respond(
        ENROLL,
        Output {
            code: 1,
            stdout: format!("{KEY}\n"),
            stderr: format!(
                "A secret recovery key has been generated:\n    {KEY}\nFailed to add\n"
            ),
        },
    );
    let r = l.round().await;
    let rec = item(&r, "luks:recovery");
    assert!(!rec.ok);
    assert_eq!(
        rec.detail.as_deref(),
        Some("登记恢复密钥失败: systemd-cryptenroll exited with 1")
    );
    for i in &r {
        assert!(!i.detail.as_deref().unwrap_or("").contains(KEY), "{i:?}");
    }
    assert!(!l.pending_path().exists());
}

/// 核对失败：取出的恢复密钥解不开分区 → 不写待托管文件、不托管。
#[tokio::test]
async fn enrolled_key_that_does_not_open_is_not_escrowed() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    l.fake
        .respond("cryptsetup open", Output::fail(2, &format!("bad {KEY}")));
    let r = l.round().await;
    assert!(!l.pending_path().exists());
    let rec = item(&r, "luks:recovery");
    assert!(
        !rec.ok && !rec.detail.as_deref().unwrap().contains(KEY),
        "{rec:?}"
    );
}

/// 托管 403 / 429：回报里看得见状态码与服务端的说明；不往下绑 pcrlock，密钥留着下一轮再试。
#[tokio::test]
async fn escrow_rejections_are_reported_with_status() {
    for (code, says) in [(403u16, "托管凭据与登记的不同"), (429, "已到上限")] {
        let l = lab().await;
        l.bootstrap();
        l.escrow_status(code).mount(&l.srv).await;
        l.policy_exists();
        l.dumps(
            UUID,
            &[&add_stray(FIRST_BOOT, "7"), &add_stray(RECOVERY, "7")],
        );
        l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
        let r = l.round().await;
        let e = item(&r, "luks:escrow");
        let d = e.detail.as_deref().unwrap();
        assert!(
            !e.ok && d.contains(&format!("托管被拒（{code}）")) && d.contains(says),
            "{d}"
        );
        assert!(!d.contains(&l.srv.uri()), "错误里不带 URL：{d}");
        assert!(l.pending_path().exists());
        assert!(l.calls_with("--tpm2-pcrlock").is_empty());
    }
}

#[tokio::test]
async fn no_identity_keeps_key_pending() {
    let mut l = lab().await;
    l.cx.identity = None;
    l.bootstrap();
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.dumps(
        UUID,
        &[&add_stray(FIRST_BOOT, "7"), &add_stray(RECOVERY, "7")],
    );
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    let e = item(&r, "luks:escrow");
    assert!(
        !e.ok && e.detail.as_deref().unwrap().contains("identity.json"),
        "{e:?}"
    );
    assert!(l.pending_path().exists());
}

/// 恢复出厂：新分区（新 UUID），luks-state 还记着旧的、HeldKey 也是旧分区的 → 用临时钥匙重登记、再托管。
#[tokio::test]
async fn new_luks_after_reset_reenrolls_with_bootstrap() {
    let l = lab().await;
    l.bootstrap();
    save_luks_state(
        &l.paths,
        &LuksState {
            escrowed_luks_uuid: Some(OLD_UUID.into()),
        },
    )
    .unwrap();
    save_held(
        &l.paths,
        &HeldKey {
            luks_uuid: OLD_UUID.into(),
            recovery_key: "old-key".into(),
        },
    )
    .unwrap();
    l.escrow_status(204).expect(1).mount(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    // HeldKey 是旧分区的、临时钥匙对得上 → 用临时钥匙解锁登记
    assert_eq!(l.fake.stdin_of(ENROLL).as_deref(), Some(BOOT.as_slice()));
    assert!(item(&r, "luks:escrow").ok);
    let h: HeldKey = serde_json::from_slice(&std::fs::read(l.held_path()).unwrap()).unwrap();
    assert_eq!((h.luks_uuid.as_str(), h.recovery_key.as_str()), (UUID, KEY));
}

#[tokio::test]
async fn luks_state_is_separate_from_sys_state() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    let sys = l.paths.var_dir.join("system-state.json");
    std::fs::create_dir_all(&l.paths.var_dir).unwrap();
    std::fs::write(&sys, br#"{"channel_override":true}"#).unwrap();
    l.dumps(UUID, &[RECOVERY, SEALED]);
    l.round().await;
    assert_eq!(
        std::fs::read(&sys).unwrap(),
        br#"{"channel_override":true}"#
    );
    assert!(l.paths.var_dir.join(LUKS_STATE_FILE).exists());
}

/// db/dbx 或 shim 的 SbatLevel 变过：这次开机用恢复密钥进来，镜像里的策略服务失败了 → 用 PIN 改写。
#[tokio::test]
async fn pcrlock_policy_rebuilt_with_pin_when_service_failed() {
    let l = lab().await;
    l.held();
    write_pin(&l.paths, &"ab".repeat(32)).unwrap();
    l.dumps(UUID, &[SEALED]);
    l.fake.respond(
        "systemctl is-failed systemd-pcrlock-make-policy",
        Output::ok("failed\n"),
    );
    let r = l.round().await;
    let cred = l.paths.root.join("run/mastersos-agent/pcrlock-cred");
    let make = format!(
        "env CREDENTIALS_DIRECTORY={} /usr/lib/systemd/systemd-pcrlock make-policy --location=770 --pcr=7 --recovery-pin=query",
        cred.display()
    );
    let calls = l.fake.calls();
    assert!(calls.contains(&make), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("remove-policy")));
    assert!(l.calls_with("systemd-cryptenroll").is_empty());
    assert!(calls.iter().all(|c| !c.contains(&"ab".repeat(32))));
    assert_eq!(l.fake.stdin_of("env"), None);
    assert!(!cred.join("pcrlock.recovery-pin").exists());
    assert!(calls.contains(&"systemctl reset-failed systemd-pcrlock-make-policy".to_string()));
    let p = item(&r, "luks:pcrlock");
    assert!(
        p.ok && p.detail.as_deref().unwrap().contains("PIN"),
        "{p:?}"
    );
}

#[tokio::test]
async fn failed_policy_service_without_pin_is_reported() {
    let l = lab().await;
    l.held();
    l.dumps(UUID, &[SEALED]);
    l.fake
        .respond("systemctl is-failed", Output::ok("failed\n"));
    let r = l.round().await;
    let p = item(&r, "luks:pcrlock");
    assert!(
        !p.ok && p.detail.as_deref().unwrap().contains("没有 PIN"),
        "{p:?}"
    );
}

/// 没有 TPM2 槽：只回报，什么都不动——不登记、不托管、不绑、也不碰临时钥匙。
#[tokio::test]
async fn no_tpm2_slot_is_reported_and_untouched() {
    for (dump, with_pending) in [(EMPTY, false), (EMPTY_REC, true)] {
        let l = lab().await;
        l.bootstrap();
        l.escrow_status(204).expect(0).mount(&l.srv).await;
        l.policy_exists();
        if with_pending {
            save_pending(&l.paths, &pending(UUID)).unwrap();
        }
        l.dumps(UUID, &[dump]);
        let r = l.round().await;
        let t = item(&r, "luks:tpm");
        assert!(
            !t.ok && t.detail.as_deref().unwrap().contains("没有 TPM2 槽"),
            "{t:?}"
        );
        for i in ["luks:recovery", "luks:escrow", "luks:pcrlock"] {
            let d = item(&r, i).detail.clone().unwrap();
            assert!(
                !item(&r, i).ok && d.contains("没有 TPM2 槽") && d.contains("reinstall"),
                "{i}: {d}"
            );
        }
        let calls = l.fake.calls();
        let allowed = [
            "bootctl status".to_string(),
            format!("cryptsetup luksUUID {DEV}"),
            format!("cryptsetup luksDump --dump-json-metadata {DEV}"),
        ];
        for c in &calls {
            assert!(allowed.contains(c), "不该跑 {c}（全部：{calls:?}）");
        }
        assert_eq!(with_pending, l.pending_path().exists());
        assert!(l.bootstrap_path().exists(), "临时钥匙没被碰");
    }
}

#[tokio::test]
async fn secure_boot_state_is_reported() {
    for (out, ok_) in [
        ("    Secure Boot: enabled (user)\n", true),
        ("    Secure Boot: disabled (setup)\n", false),
        ("", false),
    ] {
        let l = lab().await;
        l.fake.respond("bootctl status", Output::ok(out));
        l.dumps(UUID, &[EMPTY]);
        let r = l.round().await;
        let s = item(&r, "system:secureboot");
        assert_eq!(s.ok, ok_, "{s:?}");
        // 4b Task 22：system:shim-ca 跟它一起回报；bootloader-update 还没写过状态文件时是成功
        let c = item(&r, "system:shim-ca");
        assert!(
            c.ok && c.detail.as_deref() == Some("the boot loader has not been swapped yet"),
            "{c:?}"
        );
        if out.contains("disabled") {
            assert!(s.detail.as_deref().unwrap().contains("disabled (setup)"));
        }
    }
}

#[tokio::test]
async fn unreadable_header_changes_nothing() {
    let l = lab().await;
    l.fake.respond(
        "cryptsetup luksUUID",
        Output::fail(4, "Device does not exist"),
    );
    let r = l.round().await;
    assert!(!item(&r, "luks:tpm").ok);
    assert!(!item(&r, "luks:pcrlock").ok);
    assert!(l.calls_with("systemd-cryptenroll").is_empty());
}

/// 两个状态文件读不出（不是不存在）时整轮不动分区，回报 luks:escrow 失败。
#[tokio::test]
async fn unreadable_state_files_abort_the_round() {
    for case in 0..3 {
        let l = lab().await;
        std::fs::create_dir_all(l.paths.var_dir.parent().unwrap()).unwrap();
        match case {
            0 => {
                std::fs::create_dir_all(&l.paths.var_dir).unwrap();
                std::fs::write(l.paths.var_dir.join(LUKS_STATE_FILE), b"{oops").unwrap();
            }
            1 => {
                std::fs::create_dir_all(&l.paths.var_dir).unwrap();
                std::fs::write(l.pending_path(), b"{oops").unwrap();
            }
            _ => std::fs::write(&l.paths.var_dir, b"not a dir").unwrap(),
        }
        l.policy_exists();
        l.dumps(UUID, &[SEALED, SEALED]);
        let r = l.round().await;
        assert!(
            l.calls_with("systemd-cryptenroll").is_empty(),
            "case {case}: {:?}",
            l.fake.calls()
        );
        let e = item(&r, "luks:escrow");
        assert!(
            !e.ok && e.detail.as_deref().unwrap().contains("这一轮不动"),
            "case {case}: {e:?}"
        );
    }
}

/// HeldKey 读不出（坏 JSON）：整轮不动分区，回报 luks:escrow 失败（不能当成「没有 HeldKey」照常报好）。
#[tokio::test]
async fn unreadable_held_key_aborts() {
    let l = lab().await;
    l.held();
    std::fs::write(l.held_path(), b"{oops").unwrap();
    l.policy_exists();
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    assert!(l.calls_with("systemd-cryptenroll").is_empty());
    let e = item(&r, "luks:escrow");
    assert!(
        !e.ok && e.detail.as_deref().unwrap().contains("这一轮不动"),
        "{e:?}"
    );
}

/// 恢复出厂换了分区：旧分区的 HeldKey 删掉，不长期留着解不开任何东西的密钥。
#[tokio::test]
async fn stale_held_key_for_other_partition_is_removed() {
    let l = lab().await;
    l.escrowed();
    save_held(
        &l.paths,
        &HeldKey {
            luks_uuid: OLD_UUID.into(),
            recovery_key: KEY.into(),
        },
    )
    .unwrap();
    l.dumps(UUID, &[SEALED]);
    l.round().await;
    assert!(!l.held_path().exists());
}

/// 「多余槽只有临时钥匙那一个」要用临时钥匙对那个槽号试口令成功才算；文件在、但对不上 → luks:tpm 失败。
#[tokio::test]
async fn bootstrap_slot_must_actually_open_to_count() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(500).mount(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    // 第一次 cryptsetup open 是登记后核对恢复密钥（成功），第二次是试临时钥匙槽（失败）
    l.fake.respond("cryptsetup open", Output::ok(""));
    l.fake.respond(
        "cryptsetup open --test-passphrase --disable-external-tokens --key-slot=7",
        Output::fail(2, "No key available with this passphrase."),
    );
    let r = l.round().await;
    let t = item(&r, "luks:tpm");
    assert!(
        !t.ok && t.detail.as_deref().unwrap().contains("口令槽"),
        "{t:?}"
    );
    // 试的是那个槽号、钥匙经 stdin
    let probe = format!(
        "cryptsetup open --test-passphrase --disable-external-tokens --key-slot=7 --key-file=- {DEV}"
    );
    assert_eq!(l.fake.stdin_of(&probe).as_deref(), Some(BOOT.as_slice()));
}

/// 没有多余的槽、临时钥匙文件还在（去了槽没来得及删文件）：这一轮删掉文件。
#[tokio::test]
async fn bootstrap_file_removed_when_no_stray_slot() {
    let l = lab().await;
    l.held();
    l.bootstrap();
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    assert!(!l.bootstrap_path().exists());
    assert!(item(&r, "luks:tpm").ok, "{r:?}");
}

/// initrd 持久化单元没跑成时带进用户态的 /run/mastersos/luks-bootstrap-key：每轮开始删掉。
#[tokio::test]
async fn run_copy_of_bootstrap_key_is_removed() {
    let l = lab().await;
    let run = l.paths.root.join("run/mastersos");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join(BOOTSTRAP_KEY_FILE), BOOT).unwrap();
    l.dumps(UUID, &[EMPTY]);
    l.round().await;
    assert!(!run.join(BOOTSTRAP_KEY_FILE).exists());
}

/// HeldKey 与临时钥匙落盘都是 0600、目录 0700。
#[tokio::test]
async fn key_files_are_0600_in_0700_dir() {
    let l = lab().await;
    save_held(
        &l.paths,
        &HeldKey {
            luks_uuid: UUID.into(),
            recovery_key: KEY.into(),
        },
    )
    .unwrap();
    assert_eq!(mode(&l.held_path()), 0o600);
    assert_eq!(mode(&l.paths.var_dir), 0o700);
}

/// I2：Secure Boot 没开时不绑 pcrlock、也不用 PIN 改写策略，回报说清楚原因。
#[tokio::test]
async fn no_pcrlock_bind_or_repair_without_secure_boot() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    l.dumps(UUID, &[RECOVERY]);
    let r = l.round_sb_off().await;
    assert!(l.calls_with("pcrlock").is_empty(), "{:?}", l.fake.calls());
    assert!(l.calls_with("systemd-cryptenroll").is_empty());
    let p = item(&r, "luks:pcrlock");
    assert!(
        !p.ok
            && p.detail
                .as_deref()
                .unwrap()
                .contains("Secure Boot 没有开启"),
        "{p:?}"
    );
    assert!(item(&r, "luks:escrow").ok);
}

/// Minor 1：带 pcrlock 与 PCR 11、但字面 PCR 不空的槽要重新换（不改写策略）。
#[test]
fn literal_pcrs_trigger_rebind() {
    let mut i = info(SEALED);
    i.tpm2.as_mut().unwrap().literal_pcrs = vec![7];
    assert_eq!(
        next_step(&i, None, Some(UUID), Redo::None),
        Need::AddPcrlock
    );
}

/// Minor 4：上次被杀在半路留下的 PIN 凭据，下一轮开始就删掉。
#[tokio::test]
async fn stale_pin_credential_is_removed_at_job_start() {
    let l = lab().await;
    let cred = l.paths.root.join("run/mastersos-agent/pcrlock-cred");
    std::fs::create_dir_all(&cred).unwrap();
    std::fs::write(cred.join("pcrlock.recovery-pin"), "ab".repeat(32)).unwrap();
    l.dumps(UUID, &[EMPTY]);
    l.round().await;
    assert!(!cred.join("pcrlock.recovery-pin").exists());
}

#[test]
fn parse_reports_recovery_and_stray_slots() {
    let s = info(SEALED);
    assert_eq!(
        (s.recovery_slots.clone(), s.stray_slots.clone()),
        (vec![1], vec![])
    );
    assert!(s.any_pcrlock);
    assert_eq!(info(EMPTY).stray_slots, vec![0]);
    assert!(!info(FIRST_BOOT).any_pcrlock);
    // 首次开机加临时钥匙槽：它是一个不属于任何 token 的 stray
    let fb = info(&add_stray(FIRST_BOOT, "7"));
    assert_eq!(fb.stray_slots, vec![7]);
}

/// 连续登记失败攒下的孤儿：盘上已有 4 个恢复槽就不再登记。
#[tokio::test]
async fn enrollment_stops_at_max_recovery_slots() {
    let l = lab().await;
    l.bootstrap();
    let mut v: Value = serde_json::from_str(RECOVERY).unwrap();
    for n in ["3", "4", "5"] {
        v["keyslots"][n] = v["keyslots"]["1"].clone();
        v["tokens"][n] = serde_json::json!({"type": "systemd-recovery", "keyslots": [n]});
    }
    l.dumps(UUID, &[&v.to_string()]);
    let r = l.round().await;
    assert!(l.calls_with("--recovery-key").is_empty());
    let rec = item(&r, "luks:recovery");
    assert!(
        !rec.ok && rec.detail.as_deref().unwrap().contains("4 个恢复槽"),
        "{rec:?}"
    );
}

/// 托管只走 https（终审 I4）：正式镜像、明文服务端地址时连恢复密钥都不登记，已有待托管也不发。
#[tokio::test]
async fn cleartext_server_url_refuses_escrow_on_release_image() {
    let mut l = lab().await;
    l.release();
    l.bootstrap();
    l.cx.fetcher = Fetcher::from_seed(&Seed {
        server_url: "http://192.0.2.1:8080".into(),
        trust: vec![],
        fetch_token: Some("tok".into()),
        group: None,
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    });
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = LuksJob::new(l.fake.clone()).run(&l.cx).await;
    let e = item(&r, "luks:escrow");
    let d = e.detail.as_deref().unwrap();
    assert!(!e.ok && d.contains("https"), "{e:?}");
    assert!(!d.contains("192.0.2.1"), "错误里不带 URL：{d}");
    assert!(
        l.fake.calls().iter().all(|c| !c.contains("--recovery-key")),
        "不该登记恢复密钥：{:?}",
        l.fake.calls()
    );
    assert!(!l.pending_path().exists());
}

/// lab 镜像由签名的 `/usr/lib/mastersos/profile` 认出来。
#[test]
fn image_profile_marks_lab() {
    let dir = tmp_root();
    assert!(!image_is_lab(dir.path()));
    let p = dir.path().join("usr/lib/mastersos/profile");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "release\n").unwrap();
    assert!(!image_is_lab(dir.path()));
    std::fs::write(&p, "lab\n").unwrap();
    assert!(image_is_lab(dir.path()));
    std::fs::write(&p, "lab-ish\n").unwrap();
    assert!(!image_is_lab(dir.path()));
}

/// 复审 M8：这项修正之前托管的机器（luks-state 记着、分区已封好，但没有 HeldKey）：luks:escrow 仍是好，
/// detail 说清楚本机没有保管的恢复密钥；有 HeldKey 时没有这句。
#[tokio::test]
async fn escrowed_without_held_key_says_so() {
    let l = lab().await;
    l.escrowed();
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    let e = item(&r, "luks:escrow");
    assert!(
        e.ok && e
            .detail
            .as_deref()
            .unwrap()
            .contains("没有本机保管的恢复密钥"),
        "{e:?}"
    );
    let l = lab().await;
    l.held();
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    let e = item(&r, "luks:escrow");
    assert_eq!(e.detail.as_deref(), Some(format!("luks {UUID}").as_str()));
}

/// VM 165 上抓的真实 luksDump `tpm2_pubkey`（内置盘的 TPM 槽，绑的是旧 lab PCR 钥匙；2026-10-15「修之前」证据）。
const VM_TPM2_PUBKEY_OLD_LAB: &str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzNGZhdmpYa0N5WXJUcnphTWxubgpqNWxwa1N6WU5ZWXhYeUk3dDg3Q0dxYnpYM055ZUY3aXRhTElPZlpnZFZjK2tQanFhM1JNSkVsSVNmQXc2eXEwCnkxcXdIdS9RRW9rQlZtanFHR3V0TXl2VE5SaHFFckhZRC9laTU0M2lxbVFmSzlQbHo0YkVxSXBXK29xUjdNRXgKQzBzVytLais2dmZTVk5jTnRnTjRod2dLY3Fwa2ZPbzhDbjJiWk5xcGxDOUwwdzg0Nm5VOGFDQko1NVZSWTFacApnK3RGckNYNENjMUdWeXRUeFVOYnJHdkphQjh5bzdKcEhYZG96RFkzNUJqbk8xZFRBeFVpZ0QyVGtyODZXaEtxCnRKazhjMFNVOEcySkNXZzJkeUFvaDNFbkNyV3UxTDZCbHE2bzlYVUp5aXJpSU9BaDEwd1FyWFA0ZTh5L1RQUWQKRlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

/// 复审 M3：不循环的公钥比较——真实 luksDump 的 tpm2_pubkey 对仓库里那把 PEM 文件（经生产用的 image_pubkey_b64
/// 读镜像路径）：是那把（退役的 lab 钥匙）就算本镜像的，换成当前的 lab 钥匙就不算。
#[test]
fn real_tpm2_pubkey_matches_repo_pem_via_image_path() {
    let keys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../image/keys/lab");
    let mut v: Value = serde_json::from_str(SEALED).unwrap();
    v["tokens"]["2"]["tpm2_pubkey"] = Value::String(VM_TPM2_PUBKEY_OLD_LAB.into());
    let dump = v.to_string();
    for (pem, want) in [
        (keys.join("retired/tpm2-pcr-public-key-4phase.pem"), true),
        (keys.join("tpm2-pcr-public-key.pem"), false),
    ] {
        let dir = tmp_root();
        let p = dir.path().join(TPM2_PUBKEY.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(&pem, &p).unwrap();
        let img = image_pubkey_b64(dir.path());
        let i = parse_luks_dump(&dump, UUID, img.as_deref()).unwrap();
        assert_eq!(i.tpm2.unwrap().pubkey_is_image, want, "{}", pem.display());
    }
}

// ---------- shim update follow-up (plan 5 Task 8) ----------

/// A shim-prepare record from an earlier boot (`boot-a`); this boot is `boot-b` with `sbat` in SbatLevelRT, and the
/// next-shim variant sits next to the generated component.
fn shim_prepared(l: &Lab, outcome: crate::shim_predict::Outcome, predicted: &[u8], sbat: &[u8]) {
    use crate::shim_predict::*;
    use sha2::Digest;
    let root = &l.paths.root;
    let vars = root.join("sys").join(SBAT_LEVEL_RT_VAR);
    std::fs::create_dir_all(vars.parent().unwrap()).unwrap();
    let mut rt = vec![6, 0, 0, 0];
    rt.extend_from_slice(sbat);
    std::fs::write(vars, rt).unwrap();
    std::fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
    std::fs::write(root.join("proc/sys/kernel/random/boot_id"), "boot-b\n").unwrap();
    let comp = root.join(AUTHORITY_DIR);
    std::fs::create_dir_all(&comp).unwrap();
    std::fs::write(comp.join(GENERATED), "{\"records\":[]}").unwrap();
    std::fs::write(comp.join(NEXT_SHIM_VARIANT), "{\"records\":[]}").unwrap();
    std::fs::create_dir_all(&l.paths.var_dir).unwrap();
    let st = PrepareState {
        shim_sha256: "00".repeat(32),
        predicted_sbat_sha256: Some(crate::secureboot::hex(&sha2::Sha256::digest(predicted))),
        outcome,
        reason: Some("test reason".into()),
        boot_id: "boot-a".into(),
        at: 0,
    };
    std::fs::write(
        l.paths.var_dir.join(STATE_FILE),
        serde_json::to_vec(&st).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn luks_round_retires_old_variant_after_new_shim_boot() {
    use crate::shim_predict::*;
    let l = lab().await;
    l.held();
    write_pin(&l.paths, &"ab".repeat(32)).unwrap();
    l.dumps(UUID, &[SEALED]);
    let new = b"sbat,1,2023012900\nshim,2\ngrub,3\ngrub.debian,4\n";
    shim_prepared(&l, Outcome::Prepared, new, new);
    let r = l.round().await;
    let p = item(&r, "luks:pcrlock");
    assert!(p.ok && p.detail.as_deref() == Some(DONE_DETAIL), "{p:?}");
    let comp = l.paths.root.join(AUTHORITY_DIR);
    assert!(!comp.join(NEXT_SHIM_VARIANT).exists());
    assert!(comp.join(GENERATED).exists());
    let makes: Vec<String> = l.calls_with("make-policy --location");
    assert_eq!(makes.len(), 1, "{makes:?}");
    assert!(l.fake.calls().iter().all(|c| !c.contains(&"ab".repeat(32))));
    // later rounds in the same boot keep reporting it (that is what IT sees), without re-making the policy
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    assert_eq!(
        item(&r, "luks:pcrlock").detail.as_deref(),
        Some(DONE_DETAIL)
    );
    assert_eq!(l.calls_with("make-policy --location").len(), 1);
    // after the next reboot: nothing more to say, the record is gone
    std::fs::write(
        l.paths.root.join("proc/sys/kernel/random/boot_id"),
        "boot-c\n",
    )
    .unwrap();
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    assert_eq!(item(&r, "luks:pcrlock").detail, None);
    assert!(!l.paths.var_dir.join(STATE_FILE).exists());
}

#[tokio::test]
async fn luks_round_reports_failed_prepare() {
    use crate::shim_predict::*;
    let l = lab().await;
    l.held();
    write_pin(&l.paths, &"ab".repeat(32)).unwrap();
    l.dumps(UUID, &[SEALED]);
    let old = b"sbat,1,2022052400\ngrub,2\n";
    shim_prepared(&l, Outcome::Failed, old, old);
    // same boot as the failed shim-prepare
    std::fs::write(
        l.paths.root.join("proc/sys/kernel/random/boot_id"),
        "boot-a\n",
    )
    .unwrap();
    std::fs::remove_file(l.paths.root.join(AUTHORITY_DIR).join(NEXT_SHIM_VARIANT)).unwrap();
    let r = l.round().await;
    let p = item(&r, "luks:pcrlock");
    assert!(
        !p.ok && p.detail.as_deref() == Some(failed_detail("test reason").as_str()),
        "{p:?}"
    );
    assert!(p.detail.as_deref().unwrap().contains("recovery key"));
    // after the reboot (recovery key typed, policy service failed → the PIN repair), the record is cleared
    std::fs::write(
        l.paths.root.join("proc/sys/kernel/random/boot_id"),
        "boot-b\n",
    )
    .unwrap();
    l.dumps(UUID, &[SEALED]);
    l.fake.respond(
        "systemctl is-failed systemd-pcrlock-make-policy",
        Output::ok("failed\n"),
    );
    let r = l.round().await;
    let p = item(&r, "luks:pcrlock");
    assert!(
        p.ok && p.detail.as_deref().unwrap().contains("PIN"),
        "{p:?}"
    );
    assert!(!l.paths.var_dir.join(STATE_FILE).exists());
}

/// Review I1: the SbatLevel matches the prediction, but the policy service failed in this boot (the recovery key was
/// needed after all) and the agent re-sealed with its PIN — never "completed without the recovery key".
#[tokio::test]
async fn luks_round_reports_misprediction_when_pin_repair_ran() {
    use crate::shim_predict::*;
    let l = lab().await;
    l.held();
    write_pin(&l.paths, &"ab".repeat(32)).unwrap();
    l.dumps(UUID, &[SEALED]);
    let new = b"sbat,1,2023012900\nshim,2\ngrub,3\ngrub.debian,4\n";
    shim_prepared(&l, Outcome::Prepared, new, new);
    l.fake.respond(
        "systemctl is-failed systemd-pcrlock-make-policy",
        Output::ok("failed\n"),
    );
    let r = l.round().await;
    let p = item(&r, "luks:pcrlock");
    assert!(
        !p.ok && p.detail.as_deref() == Some(MISPREDICTED_DETAIL),
        "{p:?}"
    );
    assert_ne!(p.detail.as_deref(), Some(DONE_DETAIL));
    // the repair did run (PIN make-policy through the luks job's credentials directory)
    assert!(
        l.calls_with("run/mastersos-agent/pcrlock-cred").len() == 1,
        "{:?}",
        l.fake.calls()
    );
    assert!(l
        .fake
        .calls()
        .contains(&"systemctl reset-failed systemd-pcrlock-make-policy".to_string()));
    assert!(!l
        .paths
        .root
        .join(AUTHORITY_DIR)
        .join(NEXT_SHIM_VARIANT)
        .exists());
    // later rounds in the same boot (service no longer failed) keep the failure, not "completed"
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    let p = item(&r, "luks:pcrlock");
    assert!(
        !p.ok && p.detail.as_deref() == Some(MISPREDICTED_DETAIL),
        "{p:?}"
    );
}

// ---------- plan 6 Task 13: sealed escrow ----------

/// No bundle → wait for it; a bundle without recipients → wait for them; recipients that do not
/// hold up on this side (not age X25519, twice, more than 8) → wait as well, never seal to them;
/// otherwise seal to exactly the bundle's list.
#[test]
fn escrow_mode_table() {
    assert_eq!(escrow_mode(None), EscrowMode::Wait(WAIT_FIRST_BUNDLE));
    assert_eq!(WAIT_FIRST_BUNDLE, "waiting for the first bundle");
    assert_eq!(WAIT_RECIPIENTS, "waiting for escrow recipients");
    assert_eq!(
        escrow_mode(Some(&current(vec![]))),
        EscrowMode::Wait(WAIT_RECIPIENTS)
    );
    let nine: Vec<String> = (1..=9).map(recipient).collect();
    for bad in [
        vec!["age1notarecipient".to_string()],
        vec![recipient(1), recipient(1)],
        vec![recipient(1).to_uppercase()],
        nine,
    ] {
        assert_eq!(
            escrow_mode(Some(&current(bad.clone()))),
            EscrowMode::Wait(WAIT_BAD_RECIPIENTS),
            "{bad:?}"
        );
    }
    let eight: Vec<String> = (1..=8).map(recipient).collect();
    assert_eq!(
        escrow_mode(Some(&current(eight.clone()))),
        EscrowMode::Sealed {
            fp: mastersos_bundle::recipients_fp(&eight),
            recipients: eight,
        }
    );
    assert_eq!(
        escrow_mode(Some(&current(lab_recipients()))),
        EscrowMode::Sealed {
            recipients: lab_recipients(),
            fp: lab_fp(),
        }
    );
}

/// Nothing to redo while waiting or when the escrow was made to the current recipients for this
/// partition; another fingerprint (the kit changed), another partition or no record at all (an
/// escrow made before sealing) → rotate.
#[test]
fn redo_decision_table() {
    let sealed = EscrowMode::Sealed {
        recipients: lab_recipients(),
        fp: lab_fp(),
    };
    let done = |fp: &str, uuid: &str| EscrowDone {
        recipients_fp: fp.into(),
        luks_uuid: uuid.into(),
    };
    let same = done(&lab_fp(), UUID);
    let other_fp = done(&"0".repeat(64), UUID);
    let other_luks = done(&lab_fp(), OLD_UUID);
    assert_eq!(redo(Some(&same), &sealed, UUID), Redo::None);
    assert_eq!(redo(Some(&other_fp), &sealed, UUID), Redo::Rotate);
    assert_eq!(redo(Some(&other_luks), &sealed, UUID), Redo::Rotate);
    assert_eq!(redo(None, &sealed, UUID), Redo::Rotate);
    for w in [WAIT_FIRST_BUNDLE, WAIT_RECIPIENTS, WAIT_BAD_RECIPIENTS] {
        let wait = EscrowMode::Wait(w);
        for d in [None, Some(&same), Some(&other_fp)] {
            assert_eq!(redo(d, &wait, UUID), Redo::None);
        }
    }
}

/// Before the first bundle nothing is enrolled or sent: `luks:escrow` says it waits, pcrlock is
/// not bound (it follows the escrow).
#[tokio::test]
async fn no_escrow_before_first_bundle() {
    let l = lab().await;
    l.bootstrap();
    l.set_current(None);
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.policy_exists();
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    assert!(l.calls_with("--recovery-key").is_empty());
    assert!(l.calls_with("--tpm2-pcrlock").is_empty());
    assert!(!l.pending_path().exists());
    let e = item(&r, "luks:escrow");
    assert!(!e.ok);
    assert!(
        e.detail.as_deref().unwrap().contains(WAIT_FIRST_BUNDLE),
        "{e:?}"
    );
}

/// A bundle without `escrow_recipients`: the same wait, reported as such.
#[tokio::test]
async fn no_escrow_without_recipients() {
    let l = lab().await;
    l.bootstrap();
    l.set_current(Some(current(vec![])));
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    assert!(l.calls_with("--recovery-key").is_empty());
    let e = item(&r, "luks:escrow");
    assert!(!e.ok);
    assert!(
        e.detail.as_deref().unwrap().contains(WAIT_RECIPIENTS),
        "{e:?}"
    );
    // Invalid recipients in an accepted bundle: still waiting, never sealed to them.
    l.set_current(Some(current(vec![recipient(1), recipient(1)])));
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    let r = l.round().await;
    assert!(l.calls_with("--recovery-key").is_empty());
    let e = item(&r, "luks:escrow");
    assert!(
        e.detail.as_deref().unwrap().contains(WAIT_BAD_RECIPIENTS),
        "{e:?}"
    );
}

/// With recipients in the bundle the key is sealed to every one of them: the body carries the
/// age armor and their fingerprint, never the plaintext key; escrow-done.json records the
/// fingerprint and the partition, and no server address.
#[tokio::test]
async fn sealed_when_manifest_has_recipients() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(204).expect(1).mount(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    let r = l.round().await;
    assert!(item(&r, "luks:escrow").ok, "{r:?}");
    let bodies = l.escrow_bodies().await;
    assert_eq!(bodies.len(), 1);
    assert!(!String::from_utf8_lossy(&bodies[0]).contains(KEY));
    let req = mastersos_bundle::EscrowRequest::from_json(&bodies[0]).unwrap();
    req.validate().unwrap();
    assert_eq!(req.recipients_fp, lab_fp());
    assert_eq!(req.luks_uuid, UUID);
    assert_eq!(
        mastersos_bundle::x25519_stanza_count(&req.recovery_key_age),
        Some(lab_recipients().len())
    );
    let done: serde_json::Value =
        serde_json::from_slice(&std::fs::read(l.done_path()).unwrap()).unwrap();
    assert_eq!(
        done,
        serde_json::json!({"recipients_fp": lab_fp(), "luks_uuid": UUID})
    );
    assert_eq!(mode(&l.done_path()), 0o600);
}

/// A failed escrow keeps the sealed copy in escrow-pending.json; the next round sends exactly the
/// same ciphertext (no new sealing, no new key).
#[tokio::test]
async fn retry_resends_same_ciphertext() {
    let l = lab().await;
    l.bootstrap();
    let failing = l.escrow_status(500).mount_as_scoped(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    l.round().await;
    drop(failing);
    let p = l.load_pending();
    let sealed = p
        .sealed
        .clone()
        .expect("sealed once, kept in the pending file");
    assert_eq!(sealed.recipients_fp, lab_fp());
    assert!(!format!("{p:?}").contains(&sealed.recovery_key_age));

    l.escrow_status(204).expect(1).mount(&l.srv).await;
    l.dumps(UUID, &[&rec, &rec]);
    let r = l.round().await;
    assert!(item(&r, "luks:escrow").ok, "{r:?}");
    assert_eq!(l.calls_with("--recovery-key").len(), 1);
    let bodies = l.escrow_bodies().await;
    assert_eq!(bodies.len(), 2);
    let reqs: Vec<_> = bodies
        .iter()
        .map(|b| mastersos_bundle::EscrowRequest::from_json(b).unwrap())
        .collect();
    assert_eq!(reqs[0].recovery_key_age, sealed.recovery_key_age);
    assert_eq!(reqs[1].recovery_key_age, sealed.recovery_key_age);
    assert_eq!(reqs[1].recipients_fp, lab_fp());
}

/// The seed's server address changing (the same cloud under a new name) does not escrow again:
/// escrow-done.json has no address, and nothing is enrolled or sent to either server.
#[tokio::test]
async fn server_url_change_does_not_reescrow() {
    let mut l = lab().await;
    l.held();
    l.policy_exists();
    let new_srv = MockServer::start().await;
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.escrow_status(204).expect(0).mount(&new_srv).await;
    l.cx.fetcher = Fetcher::from_seed(&Seed {
        server_url: new_srv.uri(),
        trust: vec![],
        fetch_token: Some("tok".into()),
        group: None,
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    });
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    assert!(item(&r, "luks:escrow").ok, "{r:?}");
    assert!(l.calls_with("--recovery-key").is_empty());
    assert!(new_srv.received_requests().await.unwrap().is_empty());
    let done = std::fs::read_to_string(l.done_path()).unwrap();
    assert!(
        !done.contains("server_url") && !done.contains("127.0.0.1"),
        "{done}"
    );
}

const NEW_KEY: &str = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv";
const OLD_RECOVERY_SLOT: &str = "1";

/// SEALED with one more recovery slot (the new key, slot 3) next to the old one (slot 1).
fn sealed_two_recovery() -> String {
    let mut v: Value = serde_json::from_str(SEALED).unwrap();
    let any = v["keyslots"]["1"].clone();
    v["keyslots"]["3"] = any;
    v["tokens"]["9"] = serde_json::json!({"type": "systemd-recovery", "keyslots": ["3"]});
    v.to_string()
}

/// The recipients changed (the school's kit was replaced): enroll a new recovery key unlocking with
/// the held one, escrow it sealed to the new recipients, and only then wipe the old slot and hold
/// the new key.
#[tokio::test]
async fn recipients_change_rotates_luks_recovery_key() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    let new = vec![recipient(3)];
    l.set_current(Some(current(new.clone())));
    l.escrow_status(204).expect(1).mount(&l.srv).await;
    let two = sealed_two_recovery();
    l.dumps(UUID, &[SEALED, &two, &two]);
    l.fake.respond(ENROLL, Output::ok(&format!("{NEW_KEY}\n")));
    let r = l.round().await;
    assert!(item(&r, "luks:escrow").ok, "{r:?}");
    // Enrolled with the held (old) key on stdin.
    assert_eq!(l.fake.stdin_of(ENROLL).as_deref(), Some(KEY.as_bytes()));
    let bodies = l.escrow_bodies().await;
    assert_eq!(bodies.len(), 1);
    let req = mastersos_bundle::EscrowRequest::from_json(&bodies[0]).unwrap();
    assert_eq!(req.recipients_fp, mastersos_bundle::recipients_fp(&new));
    assert_eq!(
        mastersos_bundle::x25519_stanza_count(&req.recovery_key_age),
        Some(1)
    );
    for b in &bodies {
        let t = String::from_utf8_lossy(b);
        assert!(!t.contains(KEY) && !t.contains(NEW_KEY));
    }
    // Then the old slot is wiped, unlocking with the new key, after the escrow.
    let wipe = format!(
        "systemd-cryptenroll --unlock-key-file=/dev/stdin --wipe-slot={OLD_RECOVERY_SLOT} {DEV}"
    );
    assert_eq!(l.fake.stdin_of(&wipe).as_deref(), Some(NEW_KEY.as_bytes()));
    let calls = l.fake.calls();
    let i_enroll = calls.iter().position(|c| c == ENROLL).unwrap();
    let i_wipe = calls.iter().position(|c| *c == wipe).unwrap();
    assert!(i_enroll < i_wipe);
    let h: HeldKey = serde_json::from_slice(&std::fs::read(l.held_path()).unwrap()).unwrap();
    assert_eq!(h.recovery_key, NEW_KEY);
    let done: EscrowDone = serde_json::from_slice(&std::fs::read(l.done_path()).unwrap()).unwrap();
    assert_eq!(done.recipients_fp, mastersos_bundle::recipients_fp(&new));
    assert!(!l.pending_path().exists());
    // Next round: nothing more to do.
    l.dumps(UUID, &[SEALED]);
    l.round().await;
    assert_eq!(l.calls_with("--recovery-key").len(), 1);
}

/// The rotation's escrow fails: the old slot stays, the held key and escrow-done.json stay as
/// they were, and the new key waits (sealed) in the pending file for the next round.
#[tokio::test]
async fn rotate_keeps_old_slot_when_escrow_fails() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    let new = vec![recipient(3)];
    l.set_current(Some(current(new.clone())));
    l.escrow_status(500).expect(1).mount(&l.srv).await;
    let two = sealed_two_recovery();
    l.dumps(UUID, &[SEALED, &two]);
    l.fake.respond(ENROLL, Output::ok(&format!("{NEW_KEY}\n")));
    let r = l.round().await;
    assert!(!item(&r, "luks:escrow").ok, "{r:?}");
    assert!(
        l.calls_with("--wipe-slot=1").is_empty(),
        "{:?}",
        l.fake.calls()
    );
    let h: HeldKey = serde_json::from_slice(&std::fs::read(l.held_path()).unwrap()).unwrap();
    assert_eq!(h.recovery_key, KEY);
    let done: EscrowDone = serde_json::from_slice(&std::fs::read(l.done_path()).unwrap()).unwrap();
    assert_eq!(done.recipients_fp, lab_fp());
    let p = l.load_pending();
    assert_eq!(p.recovery_key, NEW_KEY);
    assert_eq!(p.replaces_slots, vec![1]);
    assert_eq!(
        p.sealed.unwrap().recipients_fp,
        mastersos_bundle::recipients_fp(&new)
    );
}

/// A pending key sealed to recipients that were replaced before it reached the server is not
/// sent: a fresh key is enrolled and sealed to the new recipients (the stale one is wiped after).
#[tokio::test]
async fn pending_sealed_to_old_recipients_is_reenrolled() {
    let l = lab().await;
    l.bootstrap();
    let failing = l.escrow_status(500).mount_as_scoped(&l.srv).await;
    let first = add_stray(FIRST_BOOT, "7");
    let rec = add_stray(RECOVERY, "7");
    l.dumps(UUID, &[&first, &rec]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    l.round().await;
    drop(failing);
    let new = vec![recipient(3)];
    l.set_current(Some(current(new.clone())));
    l.escrow_status(204).expect(1).mount(&l.srv).await;
    // Slot 1 holds the stale pending key; after enrolling, slot 3 holds the new one.
    let mut v: Value = serde_json::from_str(&rec).unwrap();
    v["keyslots"]["3"] = v["keyslots"]["1"].clone();
    v["tokens"]["9"] = serde_json::json!({"type": "systemd-recovery", "keyslots": ["3"]});
    let two = v.to_string();
    l.dumps(UUID, &[&rec, &two, &two]);
    l.fake.respond(ENROLL, Output::ok(&format!("{NEW_KEY}\n")));
    let r = l.round().await;
    assert!(item(&r, "luks:escrow").ok, "{r:?}");
    assert_eq!(l.calls_with("--recovery-key").len(), 2);
    let bodies = l.escrow_bodies().await;
    let last = mastersos_bundle::EscrowRequest::from_json(bodies.last().unwrap()).unwrap();
    assert_eq!(last.recipients_fp, mastersos_bundle::recipients_fp(&new));
    // The stale key's slot is wiped (unlocking with the new key), the new one's is kept.
    let wipes = l.calls_with("--wipe-slot=");
    assert_eq!(
        wipes,
        [format!(
            "systemd-cryptenroll --unlock-key-file=/dev/stdin --wipe-slot=1 {DEV}"
        )],
        "{:?}",
        l.fake.calls()
    );
    assert_eq!(
        l.fake.stdin_of(&wipes[0]).as_deref(),
        Some(NEW_KEY.as_bytes())
    );
    let h: HeldKey = serde_json::from_slice(&std::fs::read(l.held_path()).unwrap()).unwrap();
    assert_eq!(h.recovery_key, NEW_KEY);
}

/// Review M1: invalid recipients in the accepted bundle are reported on `luks:escrow` with what
/// is wrong, also on a machine that escrowed earlier (it cannot follow a kit change until fixed).
#[tokio::test]
async fn invalid_recipients_reported_even_when_escrowed() {
    let l = lab().await;
    l.held();
    l.policy_exists();
    let bad = recipient(1).to_uppercase();
    l.set_current(Some(current(vec![bad.clone()])));
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.dumps(UUID, &[SEALED]);
    let r = l.round().await;
    let e = item(&r, "luks:escrow");
    assert!(!e.ok, "{r:?}");
    let d = e.detail.as_deref().unwrap();
    assert!(d.contains(WAIT_BAD_RECIPIENTS) && d.contains(&bad), "{d}");
    assert!(l.calls_with("--recovery-key").is_empty());
    // Not yet escrowed: the same reason, nothing enrolled.
    let l = lab().await;
    l.bootstrap();
    l.set_current(Some(current(vec![bad.clone()])));
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    let r = l.round().await;
    let d = item(&r, "luks:escrow").detail.clone().unwrap();
    assert!(d.contains(WAIT_BAD_RECIPIENTS) && d.contains(&bad), "{d}");
    assert!(l.calls_with("--recovery-key").is_empty());
}

/// Review M2: sealing is known to work before a recovery slot is added. Recipients that cannot
/// be sealed to (here forced past the validation) stop the round before cryptenroll runs.
#[tokio::test]
async fn sealing_failure_adds_no_slot() {
    let l = lab().await;
    l.bootstrap();
    l.escrow_status(204).expect(0).mount(&l.srv).await;
    l.dumps(UUID, &[&add_stray(FIRST_BOOT, "7")]);
    l.fake.respond(ENROLL, Output::ok(&format!("{KEY}\n")));
    l.fake.respond(
        "bootctl status",
        Output::ok("    Secure Boot: enabled (user)\n"),
    );
    let mut round = Round::new(l.fake.clone(), &l.cx);
    round.mode = EscrowMode::Sealed {
        recipients: vec!["age1notarecipient".into()],
        fp: "0".repeat(64),
    };
    let r = round.run().await;
    assert!(
        l.calls_with("--recovery-key").is_empty(),
        "{:?}",
        l.fake.calls()
    );
    assert!(!l.pending_path().exists());
    let e = item(&r, "luks:escrow");
    assert!(
        !e.ok && e.detail.as_deref().unwrap().contains("sealing"),
        "{e:?}"
    );
}

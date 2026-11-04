//! `mastersos-sign` 命令行：只做参数解析，逻辑都在库里。
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use mastersos_bundle::kit::Kit;
use mastersos_sign::kit::{
    escrow_read, is_already_registered, kit_new, load_kit, read_kit, register_escrow_recipient,
};
use mastersos_sign::{
    chain, keygen, register, restore_from_paper, seed_check, sign_heartbeat, sign_pending, Api,
    SigningKey,
};

#[derive(Parser)]
#[command(
    name = "mastersos-sign",
    version,
    about = "MastersOS 学校恢复钥匙：生成、纸面备份、登记，本地验链后签名发布"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Server {
    /// 管理服务端地址，例如 https://mastersos.school.ac.th
    #[arg(long)]
    server: String,
    /// 存 token 的文件（token 不接受命令行明文）。sign / heartbeat / seed-check / verify 要 read + draft；
    /// register 要 keys。
    #[arg(long)]
    token_file: PathBuf,
}

impl Server {
    fn api(&self) -> Result<Api> {
        Api::from_token_file(&self.server, &self.token_file)
    }
}

#[derive(Args)]
struct PinDir {
    /// pin 存放目录，默认 ~/.config/mastersos-sign/（Windows：%APPDATA%\mastersos-sign\）
    #[arg(long)]
    pin_dir: Option<PathBuf>,
}

impl PinDir {
    fn get(&self) -> Result<PathBuf> {
        if let Some(d) = &self.pin_dir {
            return Ok(d.clone());
        }
        mastersos_sign::platform::config_dir("mastersos-sign")
            .context("give the pin directory with --pin-dir")
    }
}

/// The signing key: a PKCS#8 key file or a recovery kit (exactly one).
#[derive(Args)]
#[group(required = true, multiple = false)]
struct KeyArg {
    /// PKCS#8 recovery key file (`keygen`, `restore-from-paper`)
    #[arg(long)]
    key: Option<PathBuf>,
    /// Recovery kit file (0600), or `-` to read the kit from the first line of stdin
    #[arg(long)]
    kit: Option<PathBuf>,
}

/// A loaded `--key` / `--kit`.
enum Loaded {
    File(PathBuf),
    Kit(Kit),
}

impl Loaded {
    fn signing(&self) -> SigningKey<'_> {
        match self {
            Loaded::File(p) => SigningKey::File(p),
            Loaded::Kit(k) => SigningKey::Kit(k),
        }
    }
}

/// A kit file, or `-` for the first line of stdin.
fn kit_arg(p: &Path, stdin: &std::io::Stdin) -> Result<Kit> {
    if p.as_os_str() == "-" {
        read_kit(&mut stdin.lock())
    } else {
        load_kit(p)
    }
}

/// Read `--kit`; `--key` stays a path.
fn load_key_arg(k: KeyArg, stdin: &std::io::Stdin) -> Result<Loaded> {
    match (k.key, k.kit) {
        (Some(p), None) => Ok(Loaded::File(p)),
        (None, Some(p)) => Ok(Loaded::Kit(kit_arg(&p, stdin)?)),
        _ => anyhow::bail!("give exactly one of --key and --kit"),
    }
}

#[derive(Subcommand)]
enum KitCmd {
    /// Generate a recovery kit offline into --out (0600, never overwritten); prints only its
    /// key id, fingerprint and escrow recipient
    New {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Recovery kit (one master secret: the recovery key and the escrow key)
    #[command(subcommand)]
    Kit(KitCmd),
    /// Read a machine's escrowed LUKS recovery keys and open them locally with the kit (token
    /// needs read + recovery; every read is audited)
    EscrowRead {
        #[command(flatten)]
        server: Server,
        /// Recovery kit file (0600), or `-` for stdin
        #[arg(long)]
        kit: PathBuf,
        /// The machine's device_id
        #[arg(long)]
        device: String,
    },
    /// 生成恢复钥匙：私钥写进 --out（0600），纸面备份写进 --paper（0600）去打印
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// 纸面备份文件，默认 <out>.paper.txt
        #[arg(long)]
        paper: Option<PathBuf>,
    },
    /// 从纸面备份临时还原私钥（签完就删）
    RestoreFromPaper {
        /// 照抄纸面备份的文本文件
        #[arg(long)]
        paper: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// 用登记探针把恢复钥匙登记到服务端（要一个临时的 keys token）
    Register {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        key: KeyArg,
        /// 给人看的名字
        #[arg(long)]
        label: String,
    },
    /// 本地逐版验证服务端发布过的版本（首次使用时对照指纹记下 pin）
    Verify {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
    },
    /// 本地验链、算差异，确认后用恢复钥匙签名发布
    Sign {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
        #[command(flatten)]
        key: KeyArg,
        /// The pending bundle's id (printed by `mastersos publish`)
        #[arg(long)]
        pending: String,
    },
    /// 本地验链后为最新版续签心跳（学校钥匙模式下每次发布之后、以及每个月）
    Heartbeat {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
        #[command(flatten)]
        key: KeyArg,
        /// 有效期天数，1 到 31
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
    /// 用本地验证过的 trust 与版本核对一份种子
    SeedCheck {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
        /// 种子文件
        seed: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        // 错误里可能带服务端给的字符串：一样转义。
        eprintln!("错误：{}", mastersos_sign::safe::text(&format!("{e:#}")));
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    match cli.cmd {
        Cmd::Kit(KitCmd::New { out: path }) => {
            let k = kit_new(&path)?;
            println!("key id:      {}", k.key_id);
            println!("fingerprint: {}", k.fingerprint);
            println!("recipient:   {}", k.recipient);
            println!("kit:         {} (0600)", path.display());
            println!(
                "Print the kit file on paper and lock the printout away, register it with \
                 `mastersos-sign register --kit`, then move the file to a USB stick and delete it from \
                 this computer."
            );
        }
        Cmd::EscrowRead {
            server,
            kit,
            device,
        } => {
            let kit = kit_arg(&kit, &stdin)?;
            let n = escrow_read(&server.api()?, &kit, &device, &mut out).await?;
            println!("{n} recovery key(s) opened.");
        }
        Cmd::Keygen { out: key, paper } => {
            let paper_path = paper.unwrap_or_else(|| {
                let mut p = key.clone().into_os_string();
                p.push(".paper.txt");
                PathBuf::from(p)
            });
            let k = keygen(&key)?;
            if let Err(e) = mastersos_sign::write_paper(&paper_path, &k.paper) {
                let _ = std::fs::remove_file(&key);
                return Err(e);
            }
            println!("key id：{}", k.trust_key.id);
            println!(
                "指纹：  {}",
                mastersos_bundle::trust_fingerprint(&k.trust_key)
            );
            println!("公钥：  {}", k.trust_key.public_key);
            println!("私钥：  {}（0600）", key.display());
            println!(
                "纸面备份：{}（0600，含私钥）。打印出来锁进柜子，然后删掉这个文件。",
                paper_path.display()
            );
            println!(
                "登记后删除 {}；要签名时用 `mastersos-sign restore-from-paper` 临时还原，签完再删",
                key.display()
            );
        }
        Cmd::RestoreFromPaper { paper, out: key } => {
            let text = std::fs::read_to_string(&paper)
                .with_context(|| format!("读 {} 失败", paper.display()))?;
            let k = restore_from_paper(&text, &key)?;
            println!("已还原到 {}（0600）", key.display());
            println!("key id：{}", k.id);
            println!("指纹：  {}", mastersos_bundle::trust_fingerprint(&k));
            println!("请核对与纸面备份一致；签完立即删除 {}", key.display());
        }
        Cmd::Register { server, key, label } => {
            let key = load_key_arg(key, &stdin)?;
            let api = server.api()?;
            match (register(&api, key.signing(), &label).await, &key) {
                (Ok(id), _) => println!("已登记：{id}"),
                // A kit registered before (say the recipient step failed): go on to the
                // recipient.
                (Err(e), Loaded::Kit(kit)) if is_already_registered(&e) => {
                    println!("Recovery key {} is already registered.", kit.key_id())
                }
                (Err(e), _) => return Err(e),
            }
            if let Loaded::Kit(kit) = &key {
                register_escrow_recipient(&api, kit, &label, &mut out).await?;
            }
            println!("When done, ask the operator to delete this keys token (mastersos-server cloud school token delete).");
        }
        Cmd::Verify { server, pin_dir } => {
            let v =
                chain::verify_chain(&server.api()?, &pin_dir.get()?, &mut stdin.lock(), &mut out)
                    .await?;
            if v.latest != v.version {
                println!(
                    "Verified up to version {}; machines accept up to version {}. Its trust:",
                    v.latest, v.version
                );
            } else {
                println!("已验证到第 {} 版，trust：", v.version);
            }
            for k in &v.trust {
                println!("    {}", mastersos_sign::key_line(k));
            }
        }
        Cmd::Sign {
            server,
            pin_dir,
            key,
            pending,
        } => {
            let key = load_key_arg(key, &stdin)?;
            sign_pending(
                &server.api()?,
                key.signing(),
                &pin_dir.get()?,
                &pending,
                &mut stdin.lock(),
                &mut out,
            )
            .await?;
        }
        Cmd::Heartbeat {
            server,
            pin_dir,
            key,
            days,
        } => {
            let key = load_key_arg(key, &stdin)?;
            sign_heartbeat(
                &server.api()?,
                key.signing(),
                &pin_dir.get()?,
                days,
                &mut stdin.lock(),
                &mut out,
            )
            .await?;
        }
        Cmd::SeedCheck {
            server,
            pin_dir,
            seed,
        } => {
            let text = std::fs::read_to_string(&seed)
                .with_context(|| format!("读 {} 失败", seed.display()))?;
            seed_check(&server.api()?, &pin_dir.get()?, &text, &mut out).await?;
        }
    }
    Ok(())
}

//! 包管理只接受显式宿主参数；不会从下载内容发现公钥、改变设备分组或启动网络请求。
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use guard_intel::{
    package::{
        store::PackageStore, Operation, PackageKind, Release, RulePayload, SignedRelease,
        MAX_RELEASE_BYTES, PACKAGE_READER_VERSION,
    },
    KeyPair, PublicKeyBytes,
};
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, ValueEnum)]
pub enum Kind {
    Knowledge,
    Rules,
}
impl From<Kind> for PackageKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Knowledge => Self::Knowledge,
            Kind::Rules => Self::Rules,
        }
    }
}

#[derive(Args)]
pub struct StoreArgs {
    /// 宿主私有仓库路径，不能放进 Agent 的可写任务目录。
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    pubkey: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long, value_enum)]
    kind: Kind,
    /// 固定设备标识由宿主管理，模型或包内容不能决定灰度分组。
    #[arg(long)]
    device_id: String,
}
impl StoreArgs {
    fn key(&self) -> Result<PublicKeyBytes> {
        PublicKeyBytes::from_path(&self.pubkey).map_err(anyhow::Error::msg)
    }
    fn open(&self) -> Result<PackageStore> {
        PackageStore::open_existing(
            &self.store,
            self.key()?,
            &self.stream,
            self.kind.into(),
            &self.device_id,
        )
    }
}

#[derive(Subcommand)]
pub enum PackageCommand {
    /// 对规范发布正文签名；输出文件必须不存在。
    Sign {
        #[arg(long)]
        release: PathBuf,
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// 验签并显示类型与摘要；不安装、不消耗更新序号。
    Inspect {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// 创建全新的私有仓库；已有仓库不能重新初始化。
    Init {
        #[command(flatten)]
        target: StoreArgs,
    },
    /// 应用安装、撤销或恢复的签名更新。
    Apply {
        #[command(flatten)]
        target: StoreArgs,
        #[arg(long)]
        package: PathBuf,
    },
    /// 重新验签完整流水并显示当前有效包。
    Status {
        #[command(flatten)]
        target: StoreArgs,
    },
    /// 用当前有效规则包处理一份事件，输出实际引擎判决；知识包不能执行。
    Evaluate {
        #[command(flatten)]
        target: StoreArgs,
        #[arg(long)]
        event: PathBuf,
    },
}

pub fn run(command: PackageCommand) -> Result<()> {
    match command {
        PackageCommand::Sign {
            release,
            secret,
            out,
        } => {
            let release = Release::from_bytes(&read_bounded(&release, MAX_RELEASE_BYTES)?)?;
            let key = KeyPair::from_secret_path(secret).map_err(anyhow::Error::msg)?;
            let signed = SignedRelease::sign(release, &key)?;
            let verified = signed.clone().verify(&key.public)?;
            let mut file = private_new(&out)?;
            file.write_all(&serde_json::to_vec_pretty(&signed)?)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            println!(
                "{}",
                json!({"signed":true,"path":out,"release_sha256":verified.release_sha256(),"signer_sha256":verified.signer_sha256()})
            );
        }
        PackageCommand::Inspect { package, pubkey } => {
            let key = PublicKeyBytes::from_path(pubkey).map_err(anyhow::Error::msg)?;
            let verified = SignedRelease::from_path(package)?.verify(&key)?;
            let release = verified.release();
            let package_digest = match &release.operation {
                Operation::Install { package } => Some(package.digest()?),
                _ => None,
            };
            println!(
                "{}",
                json!({"verified":true,"installed":false,"kind":release.kind,"stream":release.stream,"sequence":release.sequence,"security_epoch":release.security_epoch,"compatibility":release.compatibility,"rollout":release.rollout,"package_sha256":package_digest,"release_sha256":verified.release_sha256(),"signer_sha256":verified.signer_sha256(),"instruction_authority":"none","currently_compatible_and_valid":release.check_update_context(now_ms()?,PACKAGE_READER_VERSION).is_ok()})
            );
        }
        PackageCommand::Init { target } => {
            let key = target.key()?;
            // 原子创建 0600 文件；不能先打开已有文件再声称是全新仓库。
            private_new(&target.store)?.sync_all()?;
            let mut store = PackageStore::open(
                &target.store,
                key,
                &target.stream,
                target.kind.into(),
                &target.device_id,
            )?;
            println!("{}", serde_json::to_string(&store.status()?)?);
        }
        PackageCommand::Apply { target, package } => {
            let signed = SignedRelease::from_path(package)?;
            let mut store = target.open()?;
            println!(
                "{}",
                serde_json::to_string(&store.apply(signed, now_ms()?)?)?
            );
        }
        PackageCommand::Status { target } => {
            println!("{}", serde_json::to_string(&target.open()?.status()?)?)
        }
        PackageCommand::Evaluate { target, event } => {
            ensure!(
                matches!(target.kind, Kind::Rules),
                "知识库只能作为资料查看，不能执行规则"
            );
            let mut store = target.open()?;
            let (status, package) = store.snapshot()?;
            let package =
                package.context("没有有效规则包；旧版本已撤销或尚未安装，拒绝继续使用")?;
            ensure!(package.kind == PackageKind::Rules, "有效内容不是规则包");
            let payload: RulePayload = serde_json::from_value(package.content)?;
            let event: guard_schema::GuardEvent =
                serde_json::from_slice(&read_bounded(&event, 128 * 1024)?)?;
            let mut engine =
                guard_core::Engine::new(payload.rules, guard_schema::GuardContract::default())
                    .with_intel(payload.indicators);
            let decision = engine.process(&event)?;
            println!(
                "{}",
                json!({"package":status,"decision":decision,"scope":"当前规则包对给定事件的引擎判决；不代表外部动作已执行"})
            );
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= max,
        "输入文件为空或超过大小上限"
    );
    Ok(bytes)
}
fn private_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("输出文件必须不存在且父目录由宿主保护")
}
fn now_ms() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

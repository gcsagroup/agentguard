//! 宿主私有包仓库：签名更新与激活状态在同一 SQLite 事务内提交。
//!
//! 每次读取从完整签名流水重建状态，不把未认证的缓存字段当策略。防止网络旧包重放，
//! 不宣称能抵抗本机管理员删除整个仓库或恢复其历史磁盘快照；宿主必须保护仓库路径。

use super::{
    digest, Operation, Package, PackageKind, PublicKeyBytes, SignedRelease, VerifiedRelease,
    PACKAGE_READER_VERSION,
};
use anyhow::{ensure, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

mod runtime;
pub use runtime::{PolicyLease, RuntimeSnapshot, RuntimeStore};

const MAX_UPDATES: usize = 256;
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;

pub struct PackageStore {
    db: Connection,
    key: PublicKeyBytes,
    stream: String,
    kind: PackageKind,
    device: String,
}

/// 摘要回执不含包正文；认可知识资料不会产生可执行规则。
#[derive(Debug, Clone, Serialize)]
pub struct StoreStatus {
    pub stream: String,
    pub kind: PackageKind,
    pub last_sequence: u64,
    pub security_floor: u64,
    pub active_sha256: Option<String>,
    pub active_version: Option<String>,
    pub highest_installed_version: Option<String>,
    pub revoked: Vec<String>,
    pub verified_updates: usize,
    pub instruction_authority: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateEffect {
    Installed,
    OutsideRollout,
    Revoked,
    Recovered,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateReceipt {
    pub sequence: u64,
    pub release_sha256: String,
    pub effect: UpdateEffect,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
}

#[derive(Clone)]
struct AcceptedPackage {
    package: Package,
    epoch: u64,
    compatibility: super::Compatibility,
}

#[derive(Default)]
struct State {
    sequence: u64,
    floor: u64,
    active: Option<String>,
    highest_version: Option<String>,
    known_good: BTreeMap<String, AcceptedPackage>,
    revoked: BTreeSet<String>,
    updates: usize,
    history_bytes: usize,
}

impl State {
    fn apply(
        &mut self,
        verified: &VerifiedRelease,
        now_ms: i64,
        device: &str,
    ) -> Result<UpdateReceipt> {
        let release = verified.release();
        release.check_update_context(now_ms, PACKAGE_READER_VERSION)?;
        ensure!(
            release.sequence > self.sequence,
            "旧更新序号或重复更新不能覆盖当前状态"
        );
        ensure!(
            release.security_epoch >= self.floor,
            "更新安全代次低于已接受下限"
        );
        let before = self.active.clone();
        let effect = match &release.operation {
            Operation::Install { package } => {
                let hash = package.digest()?;
                ensure!(!self.revoked.contains(&hash), "已撤销内容不能重新安装");
                if let Some(highest) = &self.highest_version {
                    let order = version(&package.version).cmp(&version(highest));
                    ensure!(
                        !order.is_lt(),
                        "普通安装不能降低版本，恢复必须使用独立签名指令"
                    );
                    if order.is_eq() {
                        ensure!(
                            self.known_good.contains_key(&hash),
                            "相同版本不能替换为不同内容"
                        );
                    }
                }
                if release.selected(device)? {
                    // 同一内容换个更新序号不能虚构更高安全代次，也不能抹掉原有兼容范围。
                    if let Some(existing) = self.known_good.get(&hash) {
                        ensure!(
                            existing.epoch == release.security_epoch
                                && existing.compatibility.min_reader
                                    == release.compatibility.min_reader
                                && existing.compatibility.max_reader
                                    == release.compatibility.max_reader,
                            "同一包摘要不能重写安全代次或兼容范围"
                        );
                    }
                    self.known_good.insert(
                        hash.clone(),
                        AcceptedPackage {
                            package: package.clone(),
                            epoch: release.security_epoch,
                            compatibility: release.compatibility,
                        },
                    );
                    self.active = Some(hash);
                    self.highest_version = Some(package.version.clone());
                    self.floor = release.security_epoch;
                    UpdateEffect::Installed
                } else {
                    // 未入选设备继续使用已有包；仍保存签名序号，拒绝更旧发布的重放。
                    UpdateEffect::OutsideRollout
                }
            }
            Operation::Revoke { digests, .. } => {
                self.revoked.extend(digests.iter().cloned());
                self.floor = release.security_epoch;
                if self.active.as_ref().is_some_and(|hash| {
                    self.revoked.contains(hash) || self.known_good[hash].epoch < self.floor
                }) {
                    self.active = None;
                }
                UpdateEffect::Revoked
            }
            Operation::Recover { digest, .. } => {
                ensure!(!self.revoked.contains(digest), "已撤销包不能恢复");
                let target = self
                    .known_good
                    .get(digest)
                    .context("只能恢复本机曾成功接受的准确包摘要")?;
                ensure!(
                    target.epoch >= release.security_epoch,
                    "恢复目标低于安全下限"
                );
                ensure!(
                    (target.compatibility.min_reader..=target.compatibility.max_reader)
                        .contains(&PACKAGE_READER_VERSION),
                    "恢复目标不兼容当前读取协议"
                );
                self.active = Some(digest.clone());
                self.floor = release.security_epoch;
                UpdateEffect::Recovered
            }
        };
        self.sequence = release.sequence;
        self.updates += 1;
        Ok(UpdateReceipt {
            sequence: release.sequence,
            release_sha256: verified.release_sha256().into(),
            effect,
            before_sha256: before,
            after_sha256: self.active.clone(),
        })
    }

    fn status(&self, stream: &str, kind: PackageKind) -> StoreStatus {
        StoreStatus {
            stream: stream.into(),
            kind,
            last_sequence: self.sequence,
            security_floor: self.floor,
            active_sha256: self.active.clone(),
            active_version: self
                .active
                .as_ref()
                .map(|h| self.known_good[h].package.version.clone()),
            highest_installed_version: self.highest_version.clone(),
            revoked: self.revoked.iter().cloned().collect(),
            verified_updates: self.updates,
            instruction_authority: "none",
        }
    }
}

impl PackageStore {
    /// 参数只能由宿主固定配置提供。一个仓库固定一个签发公钥、类型、更新流和设备。
    pub fn open(
        path: impl AsRef<Path>,
        key: PublicKeyBytes,
        stream: &str,
        kind: PackageKind,
        host_device_id: &str,
    ) -> Result<Self> {
        Self::open_mode(path.as_ref(), key, stream, kind, host_device_id, true)
    }

    /// 查询或更新已有仓库不隐式创建空仓库，也不修补身份缺失的文件。
    pub fn open_existing(
        path: impl AsRef<Path>,
        key: PublicKeyBytes,
        stream: &str,
        kind: PackageKind,
        host_device_id: &str,
    ) -> Result<Self> {
        Self::open_mode(path.as_ref(), key, stream, kind, host_device_id, false)
    }

    fn open_mode(
        path: &Path,
        key: PublicKeyBytes,
        stream: &str,
        kind: PackageKind,
        host_device_id: &str,
        initialize: bool,
    ) -> Result<Self> {
        ensure!(
            super::identifier(stream, 64)
                && !host_device_id.is_empty()
                && host_device_id.len() <= 256,
            "宿主包仓库身份无效"
        );
        let mut flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        if initialize {
            flags |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let tx = db.transaction_with_behavior(if initialize {
            TransactionBehavior::Immediate
        } else {
            // 只验证已有身份不写入，动作持有执行许可时仍可读取当前状态。
            TransactionBehavior::Deferred
        })?;
        if initialize {
            tx.execute_batch("CREATE TABLE IF NOT EXISTS package_identity (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
                signer_sha256 TEXT NOT NULL, stream TEXT NOT NULL, kind TEXT NOT NULL, device_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS package_updates (
                sequence INTEGER PRIMARY KEY, release_sha256 TEXT NOT NULL UNIQUE,
                accepted_at_ms INTEGER NOT NULL, signed_bytes BLOB NOT NULL
            );")?;
        }
        let signer = digest(&key.0);
        let device = digest(host_device_id.as_bytes());
        let kind_text = serde_json::to_string(&kind)?;
        let existing: Option<(u32, String, String, String, String)> = tx.query_row(
            "SELECT schema_version,signer_sha256,stream,kind,device_sha256 FROM package_identity WHERE singleton=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).optional()?;
        match existing {
            Some(identity) => ensure!(
                identity == (1, signer, stream.into(), kind_text, device),
                "包仓库与宿主固定身份不一致"
            ),
            None => {
                ensure!(initialize, "包仓库缺少身份，拒绝隐式初始化");
                let count: i64 =
                    tx.query_row("SELECT COUNT(*) FROM package_updates", [], |r| r.get(0))?;
                ensure!(count == 0, "已有更新流水却缺少宿主身份，拒绝重新初始化");
                tx.execute(
                    "INSERT INTO package_identity VALUES(1,1,?,?,?,?)",
                    params![signer, stream, kind_text, device],
                )?;
            }
        }
        tx.commit()?;
        let mut store = Self {
            db,
            key,
            stream: stream.into(),
            kind,
            device: host_device_id.into(),
        };
        store.status()?;
        Ok(store)
    }

    /// 签名和所有语义检查失败都不写流水；提交失败不会改变下次读取到的有效状态。
    pub fn apply(&mut self, signed: SignedRelease, now_ms: i64) -> Result<UpdateReceipt> {
        let verified = signed.verify(&self.key)?;
        check_identity(&verified, &self.stream, self.kind)?;
        let bytes = verified.signed_bytes()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = replay(&tx, &self.key, &self.stream, self.kind, &self.device)?;
        ensure!(
            state.updates < MAX_UPDATES && state.history_bytes + bytes.len() <= MAX_HISTORY_BYTES,
            "包更新流水达到保留上限，拒绝覆盖历史"
        );
        let receipt = state.apply(&verified, now_ms, &self.device)?;
        tx.execute("INSERT INTO package_updates(sequence,release_sha256,accepted_at_ms,signed_bytes) VALUES(?,?,?,?)", params![receipt.sequence as i64, receipt.release_sha256, now_ms, bytes])?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn status(&mut self) -> Result<StoreStatus> {
        let tx = self.db.transaction()?;
        let state = replay(&tx, &self.key, &self.stream, self.kind, &self.device)?;
        let status = state.status(&self.stream, self.kind);
        tx.commit()?;
        Ok(status)
    }

    /// 仅从重新验签的流水读取有效包；被撤销而未恢复时返回 None，调用方必须停止使用旧包。
    pub fn active_package(&mut self) -> Result<Option<Package>> {
        Ok(self.snapshot()?.1)
    }

    /// 状态和内容来自同一个读取事务，避免并发更新后展示与执行分别取到不同版本。
    pub fn snapshot(&mut self) -> Result<(StoreStatus, Option<Package>)> {
        let tx = self.db.transaction()?;
        let state = replay(&tx, &self.key, &self.stream, self.kind, &self.device)?;
        let status = state.status(&self.stream, self.kind);
        let package = state
            .active
            .as_ref()
            .map(|hash| state.known_good[hash].package.clone());
        tx.commit()?;
        Ok((status, package))
    }
}

fn check_identity(release: &VerifiedRelease, stream: &str, kind: PackageKind) -> Result<()> {
    ensure!(
        release.release().stream == stream && release.release().kind == kind,
        "签名更新不属于宿主固定的流或类型"
    );
    Ok(())
}

fn replay(
    db: &Connection,
    key: &PublicKeyBytes,
    stream: &str,
    kind: PackageKind,
    device: &str,
) -> Result<State> {
    let mut state = State::default();
    let (count, size): (i64, i64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(signed_bytes)),0) FROM package_updates",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        count >= 0
            && count as usize <= MAX_UPDATES
            && size >= 0
            && size as usize <= MAX_HISTORY_BYTES,
        "包更新流水超出支持范围"
    );
    let mut statement = db.prepare("SELECT sequence,release_sha256,accepted_at_ms,signed_bytes FROM package_updates ORDER BY sequence")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(3)?;
        let verified = SignedRelease::from_bytes(&bytes)?.verify(key)?;
        check_identity(&verified, stream, kind)?;
        ensure!(
            row.get::<_, i64>(0)? == verified.release().sequence as i64
                && row.get::<_, String>(1)? == verified.release_sha256(),
            "更新索引与签名正文不一致"
        );
        state.apply(&verified, row.get(2)?, device)?;
        state.history_bytes += bytes.len();
    }
    Ok(state)
}

fn version(v: &str) -> Vec<u32> {
    v.split('.')
        .map(|p| p.parse().expect("签名包已校验版本"))
        .collect()
}

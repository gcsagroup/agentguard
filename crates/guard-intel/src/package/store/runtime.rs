//! 实际动作持有立即事务，外部更新不能在旧策略动作仍运行时提交。
//!
//! 浏览器 DOM 动作可派生同一宿主的 HTTP 请求；引用计数共享同一事务，避免嵌套动作
//! 再开写锁而死锁。等待人工批准时不申请许可，真正执行前才核对准确发布代次。
use super::*;
use std::sync::{Arc, Mutex};

pub struct RuntimeSnapshot {
    status: StoreStatus,
    package: Option<Package>,
    binding_sha256: String,
}
impl RuntimeSnapshot {
    pub fn status(&self) -> &StoreStatus {
        &self.status
    }
    pub fn package(&self) -> Option<&Package> {
        self.package.as_ref()
    }
    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }
}

struct Live {
    store: PackageStore,
    active: Option<Arc<RuntimeSnapshot>>,
    users: usize,
    failed: bool,
}

#[derive(Clone)]
pub struct RuntimeStore {
    shared: Arc<Mutex<Live>>,
}
pub struct PolicyLease {
    shared: Arc<Mutex<Live>>,
    snapshot: Arc<RuntimeSnapshot>,
}

impl RuntimeStore {
    pub fn new(store: PackageStore) -> Result<Self> {
        ensure!(store.kind == PackageKind::Rules, "执行许可只支持规则包仓库");
        Ok(Self {
            shared: Arc::new(Mutex::new(Live {
                store,
                active: None,
                users: 0,
                failed: false,
            })),
        })
    }

    pub fn snapshot(&self) -> Result<Arc<RuntimeSnapshot>> {
        let mut live = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("策略许可锁失效"))?;
        ensure!(!live.failed, "策略事务状态未知，拒绝继续使用");
        if let Some(active) = &live.active {
            return Ok(active.clone());
        }
        let (status, package) = live.store.snapshot()?;
        Ok(Arc::new(snapshot(&live.store, status, package)?))
    }

    /// 返回的许可必须活到动作结束；它不是一个可序列化、可由模型伪造的授权令牌。
    pub fn acquire(&self, expected: &str) -> Result<PolicyLease> {
        let mut live = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("策略许可锁失效"))?;
        ensure!(!live.failed, "策略事务状态未知，拒绝继续使用");
        if live.active.is_none() {
            // IMMEDIATE 在 rollback journal 和 WAL 下都阻止其它写事务提交。
            live.store.db.execute_batch("BEGIN IMMEDIATE")?;
            let loaded = (|| {
                let store = &live.store;
                let state = replay(
                    &store.db,
                    &store.key,
                    &store.stream,
                    store.kind,
                    &store.device,
                )?;
                let status = state.status(&store.stream, store.kind);
                let package = state
                    .active
                    .as_ref()
                    .map(|hash| state.known_good[hash].package.clone());
                let snapshot = snapshot(store, status, package)?;
                ensure!(
                    snapshot.package.is_some() && snapshot.binding_sha256 == expected,
                    "策略发布已变化或已撤销，旧动作批准不能派发"
                );
                Ok(Arc::new(snapshot))
            })();
            match loaded {
                Ok(snapshot) => live.active = Some(snapshot),
                Err(error) => {
                    if live.store.db.execute_batch("ROLLBACK").is_err() {
                        live.failed = true;
                    }
                    return Err(error);
                }
            }
        }
        let snapshot = live.active.as_ref().expect("已持有策略事务").clone();
        ensure!(
            snapshot.binding_sha256 == expected,
            "嵌套动作使用了其它策略代次"
        );
        live.users = live.users.checked_add(1).context("策略许可计数超限")?;
        Ok(PolicyLease {
            shared: self.shared.clone(),
            snapshot,
        })
    }
}

impl PolicyLease {
    pub fn snapshot(&self) -> &RuntimeSnapshot {
        &self.snapshot
    }
}
impl Drop for PolicyLease {
    fn drop(&mut self) {
        let Ok(mut live) = self.shared.lock() else {
            return;
        };
        if live.users == 0 {
            live.failed = true;
            return;
        }
        live.users -= 1;
        if live.users == 0 {
            // 许可没有数据库写入，用 ROLLBACK 结束持锁范围；失败则锁存禁止新动作。
            if live.store.db.execute_batch("ROLLBACK").is_err() {
                live.failed = true;
            }
            live.active = None;
        }
    }
}

fn snapshot(
    store: &PackageStore,
    status: StoreStatus,
    package: Option<Package>,
) -> Result<RuntimeSnapshot> {
    let binding = serde_json::json!({"signer_sha256":digest(&store.key.0),"stream":store.stream,"kind":store.kind,
        "device_sha256":digest(store.device.as_bytes()),"sequence":status.last_sequence,"security_floor":status.security_floor,"active_sha256":status.active_sha256});
    let binding_sha256 = digest(&super::super::domain_bytes("runtime-policy", &binding)?);
    Ok(RuntimeSnapshot {
        status,
        package,
        binding_sha256,
    })
}

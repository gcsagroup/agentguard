//! 宿主持有当前预算树；独立控制面可以在主线程等待批准时撤销子树。
use crate::delegation_budget::{BudgetLimits, BudgetTree};
use crate::journal::SharedJournal;
use crate::{control_http::ControlRequest, operator::OperatorReply, PendingConfirm};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Session {
    host: String,
    tree: BudgetTree,
}
#[derive(Clone, Default)]
pub(crate) struct BudgetManager(Arc<Mutex<Option<Session>>>);
impl BudgetManager {
    pub(crate) fn start(&self, host: &str, root: &str, limits: BudgetLimits) -> Result<()> {
        let mut current = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("预算会话锁失效"))?;
        if let Some(old) = current.as_ref() {
            old.tree.close()?;
        }
        *current = Some(Session {
            host: host.to_owned(),
            tree: BudgetTree::new(root, limits, Instant::now())?,
        });
        Ok(())
    }
    pub(crate) fn current(&self, host: &str) -> Result<BudgetTree> {
        let current = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("预算会话锁失效"))?;
        let session = current.as_ref().context("预算会话尚未开始")?;
        ensure!(session.host == host, "预算不属于当前宿主会话");
        Ok(session.tree.clone())
    }
    pub(crate) fn status(&self) -> Result<Value> {
        let current = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("预算会话锁失效"))?;
        let session = current.as_ref().context("预算会话尚未开始")?;
        Ok(json!({"host_session_id":session.host,"budget":session.tree.status(Instant::now())?}))
    }
}

#[derive(Clone)]
pub struct DelegationOperator {
    manager: BudgetManager,
    journal: SharedJournal,
    pending: PendingConfirm,
}
impl DelegationOperator {
    pub(crate) fn new(
        manager: BudgetManager,
        journal: SharedJournal,
        pending: PendingConfirm,
    ) -> Self {
        Self {
            manager,
            journal,
            pending,
        }
    }
    pub(crate) fn serve(&self, request: &ControlRequest) -> OperatorReply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Revoke {
            host_session_id: guard_schema::ValidatedId,
            grant_id: guard_schema::ValidatedId,
        }
        let result = (|| -> Result<Value> {
            ensure!(self.journal.healthy(), "委托审计不可用");
            match (request.method(), request.url()) {
                ("GET", "/delegation/status") => self.manager.status(),
                ("POST", "/delegation/revoke") => {
                    ensure!(request.body().len() <= 4096, "撤销请求过大");
                    let body: Revoke = serde_json::from_slice(request.body())?;
                    // 持有当前会话锁直到撤销结果持久化，重开会话不能穿插并覆盖其含义。
                    let current = self
                        .manager
                        .0
                        .lock()
                        .map_err(|_| anyhow::anyhow!("预算会话锁失效"))?;
                    let session = current.as_ref().context("预算会话尚未开始")?;
                    ensure!(
                        session.host == body.host_session_id.as_str(),
                        "旧宿主会话不能撤销新授权"
                    );
                    let affected = session.tree.revoke(body.grant_id.as_str())?;
                    if let Some(pending) = self.pending.peek() {
                        if let Some(action) = pending.binding.as_ref().map(|b| b.action()) {
                            let message = action.spec().parameters.pointer("/delegation/message");
                            if message.and_then(|m| m["host_session_id"].as_str())
                                == Some(session.host.as_str())
                            {
                                if let Some(grant) = message.and_then(|m| m["grant_id"].as_str()) {
                                    if session.tree.check_grant(grant, Instant::now()).is_err() {
                                        self.pending.cancel_request(&pending.id);
                                    }
                                }
                            }
                        }
                    }
                    let state = session.tree.status(Instant::now())?;
                    if let Err(error) = self.journal.delegation_budget_event(&session.host, "revoked", json!({
                        "grant_id":body.grant_id,"affected":affected,"state":state,
                        "completed_effects":"not_reverted","in_flight":"cancellation_requested_outcome_requires_receipt"})) {
                        let _ = session.tree.close();
                        self.pending.pause();
                        return Err(error);
                    }
                    Ok(
                        json!({"host_session_id":session.host,"grant_id":body.grant_id,"revoked":true,"affected":affected,
                        "completed_effects":"not_reverted","budget":state}),
                    )
                }
                _ => anyhow::bail!("不支持此委托控制请求"),
            }
        })();
        match result {
            Ok(value) => (200, value),
            Err(error) => (
                409,
                json!({"error":"DELEGATION_CONTROL","detail":error.to_string()}),
            ),
        }
    }
}

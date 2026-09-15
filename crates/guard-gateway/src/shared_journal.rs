//! 同一个审计连接由执行器与来源采集器共享，源记录和终态仍是两条独立事件。
use super::*;
use std::sync::{Arc, Mutex};

const SOURCE_BINDING_ID: &str = "gateway-source-storage/v1";

#[cfg(all(test, unix))]
#[path = "shared_journal_tests.rs"]
mod tests;

#[derive(Clone)]
pub struct SharedJournal(Arc<Mutex<ExecutionJournal>>);

impl From<ExecutionJournal> for SharedJournal {
    fn from(journal: ExecutionJournal) -> Self {
        Self(Arc::new(Mutex::new(journal)))
    }
}

impl SharedJournal {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn delegation_budget_event(
        &self,
        host: &str,
        kind: &str,
        body: Value,
    ) -> Result<()> {
        let id = format!("delegation-budget/{:032x}", rand::random::<u128>());
        self.access(|journal| {
            journal.append(&AuditRecord {
                id,
                timestamp_ms: now_ms(),
                platform: "gateway".into(),
                event_type: "GatewayDelegationBudget".into(),
                source_app: "agentguard-mcp".into(),
                agent_session_id: Some(host.into()),
                rule_id: "DELEGATION-BUDGET".into(),
                severity: "Info".into(),
                action: kind.into(),
                human_message: "宿主委托预算与撤销状态；不包含私钥或工具正文".into(),
                event_json: serde_json::to_string(
                    &json!({"schema":"gateway_delegation_budget_v1","kind":kind,"body":body}),
                )?,
                evidence_ref: None,
                user_decision: None,
                attributed_agent: None,
            })
        })
    }
    fn access<T>(&self, action: impl FnOnce(&ExecutionJournal) -> Result<T>) -> Result<T> {
        let journal = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("审计共享锁失效，禁止继续执行"))?;
        action(&journal)
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn healthy(&self) -> bool {
        self.access(|journal| Ok(journal.healthy()))
            .unwrap_or(false)
    }

    pub fn status(&self) -> Value {
        self.access(|journal| Ok(journal.status()))
            .unwrap_or(json!({"persistent":true,"healthy":false,"error":"journal_lock_failed"}))
    }

    pub fn decided(&self, action: &ActionSnapshot, outcome: &Outcome) -> Result<()> {
        self.access(|journal| journal.decided(action, outcome))
    }

    pub fn started(&self, action: &ActionSnapshot, approval: Option<&str>) -> Result<()> {
        self.access(|journal| journal.started(action, approval))
    }

    pub(crate) fn decided_and_started(
        &self,
        action: &ActionSnapshot,
        outcome: &Outcome,
    ) -> Result<()> {
        self.access(|journal| journal.decided_and_started(action, outcome))
    }

    pub fn finished(
        &self,
        action: &ActionSnapshot,
        approval: Option<&str>,
        outcome: ExecutionOutcome,
        output: Option<&ExecOutput>,
    ) -> Result<()> {
        self.access(|journal| journal.finished(action, approval, outcome, output))
    }

    pub(crate) fn source_observed(&self, event: &SourceObservedEvent) -> Result<()> {
        self.access(|journal| journal.source_observed(event))
    }

    pub(crate) fn finished_with_source(
        &self,
        action: &ActionSnapshot,
        approval: Option<&str>,
        output: &ExecOutput,
        event: &SourceObservedEvent,
    ) -> Result<()> {
        self.access(|journal| {
            anyhow::ensure!(journal.healthy(), "审计写入已失败，禁止新动作");
            let source = ExecutionJournal::source_record(event)?;
            let finished = journal.record(action, approval, Some(output.outcome), Some(output))?;
            if let Err(error) = journal.store.append_pair(&source, &finished) {
                journal.healthy.set(false);
                return Err(error).context("来源与终态不能一起持久保存");
            }
            Ok(())
        })
    }

    pub(crate) fn has_source_binding(&self) -> Result<bool> {
        self.access(|journal| Ok(journal.store.record_by_id(SOURCE_BINDING_ID)?.is_some()))
    }

    /// 旧库不改写；导入全部来源和旧库绑定只有一次提交。以后旧库变化必须拒绝。
    pub(crate) fn import_sources(
        &self,
        legacy: &ExecutionJournal,
    ) -> Result<Vec<SourceObservedEvent>> {
        let snapshot = legacy.store.verified_source_snapshot()?;
        let events = snapshot
            .records()
            .iter()
            .map(|record| {
                anyhow::ensure!(
                    record.event_type == "GatewaySourceObserved",
                    "旧来源库含未知事件，禁止部分迁移"
                );
                let event: SourceObservedEvent = serde_json::from_str(&record.event_json)?;
                let expected = ExecutionJournal::source_record(&event)?;
                anyhow::ensure!(
                    expected.id == record.id && expected.timestamp_ms == record.timestamp_ms,
                    "旧来源事件与审计身份不一致"
                );
                Ok(event)
            })
            .collect::<Result<Vec<_>>>()?;
        crate::provenance::SourceCollector::validate_events(&events)?;
        let binding = json!({"schema":"gateway_source_storage_v1",
            "legacy_log_id_sha256":sha256(legacy.store.log_id()?.context("旧来源库缺少日志身份")?.as_bytes()),
            "legacy_head_sha256":snapshot.head_sha256(), "legacy_records":snapshot.records().len()});
        self.access(|journal| {
            if let Some(record) = journal.store.record_by_id(SOURCE_BINDING_ID)? {
                anyhow::ensure!(
                    record.event_type == "GatewaySourceStorageBinding"
                        && serde_json::from_str::<Value>(&record.event_json)? == binding,
                    "旧来源库的身份或内容已经变化，禁止继续恢复"
                );
            } else {
                anyhow::ensure!(
                    journal.store.source_observations(1)?.is_empty(),
                    "执行日志已有未绑定来源，禁止猜测恢复顺序"
                );
                let mut records = events
                    .iter()
                    .map(ExecutionJournal::source_record)
                    .collect::<Result<Vec<_>>>()?;
                records.push(AuditRecord {
                    id: SOURCE_BINDING_ID.into(),
                    timestamp_ms: now_ms(),
                    platform: "gateway".into(),
                    event_type: "GatewaySourceStorageBinding".into(),
                    source_app: "agentguard-mcp".into(),
                    agent_session_id: None,
                    rule_id: "GATEWAY-SOURCE".into(),
                    severity: "Info".into(),
                    action: "source_storage_binding".into(),
                    human_message: "来源日志迁移绑定；旧库保留，仅保存身份与链头摘要".into(),
                    evidence_ref: None,
                    user_decision: None,
                    event_json: serde_json::to_string(&binding)?,
                    attributed_agent: None,
                });
                anyhow::ensure!(journal.healthy(), "审计写入已失败，禁止迁移");
                if let Err(error) = journal.store.append_batch(&records) {
                    journal.healthy.set(false);
                    return Err(error).context("来源迁移不能完整提交");
                }
            }
            journal.source_events()
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl SharedJournal {
    pub(crate) fn delegation_root(
        &self,
        signed: &guard_schema::delegation::SignedDelegationGrant,
    ) -> Result<()> {
        let grant = &signed.grant;
        grant.validate()?;
        let digest = crate::delegation::grant_digest(grant)?;
        self.access(|journal| journal.append(&AuditRecord {
            id:format!("delegation-root/{}",digest.as_str()), timestamp_ms:now_ms(), platform:"gateway".into(), event_type:"GatewayDelegationRoot".into(),
            source_app:"agentguard-mcp".into(), agent_session_id:Some(grant.host_session_id.to_string()), rule_id:"DELEGATION-ROOT".into(), severity:"Info".into(),
            action:"issued".into(), human_message:"宿主已签发当前会话的委托根授权；不记录文件路径或私钥".into(),
            event_json:serde_json::to_string(&json!({"schema":"gateway_delegation_root_v1","grant_sha256":digest,"subject_id":grant.subject_id,
                "session_id":grant.session_id,"key_id":signed.key_id,"signature":signed.signature,"issued_at_ms":grant.issued_at_ms,"expires_at_ms":grant.expires_at_ms}))?,
            evidence_ref:None,user_decision:None,attributed_agent:None,
        }))
    }
    pub(crate) fn delegation_message(
        &self,
        verified: &crate::delegation::VerifiedDelegation,
        child: Option<&guard_schema::delegation::SignedDelegationGrant>,
        action: Option<&ActionSnapshot>,
    ) -> Result<()> {
        let message = &verified.envelope.message;
        let digest = sha256(&message.signing_bytes()?);
        let action_sha = action.map(|a| sha256(&a.canonical_bytes()));
        let child_sha = child
            .map(|c| crate::delegation::grant_digest(&c.grant))
            .transpose()?;
        self.access(|journal| journal.append(&AuditRecord {
            id:format!("delegation-{}/{}",if action.is_some(){"binding"}else{"accepted"},digest),timestamp_ms:now_ms(),platform:"gateway".into(),
            event_type:if action.is_some(){"GatewayDelegationDispatchBinding"}else{"GatewayDelegationAccepted"}.into(),source_app:"agentguard-mcp".into(),
            agent_session_id:Some(message.host_session_id.to_string()),rule_id:"DELEGATION-VERIFIED".into(),severity:"Info".into(),action:"authenticated".into(),
            human_message:"每条委托消息已验签并与实际执行绑定；正文和文件路径只保留摘要".into(),
            event_json:serde_json::to_string(&json!({"schema":"gateway_delegation_message_v1","receipt":verified.receipt(),"child_grant_sha256":child_sha,"action_sha256":action_sha}))?,
            evidence_ref:None,user_decision:None,attributed_agent:Some(message.actor_id.to_string()),
        }))
    }
}

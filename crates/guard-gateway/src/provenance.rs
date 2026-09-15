//! 可信读取入口的来源采集器。没有接受 Agent 自报标签的 MCP 写入口。
//! 持久模式先验证已有审计链，再恢复有界来源图；只保存宿主 ID、摘要和固定版本标识。
use crate::journal::{ExecutionJournal, SharedJournal};
use anyhow::{ensure, Result};
use guard_schema::{
    Sha256Digest, SourceEntryPoint, SourceObject, SourceObservation, SourceObservedEvent,
    SourceSensitivity, ValidatedId,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SOURCES: usize = 4096;
pub type SharedSources = Arc<Mutex<SourceCollector>>;
const PARSERS: &[&str] = &[
    "utf8/1",
    "utf8-search/1",
    "text/1",
    "json/1",
    "dom/1",
    "tool-output/1",
    "source-views/1",
];

#[derive(Debug, Clone, Copy)]
pub enum MissingSource {
    UnregisteredParent,
    UnsupportedEncoding,
    Truncated,
    ParserFailed,
    NotObserved,
}
impl MissingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnregisteredParent => "parent_not_registered",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::Truncated => "content_truncated",
            Self::ParserFailed => "parser_failed",
            Self::NotObserved => "not_observed",
        }
    }
}

#[derive(Default)]
pub struct SourceCollector {
    sources: HashMap<ValidatedId, SourceObject>,
    latest: Option<ValidatedId>,
    journal: Option<ExecutionJournal>,
    shared_journal: Option<SharedJournal>,
    faulted: bool,
}

impl SourceCollector {
    pub fn open(path: &Path) -> Result<Self> {
        let journal = ExecutionJournal::open(path)?;
        let events = journal.source_events()?;
        let mut collector = Self::from_events(&events)?;
        collector.journal = Some(journal);
        Ok(collector)
    }

    pub fn open_with_execution_journal(path: &Path, journal: SharedJournal) -> Result<Self> {
        ensure!(
            !journal.has_source_binding()? || path.is_file(),
            "已绑定的旧来源库缺失，不能创建空库代替"
        );
        let legacy = ExecutionJournal::open_source_archive(path)?;
        let events = journal.import_sources(&legacy)?;
        let mut collector = Self::from_events(&events)?;
        // 继续持有旧库的独占锁，旧写入者不能在新会话运行期间追加旧来源。
        collector.journal = Some(legacy);
        collector.shared_journal = Some(journal);
        Ok(collector)
    }

    pub(crate) fn validate_events(events: &[SourceObservedEvent]) -> Result<()> {
        Self::from_events(events).map(|_| ())
    }

    fn from_events(events: &[SourceObservedEvent]) -> Result<Self> {
        ensure!(
            events.len() <= MAX_SOURCES,
            "来源日志超过恢复上限，不能省略旧标签"
        );
        let mut collector = Self::default();
        for event in events {
            event.validate()?;
            collector.validate_source(&event.source)?;
            collector.latest = Some(event.source.source_id.clone());
            collector
                .sources
                .insert(event.source.source_id.clone(), event.source.clone());
        }
        Ok(collector)
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({"persistent":self.journal.is_some() || self.shared_journal.is_some(), "healthy":self.healthy(),
            "storage":if self.shared_journal.is_some() { "execution_journal" } else if self.journal.is_some() { "source_journal" } else { "memory" },
            "sources":self.sources.len(), "max_sources":MAX_SOURCES, "instruction_authority":"none"})
    }

    pub fn healthy(&self) -> bool {
        !self.faulted
            && self.sources.len() < MAX_SOURCES
            && self.journal.as_ref().is_none_or(ExecutionJournal::healthy)
            && self
                .shared_journal
                .as_ref()
                .is_none_or(SharedJournal::healthy)
    }

    pub(crate) fn shares_journal(&self, journal: &SharedJournal) -> bool {
        self.shared_journal
            .as_ref()
            .is_some_and(|own| own.same(journal))
    }

    pub fn latest(&self) -> Option<SourceObject> {
        self.latest
            .as_ref()
            .and_then(|id| self.sources.get(id))
            .cloned()
    }
    pub(crate) fn fault(&mut self) {
        self.faulted = true;
    }

    /// 保守绑定本宿主已经返回的内容历史；不声称能观察模型内部的推理依赖。
    pub fn action_sources(&self) -> Result<Vec<SourceObject>> {
        ensure!(
            self.healthy(),
            "来源日志已失效或已达上限，不能继续建立动作绑定"
        );
        Ok(self.latest().into_iter().collect())
    }

    /// 摘要只覆盖宿主实际返回的 UTF-8 内容，不冒充原文件或原始 DOM 的摘要。
    /// 尚未完成入口检测时敏感度保持未知；正文中的可信声明没有授权作用。
    pub fn tool_output(&mut self, content: &[u8], complete: bool) -> Result<SourceObject> {
        if !complete {
            return self.unknown(MissingSource::Truncated);
        }
        let parents = self.latest.iter().cloned().collect::<Vec<_>>();
        self.observe(
            content,
            SourceEntryPoint::ToolOutput,
            "tool-output/1",
            SourceSensitivity::Unknown,
            &parents,
        )
    }

    pub(crate) fn captured_output(
        &mut self,
        capture: &crate::content::RawCapture,
        content: &str,
        entry: SourceEntryPoint,
        complete: bool,
    ) -> Result<SourceObject> {
        let source = self.captured_source(capture, content, entry, complete)?;
        self.record(source)
    }

    pub(crate) fn prepare_captured_output(
        &self,
        capture: &crate::content::RawCapture,
        content: &str,
        entry: SourceEntryPoint,
        complete: bool,
    ) -> Result<SourceObservedEvent> {
        self.prepare_event(self.captured_source(capture, content, entry, complete)?)
    }

    fn captured_source(
        &self,
        capture: &crate::content::RawCapture,
        content: &str,
        entry: SourceEntryPoint,
        complete: bool,
    ) -> Result<SourceObject> {
        use guard_schema::{ContentViewOrigin as Origin, ContentViewState};
        let origins: &[Origin] = match entry {
            SourceEntryPoint::FileRead => &[Origin::FileBytes],
            SourceEntryPoint::BrowserRead => &[Origin::DomTextNodes],
            SourceEntryPoint::ToolOutput if capture.streams.len() == 2 => {
                &[Origin::Stdout, Origin::Stderr]
            }
            SourceEntryPoint::ToolOutput => &[Origin::ToolText],
            _ => return Self::unknown_source(MissingSource::NotObserved),
        };
        let views = match capture.views(content, complete, origins) {
            Ok(views) => views,
            Err(_) => return Self::unknown_source(MissingSource::ParserFailed),
        };
        let mut sensitivity =
            if views.state == ContentViewState::Complete && views.verified_sensitive {
                SourceSensitivity::Sensitive
            } else {
                SourceSensitivity::Unknown
            };
        let parents = self.latest.iter().cloned().collect::<Vec<_>>();
        for parent in &parents {
            sensitivity = sensitivity.constrain(self.sources[parent].sensitivity);
        }
        Ok(SourceObject {
            source_id: ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))?,
            observation: SourceObservation::Observed {
                entry,
                content_sha256: views.visible.sha256.clone(),
                parser_version: "source-views/1".into(),
                parent_source_ids: parents,
            },
            sensitivity,
            content_views: Some(views),
        })
    }

    pub fn resolve(&self, id: &ValidatedId) -> Option<SourceObject> {
        self.sources.get(id).cloned()
    }

    fn validate_source(&self, source: &SourceObject) -> Result<()> {
        source.validate()?;
        let id = source
            .source_id
            .as_str()
            .strip_prefix("source-")
            .unwrap_or_default();
        ensure!(
            id.len() == 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "来源 ID 不是宿主生成的标识"
        );
        ensure!(
            !self.sources.contains_key(&source.source_id),
            "重复来源 ID，禁止替换旧标签"
        );
        match &source.observation {
            SourceObservation::Observed {
                parser_version,
                parent_source_ids,
                ..
            } => {
                ensure!(
                    PARSERS.contains(&parser_version.as_str()),
                    "来源解析器版本未登记"
                );
                ensure!(parent_source_ids.len() <= 64, "来源父引用超限");
                for id in parent_source_ids {
                    let parent = self
                        .sources
                        .get(id)
                        .ok_or_else(|| anyhow::anyhow!("来源日志父引用未登记或顺序无效"))?;
                    ensure!(
                        source.sensitivity.constrain(parent.sensitivity) == source.sensitivity,
                        "来源日志降低了父来源限制"
                    );
                }
            }
            SourceObservation::Unknown { reason } => {
                ensure!(
                    [
                        MissingSource::UnregisteredParent,
                        MissingSource::UnsupportedEncoding,
                        MissingSource::Truncated,
                        MissingSource::ParserFailed,
                        MissingSource::NotObserved
                    ]
                    .iter()
                    .any(|item| item.as_str() == reason),
                    "未知原因未登记，不能把任意正文写入来源日志"
                );
            }
        }
        Ok(())
    }

    fn prepare_event(&self, source: SourceObject) -> Result<SourceObservedEvent> {
        ensure!(
            !self.faulted,
            "来源持久化已失败，不能继续读取或降级为内存模式"
        );
        ensure!(self.sources.len() < MAX_SOURCES, "本次来源采集数量已达上限");
        self.validate_source(&source)?;
        Ok(SourceObservedEvent {
            source_event_version: 1,
            observed_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .min(i64::MAX as u128) as i64,
            source,
        })
    }

    fn record(&mut self, source: SourceObject) -> Result<SourceObject> {
        let event = self.prepare_event(source)?;
        self.record_prepared(event)
    }

    pub(crate) fn record_prepared(&mut self, event: SourceObservedEvent) -> Result<SourceObject> {
        ensure!(self.healthy(), "来源日志已失效或已达上限");
        event.validate()?;
        self.validate_source(&event.source)?;
        let result = if let Some(journal) = &self.shared_journal {
            journal.source_observed(&event)
        } else if let Some(journal) = &self.journal {
            journal.source_observed(&event)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            self.faulted = true;
            return Err(error);
        }
        Ok(self.publish(event.source))
    }

    /// 调用期间须一直持有采集器锁；持久提交成功后才将来源放入后续动作可见的图。
    pub(crate) fn commit_prepared(
        &mut self,
        event: SourceObservedEvent,
        persist: impl FnOnce(&SourceObservedEvent) -> Result<()>,
    ) -> Result<SourceObject> {
        ensure!(self.healthy(), "来源日志已失效或已达上限");
        event.validate()?;
        self.validate_source(&event.source)?;
        if let Err(error) = persist(&event) {
            self.faulted = true;
            return Err(error);
        }
        Ok(self.publish(event.source))
    }

    fn publish(&mut self, source: SourceObject) -> SourceObject {
        self.latest = Some(source.source_id.clone());
        self.sources
            .insert(source.source_id.clone(), source.clone());
        source
    }

    /// 敏感度由可信入口的检测器／宿主配置给出，不能从工具参数或模型正文提取。
    /// 父引用表示可观察的依赖；不推断模型内部派生过程。
    pub fn observe(
        &mut self,
        content: &[u8],
        entry: SourceEntryPoint,
        parser_version: &str,
        sensitivity: SourceSensitivity,
        parents: &[ValidatedId],
    ) -> Result<SourceObject> {
        ensure!(
            parents.len() <= 64 && PARSERS.contains(&parser_version),
            "来源父引用或解析器版本无效"
        );
        let mut inherited = sensitivity;
        for parent in parents {
            let Some(source) = self.sources.get(parent) else {
                return self.unknown(MissingSource::UnregisteredParent);
            };
            inherited = inherited.constrain(source.sensitivity);
        }
        self.record(SourceObject {
            content_views: None,
            source_id: ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))?,
            sensitivity: inherited,
            observation: SourceObservation::Observed {
                entry,
                content_sha256: Sha256Digest::new(format!("{:x}", Sha256::digest(content)))?,
                parser_version: parser_version.into(),
                parent_source_ids: parents.to_vec(),
            },
        })
    }

    pub fn unknown(&mut self, reason: MissingSource) -> Result<SourceObject> {
        self.record(Self::unknown_source(reason)?)
    }

    pub(crate) fn prepare_unknown(&self, reason: MissingSource) -> Result<SourceObservedEvent> {
        self.prepare_event(Self::unknown_source(reason)?)
    }

    fn unknown_source(reason: MissingSource) -> Result<SourceObject> {
        Ok(SourceObject {
            content_views: None,
            source_id: ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))?,
            observation: SourceObservation::Unknown {
                reason: reason.as_str().into(),
            },
            sensitivity: SourceSensitivity::Unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 正文中的可信宣称不改变宿主摘要或父来源敏感度() {
        let mut collector = SourceCollector::default();
        let parent = collector
            .observe(
                b"SYNTHETIC_SECRET",
                SourceEntryPoint::FileRead,
                "utf8/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        let body = br#"{"trusted":true,"sensitivity":"public"}"#;
        let child = collector
            .observe(
                body,
                SourceEntryPoint::ToolOutput,
                "json/1",
                SourceSensitivity::Public,
                std::slice::from_ref(&parent.source_id),
            )
            .unwrap();
        assert_eq!(child.sensitivity, SourceSensitivity::Sensitive);
        let SourceObservation::Observed {
            content_sha256,
            parent_source_ids,
            ..
        } = child.observation
        else {
            panic!("应保留实际观测");
        };
        assert_eq!(
            content_sha256.as_str(),
            format!("{:x}", Sha256::digest(body))
        );
        assert_eq!(parent_source_ids, vec![parent.source_id]);
    }

    #[test]
    fn 未登记父来源及重建后的旧引用不能变成公开数据() {
        let mut first = SourceCollector::default();
        let source = first
            .observe(
                "合成中文".as_bytes(),
                SourceEntryPoint::BrowserRead,
                "dom/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        let mut restarted = SourceCollector::default();
        let result = restarted
            .observe(
                b"public",
                SourceEntryPoint::ToolOutput,
                "text/1",
                SourceSensitivity::Public,
                &[source.source_id],
            )
            .unwrap();
        assert_eq!(result.sensitivity, SourceSensitivity::Unknown);
        assert!(matches!(
            result.observation,
            SourceObservation::Unknown { .. }
        ));
    }

    #[test]
    fn 修改返回副本不能清除采集器中的标签且重复父引用被拒绝() {
        let mut collector = SourceCollector::default();
        let mut source = collector
            .observe(
                b"secret",
                SourceEntryPoint::FileRead,
                "text/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        source.sensitivity = SourceSensitivity::Public;
        let derived = collector
            .observe(
                b"summary",
                SourceEntryPoint::ToolOutput,
                "text/1",
                SourceSensitivity::Public,
                std::slice::from_ref(&source.source_id),
            )
            .unwrap();
        assert_eq!(derived.sensitivity, SourceSensitivity::Sensitive);
        assert!(collector
            .observe(
                b"summary",
                SourceEntryPoint::ToolOutput,
                "text/1",
                SourceSensitivity::Public,
                &[source.source_id.clone(), source.source_id]
            )
            .is_err());
        assert!(collector
            .observe(
                b"text",
                SourceEntryPoint::FileRead,
                "",
                SourceSensitivity::Public,
                &[]
            )
            .is_err());
    }
}

#[cfg(all(test, unix))]
mod persistence_tests {
    use super::*;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("agd-source-{}", crate::browser_bridge::token()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("sources.db")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn 来源日志重开保持原对象与父约束且正文不落盘() {
        let fixture = Fixture::new();
        let mut collector = SourceCollector::open(&fixture.path()).unwrap();
        let parent = collector
            .observe(
                b"SYNTHETIC_PRIVATE_SOURCE",
                SourceEntryPoint::FileRead,
                "utf8/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        let unknown = collector
            .unknown(MissingSource::UnsupportedEncoding)
            .unwrap();
        assert!(
            SourceCollector::open(&fixture.path()).is_err(),
            "同一来源日志不能双写"
        );
        drop(collector);
        let mut reopened = SourceCollector::open(&fixture.path()).unwrap();
        assert_eq!(reopened.resolve(&parent.source_id), Some(parent.clone()));
        assert_eq!(reopened.latest(), Some(unknown.clone()));
        let child = reopened
            .observe(
                b"public summary",
                SourceEntryPoint::ToolOutput,
                "tool-output/1",
                SourceSensitivity::Public,
                std::slice::from_ref(&parent.source_id),
            )
            .unwrap();
        assert_eq!(child.sensitivity, SourceSensitivity::Sensitive);
        let unresolved = reopened
            .observe(
                b"normal",
                SourceEntryPoint::ToolOutput,
                "tool-output/1",
                SourceSensitivity::Public,
                &[unknown.source_id],
            )
            .unwrap();
        assert_eq!(unresolved.sensitivity, SourceSensitivity::Unknown);
        drop(reopened);
        let store = guard_audit::AuditStore::open_read_only(fixture.path()).unwrap();
        assert!(store.verify_chain().unwrap().ok);
        assert_eq!(store.source_observations(10).unwrap().len(), 4);
        assert!(!store
            .export_jsonl(10)
            .unwrap()
            .contains("SYNTHETIC_PRIVATE_SOURCE"));
    }

    #[test]
    fn 有效审计链中的降级父标签或悬空引用仍拒绝恢复() {
        for dangling in [false, true] {
            let fixture = Fixture::new();
            let mut collector = SourceCollector::open(&fixture.path()).unwrap();
            let parent = collector
                .observe(
                    b"private",
                    SourceEntryPoint::FileRead,
                    "utf8/1",
                    SourceSensitivity::Sensitive,
                    &[],
                )
                .unwrap();
            drop(collector);
            let child = SourceObject {
                content_views: None,
                source_id: ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))
                    .unwrap(),
                sensitivity: SourceSensitivity::Public,
                observation: SourceObservation::Observed {
                    entry: SourceEntryPoint::ToolOutput,
                    content_sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
                    parser_version: "tool-output/1".into(),
                    parent_source_ids: vec![if dangling {
                        ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))
                            .unwrap()
                    } else {
                        parent.source_id
                    }],
                },
            };
            let journal = ExecutionJournal::open(&fixture.path()).unwrap();
            journal
                .source_observed(&SourceObservedEvent {
                    source_event_version: 1,
                    observed_at_ms: 1,
                    source: child,
                })
                .unwrap();
            drop(journal);
            let store = guard_audit::AuditStore::open_read_only(fixture.path()).unwrap();
            assert!(store.verify_chain().unwrap().ok, "负例必须是结构完整的链");
            drop(store);
            assert!(SourceCollector::open(&fixture.path()).is_err());
        }
    }

    #[test]
    fn 来源写入失败不得返回新标签或退回内存成功() {
        let fixture = Fixture::new();
        let mut collector = SourceCollector::open(&fixture.path()).unwrap();
        let source = collector
            .observe(
                b"safe",
                SourceEntryPoint::FileRead,
                "utf8/1",
                SourceSensitivity::Internal,
                &[],
            )
            .unwrap();
        // 对真实 SQLite 发出重复主键写入，触发持久层错误；不是用布尔返回值冒充磁盘写入。
        let duplicate = SourceObservedEvent {
            source_event_version: 1,
            observed_at_ms: 1,
            source: source.clone(),
        };
        assert!(collector
            .journal
            .as_ref()
            .unwrap()
            .source_observed(&duplicate)
            .is_err());
        assert!(collector
            .observe(
                b"next",
                SourceEntryPoint::FileRead,
                "utf8/1",
                SourceSensitivity::Public,
                &[]
            )
            .is_err());
        assert!(collector.unknown(MissingSource::NotObserved).is_err());
        assert_eq!(collector.latest(), Some(source));
        assert_eq!(collector.status()["healthy"], false);
        assert_eq!(collector.status()["sources"], 1);
    }

    #[test]
    fn 日志损坏和任意解析器正文均不被当作可信元数据() {
        let fixture = Fixture::new();
        let mut collector = SourceCollector::open(&fixture.path()).unwrap();
        assert!(collector
            .observe(
                b"body",
                SourceEntryPoint::FileRead,
                "PRIVATE_PARSER_CONTENT",
                SourceSensitivity::Public,
                &[]
            )
            .is_err());
        collector.unknown(MissingSource::ParserFailed).unwrap();
        drop(collector);
        let mut bytes = std::fs::read(fixture.path()).unwrap();
        bytes[0] ^= 1;
        std::fs::write(fixture.path(), bytes).unwrap();
        assert!(SourceCollector::open(&fixture.path()).is_err());
    }

    #[test]
    fn 来源磁盘故障进入真实宿主失败状态且后续文件动作不执行() {
        let fixture = Fixture::new();
        let mut collector = SourceCollector::open(&fixture.path()).unwrap();
        let source = collector.tool_output(b"previous output", true).unwrap();
        assert!(collector
            .journal
            .as_ref()
            .unwrap()
            .source_observed(&SourceObservedEvent {
                source_event_version: 1,
                observed_at_ms: 1,
                source,
            })
            .is_err());
        assert!(!collector.healthy());
        let (shell, rejected) =
            guard_shell::SafeShell::from_policy(guard_shell::ShellPolicy::default_embedded())
                .with_workspace(
                    [fixture.0.to_string_lossy().as_ref()],
                    [fixture.0.to_string_lossy().as_ref()],
                );
        assert!(rejected.is_empty());
        let engine = guard_core::Engine::from_paths(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml"),
            None::<std::path::PathBuf>,
        )
        .unwrap();
        let mut server = crate::Server::new(
            crate::Gate::new(shell, engine),
            crate::PendingConfirm::new(),
            std::time::Duration::from_secs(1),
        )
        .with_sources(Arc::new(Mutex::new(collector)));
        assert_eq!(server.host_session_state(), "failed");
        let path = fixture.0.join("must-not-write.txt");
        let result = server.gate_and_run(
            crate::ToolCall::WriteFile {
                path: path.clone(),
                contents: "不得执行".into(),
            },
            guard_shell::ShellAction {
                tool: "write_file".into(),
                action: None,
                target: Some(path.to_string_lossy().into()),
                args: vec![],
            },
        );
        assert!(matches!(result, crate::Handled::Refused { .. }));
        assert!(!path.exists());
    }
}

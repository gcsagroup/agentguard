use super::*;
use crate::journal::tests::{action, temp_dir};
use crate::provenance::{MissingSource, SourceCollector};
use guard_schema::{SourceEntryPoint, SourceSensitivity};

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(temp_dir())
    }
    fn main(&self) -> std::path::PathBuf {
        self.0.join("audit.db")
    }
    fn legacy(&self) -> std::path::PathBuf {
        self.0.join("sources.db")
    }
    fn journal(&self) -> SharedJournal {
        ExecutionJournal::open(&self.main()).unwrap().into()
    }
    fn rows(&self) -> Vec<AuditRecord> {
        AuditStore::open_read_only_with_key(self.main(), None)
            .unwrap()
            .verified_snapshot()
            .unwrap()
            .records()
            .to_vec()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn 迁移保持旧库字节及来源图且重开不重复导入() {
    let f = Fixture::new();
    let mut old = SourceCollector::open(&f.legacy()).unwrap();
    let parent = old
        .observe(
            b"PRIVATE_MIGRATION_CANARY",
            SourceEntryPoint::FileRead,
            "utf8/1",
            SourceSensitivity::Sensitive,
            &[],
        )
        .unwrap();
    let unknown = old.unknown(MissingSource::ParserFailed).unwrap();
    drop(old);
    let original = std::fs::read(f.legacy()).unwrap();
    let journal = f.journal();
    let mut sources =
        SourceCollector::open_with_execution_journal(&f.legacy(), journal.clone()).unwrap();
    assert_eq!(sources.resolve(&parent.source_id), Some(parent.clone()));
    assert_eq!(sources.latest(), Some(unknown));
    assert!(
        SourceCollector::open(&f.legacy()).is_err(),
        "旧日志独占锁仍有效"
    );
    assert!(
        ExecutionJournal::open(&f.main()).is_err(),
        "主日志独占锁仍有效"
    );
    let child = sources
        .observe(
            b"public summary",
            SourceEntryPoint::ToolOutput,
            "tool-output/1",
            SourceSensitivity::Public,
            &[parent.source_id],
        )
        .unwrap();
    assert_eq!(child.sensitivity, SourceSensitivity::Sensitive);
    assert_eq!(f.rows().len(), 4);
    assert!(!serde_json::to_string(&f.rows())
        .unwrap()
        .contains("PRIVATE_MIGRATION_CANARY"));
    drop(sources);
    drop(journal);
    assert!(std::fs::read(f.legacy()).unwrap() == original, "旧库未改写");
    let journal = f.journal();
    let restored = SourceCollector::open_with_execution_journal(&f.legacy(), journal).unwrap();
    assert_eq!(restored.latest(), Some(child));
    assert_eq!(restored.status()["sources"], 3);
    assert_eq!(f.rows().len(), 4);
}

#[test]
fn 旧库缺失或后续变化拒绝恢复且主库不追加() {
    for missing in [true, false] {
        let f = Fixture::new();
        let journal = f.journal();
        drop(SourceCollector::open_with_execution_journal(&f.legacy(), journal.clone()).unwrap());
        let before = serde_json::to_value(f.rows()).unwrap();
        if missing {
            std::fs::rename(f.legacy(), f.0.join("preserved.db")).unwrap();
        } else {
            SourceCollector::open(&f.legacy())
                .unwrap()
                .unknown(MissingSource::NotObserved)
                .unwrap();
        }
        assert!(SourceCollector::open_with_execution_journal(&f.legacy(), journal).is_err());
        assert_eq!(before, serde_json::to_value(f.rows()).unwrap());
        assert_eq!(f.legacy().is_file(), !missing);
    }
}

#[test]
fn 旧库含未知事件时拒绝部分迁移() {
    let f = Fixture::new();
    let old = ExecutionJournal::open(&f.legacy()).unwrap();
    old.decided(&action(), &Outcome::Execute { findings: vec![] })
        .unwrap();
    old.started(&action(), None).unwrap();
    drop(old);
    let original = std::fs::read(f.legacy()).unwrap();
    let journal = f.journal();
    assert!(SourceCollector::open_with_execution_journal(&f.legacy(), journal).is_err());
    assert!(f.rows().is_empty());
    assert!(
        std::fs::read(f.legacy()).unwrap() == original,
        "无效旧库也不能触发恢复改写"
    );
}

#[test]
fn 迁移写入失败不发布来源且不降级为内存模式() {
    let f = Fixture::new();
    SourceCollector::open(&f.legacy())
        .unwrap()
        .unknown(MissingSource::NotObserved)
        .unwrap();
    drop(f.journal());
    let journal: SharedJournal = ExecutionJournal {
        store: AuditStore::open_read_only_with_key(f.main(), None).unwrap(),
        _lock: File::create(f.0.join("test-only-lock")).unwrap(),
        healthy: Cell::new(true),
        recovered_unknown: 0,
    }
    .into();
    assert!(SourceCollector::open_with_execution_journal(&f.legacy(), journal.clone()).is_err());
    assert!(!journal.healthy());
    assert!(f.rows().is_empty());
    assert_eq!(
        SourceCollector::open(&f.legacy()).unwrap().status()["sources"],
        1
    );
}

#[test]
fn 来源与终态同存后恢复不重放且摘要绑定完整响应() {
    let f = Fixture::new();
    let action = action();
    let journal = f.journal();
    let mut sources =
        SourceCollector::open_with_execution_journal(&f.legacy(), journal.clone()).unwrap();
    journal
        .decided_and_started(&action, &Outcome::Execute { findings: vec![] })
        .unwrap();
    let event = sources.prepare_unknown(MissingSource::NotObserved).unwrap();
    let output = ExecOutput {
        ok: true,
        detail: "实际正文\n守卫发现".into(),
        truncated: false,
        outcome: ExecutionOutcome::Success,
        dispatched: true,
        capture: None,
    };
    let source = sources
        .commit_prepared(event, |event| {
            journal.finished_with_source(&action, None, &output, event)
        })
        .unwrap();
    let rows = f.rows();
    assert_eq!(
        rows.iter()
            .map(|r| r.event_type.as_str())
            .collect::<Vec<_>>(),
        [
            "GatewaySourceStorageBinding",
            "GatewayDecision",
            "GatewayExecutionStarted",
            "GatewaySourceObserved",
            "GatewayExecutionFinished"
        ]
    );
    let terminal: Value = serde_json::from_str(&rows[4].event_json).unwrap();
    assert_eq!(terminal["output_sha256"], sha256(output.detail.as_bytes()));
    assert!(!rows[4].event_json.contains("实际正文"));
    let view = crate::execution_view::read_execution_log(&f.main(), None).unwrap();
    assert_eq!(view.records_verified, 5);
    assert_eq!(view.other_records, 2);
    assert_eq!(view.actions.len(), 1);
    drop(sources);
    drop(journal);
    let journal = f.journal();
    assert_eq!(journal.status()["recovered_unknown"], 0);
    let restored = SourceCollector::open_with_execution_journal(&f.legacy(), journal).unwrap();
    assert_eq!(restored.latest(), Some(source));
    assert_eq!(f.rows().len(), 5);
}

#[test]
fn 终态主键冲突回滚前一来源且不发布新标签() {
    let f = Fixture::new();
    let journal = f.journal();
    let mut sources =
        SourceCollector::open_with_execution_journal(&f.legacy(), journal.clone()).unwrap();
    journal.started(&action(), None).unwrap();
    let output = ExecOutput {
        ok: true,
        detail: "不可发布正文".into(),
        truncated: false,
        outcome: ExecutionOutcome::Success,
        dispatched: true,
        capture: None,
    };
    journal
        .finished(&action(), None, output.outcome, Some(&output))
        .unwrap();
    let before = serde_json::to_value(f.rows()).unwrap();
    let event = sources.prepare_unknown(MissingSource::NotObserved).unwrap();
    assert!(sources
        .commit_prepared(event, |event| journal.finished_with_source(
            &action(),
            None,
            &output,
            event
        ))
        .is_err());
    assert!(!journal.healthy());
    assert!(!sources.healthy());
    assert!(sources.latest().is_none());
    assert_eq!(sources.status()["sources"], 0);
    assert_eq!(before, serde_json::to_value(f.rows()).unwrap());
}

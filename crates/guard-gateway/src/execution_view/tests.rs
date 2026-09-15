use super::*;
use crate::{journal::ExecutionJournal, ExecOutput, Outcome};
use guard_schema::{
    ActionSnapshot, ActionSpec, ExecutionOutcome, ToolIdentity, ValidatedId,
    EXECUTION_CONTRACT_VERSION,
};
use serde_json::json;

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("agd-execution-view-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("audit.db")
    }
    fn journal(&self) -> ExecutionJournal {
        ExecutionJournal::open(&self.path()).unwrap()
    }
    fn read(&self) -> ExecutionLogView {
        read_execution_log(&self.path(), None).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn action(id: &str) -> ActionSnapshot {
    let id_of = |s: &str| ValidatedId::new(s).unwrap();
    ActionSnapshot::new(ActionSpec {
        contract_version: EXECUTION_CONTRACT_VERSION,
        session_id: id_of("host-session"),
        action_id: id_of(id),
        request_id: id_of(id),
        policy_version: id_of("host-policy"),
        tool: ToolIdentity {
            registration: None,
            service: "gateway".into(),
            name: "write_file".into(),
            version: "1".into(),
        },
        target: "/private/DO_NOT_EXPOSE_PATH".into(),
        parameters: json!({"contents":"DO_NOT_EXPOSE_BODY"}),
        issued_at_ms: 1,
        expires_at_ms: 60000,
        nonce: "ab".repeat(16),
        sources: vec![],
    })
    .unwrap()
}
fn output(outcome: ExecutionOutcome, dispatched: bool) -> ExecOutput {
    serde_json::from_value(json!({"ok":outcome==ExecutionOutcome::Success,"detail":"DO_NOT_EXPOSE_OUTPUT","truncated":false,"outcome":outcome,"dispatched":dispatched})).unwrap()
}
#[test]
fn 真实日志按终态区分阻断未知和工具返回() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let refused = action("refused");
    journal
        .decided(&refused, &Outcome::Refuse { findings: vec![] })
        .unwrap();
    journal
        .finished(&refused, None, ExecutionOutcome::Refused, None)
        .unwrap();
    let waiting = action("waiting");
    journal
        .decided(&waiting, &Outcome::NeedsConfirmation { findings: vec![] })
        .unwrap();
    let started = action("started");
    journal.started(&started, Some("approval")).unwrap();
    let success = action("success");
    journal.started(&success, None).unwrap();
    journal
        .finished(
            &success,
            None,
            ExecutionOutcome::Success,
            Some(&output(ExecutionOutcome::Success, true)),
        )
        .unwrap();
    let partial = action("partial");
    journal.started(&partial, None).unwrap();
    journal
        .finished(
            &partial,
            None,
            ExecutionOutcome::TimedOut,
            Some(&output(ExecutionOutcome::TimedOut, true)),
        )
        .unwrap();
    let log = fixture.read();
    assert_eq!(log.records_verified, 8);
    assert_eq!(
        log.actions
            .iter()
            .map(|a| a.classification)
            .collect::<Vec<_>>(),
        ["unknown", "record", "unknown", "alert", "blocked"]
    );
    assert_eq!(log.actions[2].state, "started_without_terminal");
    let text = serde_json::to_string(&log).unwrap();
    for secret in [
        "DO_NOT_EXPOSE_PATH",
        "DO_NOT_EXPOSE_BODY",
        "DO_NOT_EXPOSE_OUTPUT",
        "host-session",
        "approval\"",
    ] {
        assert!(!text.contains(secret));
    }
    assert_eq!(log.signature_attribution, "not_verified");
    // 读取没有竞争网关写入者锁，也没有把正在运行的动作恢复成终态。
    assert_eq!(fixture.read().records_verified, 8);
    drop(journal);
    let reopened = fixture.journal();
    let recovered = fixture.read();
    assert_eq!(recovered.records_verified, 9);
    assert_eq!(recovered.actions[0].state, "effects_unknown");
    drop(reopened);
}
#[test]
fn 自洽哈希链也不能掩盖动作或批准绑定矛盾() {
    for change_approval in [false, true] {
        let fixture = Fixture::new();
        let journal = fixture.journal();
        let first = action("same-id");
        journal.started(&first, Some("one")).unwrap();
        let mut spec = first.spec().clone();
        if !change_approval {
            spec.target = "/different".into();
        }
        let second = ActionSnapshot::new(spec).unwrap();
        journal
            .finished(
                &second,
                Some(if change_approval { "two" } else { "one" }),
                ExecutionOutcome::Success,
                Some(&output(ExecutionOutcome::Success, true)),
            )
            .unwrap();
        assert!(read_execution_log(&fixture.path(), None).is_err());
    }
}
#[test]
fn 已派发拒绝和缺少开始的成功不能显示为可信结果() {
    for missing_start in [false, true] {
        let fixture = Fixture::new();
        let journal = fixture.journal();
        let current = action("contradictory");
        if !missing_start {
            journal.started(&current, None).unwrap();
        }
        let outcome = if missing_start {
            ExecutionOutcome::Success
        } else {
            ExecutionOutcome::Refused
        };
        journal
            .finished(&current, None, outcome, Some(&output(outcome, true)))
            .unwrap();
        assert!(read_execution_log(&fixture.path(), None).is_err());
    }
}
#[test]
fn 终态之后追加开始记录不能倒序伪装执行链() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let current = action("late-start");
    journal
        .finished(&current, None, ExecutionOutcome::Refused, None)
        .unwrap();
    journal.started(&current, None).unwrap();
    assert!(read_execution_log(&fixture.path(), None).is_err());
}
#[test]
fn 无终态拒绝判决不能声称实际已阻断() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    journal
        .decided(
            &action("only-decision"),
            &Outcome::Refuse { findings: vec![] },
        )
        .unwrap();
    assert_eq!(fixture.read().actions[0].classification, "alert");
    assert_eq!(fixture.read().actions[0].state, "decision_without_terminal");
}
#[test]
#[ignore = "显式读取本次指定的真实生产日志，只导出无正文的验证视图"]
fn 读取实际生产日志生成证据视图() {
    let path = std::env::var_os("AGENTGUARD_EXECUTION_LOG").expect("实际日志路径");
    let output = std::env::var_os("AGENTGUARD_EXECUTION_VIEW").expect("证据输出路径");
    let log = read_execution_log(Path::new(&path), None).unwrap();
    std::fs::write(output, serde_json::to_vec_pretty(&log).unwrap()).unwrap();
}

#[test]
fn 孤立拒绝终态缺少前序绑定时保持未知() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    journal
        .finished(&action("orphan"), None, ExecutionOutcome::Refused, None)
        .unwrap();
    let log = fixture.read();
    assert_eq!(log.actions[0].classification, "unknown");
    assert_eq!(log.actions[0].state, "terminal_without_prior");
}

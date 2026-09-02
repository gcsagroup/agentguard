//! `guard-cli acceptance-trace-check` 的端到端:真的建一个审计库、真的写一份 trace、真的跑二进制。
//!
//! guard-core 里的 `acceptance_trace::check` 已经有 15 条纯函数测试;这里补的是「CLI 把库读对了、
//! 退出码对了、marker 打对了」——验收报告要贴的就是这条命令的输出。

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use guard_audit::{AuditRecord, AuditStore, UserDecision};
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent, Severity};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guard-cli"))
}

fn event(id: &str, ts: i64, et: EventType, app: &str, text: &str) -> GuardEvent {
    let mut metadata = HashMap::new();
    metadata.insert("ui_text".to_string(), text.to_string());
    GuardEvent {
        event_id: id.into(),
        timestamp_ms: ts,
        platform: "macos".into(),
        event_type: et,
        source_app: app.into(),
        agent_context_id: Some("s1".into()),
        metadata,
    }
}

fn decision(action: DecisionAction, severity: Severity, rule: &str, confirm: bool) -> Decision {
    Decision {
        action,
        severity,
        rule_id: rule.into(),
        human_message: format!("{rule} fired"),
        require_confirm: confirm,
    }
}

/// 建一个像真机验收那样的小库:SESSION-START、一条 CRIT-001(用户拒绝)、一条 OVL-007(超时)、
/// SESSION-END。返回 (库路径, crit 记录 id, ovl 记录 id)。
fn build_db(dir: &std::path::Path) -> (PathBuf, String, String) {
    let db = dir.join("audit.db");
    let store = AuditStore::open(&db).unwrap();
    let start = AuditRecord::from_event_decision(
        &event("e0", 1_000, EventType::AgentSessionStart, "Claude", ""),
        &decision(
            DecisionAction::LogOnly,
            Severity::Info,
            "SESSION-START",
            false,
        ),
    );
    store.append(&start).unwrap();
    let crit = AuditRecord::from_event_decision(
        &event(
            "e1",
            3_000,
            EventType::UiTreeDelta,
            "Safari",
            "请确认支付 $299",
        ),
        &decision(DecisionAction::Block, Severity::Critical, "CRIT-001", true),
    );
    store.append(&crit).unwrap();
    let ovl = AuditRecord::from_event_decision(
        &event(
            "e2",
            5_000,
            EventType::UiTreeDelta,
            "ScreenCapture",
            "[AG_TRANSPARENT_OVERLAY]",
        ),
        &decision(DecisionAction::Block, Severity::High, "OVL-007", true),
    );
    store.append(&ovl).unwrap();
    let end = AuditRecord::from_event_decision(
        &event("e3", 131_000, EventType::AgentSessionEnd, "Claude", ""),
        &decision(
            DecisionAction::LogOnly,
            Severity::Info,
            "SESSION-END",
            false,
        ),
    );
    store.append(&end).unwrap();
    store
        .set_user_decision(&crit.id, UserDecision::Deny)
        .unwrap();
    store
        .set_user_decision(&ovl.id, UserDecision::Timeout)
        .unwrap();
    (db, crit.id, ovl.id)
}

fn trace_for(crit: &str, ovl: &str) -> String {
    [
        r#"{"ts":1000,"kind":"session_start","session_id":"s1"}"#.to_string(),
        r#"{"ts":2000,"kind":"observe_tick","source":"ax","events":1,"suppressed":0}"#.to_string(),
        r#"{"ts":2500,"kind":"state","protection_state":"active"}"#.to_string(),
        format!(r#"{{"ts":3000,"kind":"confirm_enqueued","request_id":1,"audit_id":"{crit}","rule_id":"CRIT-001"}}"#),
        r#"{"ts":3100,"kind":"confirm_shown","request_id":1}"#.to_string(),
        format!(r#"{{"ts":4000,"kind":"confirm_resolved","request_id":1,"audit_id":"{crit}","approve":false,"outcome":"resolved"}}"#),
        format!(r#"{{"ts":5000,"kind":"confirm_enqueued","request_id":2,"audit_id":"{ovl}","rule_id":"OVL-007"}}"#),
        format!(r#"{{"ts":130000,"kind":"confirm_expired","request_id":2,"audit_id":"{ovl}","rule_id":"OVL-007"}}"#),
        r#"{"ts":131000,"kind":"session_end","session_id":"s1"}"#.to_string(),
        r#"{"ts":131100,"kind":"state","protection_state":"stopped","reasons":["no_session"]}"#.to_string(),
    ]
    .join("\n")
        + "\n"
}

fn run(trace: &std::path::Path, db: &std::path::Path, json: bool) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    cmd.args(["acceptance-trace-check", "--trace"])
        .arg(trace)
        .arg("--audit-db")
        .arg(db);
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn 一致的trace与库通过并打出marker() {
    let dir = tempfile::tempdir().unwrap();
    let (db, crit, ovl) = build_db(dir.path());
    let trace = dir.path().join("trace.jsonl");
    std::fs::write(&trace, trace_for(&crit, &ovl)).unwrap();
    let (code, out, err) = run(&trace, &db, false);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert!(
        out.contains("AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS"),
        "{out}"
    );
    assert_eq!(out.matches("PASS ").count(), 6, "{out}");
    assert!(!out.contains("FAIL"));

    let (code, out, _) = run(&trace, &db, true);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["all_pass"], true);
    assert_eq!(v["audit_rows"], 4);
    assert_eq!(v["checks"].as_array().unwrap().len(), 6);
}

/// 报告 P0-5 的形状:用户拒绝了 CRIT-001,回执却落在 OVL-007 的记录上。退出 1。
#[test]
fn 回执落错记录退出1并点名() {
    let dir = tempfile::tempdir().unwrap();
    let (db, crit, ovl) = build_db(dir.path());
    // 交换 trace 里两条记录的 audit_id:UI 展示的是 CRIT-001(request 1),回执却写到了 ovl 的记录。
    let trace = dir.path().join("trace.jsonl");
    std::fs::write(&trace, trace_for(&ovl, &crit)).unwrap();
    let (code, out, err) = run(&trace, &db, false);
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("acceptance-trace-check: FAIL"));
    assert!(
        out.contains("FAIL every confirmation receipt matches"),
        "{out}"
    );
    assert!(out.contains("shown rule CRIT-001"), "{out}");
    assert!(!out.contains("AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS"));
}

/// 报告第 3 条的形状:End 之后还在采——库里会话结束后多出一条观察记录。
#[test]
fn 会话结束后仍有观察记录退出1() {
    let dir = tempfile::tempdir().unwrap();
    let (db, crit, ovl) = build_db(dir.path());
    {
        let store = AuditStore::open(&db).unwrap();
        let late = AuditRecord::from_event_decision(
            &event(
                "late",
                140_000,
                EventType::ScreenFrame,
                "ScreenCapture",
                "still capturing",
            ),
            &decision(DecisionAction::Alert, Severity::Low, "OVL-007", false),
        );
        store.append(&late).unwrap();
    }
    let trace = dir.path().join("trace.jsonl");
    std::fs::write(&trace, trace_for(&crit, &ovl)).unwrap();
    let (code, out, _) = run(&trace, &db, false);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("FAIL no observation after session end"),
        "{out}"
    );
}

#[test]
fn 坏trace行也让检查失败() {
    let dir = tempfile::tempdir().unwrap();
    let (db, crit, ovl) = build_db(dir.path());
    let trace = dir.path().join("trace.jsonl");
    std::fs::write(&trace, trace_for(&crit, &ovl) + "garbage line\n").unwrap();
    let (code, out, _) = run(&trace, &db, false);
    assert_eq!(code, 1);
    assert!(out.contains("PARSE-ERROR"), "{out}");
}

//! 持久记忆提案必须经过规则与计划；普通事件不能自报走可信宿主入口。
use super::*;
use std::collections::HashMap;

fn event(kind: EventType) -> GuardEvent {
    GuardEvent {
        event_id: "memory-proposal".into(),
        timestamp_ms: 1,
        platform: "gateway".into(),
        event_type: kind,
        source_app: "agentguard-mcp".into(),
        agent_context_id: Some("memory-host-session".into()),
        metadata: HashMap::from([("item_key".into(), "preference".into())]),
    }
}
fn engine(contract: GuardContract) -> Engine {
    Engine::new(
        RuleSet::from_yaml_str("version: '1.0'\nrules: []").unwrap(),
        contract,
    )
}

#[test]
fn 持久提案不提前记为保存且普通事件不能自报批准() {
    let mut engine = engine(GuardContract::default());
    let mut write = event(EventType::MemoryWrite);
    let decision = engine
        .process_persistent_memory(&write, &["preference".into()])
        .unwrap();
    assert!(decision.require_confirm);
    assert_eq!(decision.action, DecisionAction::Alert);
    assert!(!engine.privacy.has_saved("preference"));
    write
        .metadata
        .insert("persistent_memory".into(), "true".into());
    write.metadata.insert("user_approved".into(), "true".into());
    assert_eq!(
        engine.process(&write).unwrap().action,
        DecisionAction::Block
    );
    assert!(!engine.privacy.has_saved("preference"));
    assert!(engine
        .process_persistent_memory(&event(EventType::ProcessExec), &["preference".into()])
        .is_err());
}

#[test]
fn 契约硬禁止不能转成可批准的持久写入() {
    let contract = GuardContract {
        on_memory_write: guard_schema::EnforcementMode::Deny,
        ..Default::default()
    };
    let mut engine = engine(contract);
    let decision = engine
        .process_persistent_memory(&event(EventType::MemoryWrite), &["preference".into()])
        .unwrap();
    assert_eq!(decision.action, DecisionAction::Block);
    assert!(!decision.require_confirm);
    assert!(!engine.privacy.has_saved("preference"));
}

#[test]
fn 持久记忆入口不绕过任务计划() {
    let plans = guard_schema::TaskPlanLibrary::from_yaml_str("plans:\n  - task_profile: memory-read-only\n    goal: 只读记忆\n    allow: [recall_memory]\n    max:\n      persist_memory: 0\n").unwrap();
    let contract = GuardContract {
        on_plan_drift: guard_schema::EnforcementMode::Block,
        ..Default::default()
    };
    let mut engine = engine(contract).with_task_plans(plans);
    let mut start = event(EventType::AgentSessionStart);
    start
        .metadata
        .insert("task_profile".into(), "memory-read-only".into());
    engine.process(&start).unwrap();
    let denied = engine
        .process_persistent_memory(&event(EventType::MemoryWrite), &["preference".into()])
        .unwrap();
    assert_eq!(denied.action, DecisionAction::Block);
    assert!(!engine.privacy.has_saved("preference"));
}

#[test]
fn 检索逐个核对真实条目并只计一次读取预算() {
    let plans = guard_schema::TaskPlanLibrary::from_yaml_str("plans:\n  - task_profile: limited-memory\n    goal: 限定读取\n    allow: [recall_memory]\n    max: {recall_memory: 2}\n    scope: {data_keys: [preference, allowed-doc]}\n").unwrap();
    let contract = GuardContract {
        on_plan_drift: guard_schema::EnforcementMode::Block,
        ..Default::default()
    };
    let mut engine = engine(contract).with_task_plans(plans);
    let mut start = event(EventType::AgentSessionStart);
    start
        .metadata
        .insert("task_profile".into(), "limited-memory".into());
    engine.process(&start).unwrap();
    let mut read = event(EventType::MemoryRead);
    read.metadata.insert("item_key".into(), "preference".into());
    let denied = engine
        .process_persistent_memory(&read, &["preference".into(), "private-doc".into()])
        .unwrap();
    assert_eq!(denied.action, DecisionAction::Block);
    assert_eq!(denied.rule_id, "SCOPE-DATA");
    assert!(!engine.persistent_memory_key_allowed("private-doc"));
    assert!(engine.persistent_memory_key_allowed("allowed-doc"));
    assert_ne!(
        engine
            .process_persistent_memory(&read, &["preference".into(), "allowed-doc".into()])
            .unwrap()
            .action,
        DecisionAction::Block
    );
    assert_ne!(
        engine.process_persistent_memory(&read, &[]).unwrap().action,
        DecisionAction::Block
    );
    assert_eq!(
        engine
            .process_persistent_memory(&read, &[])
            .unwrap()
            .rule_id,
        "PLAN-OVER-BUDGET"
    );
}

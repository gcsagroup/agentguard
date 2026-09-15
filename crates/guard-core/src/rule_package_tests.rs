use super::tests::event;
use super::*;
use guard_intel::package::RulePayload;

fn rules(action: &str, confirm: bool, step: &str) -> RuleSet {
    RuleSet::from_yaml_str(&format!("version: '1.0'\nrules:\n - id: PKG-TEST\n   name: 合成规则\n   severity: high\n   action: {action}\n   require_confirm: {confirm}\n   match_any_text: [合成标记]\n   step_kind: {step}\n")).unwrap()
}
fn package(action: &str, confirm: bool, step: &str) -> RulePayload {
    RulePayload {
        rules: rules(action, confirm, step),
        indicators: ThreatBundle::default(),
    }
}
fn input() -> GuardEvent {
    event(
        EventType::ProcessExec,
        "shell",
        &[("argv0", "node"), ("ui_text", "合成标记")],
    )
}

#[test]
fn 包的允许和确认不能降低宿主硬拒() {
    for (action, confirm) in [("allow", false), ("alert", true), ("block", true)] {
        let mut engine = Engine::new(rules("block", false, "run_shell"), GuardContract::default());
        engine.set_rule_package(Some(package(action, confirm, "observe")));
        let decision = engine.process(&input()).unwrap();
        assert_eq!(decision.action, DecisionAction::Block);
        assert!(!decision.require_confirm);
    }
}

#[test]
fn 两层的确认要求都保留且附加包可以阻断() {
    for (base, extra) in [(true, false), (false, true)] {
        let mut engine = Engine::new(rules("alert", base, "run_shell"), GuardContract::default());
        engine.set_rule_package(Some(package("alert", extra, "observe")));
        assert!(engine.process(&input()).unwrap().require_confirm);
    }
    let mut engine = Engine::new(rules("allow", false, "run_shell"), GuardContract::default());
    engine.set_rule_package(Some(package("block", false, "observe")));
    assert_eq!(
        engine.process(&input()).unwrap().action,
        DecisionAction::Block
    );
}

#[test]
fn 更新不会重置预算且包拒绝不会扣减执行预算() {
    let plans = guard_schema::TaskPlanLibrary::from_yaml_str("require_plan: false\nplans:\n - task_profile: test\n   goal: 合成预算测试\n   allow: [app_switch, run_shell, observe]\n   max: {run_shell: 1}\n   order: []\n").unwrap();
    let mut engine = Engine::new(
        RuleSet::from_yaml_str("version: '1.0'\nrules: []").unwrap(),
        GuardContract {
            on_plan_drift: guard_schema::EnforcementMode::Block,
            ..Default::default()
        },
    )
    .with_task_plans(plans);
    engine
        .process(&event(
            EventType::AgentSessionStart,
            "shell",
            &[("task_profile", "test")],
        ))
        .unwrap();
    engine.set_rule_package(Some(package("block", false, "observe")));
    assert_eq!(
        engine.process(&input()).unwrap().action,
        DecisionAction::Block
    );
    engine.set_rule_package(Some(package("allow", false, "observe")));
    assert_ne!(
        engine.process(&input()).unwrap().action,
        DecisionAction::Block
    );
    engine.set_rule_package(Some(package("allow", false, "observe")));
    let over = engine.process(&input()).unwrap();
    assert_eq!(over.rule_id, "PLAN-OVER-BUDGET", "{over:?}");
    assert_eq!(over.action, DecisionAction::Block);
}

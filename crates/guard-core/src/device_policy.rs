//! 企业设备策略的**执法**(报告 P1-9)。
//!
//! 真机报告:桌面端的「同步企业策略」按钮把策略拉下来、缓存、显示 policy ID——然后就没有
//! 然后了。`DevicePolicy` 里的 `require_confirm_critical` / `block_malicious_domains` /
//! `allowed_agents` 没有一条进过引擎。用户以为策略生效了,实际只是下载了一个文件。
//!
//! 这个模块是引擎侧的落点:一份**已验证**的策略被原子地装进 `Engine`,每条判决落定之前
//! 过一遍 [`EnforcedPolicy::apply`]。三条原则:
//!
//! 1. **只收紧,不放宽。** 策略能把 Alert 变 Block、能强制 require_confirm、能拒掉不在名单
//!    上的 agent;不能把 Block 变 Allow、不能关掉确认。一份被削弱的策略(即便签名合法)
//!    也不会让引擎比没有策略时更松——策略下发通道被攻破的代价就此封顶。
//! 2. **未验证的策略不执法。** 签名验不过、或者根本没配验签公钥,策略只显示为「未验证」,
//!    不进引擎。壳子负责这条:见 `apps/desktop-*/src-tauri` 的 `load_device_policy`。
//! 3. **失败保持上一份。** 新策略拉取/验证失败时引擎里的旧策略不动,状态进入 degraded 并
//!    说明原因——不是"同步失败所以没有策略了"。
//!
//! 结构上不依赖 `guard-sync`(那个 crate 带 HTTP 客户端),字段由壳子从 `DevicePolicy` 抄过来。

use guard_schema::{Decision, DecisionAction, Severity};
use serde::Serialize;

/// 不在名单上的 agent 被拒时的 rule_id。
pub const POLICY_AGENT_RULE_ID: &str = "POLICY-AGENT-NOT-ALLOWED";

/// 装进引擎的策略。字段与 `guard_sync::DevicePolicy` 对应,外加来源与时间。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcedPolicy {
    pub policy_id: String,
    pub version: String,
    pub require_confirm_critical: bool,
    pub block_malicious_domains: bool,
    /// 空 = 不限制。
    pub allowed_agents: Vec<String>,
    /// 签名验过(带外公钥)。壳子只会把 `true` 的装进引擎;字段保留是为了状态里如实显示。
    pub verified: bool,
    /// 验签用的公钥指纹(hex 前 16 位),给状态显示「签名者」。
    pub signer: Option<String>,
    pub applied_at_ms: u64,
}

impl EnforcedPolicy {
    /// 把策略叠在一条已落定的判决上。**只收紧。**
    ///
    /// `session_agent` 是当前会话声明的 agent 名(AgentSessionStart 的 `source_app`);
    /// 没有会话时为 `None`,名单检查跳过。
    pub fn apply(&self, mut d: Decision, session_agent: Option<&str>) -> Decision {
        // 3. allowed_agents:名单非空且会话 agent 不在其中 → 整条会话的每个事件都拒。
        if let Some(agent) = session_agent {
            if !self.allowed_agents.is_empty()
                && !self
                    .allowed_agents
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(agent.trim()))
            {
                return Decision {
                    action: DecisionAction::Block,
                    severity: Severity::High,
                    rule_id: POLICY_AGENT_RULE_ID.into(),
                    human_message: format!(
                        "agent '{agent}' is not in device policy {}@{} allowed_agents [{}]",
                        self.policy_id,
                        self.version,
                        self.allowed_agents.join(", ")
                    ),
                    require_confirm: false,
                };
            }
        }
        // 2. block_malicious_domains:INTEL-DOMAIN 的 Alert 提为 Block。
        if self.block_malicious_domains
            && d.rule_id == guard_schema::INTEL_DOMAIN_RULE_ID
            && matches!(d.action, DecisionAction::Alert | DecisionAction::LogOnly)
        {
            d.action = DecisionAction::Block;
            d.human_message
                .push_str(" [policy: block_malicious_domains]");
        }
        // 1. require_confirm_critical:Critical 且不是放行的判决必须过人。
        if self.require_confirm_critical
            && matches!(d.severity, Severity::Critical)
            && !matches!(d.action, DecisionAction::Allow)
            && !d.require_confirm
        {
            d.require_confirm = true;
            d.human_message
                .push_str(" [policy: require_confirm_critical]");
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EnforcedPolicy {
        EnforcedPolicy {
            policy_id: "enterprise-poc".into(),
            version: "0.1.0".into(),
            require_confirm_critical: true,
            block_malicious_domains: true,
            allowed_agents: vec!["Claude".into(), "Cursor".into()],
            verified: true,
            signer: Some("ab12cd34ef56ab78".into()),
            applied_at_ms: 1,
        }
    }

    fn d(action: DecisionAction, severity: Severity, rule: &str, confirm: bool) -> Decision {
        Decision {
            action,
            severity,
            rule_id: rule.into(),
            human_message: "m".into(),
            require_confirm: confirm,
        }
    }

    #[test]
    fn 名单外的agent整条会话被拒_名单内与无会话不受影响() {
        let p = policy();
        let out = p.apply(
            d(DecisionAction::Allow, Severity::Info, "ALLOW", false),
            Some("EvilBot"),
        );
        assert_eq!(out.action, DecisionAction::Block);
        assert_eq!(out.rule_id, POLICY_AGENT_RULE_ID);
        assert!(out.human_message.contains("EvilBot"));
        // 名单内(大小写不敏感)
        let out = p.apply(
            d(DecisionAction::Allow, Severity::Info, "ALLOW", false),
            Some("claude"),
        );
        assert_eq!(out.action, DecisionAction::Allow);
        // 没有会话:名单不检查
        let out = p.apply(
            d(DecisionAction::Allow, Severity::Info, "ALLOW", false),
            None,
        );
        assert_eq!(out.action, DecisionAction::Allow);
        // 空名单 = 不限制
        let mut open = policy();
        open.allowed_agents.clear();
        let out = open.apply(
            d(DecisionAction::Allow, Severity::Info, "ALLOW", false),
            Some("EvilBot"),
        );
        assert_eq!(out.action, DecisionAction::Allow);
    }

    #[test]
    fn 恶意域alert提为block_其他规则不动() {
        let p = policy();
        let out = p.apply(
            d(
                DecisionAction::Alert,
                Severity::High,
                guard_schema::INTEL_DOMAIN_RULE_ID,
                false,
            ),
            Some("Claude"),
        );
        assert_eq!(out.action, DecisionAction::Block);
        assert!(out.human_message.contains("block_malicious_domains"));
        let out = p.apply(
            d(DecisionAction::Alert, Severity::High, "PRIV-FM", false),
            Some("Claude"),
        );
        assert_eq!(out.action, DecisionAction::Alert, "别的 Alert 不受影响");
    }

    #[test]
    fn critical非放行判决强制过人_allow与非critical不动() {
        let p = policy();
        let out = p.apply(
            d(DecisionAction::Block, Severity::Critical, "CRIT-009", false),
            Some("Claude"),
        );
        assert!(out.require_confirm);
        let out = p.apply(
            d(DecisionAction::Allow, Severity::Critical, "X", false),
            Some("Claude"),
        );
        assert!(!out.require_confirm, "放行的不需要人确认");
        let out = p.apply(
            d(DecisionAction::Block, Severity::High, "X", false),
            Some("Claude"),
        );
        assert!(!out.require_confirm, "非 Critical 不强制");
    }

    /// 只收紧不放宽:策略字段全 false/空 → 判决原样;任何配置都不能把 Block 变 Allow 或
    /// 把 require_confirm 由 true 变 false。
    #[test]
    fn 策略永远不放宽判决() {
        let loose = EnforcedPolicy {
            require_confirm_critical: false,
            block_malicious_domains: false,
            allowed_agents: vec![],
            ..policy()
        };
        let strict_in = d(DecisionAction::Block, Severity::Critical, "CRIT-001", true);
        let out = loose.apply(strict_in.clone(), Some("Claude"));
        assert_eq!(out.action, strict_in.action);
        assert_eq!(out.severity, strict_in.severity);
        assert_eq!(out.rule_id, strict_in.rule_id);
        assert_eq!(out.human_message, strict_in.human_message);
        assert_eq!(out.require_confirm, strict_in.require_confirm);
        let out = policy().apply(strict_in.clone(), Some("Claude"));
        assert_eq!(out.action, DecisionAction::Block);
        assert!(out.require_confirm);
    }
}

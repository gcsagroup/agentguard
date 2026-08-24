//! 判决层：把"引擎怎么看这次调用"变成"这次调用要不要执行"。
//!
//! # 这是本项目第一次真的能拦住东西
//!
//! 在这之前，AgentGuard 是一个**旁路观察器**：它看到的每一样输入都描述一件**已经发生**的事，
//! 所以判决只有两种用途——记下来、告诉人。`docs/scope-and-non-goals.md` 把这件事写成了三条
//! 独立的理由，第三条是"什么都不强制执行：`SafeShell::propose()` 返回一个枚举"。
//!
//! 网关改变的是**位置**，不是判决逻辑。智能体调 `agentguard.run_shell` 而不是调自己的 shell，
//! 于是网关是那个**执行者**；执行者拒绝执行，是拦截，不是建议。
//!
//! # 但这是协作式控制，不是边界
//!
//! `docs/interception-design.md` §2 把这条区分写成不能含混的一条：
//!
//! * **协作式**：智能体自愿把动作交给守卫。守卫能拒。绕过去的智能体不受影响。
//! * **内核执行**：内核代为拒绝。智能体配不配合无关。
//!
//! 这一层是**协作式**。一个直接 `std::process::Command` 的智能体框架完全不受它影响。所以
//! 每一条响应都带 `enforcement: "cooperative"`，`initialize` 的结果里也写着——本项目在自己的
//! 能力表里已经把"通知"和"阻断门"记成同一个勾一次，不能再来一次。
//!
//! # 判决到行为的映射
//!
//! | 判决 | 行为 |
//! |---|---|
//! | `Allow` | 执行，返回结果 |
//! | `LogOnly` | 执行，记录 |
//! | `Alert` | 执行，**并把发现附在结果里**，让智能体自己看到 |
//! | `Block` | **不执行**，返回一个点名规则的工具错误 |
//! | `require_confirm` | **挂住调用**等人答；超时**拒绝** |
//!
//! `Alert` 执行而不是拒绝，是有意的：告警的语义是"这值得知道"，不是"这不许做"。把它升级成拒绝
//! 会让误报的代价变成工作被打断，而被打断够多次，人就会把网关关掉——那时防护是零。
//!
//! # 两道判决，不是一道
//!
//! 每次调用先过 `guard-shell`（拿 B0 的路径模型：敏感目标、工作区包含、`..`、符号链接），
//! 再过 `guard_core::Engine`。两道都过才执行。
//!
//! 顺序是路径在前。理由：路径判决不需要会话，而引擎的很多规则需要；一个没开会话的调用如果
//! 先过引擎，会得到一堆和"这条命令要删什么"无关的判据。
//!
//! ## 引擎那道门实际贡献什么
//!
//! 这一段写第一版时是错的，值得留着说明白。当时写的是"拿 `PLAN-*` / `SCOPE-*` / `CRIT-*`"，
//! 然后一条测试失败了：27 条 YAML 规则**全部**声明了 `platforms`，而网关的 platform 是
//! `gateway`，不在任何一条的列表里 —— 三样东西里有一样根本没接上。
//!
//! 准确的说法是：
//!
//! * **引擎自身的判据**（`PLAN-*`、`SCOPE-*`、`SESSION-*`、`FLOW-*`、`AGENT-*`）是 Rust 状态机的
//!   结论，不是 YAML 规则，不受 `platforms` 影响 —— 这是引擎在这条路上真正贡献的部分。
//! * **`CRIT-*`** 现在把 `gateway` 加进了 platforms，所以"这段文本意味着一次付款/转账/永久删除"
//!   在网关上也会触发。修法是改规则的平台列表，不是让网关谎报平台 —— 谎报会把一条 Linux 上
//!   经网关发生的动作在审计里记成 macOS，和共享 `uitree` 时硬编码 `"macos"` 是同一种错误。
//! * **`OVL-*` / `ENV-*` / `UI-REVALIDATE` 刻意不扩到网关。** 它们分别需要像素、Android 环境、
//!   UI 树；给它们加 `gateway` 会让一条只在特定平台有意义的规则对一条命令发言。

use guard_core::Engine;
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent, Severity};
use guard_shell::{SafeShell, ShellAction, ShellDecision, ShellVerdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 这一层的强制力等级。永远是协作式；作为字段存在，是为了让它出现在每一条响应里，
/// 而不是只出现在一份文档里。
pub const ENFORCEMENT: &str = "cooperative";

/// 网关对一次调用的最终结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// 执行。`findings` 非空时是 `Alert`：执行了，但要把发现一起交回去。
    Execute { findings: Vec<Finding> },
    /// 不执行。
    Refuse { findings: Vec<Finding> },
    /// 需要人确认才能定。调用方负责挂住并回来重问。
    NeedsConfirmation { findings: Vec<Finding> },
}

impl Outcome {
    pub fn findings(&self) -> &[Finding] {
        match self {
            Outcome::Execute { findings }
            | Outcome::Refuse { findings }
            | Outcome::NeedsConfirmation { findings } => findings,
        }
    }
}

/// 一条判据，以及它来自哪一层。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// `SHELL-PATH-SENSITIVE`、`CRIT-001` 之类。
    pub rule_id: String,
    /// `path`（guard-shell）或 `engine`（guard-core）。让读的人知道是哪一道门说的话。
    pub layer: String,
    pub severity: String,
    pub message: String,
}

/// 网关的判决器。
pub struct Gate {
    shell: SafeShell,
    engine: Engine,
    /// 递增的事件序号，用于 `event_id`。
    seq: u64,
    /// 会话 id，`session_start` 之后才有。
    session_id: Option<String>,
}

impl Gate {
    pub fn new(shell: SafeShell, engine: Engine) -> Self {
        Self {
            shell,
            engine,
            seq: 0,
            session_id: None,
        }
    }

    pub fn shell(&self) -> &SafeShell {
        &self.shell
    }

    pub fn engine_status(&self) -> guard_core::EngineStatus {
        self.engine.status()
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// 开一个会话，并声明任务。任务名选中计划，计划带着资源天花板（Aura §4.4）。
    pub fn start_session(
        &mut self,
        session_id: impl Into<String>,
        task_profile: Option<&str>,
    ) -> anyhow::Result<Decision> {
        let sid = session_id.into();
        self.session_id = Some(sid.clone());
        let mut metadata = HashMap::new();
        if let Some(p) = task_profile.map(str::trim).filter(|p| !p.is_empty()) {
            metadata.insert("task_profile".to_string(), p.to_string());
        }
        let event = self.event(EventType::AgentSessionStart, "agentguard-mcp", metadata);
        self.engine.process(&event)
    }

    pub fn end_session(&mut self) -> anyhow::Result<Decision> {
        let event = self.event(EventType::AgentSessionEnd, "agentguard-mcp", HashMap::new());
        self.session_id = None;
        self.engine.process(&event)
    }

    fn event(
        &mut self,
        event_type: EventType,
        source_app: &str,
        metadata: HashMap<String, String>,
    ) -> GuardEvent {
        self.seq += 1;
        GuardEvent {
            event_id: format!("mcp-{}", self.seq),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            platform: "gateway".into(),
            event_type,
            source_app: source_app.into(),
            agent_context_id: self.session_id.clone(),
            metadata,
        }
    }

    /// 判一次工具调用。
    ///
    /// **这个函数不执行任何东西。** 它只回答"该不该执行"，执行在调用方。分开是为了让
    /// "拦住了"这件事可以被测试：测试可以断言返回了 `Refuse`，也可以断言那条命令**确实没有
    /// 副作用**——两件不同的事，而只断言前者是这个项目反复抓到的那种缺陷。
    pub fn judge(&mut self, action: &ShellAction) -> Outcome {
        let mut findings = Vec::new();

        // ---- 第一道：路径与 shell（B0） ----
        let sv = self.shell.evaluate(action);
        if sv.decision == ShellDecision::Deny {
            findings.push(Finding {
                rule_id: sv.rule_id.clone(),
                layer: "path".into(),
                severity: shell_severity(&sv),
                message: sv.detail.clone(),
            });
            return Outcome::Refuse { findings };
        }
        // 天花板事前授权过的确认要求，记成"已满足"而不是一条警告。
        //
        // 第一版把它按 medium 原样贴回结果，于是每一次落在授权内的写都带着一句
        // 「requires user confirmation」——一个已经被满足的要求被当成未满足的警告展示，
        // 读的人只会学会忽略这一栏。
        let ceiling_ok = self.ceiling_authorises(&sv, action);
        findings.push(if ceiling_ok {
            Finding {
                rule_id: sv.rule_id.clone(),
                layer: "path".into(),
                severity: "info".into(),
                message: format!(
                    "{}；已由会话声明的 paths 天花板事前授权，无需逐次确认",
                    sv.detail
                ),
            }
        } else {
            Finding {
                rule_id: sv.rule_id.clone(),
                layer: "path".into(),
                severity: shell_severity(&sv),
                message: sv.detail.clone(),
            }
        });

        // ---- 第二道：规则引擎 ----
        let event = self.tool_event(action);
        let decision = match self.engine.process(&event) {
            Ok(d) => d,
            // 引擎出错时**拒绝**，不放行。一个判不出来的守卫必须表现得像判了"不行"，
            // 否则"引擎挂了"就成了绕过它的办法。
            Err(e) => {
                findings.push(Finding {
                    rule_id: "GATEWAY-ENGINE-ERROR".into(),
                    layer: "engine".into(),
                    severity: "high".into(),
                    message: format!("引擎无法给出判决（{e}）；按拒绝处理，因为判不出来不等于可以"),
                });
                return Outcome::Refuse { findings };
            }
        };
        findings.push(Finding {
            rule_id: decision.rule_id.clone(),
            layer: "engine".into(),
            severity: format!("{:?}", decision.severity).to_lowercase(),
            message: decision.human_message.clone(),
        });

        // require_confirm 优先于 action：一个带 require_confirm 的 Alert 也必须挂住。
        if decision.require_confirm {
            return Outcome::NeedsConfirmation { findings };
        }
        match decision.action {
            DecisionAction::Block => Outcome::Refuse { findings },
            // 引擎侧没有 Ask，所以剩下三种都是"可以执行"，还要看 shell 那道门。
            DecisionAction::Allow | DecisionAction::LogOnly | DecisionAction::Alert => {
                if sv.decision == ShellDecision::Ask && !ceiling_ok {
                    Outcome::NeedsConfirmation { findings }
                } else {
                    Outcome::Execute { findings }
                }
            }
        }
    }

    /// 已声明的 paths 天花板，能不能替代一次逐次确认。
    ///
    /// # 为什么需要这个判断
    ///
    /// 写这一层的第一版没有它，结果是：默认策略里 `write_file` 和 `run_terminal` 都属于
    /// `require_confirm`，于是网关对智能体的**每一次写、每一条命令**都挂起等人答。两个本该
    /// 通过的测试因此失败，而那不是测试写错了 —— 那是网关在告诉我它不可用。
    ///
    /// 而一个不可用的闸门会被关掉，关掉之后防护是零。这和 B0 自查时改掉的那两处是同一类错误：
    /// **把"更严"当成"更安全"**。
    ///
    /// # 为什么天花板可以替代确认
    ///
    /// 因为人已经答过了 —— 在 `task-plans.yaml` 里，会话开始之前。`scope.paths` 就是那句
    /// 事前授权，这正是 Aura §4.4 会话令牌的模型：令牌带着事前批准的范围，范围内不再逐次问。
    ///
    /// # 三条不放松的边界
    ///
    /// 1. **天花板必须已声明。** 没声明就没人答过，照旧挂起。
    /// 2. **每一个路径操作数都必须可归约且落在授权内。** 通配符、空串、归约不了的东西都不算
    ///    ——"证明不了"不是"在里面"。
    /// 3. **只对 `SHELL-CONFIRM` 生效。** 引擎自己判的 `require_confirm`（`CRIT-*` 那一类：
    ///    付款、转账）在上面已经先返回了，走不到这里；`SHELL-PATH-*` 的 Ask 也不适用，因为
    ///    那些恰恰是"证明不了"。
    fn ceiling_authorises(&self, sv: &ShellVerdict, action: &ShellAction) -> bool {
        if sv.rule_id != "SHELL-CONFIRM" {
            return false;
        }
        if !self.shell.workspace().is_declared() {
            return false;
        }
        let claims = self.shell.path_claims(action);
        if claims.is_empty() {
            // 没有路径操作数的命令（`git status`、`echo`）没有可以被天花板覆盖的东西，
            // 所以天花板对它无话可说，照旧确认。
            return false;
        }
        claims.iter().all(|c| {
            c.resolved
                .as_ref()
                .is_some_and(|p| self.shell.workspace().contains(p, c.intent).is_some())
        })
    }

    /// 把一次工具调用变成引擎能看的事件。
    ///
    /// # 事件类型是按意图选的（B1）
    ///
    /// 第一版全部装进 `EventType::UiTreeDelta`，因为当时 `EventType` 里没有文件系统类型。
    /// 后果是：命令文本能走文本类规则（注入、`CRIT-*`），但走不了任何以"这是一次删除"为
    /// 前提的规则，而且**判决进不了签名审计记录**——网关拒绝了一次删除，那次拒绝没有可归属
    /// 的记录。
    ///
    /// 现在按意图选 `FileWrite` / `FileDelete` / `ProcessExec`，并且带上 `path`，让引擎用
    /// `guard_schema::paths` **自己再判一次**包含关系。`ui_text` 仍然带着完整命令，所以
    /// 文本类规则不受影响。
    fn tool_event(&mut self, action: &ShellAction) -> GuardEvent {
        let mut metadata = HashMap::new();
        let command = std::iter::once(action.tool.as_str())
            .chain(action.action.as_deref())
            .chain(action.target.as_deref())
            .chain(action.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        metadata.insert("ui_text".into(), command.clone());
        metadata.insert("gateway_tool".into(), action.tool.clone());
        if let Some(a) = &action.action {
            metadata.insert("gateway_action".into(), a.clone());
        }
        if let Some(t) = &action.target {
            metadata.insert("gateway_target".into(), t.clone());
        }

        // 选事件类型，并给出**引擎要判的那条路径**。
        //
        // 路径取的是"写/删意图落在哪个操作数上"，也就是 B0 的 `assign_intents` 的结论——
        // `cp a b` 里引擎要判的是 `b`，不是 `a`。用同一个函数，因为两处对"哪个是目标"的
        // 判断不一致的话，网关拦的和审计记的就是两条不同的路径。
        let claims = self.shell.path_claims(action);
        let target_claim = claims
            .iter()
            .filter(|c| c.intent.needs_write())
            .find_map(|c| c.resolved.as_ref().map(|p| (c.intent, p.clone())));

        let event_type = match target_claim.as_ref().map(|(i, _)| *i) {
            Some(guard_schema::paths::PathIntent::Delete) => EventType::FileDelete,
            Some(guard_schema::paths::PathIntent::Write) => EventType::FileWrite,
            // 没有写/删目标的调用（`git status`、`echo`）记成一次程序执行，让它进计划预算。
            _ => EventType::ProcessExec,
        };
        if let Some((_, path)) = target_claim {
            metadata.insert("path".into(), path.to_string_lossy().into_owned());
        }
        if event_type == EventType::ProcessExec {
            if let Some(a) = &action.action {
                metadata.insert("argv0".into(), a.clone());
            }
        }
        self.event(event_type, "agentguard-mcp", metadata)
    }
}

fn shell_severity(v: &ShellVerdict) -> String {
    match v.decision {
        ShellDecision::Deny => "high",
        ShellDecision::Ask => "medium",
        ShellDecision::Allow => "info",
    }
    .to_string()
}

/// 判决里最高的严重度，给日志和 UI 用。
pub fn worst_severity(findings: &[Finding]) -> Severity {
    let rank = |s: &str| match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    let top = findings
        .iter()
        .map(|f| rank(&f.severity))
        .max()
        .unwrap_or(0);
    match top {
        4 => Severity::Critical,
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Info,
    }
}

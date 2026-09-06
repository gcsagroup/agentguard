//! 防护状态机(报告 P0-3)。
//!
//! 真机报告记到的症状:界面写着「守护中」,而那一刻 AX 轮询没开、SCK 没在采、
//! 或者审计库根本写不进去。原因是壳子把 `session_active` 一个布尔直接翻译成
//! 「守护中」——会话开了 ≠ 有人在看。
//!
//! 这里把「什么叫在守护」写成一个纯函数:
//!
//! ```text
//! Active  ⇔  有会话
//!         ∧  至少一个观察器在运行
//!         ∧  最近一次观察(心跳)在 TTL 之内
//!         ∧  审计可写(开着,且上一次写没有失败)
//!         ∧  没有待确认、没有暂停、观察器没报错
//! ```
//!
//! 其余每种「不满足」都对应一个明确状态和一组机器可读的原因码;壳子把状态和原因码
//! 原样交给前端,前端查词表翻成人话。状态判定不写在壳子里,是因为壳子只能在真机上
//! 编译——而这个函数在任何机器上都要能被红-绿测试盯住。
//!
//! 只做判定,不做 I/O;时间由调用方传入(`now_ms`),所以「心跳过期」可以在测试里
//! 用假时钟精确复现,而不用 sleep。

use serde::Serialize;

/// 防护状态。序列化成 snake_case 字符串,前端词表键就是 `state.<这个字符串>`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// 没有会话。此时其他一切都不算——没有 agent 要守。
    Stopped,
    /// 有一条高危判决在等用户拍板;agent 的动作被挂起。
    ConfirmationPending,
    /// 引擎在关键拒绝后暂停,所有事件按 SESSION-PAUSED 拦。
    Paused,
    /// 会话在,但这台机器上没有任何一个观察器可用(权限没给)。只有仿真/扩展路径。
    PermissionRequired,
    /// 观察器刚启动,还没收到第一次心跳,仍在启动宽限期内。
    ObserverStarting,
    /// 会话在、看起来该在守护,但有一项健康条件不满足:观察器停了、心跳过期、
    /// 审计写不进去、观察器报错。**这是不能显示成绿色的那种状态。**
    Degraded,
    /// 上面所有条件都满足。唯一允许显示成「守护中」的状态。
    Active,
}

impl ProtectionState {
    /// 只有 `Active` 才算「在守护」。给壳子/测试用,免得各处自己比枚举。
    pub fn is_protecting(self) -> bool {
        matches!(self, ProtectionState::Active)
    }

    /// 与 serde 输出一致的稳定字符串(前端词表键后缀)。
    pub fn as_str(self) -> &'static str {
        match self {
            ProtectionState::Stopped => "stopped",
            ProtectionState::ConfirmationPending => "confirmation_pending",
            ProtectionState::Paused => "paused",
            ProtectionState::PermissionRequired => "permission_required",
            ProtectionState::ObserverStarting => "observer_starting",
            ProtectionState::Degraded => "degraded",
            ProtectionState::Active => "active",
        }
    }
}

/// 状态成因,机器可读。前端词表键是 `reason.<snake_case>`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NoSession,
    ConfirmPending,
    EnginePaused,
    NoObserverAvailable,
    /// A platform explicitly reported that access needed by a release-required
    /// observer was denied. This is opt-in: platforms that do not classify their
    /// probes keep the pre-existing `NoObserverAvailable` behaviour.
    RequiredObservationPermission,
    /// At least one capability the calling product marks as required for its
    /// release contract is unavailable. Other healthy observers must not turn
    /// that partial coverage into an `Active` claim.
    RequiredCapabilityUnavailable,
    ObserverWarmingUp,
    ObserverNotRunning,
    ObserverError,
    HeartbeatNever,
    HeartbeatStale,
    AuditDisabled,
    AuditUnwritable,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::NoSession => "no_session",
            Reason::ConfirmPending => "confirm_pending",
            Reason::EnginePaused => "engine_paused",
            Reason::NoObserverAvailable => "no_observer_available",
            Reason::RequiredObservationPermission => "required_observation_permission",
            Reason::RequiredCapabilityUnavailable => "required_capability_unavailable",
            Reason::ObserverWarmingUp => "observer_warming_up",
            Reason::ObserverNotRunning => "observer_not_running",
            Reason::ObserverError => "observer_error",
            Reason::HeartbeatNever => "heartbeat_never",
            Reason::HeartbeatStale => "heartbeat_stale",
            Reason::AuditDisabled => "audit_disabled",
            Reason::AuditUnwritable => "audit_unwritable",
        }
    }
}

/// 判定输入。全部是壳子手里现成的事实,不要求壳子先做任何解释。
#[derive(Debug, Clone, Default)]
pub struct StateInputs<'a> {
    pub session_active: bool,
    pub paused: bool,
    pub pending_confirm: bool,
    /// 这台机器上**可用**的观察器数(权限探测通过的)。
    pub observers_available: u32,
    /// 当前**在跑**的观察器数(轮询线程/流在工作)。
    pub observers_running: u32,
    /// The product calling this state machine decides which capabilities are
    /// release-required. `true` means at least one of those probes failed because
    /// the operating system denied access, so the user must never see `Active`.
    /// Kept separate from a generic capability failure so the shell can say
    /// "permission needed" only when that is the actual diagnosis.
    pub required_observation_permission: bool,
    /// At least one release-required capability is unavailable for a reason other
    /// than an access/permission denial (for example, no OCR language engine).
    /// This is deliberately opt-in so a platform where OCR is optional is not
    /// silently reclassified as incomplete.
    pub required_capability_unavailable: bool,
    /// 观察器最近报的错(为 `Some` 就算不健康,内容给前端展示)。
    pub observer_error: Option<&'a str>,
    /// 引擎是否挂了审计库。
    pub audit_enabled: bool,
    /// 引擎最近一次审计写入失败的错误(为 `Some` = 不可写)。
    pub audit_error: Option<&'a str>,
    /// 观察器启动时刻(用来判断「还在启动宽限内」)。`None` = 没启动过。
    pub observer_started_ms: Option<u64>,
    /// 最近一次成功观察的时刻。`None` = 从没观察到。
    pub last_heartbeat_ms: Option<u64>,
    pub now_ms: u64,
}

/// 时间阈值。
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// 心跳超过这么久没更新就算过期。
    pub heartbeat_ttl_ms: u64,
    /// 观察器启动后允许没有心跳的宽限。
    pub startup_grace_ms: u64,
}

impl Default for Thresholds {
    /// AX 轮询 2.5 s、SCK 1.5 s:10 s = 连续四拍没有任何一路观察到东西;8 s 的启动宽限
    /// 覆盖首次 AX 权限弹窗和 SCK 流建立。
    fn default() -> Self {
        Thresholds {
            heartbeat_ttl_ms: 10_000,
            startup_grace_ms: 8_000,
        }
    }
}

/// 判定结果:状态 + 全部成因(不是只给第一条,前端要能把所有不满足的都列出来)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Derived {
    pub state: ProtectionState,
    pub reasons: Vec<Reason>,
}

impl Derived {
    fn one(state: ProtectionState, reason: Reason) -> Self {
        Derived {
            state,
            reasons: vec![reason],
        }
    }
}

/// 从事实推状态。优先级(高→低):
///
/// 1. 没会话 → `Stopped`(其他一切不看)。
/// 2. 待确认 → `ConfirmationPending`(agent 已被挂起,用户此刻该做的事是拍板)。
/// 3. 暂停 → `Paused`。
/// 4. 调用方确认缺少所需权限 → `PermissionRequired`；没有显式分类且没有可用观察器时
///    仍沿用 `PermissionRequired`。
/// 5. 首发必需能力缺失或任何健康条件不满足 → `Degraded`(带全部原因)。
/// 6. 只差第一次心跳且在宽限内 → `ObserverStarting`。
/// 7. 否则 → `Active`。
///
/// 5 排在 6 前面:审计写不进去的时候,「启动中」这种中性词会掩盖一个真问题。
pub fn derive(i: &StateInputs<'_>, t: &Thresholds) -> Derived {
    if !i.session_active {
        return Derived::one(ProtectionState::Stopped, Reason::NoSession);
    }
    if i.pending_confirm {
        return Derived::one(ProtectionState::ConfirmationPending, Reason::ConfirmPending);
    }
    if i.paused {
        return Derived::one(ProtectionState::Paused, Reason::EnginePaused);
    }
    if i.required_observation_permission {
        let mut reasons = vec![Reason::RequiredObservationPermission];
        if i.required_capability_unavailable {
            reasons.push(Reason::RequiredCapabilityUnavailable);
        }
        return Derived {
            state: ProtectionState::PermissionRequired,
            reasons,
        };
    }
    if i.observers_available == 0 && !i.required_capability_unavailable {
        return Derived::one(
            ProtectionState::PermissionRequired,
            Reason::NoObserverAvailable,
        );
    }

    let mut degraded = Vec::new();
    let mut warming = false;

    if i.required_capability_unavailable {
        degraded.push(Reason::RequiredCapabilityUnavailable);
    }

    if i.observers_running == 0 {
        degraded.push(Reason::ObserverNotRunning);
    }
    if i.observer_error.is_some() {
        degraded.push(Reason::ObserverError);
    }
    match i.last_heartbeat_ms {
        Some(hb) => {
            // saturating:时钟回拨(now < hb)按「刚刚」处理,不 panic、不误报过期。
            if i.now_ms.saturating_sub(hb) > t.heartbeat_ttl_ms {
                degraded.push(Reason::HeartbeatStale);
            }
        }
        None => {
            let within_grace = i
                .observer_started_ms
                .map(|s| i.now_ms.saturating_sub(s) <= t.startup_grace_ms)
                .unwrap_or(false);
            if within_grace && i.observers_running > 0 {
                warming = true;
            } else {
                degraded.push(Reason::HeartbeatNever);
            }
        }
    }
    if !i.audit_enabled {
        degraded.push(Reason::AuditDisabled);
    } else if i.audit_error.is_some() {
        degraded.push(Reason::AuditUnwritable);
    }

    if !degraded.is_empty() {
        return Derived {
            state: ProtectionState::Degraded,
            reasons: degraded,
        };
    }
    if warming {
        return Derived::one(ProtectionState::ObserverStarting, Reason::ObserverWarmingUp);
    }
    Derived {
        state: ProtectionState::Active,
        reasons: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Thresholds = Thresholds {
        heartbeat_ttl_ms: 10_000,
        startup_grace_ms: 8_000,
    };

    /// 一组「全绿」输入;每个测试从这里改掉一项。
    fn healthy() -> StateInputs<'static> {
        StateInputs {
            session_active: true,
            paused: false,
            pending_confirm: false,
            observers_available: 2,
            observers_running: 1,
            required_observation_permission: false,
            required_capability_unavailable: false,
            observer_error: None,
            audit_enabled: true,
            audit_error: None,
            observer_started_ms: Some(90_000),
            last_heartbeat_ms: Some(99_000),
            now_ms: 100_000,
        }
    }

    #[test]
    fn 全部条件满足才是active且没有原因() {
        let d = derive(&healthy(), &T);
        assert_eq!(d.state, ProtectionState::Active);
        assert!(d.reasons.is_empty());
        assert!(d.state.is_protecting());
    }

    #[test]
    fn 没有会话就是stopped_其他全绿也不算() {
        let mut i = healthy();
        i.session_active = false;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Stopped);
        assert_eq!(d.reasons, vec![Reason::NoSession]);
        assert!(!d.state.is_protecting());
    }

    #[test]
    fn 首发必需能力缺失时其余观察器有心跳也不能active() {
        let mut i = healthy();
        i.observers_available = 1;
        i.required_capability_unavailable = true;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert!(d.reasons.contains(&Reason::RequiredCapabilityUnavailable));
        assert!(!d.state.is_protecting());
    }

    #[test]
    fn 明确的权限拒绝与普通能力缺失分开报告() {
        let mut i = healthy();
        i.required_observation_permission = true;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::PermissionRequired);
        assert_eq!(d.reasons, vec![Reason::RequiredObservationPermission]);

        // Required capability flags are opt-in. A caller that treats one optional
        // capability (for example OCR on another SKU) as optional remains active.
        let optional = healthy();
        assert_eq!(derive(&optional, &T).state, ProtectionState::Active);
    }

    /// 报告里的原症状:会话开着、观察器没跑,旧界面显示「守护中」。
    #[test]
    fn 会话在但观察器没在跑是degraded而不是active() {
        let mut i = healthy();
        i.observers_running = 0;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert!(d.reasons.contains(&Reason::ObserverNotRunning));
        assert!(!d.state.is_protecting());
    }

    #[test]
    fn 没有任何可用观察器是permission_required() {
        let mut i = healthy();
        i.observers_available = 0;
        i.observers_running = 0;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::PermissionRequired);
        assert_eq!(d.reasons, vec![Reason::NoObserverAvailable]);
    }

    #[test]
    fn 心跳过期是degraded_心跳在ttl边界内仍是active() {
        let mut i = healthy();
        i.last_heartbeat_ms = Some(100_000 - 10_000); // 恰好 TTL,不算过期
        assert_eq!(derive(&i, &T).state, ProtectionState::Active);
        i.last_heartbeat_ms = Some(100_000 - 10_001);
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(d.reasons, vec![Reason::HeartbeatStale]);
    }

    #[test]
    fn 启动宽限内没有心跳是observer_starting_超过宽限变degraded() {
        let mut i = healthy();
        i.last_heartbeat_ms = None;
        i.observer_started_ms = Some(100_000 - 3_000);
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::ObserverStarting);
        assert_eq!(d.reasons, vec![Reason::ObserverWarmingUp]);

        i.observer_started_ms = Some(100_000 - 8_001);
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(d.reasons, vec![Reason::HeartbeatNever]);
    }

    #[test]
    fn 从没启动过观察器又没心跳不算启动中() {
        let mut i = healthy();
        i.last_heartbeat_ms = None;
        i.observer_started_ms = None;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(d.reasons, vec![Reason::HeartbeatNever]);
    }

    /// 审计写不进去时,不允许显示成绿色——也不允许被「启动中」这种中性词盖住。
    #[test]
    fn 审计不可写压过启动中且一定不是active() {
        let mut i = healthy();
        i.audit_error = Some("disk full");
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(d.reasons, vec![Reason::AuditUnwritable]);

        // 同时还在启动宽限内:仍然 Degraded,原因只有审计(心跳缺失被宽限吸收)。
        i.last_heartbeat_ms = None;
        i.observer_started_ms = Some(99_000);
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(d.reasons, vec![Reason::AuditUnwritable]);
    }

    #[test]
    fn 审计没开也是degraded() {
        let mut i = healthy();
        i.audit_enabled = false;
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(d.reasons, vec![Reason::AuditDisabled]);
    }

    #[test]
    fn 观察器报错是degraded并列出全部原因() {
        let mut i = healthy();
        i.observer_error = Some("AX permission revoked");
        i.observers_running = 0;
        i.last_heartbeat_ms = Some(0);
        let d = derive(&i, &T);
        assert_eq!(d.state, ProtectionState::Degraded);
        assert_eq!(
            d.reasons,
            vec![
                Reason::ObserverNotRunning,
                Reason::ObserverError,
                Reason::HeartbeatStale
            ]
        );
    }

    #[test]
    fn 待确认优先于暂停_暂停优先于健康问题() {
        let mut i = healthy();
        i.pending_confirm = true;
        i.paused = true;
        i.observers_running = 0;
        assert_eq!(derive(&i, &T).state, ProtectionState::ConfirmationPending);
        i.pending_confirm = false;
        assert_eq!(derive(&i, &T).state, ProtectionState::Paused);
        i.paused = false;
        assert_eq!(derive(&i, &T).state, ProtectionState::Degraded);
    }

    #[test]
    fn 时钟回拨不panic也不误报过期() {
        let mut i = healthy();
        i.last_heartbeat_ms = Some(200_000); // 比 now 还晚
        i.observer_started_ms = Some(300_000);
        assert_eq!(derive(&i, &T).state, ProtectionState::Active);
    }

    /// 前端词表键是 `state.<str>` / `reason.<str>`;serde 输出和 `as_str` 必须一致,
    /// 否则壳子 DTO 里的字符串和前端查表用的字符串对不上,界面显示 key 名。
    #[test]
    fn 序列化字符串与as_str一致() {
        for s in [
            ProtectionState::Stopped,
            ProtectionState::ConfirmationPending,
            ProtectionState::Paused,
            ProtectionState::PermissionRequired,
            ProtectionState::ObserverStarting,
            ProtectionState::Degraded,
            ProtectionState::Active,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
        for r in [
            Reason::NoSession,
            Reason::ConfirmPending,
            Reason::EnginePaused,
            Reason::NoObserverAvailable,
            Reason::ObserverWarmingUp,
            Reason::ObserverNotRunning,
            Reason::ObserverError,
            Reason::HeartbeatNever,
            Reason::HeartbeatStale,
            Reason::AuditDisabled,
            Reason::AuditUnwritable,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(json, format!("\"{}\"", r.as_str()));
        }
    }
}

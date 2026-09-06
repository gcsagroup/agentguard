//! AgentGuard macOS shell: Menu Bar tray + TCC onboarding + MacAdapter simulation.

// 发布壳会自动生成审计加密密钥，因此“Release 但明文”不是一个合法兼容模式。
// 只在 debug 允许 audit-sqlite；Release 少了显式 feature 时必须在产物生成前失败。
#[cfg(all(
    any(agentguard_release_profile, not(debug_assertions)),
    not(feature = "audit-sqlcipher")
))]
compile_error!(
    "desktop-macos Release requires SQLCipher; rebuild with \
     --no-default-features --features audit-sqlcipher"
);

#[cfg(all(feature = "audit-sqlite", feature = "audit-sqlcipher"))]
compile_error!(
    "audit-sqlite and audit-sqlcipher are mutually exclusive; use \
     --no-default-features --features audit-sqlcipher for Release"
);

#[path = "../../../desktop-build-info.rs"]
mod build_info;

use std::collections::HashMap;
use std::path::PathBuf;

// Release 可打开调试断言辅助定位问题，但不能因此启用开发资源、明文审计或自动批准。
const DEVELOPMENT_BUILD: bool = cfg!(all(debug_assertions, not(agentguard_release_profile)));

#[cfg(all(test, agentguard_release_profile))]
#[test]
fn release开启调试断言仍保持安全发布语义() {
    let status = security_status().unwrap();
    assert!(status.release_build && status.sqlcipher && status.intel_fail_closed);
    assert!(!status.auto_approve_allowed);
}
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use guard_audit::{
    auto_approve_allowed, ensure_macos_keychain_audit_key, sqlcipher_enabled, AuditRecord,
    AuditStore, MacKeychainDeviceKey, SessionReport, UserDecision,
};
use guard_billing::load_or_free;
use guard_core::acceptance_trace::{TraceLine, TraceWriter};
use guard_core::confirm_queue::{
    ConfirmQueue, PendingItem, PersistedPending, ResolveOutcome, DEFAULT_CONFIRM_TTL_MS,
};
use guard_core::device_policy::EnforcedPolicy;
use guard_core::event_dedup::{Aggregator, Verdict, REPEAT_COUNT_KEY};
use guard_core::observe_state::{self, StateInputs, Thresholds};
use guard_core::{AutoApprove, ConfirmRequest, Engine};
use guard_intel::load_release;
use guard_intel::PublicKeyBytes;
use guard_netmon::{evaluate_flow, FlowSummary};
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent};
use guard_sync::{
    pull_policy_verified, signer_fingerprint, sync_to_cache, sync_to_cache_verified, DevicePolicy,
};
use mac_adapter::{
    ax_probe, demo_transparent_overlay_frame, live_ax_snapshot, mac_capabilities, sck_probe,
    start_ax_observer as start_native_ax_observer, start_capture_session_generation,
    stop_ax_observer as stop_native_ax_observer, stop_capture_session_generation,
    take_ax_notifications, AxCapture, AxNativeCallFailure, AxNativeGate, MacAdapter,
    ObserverGeneration, ObserverLifecycle, ObserverWorker, StopOutcome,
};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State};
use win_adapter::{PlatformAdapter, SimObservation};

struct AppState {
    engine: Mutex<Engine>,
    /// Release 的 Keychain + SQLCipher 初始化状态。它与 UI/观察器锁完全独立：
    /// Keychain IPC 可以等待用户，但绝不能再阻止首窗创建或冻结 Tauri 主线程。
    audit_bootstrap: Mutex<AuditBootstrapState>,
    /// `setup` 理论上只执行一次；仍用 CAS 把“只能启动一个 Keychain worker”钉死，
    /// 避免未来窗口/生命周期重构时重复弹系统授权框或并发创建密钥。
    audit_bootstrap_started: AtomicBool,
    audit_bootstrap_generation: AtomicU64,
    audit_recovery_running: AtomicBool,
    adapter: Mutex<MacAdapter>,
    auto_approve: Mutex<bool>,
    // P0-5:待确认改成带不可变 request_id 的有界队列(guard_core::ConfirmQueue)。
    // 后台 AX/SCK 事件只能**入队**,不再覆盖用户正在看的那一条;确认按 request_id 做
    // compare-and-swap。逻辑在 guard-core 里纯函数实现并有并发测试。
    pending: Mutex<ConfirmQueue>,
    tcc_acknowledged: Mutex<bool>,
    sck_streaming: Mutex<bool>,
    sck_native_ok: Mutex<bool>,
    sck_message: Mutex<String>,
    /// poller 线程执行原生 stop 的错误，交给有界 drain 的控制路径读取。
    sck_stop_error: Mutex<Option<String>>,
    /// SCK poller 的单调代际、取消与 worker 排空。不能退回可 ABA 的共享布尔值。
    sck_lifecycle: ObserverLifecycle,
    /// 串行化可能阻塞的原生 SCK start/stop；只在 blocking worker 中持有。
    sck_control: Mutex<()>,
    /// Background AXObserver driver. A 50ms tick drains notifications; the adapter
    /// coalesces captures to 150ms debounce / 800ms max latency / 3s fallback.
    ax_lifecycle: ObserverLifecycle,
    /// 所有 AX FFI 的单飞执行面；只保护原生桥，不参与 UI/引擎/适配器锁序。
    ax_native_gate: AxNativeGate,
    /// poller 内原生 stop 的失败；没有确认卸载前不允许下一代启动。
    ax_stop_error: Mutex<Option<String>>,
    /// 串行化 AX 原生注册/卸载；只在 blocking worker 中持有。
    ax_control: Mutex<()>,
    /// start/end 每次推进；异步启动完成时必须仍匹配，防止“结束后迟到地武装”。
    session_generation: AtomicU64,
    /// 串行化完整的异步会话转换；Tokio mutex 可跨 await，且不会阻塞 Tauri UI 线程。
    session_control: tauri::async_runtime::Mutex<()>,
    /// Last UiTreeDelta **per source_app**, for pop-up / TOCTOU revalidation.
    ///
    /// 报告第 4 条:以前是单个 `Option`,SCK 帧(source=ScreenCapture)和 AX 快照
    /// (source=Safari)交替到达,指纹里带 source_app,于是每次交替都被判成
    /// 「UI 在决策和执行之间变了」→ UI-REVALIDATE 风暴;演示注入的支付事件也被拿去和
    /// 上一帧比,得到 UI-REVALIDATE 而不是 CRIT-001。按来源分开比,跨来源不比。
    /// 会话开始/结束清空。
    last_ui_event: Mutex<HashMap<String, GuardEvent>>,
    ax_message: Mutex<String>,
    /// P0-3:最近一次**成功**观察的时刻(ms since epoch,0 = 没有)。SCK/AX 轮询成功时更新。
    heartbeat_ms: AtomicU64,
    /// P0-3:观察器最近一次启动的时刻(0 = 没启动过),给状态机判「启动宽限」。
    observer_started_ms: AtomicU64,
    /// P0-3:观察器循环因错误停下时留下的原因(AX 权限被收回等)。成功轮询即清空。
    observer_error: Mutex<Option<String>>,
    /// P2-3:观察事件聚合器。只在 SCK/AX 轮询路径上用;会话边界 reset。
    aggregator: Mutex<Aggregator>,
    /// P1-4:本次运行里因超时(两分钟没人拍板)被按拒绝处理并写了 Timeout 回执的确认数。
    confirms_timed_out: AtomicUsize,
    /// P1-4:启动时发现上次运行遗留的待确认数(逐条写了 Timeout 回执)。
    orphaned_confirms: AtomicUsize,
    /// P1-9:设备策略的对外状态(验证/执法/最近一次失败),与引擎里装的那份一致。
    policy_status: Mutex<PolicyStatusDto>,
    /// 阶段 D:验收 trace(AGENTGUARD_ACCEPTANCE_TRACE 设定时写,否则空转)。
    trace: TraceWriter,
    /// 上一次向 UI 报出的队首 request_id,避免每次轮询都写一条 confirm_shown。
    last_shown_request: Mutex<Option<u64>>,
}

fn trace_line(kind: &str) -> TraceLine {
    TraceLine::new(now_epoch_ms(), kind)
}

/// P1-9:策略状态。`enforced` 只在签名验过并装进引擎时为 true;`verified=false` 的策略
/// 只显示,不执法——状态栏要把这两种情况分开说。
#[derive(Serialize, Clone, Default)]
struct PolicyStatusDto {
    policy_id: String,
    version: String,
    verified: bool,
    enforced: bool,
    signer: Option<String>,
    applied_at_ms: u64,
    /// 最近一次同步/验证失败的原因(失败时引擎保留上一份策略,这里说明为什么是上一份)。
    last_error: Option<String>,
    source: String,
}

/// P1-9:策略验签公钥。来源:`AGENTGUARD_POLICY_PUBKEY`(文件路径,32 字节 / hex / base64)
/// > 数据目录 `policy-pubkey.hex`。都没有 = **未验证模式**:策略只显示,不进引擎。
fn policy_pubkey() -> Option<PublicKeyBytes> {
    if let Ok(p) = std::env::var("AGENTGUARD_POLICY_PUBKEY") {
        if let Ok(k) = PublicKeyBytes::from_path(&p) {
            return Some(k);
        }
    }
    let mut p = dirs_next_data();
    p.push("agentguard");
    p.push("policy-pubkey.hex");
    PublicKeyBytes::from_path(&p).ok()
}

fn policy_cache_path() -> PathBuf {
    let mut p = dirs_next_data();
    p.push("agentguard");
    let _ = std::fs::create_dir_all(&p);
    p.push("device-cache.yaml");
    p
}

fn enforced_from(policy: &DevicePolicy, signer: Option<String>) -> EnforcedPolicy {
    EnforcedPolicy {
        policy_id: policy.policy_id.clone(),
        version: policy.version.clone(),
        require_confirm_critical: policy.require_confirm_critical,
        block_malicious_domains: policy.block_malicious_domains,
        allowed_agents: policy.allowed_agents.clone(),
        verified: true,
        signer,
        applied_at_ms: now_epoch_ms(),
    }
}

/// P1-9:把一份策略来源同步进来并决定执不执法。
///
/// * 配了公钥:`sync_to_cache_verified`(原字节 + .sig 落缓存)→ 验过 → **原子换进引擎**,
///   `enforced=true`。验不过/拉不到:引擎里的上一份**不动**,状态记 `last_error`(degraded)。
/// * 没配公钥:`sync_to_cache`(未验证)→ 只更新显示,`enforced=false`,引擎不动,并在
///   `last_error` 里说明"没有验签公钥,策略仅显示"。
fn load_device_policy(state: &AppState, source: &str) -> Result<PolicyStatusDto, String> {
    let cache = policy_cache_path();
    let mut status = state
        .policy_status
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    status.source = source.to_string();
    match policy_pubkey() {
        Some(pk) => match sync_to_cache_verified(source, &pk, &cache) {
            Ok(policy) => {
                let fp = signer_fingerprint(&pk);
                let enforced = enforced_from(&policy, Some(fp.clone()));
                let applied_at = enforced.applied_at_ms;
                state
                    .engine
                    .lock()
                    .map_err(|e| e.to_string())?
                    .set_device_policy(Some(enforced));
                status = PolicyStatusDto {
                    policy_id: policy.policy_id,
                    version: policy.version,
                    verified: true,
                    enforced: true,
                    signer: Some(fp),
                    applied_at_ms: applied_at,
                    last_error: None,
                    source: source.to_string(),
                };
            }
            Err(e) => {
                // 失败保持上一份:引擎不动,只把原因写进状态。
                status.last_error = Some(format!(
                    "verified sync failed; keeping previous policy: {e}"
                ));
            }
        },
        None => match sync_to_cache(source, &cache) {
            Ok(policy) => {
                status = PolicyStatusDto {
                    policy_id: policy.policy_id,
                    version: policy.version,
                    verified: false,
                    enforced: false,
                    signer: None,
                    applied_at_ms: now_epoch_ms(),
                    last_error: Some(
                        "no policy public key configured (AGENTGUARD_POLICY_PUBKEY or \
                         policy-pubkey.hex); policy is displayed only and NOT enforced"
                            .into(),
                    ),
                    source: source.to_string(),
                };
            }
            Err(e) => {
                status.last_error = Some(format!("sync failed: {e}"));
            }
        },
    }
    *state.policy_status.lock().map_err(|e| e.to_string())? = status.clone();
    Ok(status)
}

/// P1-9:启动时从缓存恢复——**只**恢复能再验过签的那份(缓存旁的 .sig + 公钥)。没公钥或
/// 验不过,引擎里就没有策略,状态如实说。
fn restore_device_policy_at_startup(engine: &mut Engine) -> PolicyStatusDto {
    let cache = policy_cache_path();
    let src = cache.to_string_lossy().into_owned();
    let Some(pk) = policy_pubkey() else {
        let shown = DevicePolicy::from_path(&cache).ok();
        return PolicyStatusDto {
            policy_id: shown
                .as_ref()
                .map(|p| p.policy_id.clone())
                .unwrap_or_default(),
            version: shown
                .as_ref()
                .map(|p| p.version.clone())
                .unwrap_or_default(),
            verified: false,
            enforced: false,
            signer: None,
            applied_at_ms: 0,
            last_error: Some(if shown.is_some() {
                "cached policy present but no public key configured; displayed only, NOT enforced"
                    .into()
            } else {
                "no device policy".into()
            }),
            source: src,
        };
    };
    match pull_policy_verified(&src, &pk) {
        Ok(policy) => {
            let fp = signer_fingerprint(&pk);
            let enforced = enforced_from(&policy, Some(fp.clone()));
            let applied_at = enforced.applied_at_ms;
            engine.set_device_policy(Some(enforced));
            PolicyStatusDto {
                policy_id: policy.policy_id,
                version: policy.version,
                verified: true,
                enforced: true,
                signer: Some(fp),
                applied_at_ms: applied_at,
                last_error: None,
                source: src,
            }
        }
        Err(e) => PolicyStatusDto {
            policy_id: String::new(),
            version: String::new(),
            verified: false,
            enforced: false,
            signer: Some(signer_fingerprint(&pk)),
            applied_at_ms: 0,
            last_error: Some(format!(
                "cached policy did not verify; nothing enforced: {e}"
            )),
            source: src,
        },
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn advance_session_generation(state: &AppState) -> u64 {
    loop {
        let generation = state
            .session_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        if generation != 0 {
            return generation;
        }
    }
}

fn session_generation_matches(state: &AppState, expected: Option<u64>) -> bool {
    expected.is_none_or(|generation| state.session_generation.load(Ordering::SeqCst) == generation)
}

#[derive(Serialize)]
struct StatusDto {
    rules_loaded: usize,
    policy_id: String,
    audit_enabled: bool,
    /// 只有 Keychain、SQLCipher 和行签名器全部可用并已原子装入引擎时才为 true。
    audit_ready: bool,
    /// pending | ready | failed，供界面禁用开始按钮并解释首启等待。
    audit_bootstrap_state: &'static str,
    audit_operation_running: bool,
    audit_recovery_running: bool,
    audit_data_path: String,
    build_version: &'static str,
    build_revision: &'static str,
    build_time: &'static str,
    build_profile: &'static str,
    audit_legacy_available: bool,
    paused: bool,
    session_active: bool,
    accessibility: bool,
    screen_capture: bool,
    privacy_composite: f32,
    pending_confirm: bool,
    intel_version: String,
    tcc_acknowledged: bool,
    plan: String,
    pro_active: bool,
    device_policy_id: String,
    sck_streaming: bool,
    sck_native_ok: bool,
    sck_message: String,
    sck_auto_poll: bool,
    ax_message: String,
    ax_auto_poll: bool,
    /// sim | partial | full — honest coverage level from TCC.
    protection_mode: String,
    protection_summary: String,
    /// P0-3:状态机输出(`guard_core::observe_state`)。前端只信这个字段来画状态灯;
    /// `session_active` 等原始布尔仍在,但不再被翻译成「守护中」。
    protection_state: String,
    /// 状态成因码(前端查 `reason.*` 词表)。Active 时为空。
    state_reasons: Vec<String>,
    observers_available: u32,
    observers_running: u32,
    /// 距最近一次成功观察的毫秒数;`None` = 还没观察到。
    heartbeat_age_ms: Option<u64>,
    /// 引擎最近一次审计写入失败的错误;空串 = 可写。
    audit_error: String,
    observer_error: String,
    /// P2-3:本会话被聚合器折叠掉的重复观察条数。
    suppressed_events: u64,
    /// P1-4:本次运行超时默认拒绝的确认数;上次运行遗留、启动时按超时处理的确认数。
    confirms_timed_out: usize,
    orphaned_confirms: usize,
    /// 当前等待中的确认数(状态灯之外,给「待确认 N」用)。
    pending_count: usize,
    /// P1-9:设备策略状态(验证/执法/失败原因)。`device_policy_id` 保留给旧前端。
    policy: PolicyStatusDto,
}

#[derive(Serialize)]
struct DecisionDto {
    action: String,
    rule_id: String,
    human_message: String,
    require_confirm: bool,
    /// AX/SCK report a state that already exists in another application. The
    /// internal Block verdict is not proof of pre-execution enforcement there.
    effect: &'static str,
    external_action_blocked: bool,
}

#[derive(Serialize)]
struct ConfirmDto {
    /// P0-5:不可变的请求 id。UI 显示它、resolve 时原样回传,后端据此 compare-and-swap。
    request_id: u64,
    rule_id: String,
    severity: String,
    human_message: String,
    source_app: String,
    ui_excerpt: Option<String>,
    effect: &'static str,
    external_action_blocked: bool,
}

const OBSERVED_ONLY_EFFECT: &str = "observed_only";
const EXTERNAL_ACTION_BLOCKED: bool = false;

#[derive(Serialize)]
struct ObservedAuditRecordDto {
    #[serde(flatten)]
    record: AuditRecord,
    effect: &'static str,
    external_action_blocked: bool,
}

impl From<AuditRecord> for ObservedAuditRecordDto {
    fn from(record: AuditRecord) -> Self {
        Self {
            record,
            effect: OBSERVED_ONLY_EFFECT,
            external_action_blocked: EXTERNAL_ACTION_BLOCKED,
        }
    }
}

#[derive(Debug, Serialize)]
struct ObservedSessionReport {
    generated_at_ms: i64,
    record_count: usize,
    risk_verdict_count: usize,
    alert_count: usize,
    allow_count: usize,
    log_only_count: usize,
    confirm_decisions: guard_audit::ConfirmStats,
    confirm_source: guard_audit::ConfirmSource,
    by_rule: Vec<guard_audit::RuleCount>,
    by_source_app: Vec<guard_audit::AppCount>,
    top_messages: Vec<String>,
    summary_note: String,
    effect: &'static str,
    external_action_blocked: bool,
}

impl From<SessionReport> for ObservedSessionReport {
    fn from(report: SessionReport) -> Self {
        let risk_total = report.block_count + report.alert_count;
        let summary_note = if risk_total == 0 {
            "本窗口未记录高危风险判决；这只表示旁路观察未命中，不代表外部动作受控。".to_string()
        } else {
            format!(
                "本窗口记录高危风险判决/告警 {risk_total} 次；这些是旁路观测结果，未阻止外部应用中已经发生的动作。"
            )
        };
        Self {
            generated_at_ms: report.generated_at_ms,
            record_count: report.record_count,
            risk_verdict_count: report.block_count,
            alert_count: report.alert_count,
            allow_count: report.allow_count,
            log_only_count: report.log_only_count,
            confirm_decisions: report.confirm_decisions,
            confirm_source: report.confirm_source,
            by_rule: report.by_rule,
            by_source_app: report.by_source_app,
            top_messages: report.top_messages,
            summary_note,
            effect: OBSERVED_ONLY_EFFECT,
            external_action_blocked: EXTERNAL_ACTION_BLOCKED,
        }
    }
}

impl ObservedSessionReport {
    fn to_markdown(&self) -> String {
        let mut markdown = String::new();
        markdown.push_str("# AgentGuard macOS 会话摘要\n\n");
        markdown.push_str(&format!("生成时间 (ms): {}\n\n", self.generated_at_ms));
        markdown.push_str("## 效果边界\n\n");
        markdown.push_str(&format!(
            "- `effect={}`\n- `external_action_blocked={}`\n\n",
            self.effect, self.external_action_blocked
        ));
        markdown.push_str("macOS 桌面端在 AX/SCK 呈现后进行旁路观察；风险确认只能暂停本会话和后续观察，不能撤销外部应用中已经发生的动作。\n\n");
        markdown.push_str("## 概览\n\n");
        markdown.push_str(&format!(
            "| 指标 | 值 |\n| --- | --- |\n| 记录数 | {} |\n| 风险判决（内部动作枚举） | {} |\n| Alert | {} |\n| Allow | {} |\n| LogOnly | {} |\n\n",
            self.record_count,
            self.risk_verdict_count,
            self.alert_count,
            self.allow_count,
            self.log_only_count
        ));
        markdown.push_str(&format!(
            "确认：approve={} deny={} timeout={} pending≈{}（来源：{}）\n\n",
            self.confirm_decisions.approve,
            self.confirm_decisions.deny,
            self.confirm_decisions.timeout,
            self.confirm_decisions.pending,
            self.confirm_source.label()
        ));
        markdown.push_str(&format!("> {}\n\n", self.summary_note));
        markdown.push_str("## 规则命中\n\n");
        for rule in &self.by_rule {
            markdown.push_str(&format!("- `{}`: {}\n", rule.rule_id, rule.count));
        }
        markdown.push_str("\n## 来源应用\n\n");
        for app in &self.by_source_app {
            markdown.push_str(&format!("- {}: {}\n", app.source_app, app.count));
        }
        if !self.top_messages.is_empty() {
            markdown.push_str("\n## 高危摘要\n\n");
            for message in &self.top_messages {
                markdown.push_str(&format!("- {message}\n"));
            }
        }
        markdown
    }

    fn write_json(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn write_markdown(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_markdown())?;
        Ok(())
    }

    fn completion_message(&self, json_path: &std::path::Path, md_path: &std::path::Path) -> String {
        format!(
            "{} · risk_verdicts={} alerts={} · effect={} external_action_blocked={} → {} / {}",
            self.summary_note,
            self.risk_verdict_count,
            self.alert_count,
            self.effect,
            self.external_action_blocked,
            json_path.display(),
            md_path.display()
        )
    }
}

#[derive(Serialize)]
struct TccStatusDto {
    accessibility: bool,
    screen_capture: bool,
    accessibility_hint: String,
    screen_capture_hint: String,
    acknowledged: bool,
    simulation_only: bool,
    protection_mode: String,
    coverage_lines: Vec<String>,
}

fn protection_coverage(accessibility: bool, screen_capture: bool) -> (String, String, Vec<String>) {
    let mut lines = Vec::new();
    lines.push(if accessibility {
        "✓ 辅助功能：可读 Agent/浏览器 UI 树".into()
    } else {
        "✗ 辅助功能未授权 → 无法读真实窗口，仅仿真/扩展注入".into()
    });
    lines.push(if screen_capture {
        "✓ 屏幕录制：可启用 SCK 粗粒度帧统计".into()
    } else {
        "✗ 屏幕录制未授权 → SCK 原生捕获不可用，可用「屏幕浮层帧」仿真".into()
    });
    lines.push("✓ 规则引擎 / 审计 / Threat Intel（本地）始终可用".into());
    lines.push("✓ Chromium 扩展路径不依赖上述 macOS 权限".into());

    let mode = match (accessibility, screen_capture) {
        (true, true) => "full",
        (true, false) | (false, true) => "partial",
        (false, false) => "sim",
    };
    let summary = match mode {
        "full" => "防护范围：完整（AX + 可选 SCK）".into(),
        "partial" => "防护范围：部分（缺权限，非完整桌面守护）".into(),
        _ => "防护范围：仿真（未授权 TCC，请勿当作已在真实守护）".into(),
    };
    (mode.into(), summary, lines)
}

/// macOS 首个 GA 的桌面观察合同是「AX 必需，SCK 可选增强」。
///
/// AX 承担窗口文字、表单字段和按钮语义的主路径；SCK 增加像素、浮层和隐写覆盖，
/// 没有 SCK 时横幅会如实显示 partial，但只要 AX 健康，状态灯仍可为 Active。
/// 反过来，只有 SCK 心跳而没有 AX 不能冒充桌面守护。返回值依次对应共享状态机的
/// `(required_observation_permission, required_capability_unavailable)`。
fn mac_required_observation_state(accessibility_granted: bool, ax_running: bool) -> (bool, bool) {
    (!accessibility_granted, accessibility_granted && !ax_running)
}

#[derive(Serialize)]
struct SckProbeDto {
    ok: bool,
    error: String,
    screen_capture: bool,
}

#[derive(Serialize)]
struct CaptureSessionDto {
    native: bool,
    message: String,
}

#[derive(Serialize)]
struct SckPollDto {
    decisions: Vec<DecisionDto>,
    frames_drained: usize,
    /// P2-3:这一拍被折叠掉的重复观察条数。
    suppressed: usize,
    /// P2-3:一段重复观察结束时的人读摘要(不进审计——审计里是带 repeat_count 的周期摘要行)。
    summaries: Vec<String>,
}

const BUNDLED_RULES: &str = "agentguard/rules/p0_rules.yaml";
const BUNDLED_DEVICE_POLICY: &str = "agentguard/policies/pro-trial.yaml";
const BUNDLED_TASK_PLANS: &str = "agentguard/policies/task-plans.yaml";
const BUNDLED_INTEL: &str = "agentguard/intel/bundle.json";
const BUNDLED_INTEL_PUBKEY: &str = "agentguard/intel/public.hex";
fn audit_keychain_service() -> String {
    let base = "com.agentguard.desktop.macos.audit";
    if build_info::PROFILE.is_empty() {
        base.into()
    } else {
        format!("{base}.acceptance.{}", build_info::PROFILE)
    }
}
const AUDIT_CIPHER_ACCOUNT: &str = "sqlcipher-v1";
const AUDIT_SIGNING_ACCOUNT: &str = "ed25519-v1";
const AUDIT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuditBootstrapState {
    Pending,
    Ready,
    Failed(String),
}

impl AuditBootstrapState {
    fn state_name(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Failed(_) => "failed",
        }
    }

    fn blocking_reason(&self) -> Option<String> {
        match self {
            Self::Pending => Some(
                "protected audit is initializing; complete or deny the macOS Keychain prompt"
                    .into(),
            ),
            Self::Ready => None,
            Self::Failed(reason) => Some(reason.clone()),
        }
    }

    /// A late successful Keychain reply may recover a timeout. The timeout is a UI/service
    /// availability boundary, not cancellation of Security.framework's in-flight Mach call.
    fn complete_success(&mut self) {
        *self = Self::Ready;
    }

    fn complete_failure(&mut self, reason: String) {
        if !matches!(self, Self::Ready) {
            *self = Self::Failed(reason);
        }
    }

    fn mark_timeout(&mut self) {
        if matches!(self, Self::Pending) {
            *self = Self::Failed(format!(
                "macOS Keychain did not respond within {} seconds; protection remains off",
                AUDIT_BOOTSTRAP_TIMEOUT.as_secs()
            ));
        }
    }
}

/// Resolve a path from inside `AgentGuard.app/Contents/MacOS/AgentGuard` to
/// `Contents/Resources`. Keeping this independent from Tauri's live AppHandle
/// lets the engine fail closed before any observer or window is started.
fn bundle_resources_from_executable(executable: &std::path::Path) -> Option<PathBuf> {
    let macos = executable.parent()?;
    if macos.file_name()? != "MacOS" {
        return None;
    }
    let contents = macos.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    Some(contents.join("Resources"))
}

fn required_runtime_resource(
    environment: &str,
    bundled_relative: &str,
    development_candidates: &[PathBuf],
) -> anyhow::Result<PathBuf> {
    // Environment overrides are developer conveniences, not a Release trust
    // boundary. A production launch must use resources sealed into the signed
    // app bundle so a parent process cannot replace its rules or trust anchor.
    if DEVELOPMENT_BUILD {
        if let Some(path) = std::env::var_os(environment).map(PathBuf::from) {
            if path.is_file() {
                return Ok(path);
            }
            anyhow::bail!(
                "{environment} does not name a regular file: {}",
                path.display()
            );
        }
    }

    if let Ok(executable) = std::env::current_exe() {
        if let Some(resources) = bundle_resources_from_executable(&executable) {
            let candidate = resources.join(bundled_relative);
            if candidate.is_file() {
                return Ok(candidate);
            }
            if !DEVELOPMENT_BUILD {
                anyhow::bail!(
                    "required signed-bundle resource is missing: {}",
                    candidate.display()
                );
            }
        }
    }

    if DEVELOPMENT_BUILD {
        if let Some(path) = development_candidates.iter().find(|path| path.is_file()) {
            return Ok(path.clone());
        }
    }
    anyhow::bail!("required runtime resource {bundled_relative} is unavailable; refusing to start")
}

fn rules_path() -> anyhow::Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    required_runtime_resource(
        "AGENTGUARD_RULES",
        BUNDLED_RULES,
        &[
            manifest.join("../../../crates/guard-schema/rules/p0_rules.yaml"),
            PathBuf::from("crates/guard-schema/rules/p0_rules.yaml"),
        ],
    )
}

fn audit_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_AUDIT_DB") {
        return PathBuf::from(p);
    }
    let mut dir = dirs_next_data();
    dir.push(build_info::data_directory());
    let _ = std::fs::create_dir_all(&dir);
    dir.push("audit-macos.db");
    dir
}

fn dirs_next_data() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support");
    }
    std::env::temp_dir()
}

fn entitlement_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_ENTITLEMENT") {
        return PathBuf::from(p);
    }
    let mut dir = dirs_next_data();
    dir.push(build_info::data_directory());
    let _ = std::fs::create_dir_all(&dir);
    dir.push("entitlement.json");
    dir
}

fn device_policy_path() -> anyhow::Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    required_runtime_resource(
        "AGENTGUARD_DEVICE_POLICY",
        BUNDLED_DEVICE_POLICY,
        &[
            manifest.join("../../../policies/device-cache.yaml"),
            manifest.join("../../../policies/pro-trial.yaml"),
            PathBuf::from("policies/pro-trial.yaml"),
        ],
    )
}

fn intel_pubkey_path() -> anyhow::Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    required_runtime_resource(
        "AGENTGUARD_INTEL_PUBKEY",
        BUNDLED_INTEL_PUBKEY,
        &[
            manifest.join("../../../intel/keys/public.hex"),
            PathBuf::from("intel/keys/public.hex"),
        ],
    )
}

fn load_intel() -> anyhow::Result<guard_intel::ThreatBundle> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bundle = required_runtime_resource(
        "AGENTGUARD_INTEL",
        BUNDLED_INTEL,
        &[
            manifest.join("../../../intel/bundle.json"),
            PathBuf::from("intel/bundle.json"),
        ],
    )?;
    let pk = intel_pubkey_path()?;
    if DEVELOPMENT_BUILD {
        return guard_intel::load_or_default(&bundle)
            .context("load development threat-intelligence bundle");
    }
    load_release(&bundle, &pk).context("verify signed-bundle threat intelligence")
}

fn open_audit_store() -> anyhow::Result<AuditStore> {
    let path = audit_db_path();
    if sqlcipher_enabled() {
        let mut receipt_path = path.as_os_str().to_os_string();
        receipt_path.push(".recovery.json");
        if !PathBuf::from(receipt_path).try_exists()?
            && guard_audit::has_legacy_plaintext_audit(&path)?
        {
            anyhow::bail!("AUDIT_LEGACY_PLAINTEXT: 检测到旧版明文记录，请在 App 中确认保留历史并升级；原文件未修改");
        }
        let passphrase =
            ensure_macos_keychain_audit_key(&audit_keychain_service(), AUDIT_CIPHER_ACCOUNT)
                .context("load SQLCipher passphrase from macOS Keychain")?;
        let signer =
            MacKeychainDeviceKey::load_or_create(&audit_keychain_service(), AUDIT_SIGNING_ACCOUNT)
                .context("load audit signing seed from macOS Keychain")?;
        // One atomic contract: encrypted writer + working signer, or no writer.
        // `open_protected` also detects a legacy plaintext DB before SQLite can
        // modify it. We do not silently branch history into a sibling database.
        let path = guard_audit::resolve_recovered_audit(&path, &signer)?;
        return AuditStore::open_protected(&path, &passphrase, Box::new(signer))
            .context("open protected macOS audit database");
    }

    if !DEVELOPMENT_BUILD {
        anyhow::bail!("Release audit requires SQLCipher");
    }
    let signer = guard_audit::FileDeviceKey::load_or_create(
        audit_db_path().with_file_name("audit-signing.debug.key"),
    )
    .context("load development audit signer")?;
    AuditStore::open(&path)
        .context("open development audit database")?
        .with_signer(Box::new(signer))
        .context("attach development audit signer")
}

fn build_engine_without_audit() -> anyhow::Result<Engine> {
    // The task-plan library, so a session that names a `task_profile` gets its trajectory plan and
    // its Aura §4.4 resource ceiling. Release resources come only from the signed app bundle.
    let mut engine = Engine::from_paths(rules_path()?, None::<PathBuf>)
        .context("load bundled rules")?
        .with_intel(load_intel()?);
    if let Some(plans) = load_task_plans()? {
        engine = engine.with_task_plans(plans);
    }
    let policy_path = device_policy_path()?;
    DevicePolicy::from_path(&policy_path)
        .with_context(|| format!("parse device policy {}", policy_path.display()))?;
    Ok(engine)
}

fn build_engine() -> anyhow::Result<Engine> {
    Ok(build_engine_without_audit()?.with_audit(open_audit_store()?))
}

fn audit_bootstrap_snapshot(state: &AppState) -> Result<(bool, String, &'static str), String> {
    let state = state.audit_bootstrap.lock().map_err(|e| e.to_string())?;
    Ok((
        matches!(*state, AuditBootstrapState::Ready),
        state.blocking_reason().unwrap_or_default(),
        state.state_name(),
    ))
}

fn require_protected_audit(state: &AppState) -> Result<(), String> {
    let (ready, reason, _) = audit_bootstrap_snapshot(state)?;
    if ready {
        Ok(())
    } else {
        Err(format!(
            "protected audit is unavailable; refusing to start protection: {reason}"
        ))
    }
}

/// Start one background Release-security bootstrap. Security.framework has no cancellable API for
/// a pending login-Keychain ACL prompt, so the native call gets its own worker and never holds a
/// Tauri/engine/adapter lock. A separate watchdog makes the UI fail closed after a wall-clock
/// deadline; a later successful reply may still atomically install the fully protected engine.
fn start_protected_audit_bootstrap(app: AppHandle) {
    let generation = {
        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        if state
            .audit_bootstrap_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        if let Ok(mut bootstrap) = state.audit_bootstrap.lock() {
            *bootstrap = AuditBootstrapState::Pending;
        }
        state
            .audit_bootstrap_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1
    };

    let watchdog_app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(AUDIT_BOOTSTRAP_TIMEOUT);
        let Some(state) = watchdog_app.try_state::<AppState>() else {
            return;
        };
        if state.audit_bootstrap_generation.load(Ordering::SeqCst) != generation {
            return; // 上一次启动的迟到看门狗不能覆盖用户重试后的状态。
        }
        let changed = state
            .audit_bootstrap
            .lock()
            .map(|mut bootstrap| {
                let was_pending = matches!(*bootstrap, AuditBootstrapState::Pending);
                bootstrap.mark_timeout();
                was_pending
            })
            .unwrap_or(false);
        if changed {
            let _ = watchdog_app.emit("audit-bootstrap-changed", "failed");
        }
    });

    std::thread::spawn(move || {
        let worker_state = app.state::<AppState>();
        let _running = AuditOperationGuard(&worker_state.audit_bootstrap_started);
        let result = (|| -> anyhow::Result<(Engine, PolicyStatusDto, usize)> {
            let mut engine = build_engine()?;
            let orphaned = restore_orphaned_confirms(&engine);
            let policy_status = restore_device_policy_at_startup(&mut engine);
            Ok((engine, policy_status, orphaned))
        })();

        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        match result {
            Ok((engine, policy_status, orphaned)) => {
                // Install all dependent state before publishing Ready. Commands read Ready first,
                // then lock the engine, so they can never observe a half-installed audit writer.
                if let Ok(mut slot) = state.engine.lock() {
                    *slot = engine;
                } else {
                    if let Ok(mut bootstrap) = state.audit_bootstrap.lock() {
                        bootstrap.complete_failure(
                            "protected engine lock was poisoned during startup".into(),
                        );
                    }
                    let _ = app.emit("audit-bootstrap-changed", "failed");
                    return;
                }
                if let Ok(mut slot) = state.policy_status.lock() {
                    *slot = policy_status;
                }
                state.orphaned_confirms.store(orphaned, Ordering::Relaxed);
                if let Ok(mut bootstrap) = state.audit_bootstrap.lock() {
                    bootstrap.complete_success();
                }
                let _ = app.emit("audit-bootstrap-changed", "ready");
            }
            Err(error) => {
                if let Ok(mut bootstrap) = state.audit_bootstrap.lock() {
                    bootstrap.complete_failure(format!(
                        "protected audit initialization failed: {error:#}"
                    ));
                }
                let _ = app.emit("audit-bootstrap-changed", "failed");
            }
        }
    });
}

struct AuditOperationGuard<'a>(&'a AtomicBool);

impl Drop for AuditOperationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[tauri::command]
fn retry_audit_initialization(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if audit_bootstrap_snapshot(state.inner())?.0 {
        return Err("加密记录已经就绪".into());
    }
    if state.audit_bootstrap_started.load(Ordering::SeqCst) {
        return Err("系统密钥请求或数据升级尚未结束，请先处理现有提示".into());
    }
    start_protected_audit_bootstrap(app);
    Ok(())
}

#[tauri::command]
async fn recover_legacy_audit(
    app: AppHandle,
    approved: bool,
) -> Result<guard_audit::RecoveryReceipt, String> {
    if !approved {
        return Err("尚未确认保留历史并升级；未修改数据".into());
    }
    {
        let state = app.state::<AppState>();
        if audit_bootstrap_snapshot(state.inner())?.0 {
            return Err("记录已经就绪，不能重复迁移".into());
        }
        state
            .audit_bootstrap_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "已有密钥请求或数据操作正在执行，请稍后重试")?;
        state.audit_recovery_running.store(true, Ordering::SeqCst);
    }
    let worker_app = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = worker_app.state::<AppState>();
        let _initializing = AuditOperationGuard(&state.audit_bootstrap_started);
        let _recovering = AuditOperationGuard(&state.audit_recovery_running);
        let result = (|| -> anyhow::Result<guard_audit::RecoveryReceipt> {
            let key =
                ensure_macos_keychain_audit_key(&audit_keychain_service(), AUDIT_CIPHER_ACCOUNT)?;
            let signer = MacKeychainDeviceKey::load_or_create(
                &audit_keychain_service(),
                AUDIT_SIGNING_ACCOUNT,
            )?;
            guard_audit::migrate_legacy_audit(&audit_db_path(), &key, &signer)
        })();
        if let Err(error) = &result {
            if let Ok(mut bootstrap) = state.audit_bootstrap.lock() {
                bootstrap.complete_failure(format!("历史升级未完成：{error:#}"));
            }
        }
        result.map_err(|error| format!("{error:#}"))
    })
    .await
    .map_err(|error| error.to_string())?;
    if result.is_ok() {
        start_protected_audit_bootstrap(app);
    }
    result
}

/// The operator's task-plan library. It remains optional for development, but
/// a Release bundle must contain and parse the curated library.
fn load_task_plans() -> anyhow::Result<Option<guard_schema::TaskPlanLibrary>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = required_runtime_resource(
        "AGENTGUARD_TASK_PLANS",
        BUNDLED_TASK_PLANS,
        &[
            manifest.join("../../../policies/task-plans.yaml"),
            PathBuf::from("policies/task-plans.yaml"),
        ],
    )?;
    let yaml = std::fs::read_to_string(&path)
        .with_context(|| format!("read task plans {}", path.display()))?;
    let plans = guard_schema::TaskPlanLibrary::from_yaml_str(&yaml)
        .with_context(|| format!("parse task plans {}", path.display()))?;
    Ok(Some(plans))
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> Result<StatusDto, String> {
    // P1-4:每次有人看状态都先把超时的确认按拒绝处理掉——不然它们会一直「等着」。
    sweep_expired_confirms(state.inner())?;
    // 状态读取逐锁复制后立即释放。除了避免把磁盘/TCC 查询带进共享锁，也消除了历史上的
    // engine -> adapter 与会话路径 adapter -> engine 反向锁序。
    let (st, score) = {
        let engine = state.engine.lock().map_err(|e| e.to_string())?;
        (engine.status(), engine.privacy_score())
    };
    let (audit_ready, audit_bootstrap_error, audit_bootstrap_state) =
        audit_bootstrap_snapshot(state.inner())?;
    let audit_error = st.audit_error.clone().unwrap_or(audit_bootstrap_error);
    let audit_enabled = st.audit_enabled && audit_ready;
    let session_active = state
        .adapter
        .lock()
        .map_err(|e| e.to_string())?
        .has_session();
    let (pending_confirm, pending_count) = {
        let pending = state.pending.lock().map_err(|e| e.to_string())?;
        (!pending.is_empty(), pending.len())
    };
    let tcc = *state.tcc_acknowledged.lock().map_err(|e| e.to_string())?;
    let caps = mac_capabilities();
    let ent = load_or_free(entitlement_path());
    let device_policy_path = device_policy_path().map_err(|error| error.to_string())?;
    let device_policy = DevicePolicy::from_path(&device_policy_path).map_err(|error| {
        format!(
            "parse device policy {}: {error}",
            device_policy_path.display()
        )
    })?;
    let sck_streaming = *state.sck_streaming.lock().map_err(|e| e.to_string())?;
    let sck_native_ok = *state.sck_native_ok.lock().map_err(|e| e.to_string())?;
    let sck_message = state.sck_message.lock().map_err(|e| e.to_string())?.clone();
    let sck_auto_poll = state.sck_lifecycle.active().is_some();
    let ax_message = state.ax_message.lock().map_err(|e| e.to_string())?.clone();
    let (protection_mode, protection_summary, _) =
        protection_coverage(caps.accessibility, caps.screen_capture);
    let ax_auto_poll = state.ax_lifecycle.active().is_some();
    let observer_error = state
        .observer_error
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    let suppressed_events = state
        .aggregator
        .lock()
        .map_err(|e| e.to_string())?
        .suppressed_total();
    let now = now_epoch_ms();
    let hb = state.heartbeat_ms.load(Ordering::Relaxed);
    let started = state.observer_started_ms.load(Ordering::Relaxed);
    let observers_available = caps.accessibility as u32 + caps.screen_capture as u32;
    let observers_running = ax_auto_poll as u32 + (sck_streaming && sck_auto_poll) as u32;
    let (required_observation_permission, required_capability_unavailable) =
        mac_required_observation_state(caps.accessibility, ax_auto_poll);
    let derived = observe_state::derive(
        &StateInputs {
            session_active,
            paused: st.paused,
            pending_confirm,
            observers_available,
            observers_running,
            // AX 是 macOS 首发桌面守护的必需路径；SCK 是可选像素增强。这样只有
            // SCK 在跑时不会被共享心跳误判为 Active，而 AX-only 仍可保持 Active。
            required_observation_permission,
            required_capability_unavailable,
            observer_error: observer_error.as_deref(),
            audit_enabled,
            audit_error: (!audit_error.is_empty()).then_some(audit_error.as_str()),
            observer_started_ms: (started > 0).then_some(started),
            last_heartbeat_ms: (hb > 0).then_some(hb),
            now_ms: now,
        },
        &Thresholds::default(),
    );
    if state.trace.enabled() {
        state.trace.write(&TraceLine {
            protection_state: Some(derived.state.as_str().to_string()),
            reasons: derived
                .reasons
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            ..trace_line("state")
        });
    }
    Ok(StatusDto {
        rules_loaded: st.rules_loaded,
        policy_id: st.policy_id,
        audit_enabled,
        audit_ready,
        audit_bootstrap_state,
        audit_operation_running: state.audit_bootstrap_started.load(Ordering::SeqCst),
        audit_recovery_running: state.audit_recovery_running.load(Ordering::SeqCst),
        audit_data_path: audit_db_path().display().to_string(),
        build_version: env!("CARGO_PKG_VERSION"),
        build_revision: build_info::REVISION,
        build_time: build_info::TIME,
        build_profile: build_info::PROFILE,
        audit_legacy_available: !audit_ready
            && guard_audit::has_legacy_plaintext_audit(&audit_db_path()).unwrap_or(false),
        paused: st.paused,
        session_active,
        accessibility: caps.accessibility,
        screen_capture: caps.screen_capture,
        privacy_composite: score.composite,
        pending_confirm,
        intel_version: st.intel_version,
        tcc_acknowledged: tcc,
        plan: format!("{:?}", ent.plan),
        pro_active: ent.is_active(),
        device_policy_id: device_policy.policy_id,
        sck_streaming,
        sck_native_ok,
        sck_message,
        sck_auto_poll,
        ax_message,
        ax_auto_poll,
        protection_mode,
        protection_summary,
        protection_state: derived.state.as_str().to_string(),
        state_reasons: derived
            .reasons
            .iter()
            .map(|r| r.as_str().to_string())
            .collect(),
        observers_available,
        observers_running,
        heartbeat_age_ms: (hb > 0).then(|| now.saturating_sub(hb)),
        audit_error,
        observer_error: observer_error.unwrap_or_default(),
        suppressed_events,
        confirms_timed_out: state.confirms_timed_out.load(Ordering::Relaxed),
        orphaned_confirms: state.orphaned_confirms.load(Ordering::Relaxed),
        pending_count,
        policy: state
            .policy_status
            .lock()
            .map_err(|e| e.to_string())?
            .clone(),
    })
}

#[tauri::command]
fn get_tcc_status(state: State<'_, AppState>) -> Result<TccStatusDto, String> {
    let acknowledged = *state.tcc_acknowledged.lock().map_err(|e| e.to_string())?;
    let caps = mac_capabilities();
    let (protection_mode, _, coverage_lines) =
        protection_coverage(caps.accessibility, caps.screen_capture);
    Ok(TccStatusDto {
        accessibility: caps.accessibility,
        screen_capture: caps.screen_capture,
        accessibility_hint: if caps.accessibility {
            "辅助功能：已授权".into()
        } else {
            "系统设置 → 隐私与安全性 → 辅助功能 → 允许 AgentGuard".into()
        },
        screen_capture_hint: if caps.screen_capture {
            "屏幕录制：已授权".into()
        } else {
            "系统设置 → 隐私与安全性 → 屏幕录制 → 允许 AgentGuard（ScreenCaptureKit）".into()
        },
        acknowledged,
        simulation_only: !caps.accessibility && !caps.screen_capture,
        protection_mode,
        coverage_lines,
    })
}

#[tauri::command]
fn probe_permissions() -> Result<mac_adapter::MacCapabilities, String> {
    Ok(mac_capabilities())
}

/// 一次守护会话该武装哪些观察器:`(AX 树观察, 屏幕抓取)` —— 授权了就开,没授权就不开,
/// 桌面会话入口另行要求 AX 必需权限。仿真有独立自检入口，扩展状态不由这里推断。
///
/// 为什么抽成纯函数:真机上 TCC 授权与 AXObserver 注册在这个容器里都测不到,但"授权矩阵 →
/// 该开什么"这一步能测,而它恰好是 macOS 壳子以前**整个缺失**的一步。Windows 壳子的
/// `start_guard_session` 里一直写着 "Observation begins with the session and ends with it";
/// macOS 这边只登记会话,真正打开监控的两个按钮(AX 实时观察 / 开始抓屏)埋在
/// 「开发者面板(演示与诊断)」里 —— 于是用户授权、点「开始守护」,却没有任何东西在看,
/// 状态灯停在"守护不完整",而唯一的出路被标成了开发者诊断。这是功能缺陷,不是文案问题。
fn observers_for_session(caps: &mac_adapter::MacCapabilities) -> (bool, bool) {
    (caps.accessibility, caps.screen_capture)
}

/// 系统设置里两个隐私面板的 anchor。抽出来是为了在非 macOS 上也能测这张映射表
/// (`open` 本身只有 macOS 有)。
fn privacy_pane_anchor(which: &str) -> Option<&'static str> {
    match which {
        "accessibility" => Some("Privacy_Accessibility"),
        "screen" => Some("Privacy_ScreenCapture"),
        _ => None,
    }
}

/// 直接把用户送到该点的那一页。以前界面只印一行"系统设置 → 隐私与安全性 → 辅助功能 → 允许
/// AgentGuard",四层路径要用户自己找。
#[cfg(target_os = "macos")]
fn open_settings_pane(anchor: &str) -> Result<(), String> {
    let url = format!("x-apple.systempreferences:com.apple.preference.security?{anchor}");
    let status = std::process::Command::new("open")
        .arg(&url)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open {url} exited with {status}"))
    }
}

/// 非 macOS 上没有这个面板。壳子只发 macOS,这一支只是让整棵树在 Linux 上也能编过、能测
/// 上面那张映射表(和仓库里其他 `#[cfg]` 双支同一种写法)。
#[cfg(not(target_os = "macos"))]
fn open_settings_pane(_anchor: &str) -> Result<(), String> {
    Err("opening System Settings is only available on macOS".into())
}

#[tauri::command]
async fn open_privacy_settings(which: String) -> Result<(), String> {
    let anchor = privacy_pane_anchor(&which).ok_or_else(|| format!("unknown pane: {which}"))?;
    // 仅打开设置页不会把从未请求过权限的 App 加入列表。先以当前 App 的身份请求，
    // 用户仍在系统界面决定是否授权。系统提示不持有产品状态锁，也不阻塞首窗线程。
    static REQUESTING: AtomicBool = AtomicBool::new(false);
    if REQUESTING.swap(true, Ordering::AcqRel) {
        return Err("已有系统授权请求正在处理，请先完成该提示".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        struct RequestGuard;
        impl Drop for RequestGuard {
            fn drop(&mut self) {
                REQUESTING.store(false, Ordering::Release);
            }
        }
        let _request_guard = RequestGuard;
        match which.as_str() {
            "accessibility" => {
                mac_adapter::permissions::request_accessibility_prompt();
            }
            "screen" => {
                mac_adapter::permissions::request_screen_capture();
            }
            _ => unreachable!("授权入口已由 privacy_pane_anchor 验证"),
        }
        open_settings_pane(anchor)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
fn acknowledge_tcc(state: State<'_, AppState>) -> Result<(), String> {
    *state.tcc_acknowledged.lock().map_err(|e| e.to_string())? = true;
    Ok(())
}

/// 把一条 require_confirm 判决入队,返回它不可变的 request_id(供日志/测试)。
///
/// 唯一的入队路径。以前是散落各处的 `*state.pending.lock() = Some(...)`,新事件直接覆盖
/// 旧的 —— 那正是 P0-5 的成因。集中到这里之后,后台事件只会**排在后面**,不会顶替。
fn enqueue_confirm(state: &AppState, engine: &Engine, req: ConfirmRequest) -> Result<u64, String> {
    let (audit_id, rule_id) = (req.audit_id.clone(), req.rule_id.clone());
    let (id, evicted) = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        enqueue_pending_with_engine(&mut q, engine, req, now_epoch_ms())?
    };
    if let Some(item) = evicted {
        state.confirms_timed_out.fetch_add(1, Ordering::Relaxed);
        state.trace.write(&TraceLine {
            request_id: Some(item.request_id),
            audit_id: item.audit_id,
            rule_id: Some(item.rule_id),
            ..trace_line("confirm_capacity_timeout")
        });
    }
    state.trace.write(&TraceLine {
        request_id: Some(id),
        audit_id,
        rule_id: Some(rule_id),
        ..trace_line("confirm_enqueued")
    });
    Ok(id)
}

/// 旧版本的全局明文 sidecar 路径。只用于识别并警告；绝不读取、导入、执行或删除。
fn legacy_pending_confirms_path() -> PathBuf {
    let mut p = dirs_next_data();
    p.push("agentguard");
    p.push("pending-confirms.json");
    p
}

fn warn_legacy_pending_sidecar() {
    let path = legacy_pending_confirms_path();
    warn_legacy_pending_sidecar_at(&path);
}

fn warn_legacy_pending_sidecar_at(path: &std::path::Path) {
    if std::fs::symlink_metadata(path).is_ok() {
        eprintln!(
            "agentguard: ignored legacy untrusted sidecar {}; it was not read, imported, executed, or deleted",
            path.display()
        );
    }
}

fn required_pending_audit_id(item: &PersistedPending) -> Result<&str, String> {
    item.audit_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| format!("待确认请求 {} 缺少审计 ID；保持队列不变", item.request_id))
}

fn commit_pending_transition(
    store: &AuditStore,
    decisions: &[(&str, UserDecision)],
    remaining: &[PersistedPending],
) -> Result<(), String> {
    let json = if remaining.is_empty() {
        None
    } else {
        Some(serde_json::to_string(remaining).map_err(|e| format!("序列化待确认快照失败:{e}"))?)
    };
    store
        .commit_pending_confirmation_transition(decisions, json.as_deref())
        .map_err(|e| format!("提交待确认审计事务失败:{e}"))
}

fn commit_timeout_transition(
    store: &AuditStore,
    removed: &[PersistedPending],
    remaining: &[PersistedPending],
) -> Result<(), String> {
    let audit_ids: Vec<&str> = removed
        .iter()
        .map(required_pending_audit_id)
        .collect::<Result<_, _>>()?;
    let decisions: Vec<_> = audit_ids
        .iter()
        .map(|audit_id| (*audit_id, UserDecision::Timeout))
        .collect();
    commit_pending_transition(store, &decisions, remaining)
}

/// `process_one` 已持有 engine mutex；这里直接复用，不能重入 `state.engine`。队列先预演
/// 入队及可能的容量挤出，审计事务成功后才真正修改内存。
fn enqueue_pending_with_engine(
    queue: &mut ConfirmQueue,
    engine: &Engine,
    req: ConfirmRequest,
    now_ms: u64,
) -> Result<(u64, Option<PersistedPending>), String> {
    req.audit_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| "高危确认缺少审计 ID；拒绝入队".to_string())?;
    let store = engine
        .audit()
        .ok_or_else(|| "审计不可用；拒绝修改待确认队列".to_string())?;
    let mut committed_eviction = None;
    let request_id = queue.try_enqueue_at(req, now_ms, |evicted, remaining| {
        if let Some(item) = evicted {
            commit_timeout_transition(store, std::slice::from_ref(item), remaining)?;
            committed_eviction = Some(item.clone());
        } else {
            commit_pending_transition(store, &[], remaining)?;
        }
        Ok::<_, String>(())
    })?;
    Ok((request_id, committed_eviction))
}

fn resolve_pending_with_engine(
    engine: &mut Engine,
    queue: &mut ConfirmQueue,
    request_id: u64,
    approve: bool,
) -> Result<(ResolveOutcome, bool), String> {
    let decision = if approve {
        UserDecision::Approve
    } else {
        UserDecision::Deny
    };
    let outcome = {
        let store = engine.audit();
        queue.try_resolve(request_id, approve, |removed, remaining| {
            let store = store.ok_or_else(|| "审计不可用；确认请求保持待处理".to_string())?;
            let audit_id = required_pending_audit_id(removed)?;
            commit_pending_transition(store, &[(audit_id, decision)], remaining)
        })?
    };
    if matches!(outcome, ResolveOutcome::Resolved { .. }) {
        if approve {
            engine.resume();
        } else {
            engine.pause();
        }
    }
    Ok((outcome, !queue.is_empty()))
}

fn expire_pending_with_engine(
    engine: &mut Engine,
    queue: &mut ConfirmQueue,
    now_ms: u64,
) -> Result<Vec<PendingItem>, String> {
    let expired = {
        let store = engine.audit();
        queue.try_expire(now_ms, DEFAULT_CONFIRM_TTL_MS, |removed, remaining| {
            let store = store.ok_or_else(|| "审计不可用；超时请求保持待处理".to_string())?;
            commit_timeout_transition(store, removed, remaining)
        })?
    };
    if !expired.is_empty() {
        engine.pause();
    }
    Ok(expired)
}

fn bump_pending_generation_with_engine(
    engine: &Engine,
    queue: &mut ConfirmQueue,
) -> Result<Vec<PersistedPending>, String> {
    let store = engine
        .audit()
        .ok_or_else(|| "审计不可用；会话代际与待确认队列保持不变".to_string())?;
    let mut removed_items = Vec::new();
    queue.try_bump_generation(|removed, remaining| {
        commit_timeout_transition(store, removed, remaining)?;
        removed_items = removed.to_vec();
        Ok::<_, String>(())
    })?;
    Ok(removed_items)
}

/// 从当前审计库恢复上次运行遗留的待确认。JSON 先完整解析，语法损坏则保留原值供诊断，
/// 且不会铸造任何回执；全部可处理项成功后才清理该库里的运行时 key。
fn restore_orphaned_from_store(store: &AuditStore) -> usize {
    let text = match store.pending_confirmations_json() {
        Ok(Some(text)) => text,
        Ok(None) => return 0,
        Err(e) => {
            eprintln!("agentguard: pending confirmations could not be loaded from audit DB: {e}");
            return 0;
        }
    };
    let items: Vec<PersistedPending> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "agentguard: pending confirmations in audit DB are unreadable ({e}); retaining the value and minting no receipts"
            );
            return 0;
        }
    };
    if items.len() > 64 {
        eprintln!(
            "agentguard: pending confirmations in audit DB exceed the queue limit; retaining the value and minting no receipts"
        );
        return 0;
    }
    let audit_ids: Vec<&str> = match items
        .iter()
        .map(|item| {
            item.audit_id
                .as_deref()
                .filter(|id| !id.trim().is_empty())
                .ok_or(())
        })
        .collect()
    {
        Ok(ids) => ids,
        Err(()) => {
            eprintln!(
                "agentguard: pending confirmations in audit DB contain a missing audit id; retaining the value and minting no receipts"
            );
            return 0;
        }
    };
    if let Err(e) = store.timeout_pending_confirmations_and_clear(&audit_ids) {
        eprintln!(
            "agentguard: pending-confirmation recovery failed atomically ({e}); retaining the value and minting no partial receipt set"
        );
        return 0;
    }
    items.len()
}

fn restore_orphaned_confirms(engine: &Engine) -> usize {
    warn_legacy_pending_sidecar();
    match engine.audit() {
        Some(store) => restore_orphaned_from_store(store),
        None => 0,
    }
}

/// P1-4:把等了超过 TTL 的确认按拒绝处理。整批 Timeout 回执和剩余快照先原子提交；
/// 失败时队列与引擎状态不变，成功后才移出、暂停并计数。
fn sweep_expired_confirms(state: &AppState) -> Result<Vec<u64>, String> {
    // 所有队列修改都按 engine -> pending 的顺序串行化，避免一个较早的快照在等待
    // engine 锁后反过来覆盖刚写入的新快照。
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let expired = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        expire_pending_with_engine(&mut engine, &mut q, now_epoch_ms())?
    };
    if expired.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::with_capacity(expired.len());
    for it in &expired {
        ids.push(it.request_id);
        state.trace.write(&TraceLine {
            request_id: Some(it.request_id),
            audit_id: it.request.audit_id.clone(),
            rule_id: Some(it.request.rule_id.clone()),
            ..trace_line("confirm_expired")
        });
    }
    state
        .confirms_timed_out
        .fetch_add(ids.len(), Ordering::Relaxed);
    Ok(ids)
}

/// P1-4:高危确认到了,把窗口拉到前面。窗口隐藏/最小化时以前只 emit 一个事件给一个没人看的
/// WebView。`main` 是 tauri.conf.json 里唯一的窗口标签。
fn bring_to_front(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// P1-4:菜单栏图标旁的文字——有待确认时显示「‖ N」,没有就清掉。托盘是窗口关着时唯一
/// 还看得见的东西。
fn update_tray_badge(app: &AppHandle, pending: usize) {
    if let Some(tray) = app.tray_by_id("agentguard-tray") {
        let title = if pending > 0 {
            Some(format!("‖ {pending}"))
        } else {
            None
        };
        let _ = tray.set_title(title.as_deref());
        let _ = tray.set_tooltip(Some(if pending > 0 {
            format!("AgentGuard — {pending} confirmation(s) waiting")
        } else {
            "AgentGuard".to_string()
        }));
    }
}

#[tauri::command]
fn get_pending_confirm(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<ConfirmDto>, String> {
    sweep_expired_confirms(state.inner())?;
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
    update_tray_badge(&app, pending.len());
    // 验收 trace:队首变了才记一条 confirm_shown(UI 此刻展示的就是它)。
    if let Ok(mut last) = state.last_shown_request.lock() {
        let now_front = pending.front().map(|p| p.request_id);
        if now_front != *last {
            *last = now_front;
            if let Some(id) = now_front {
                state.trace.write(&TraceLine {
                    request_id: Some(id),
                    ..trace_line("confirm_shown")
                });
            }
        }
    }
    // 永远显示队首(最旧)那一条。它稳定不变,直到被 resolve 移除 —— UI 不再"内容一直在跳"。
    Ok(pending.front().map(|p| ConfirmDto {
        request_id: p.request_id,
        rule_id: p.request.rule_id.clone(),
        severity: p.request.severity.clone(),
        human_message: p.request.human_message.clone(),
        source_app: p.request.source_app.clone(),
        ui_excerpt: p.request.ui_excerpt.clone(),
        effect: OBSERVED_ONLY_EFFECT,
        external_action_blocked: EXTERNAL_ACTION_BLOCKED,
    }))
}

/// resolve_confirm 的结果,回给前端。`stale` 时前端应刷新 pending 而不是当作成功。
#[derive(Serialize)]
struct ResolveDto {
    /// 是否真的解析了这条 request_id(false = 它已过期/被别的会话清掉,未触碰任何请求)。
    resolved: bool,
    /// 解析后队列里是否还有下一条待确认(前端据此决定是否继续弹)。
    has_next: bool,
}

#[tauri::command]
fn resolve_confirm(
    state: State<'_, AppState>,
    request_id: u64,
    approve: bool,
) -> Result<ResolveDto, String> {
    // P0-5 的核心:按 request_id compare-and-swap,只解析用户确实看到的那一条。
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let (outcome, has_next) = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        resolve_pending_with_engine(&mut engine, &mut q, request_id, approve)?
    };
    let ResolveOutcome::Resolved { approve, audit_id } = outcome else {
        // Stale:用户看到的请求已经不在了(新会话清掉 / 被挤出 / 已解析过)。不改引擎状态,
        // 让前端重新拉 pending —— 绝不把一个过期的"同意"当作对当前请求的同意。
        state.trace.write(&TraceLine {
            request_id: Some(request_id),
            approve: Some(approve),
            outcome: Some("stale".into()),
            ..trace_line("confirm_resolved")
        });
        return Ok(ResolveDto {
            resolved: false,
            has_next,
        });
    };
    state.trace.write(&TraceLine {
        request_id: Some(request_id),
        audit_id: audit_id.clone(),
        approve: Some(approve),
        outcome: Some("resolved".into()),
        ..trace_line("confirm_resolved")
    });

    // 回执、新快照、内存移除与引擎状态已经由上面的两阶段 helper 按顺序完成；任何数据库
    // 错误都会在这里之前返回，原请求仍可重试。
    Ok(ResolveDto {
        resolved: true,
        has_next,
    })
}

#[tauri::command]
fn list_audit(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<ObservedAuditRecordDto>, String> {
    require_protected_audit(state.inner())?;
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let store = engine.audit().ok_or("audit disabled")?;
    store
        .list_recent(limit.unwrap_or(50))
        .map(|records| {
            records
                .into_iter()
                .map(ObservedAuditRecordDto::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn export_session_report(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<String, String> {
    require_protected_audit(state.inner())?;
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let store = engine.audit().ok_or("audit disabled")?;
    let records = store
        .list_recent(limit.unwrap_or(500))
        .map_err(|e| e.to_string())?;
    let report = ObservedSessionReport::from(SessionReport::from_records(&records));
    let mut dir = dirs_next_data();
    dir.push(build_info::data_directory());
    dir.push("reports");
    let _ = std::fs::create_dir_all(&dir);
    let stamp = report.generated_at_ms;
    let json_path = dir.join(format!("session-{stamp}.json"));
    let md_path = dir.join(format!("session-{stamp}.md"));
    report
        .write_json(&json_path)
        .map_err(|error| error.to_string())?;
    report
        .write_markdown(&md_path)
        .map_err(|error| error.to_string())?;
    Ok(report.completion_message(&json_path, &md_path))
}

#[tauri::command]
fn set_auto_approve(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if enabled && !(DEVELOPMENT_BUILD && auto_approve_allowed()) {
        return Err("auto-approve is unavailable in release builds".into());
    }
    *state.auto_approve.lock().map_err(|e| e.to_string())? = enabled;
    Ok(())
}

#[tauri::command]
fn security_status() -> Result<SecurityStatusDto, String> {
    Ok(SecurityStatusDto {
        release_build: !DEVELOPMENT_BUILD,
        sqlcipher: sqlcipher_enabled(),
        auto_approve_allowed: DEVELOPMENT_BUILD && auto_approve_allowed(),
        intel_fail_closed: !DEVELOPMENT_BUILD,
    })
}

#[derive(Serialize)]
struct SecurityStatusDto {
    release_build: bool,
    sqlcipher: bool,
    auto_approve_allowed: bool,
    intel_fail_closed: bool,
}

#[tauri::command]
fn resume_session(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.lock().map_err(|e| e.to_string())?.resume();
    Ok(())
}

#[tauri::command]
async fn start_guard_session(
    app: AppHandle,
    state: State<'_, AppState>,
    task_profile: Option<String>,
    task_apps: Option<Vec<String>>,
) -> Result<String, String> {
    require_protected_audit(state.inner())?;
    // 首页的“开始”明确指桌面观察；仿真保留独立自检入口，不能创建没有必需观察能力的守护会话。
    if !mac_capabilities().accessibility {
        return Err("DESKTOP_ACCESSIBILITY_REQUIRED".into());
    }
    let _session_control = state.session_control.lock().await;
    // Keychain 初始化可在排队等待 session_control 时完成或失败，进入转换前再核对一次。
    require_protected_audit(state.inner())?;
    if !mac_capabilities().accessibility {
        return Err("DESKTOP_ACCESSIBILITY_REQUIRED".into());
    }
    let session_generation = advance_session_generation(state.inner());
    // 先失效并排空上一代，再创建新会话。若反过来，旧 poller 能在 stop 到达前把事件写进
    // 新 adapter/session，恰好重现 start/end/start 的跨代际污染。
    let ax_stop = stop_ax_observer(app.clone()).await?;
    let sck_stop = stop_sck_capture(app.clone()).await?;
    ensure_drained("AX", ax_stop)?;
    ensure_drained("SCK", sck_stop)?;
    if !session_generation_matches(state.inner(), Some(session_generation)) {
        return Err("session start superseded by a newer transition".into());
    }
    let sid = uuid::Uuid::new_v4().to_string();
    // Aura §4.4: naming the task is what selects its plan, and with it the resource ceiling. Both
    // arguments are optional, so a caller that does not know the task opens an unscoped session
    // exactly as before — but a caller that does know can no longer only *not* say so, which was
    // the position the shell was in when the plan library was loaded and never selected from.
    let task = guard_schema::TaskDeclaration {
        profile: task_profile
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        apps: task_apps.unwrap_or_default(),
        ..Default::default()
    };
    // P0-3/P0-5:上一会话遗留项先以系统 Timeout 结案；事务失败则不启动新会话。
    let removed = {
        let engine = state.engine.lock().map_err(|e| e.to_string())?;
        let mut queue = state.pending.lock().map_err(|e| e.to_string())?;
        bump_pending_generation_with_engine(&engine, &mut queue)?
    };
    state
        .confirms_timed_out
        .fetch_add(removed.len(), Ordering::Relaxed);
    for item in removed {
        state.trace.write(&TraceLine {
            request_id: Some(item.request_id),
            audit_id: item.audit_id,
            rule_id: Some(item.rule_id),
            ..trace_line("confirm_session_timeout")
        });
    }

    let session_events = {
        let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
        adapter.start_task_session(sid.clone(), "Claude", &task);
        adapter.poll_events().map_err(|e| e.to_string())?
    };
    state.trace.write(&TraceLine {
        session_id: Some(sid.clone()),
        ..trace_line("session_start")
    });
    reset_observation_memory(state.inner())?;
    process_events(state.inner(), session_events)?;

    // 观察随会话开始 —— 和 Windows 壳子("Observation begins with the session and ends with it")
    // 对齐。以前这里只有"观察器若已在跑就重置启动宽限",也就是说:**开始守护不会开始观察**,
    // 用户必须先去开发者面板打开 AX/抓屏。会话结束一直是会停掉观察器的(P0-3),
    // 只有开始这一半没接上,于是"开始"和"结束"不对称,状态灯永远停在"守护不完整"。
    //
    // 武装失败不阻止会话开始:会话是策略与审计的边界,拒绝开会话比少一个观察器更糟;
    // 而"少一个观察器"不会被瞒着 —— 状态机按 observers_running 判 degraded,
    // 失败原因写进 ax_message / sck_message 显示在界面上。
    let caps = mac_capabilities();
    let (arm_ax, arm_sck) = observers_for_session(&caps);
    if arm_ax {
        if let Err(e) = arm_ax_observer(app.clone(), Some(session_generation)).await {
            *state.ax_message.lock().map_err(|le| le.to_string())? =
                format!("AX observation could not start: {e}");
        }
    }
    if arm_sck {
        if let Err(e) = arm_sck_capture(app, Some(session_generation)).await {
            *state.sck_message.lock().map_err(|le| le.to_string())? =
                format!("screen capture could not start: {e}");
        }
    }
    if state.ax_lifecycle.active().is_some() || state.sck_lifecycle.active().is_some() {
        state
            .observer_started_ms
            .store(now_epoch_ms(), Ordering::Relaxed);
    }
    Ok(sid)
}

/// 会话边界:清掉所有「上一段观察」的记忆。
///
/// - `last_ui_event`:报告第 4 条——不清的话,新会话第一条事件被拿去和上一会话最后一帧比,
///   得到 UI-REVALIDATE。
/// - 聚合器:上一会话见过的画面在新会话里第一次出现要当首次记。
/// - 心跳/启动时刻:新会话从零起算,不拿旧会话的心跳冒充「在观察」。
fn reset_observation_memory(state: &AppState) -> Result<(), String> {
    state
        .last_ui_event
        .lock()
        .map_err(|e| e.to_string())?
        .clear();
    state.aggregator.lock().map_err(|e| e.to_string())?.reset();
    state.heartbeat_ms.store(0, Ordering::Relaxed);
    state.observer_started_ms.store(0, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
async fn end_guard_session(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let _session_control = state.session_control.lock().await;
    // 先使尚未完成的异步 start 失效，再取消/排空 poller。原生 stop 最慢可到 3 秒，
    // 这些等待都在 Tauri blocking worker，不占 UI 线程。
    advance_session_generation(state.inner());
    let ax_stop = stop_ax_observer(app.clone()).await?;
    let sck_stop = stop_sck_capture(app).await?;
    if matches!(ax_stop, StopOutcome::TimedOut { .. })
        || matches!(sck_stop, StopOutcome::TimedOut { .. })
    {
        return Err(format!(
            "observer stop timed out (AX: {ax_stop:?}; SCK: {sck_stop:?}); session remains active"
        ));
    }
    // 原生观察器已安全排空后再提交待确认结案；失败则 adapter 会话仍保持，队列可重试。
    let removed = {
        let engine = state.engine.lock().map_err(|e| e.to_string())?;
        let mut queue = state.pending.lock().map_err(|e| e.to_string())?;
        bump_pending_generation_with_engine(&engine, &mut queue)?
    };
    state
        .confirms_timed_out
        .fetch_add(removed.len(), Ordering::Relaxed);
    for item in removed {
        state.trace.write(&TraceLine {
            request_id: Some(item.request_id),
            audit_id: item.audit_id,
            rule_id: Some(item.rule_id),
            ..trace_line("confirm_session_timeout")
        });
    }
    let session_events = {
        let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
        adapter.end_session("Claude");
        adapter.poll_events().map_err(|e| e.to_string())?
    };
    state.trace.write(&trace_line("session_end"));
    if let Ok(mut s) = state.sck_streaming.lock() {
        *s = false;
    }
    process_events(state.inner(), session_events)?;
    reset_observation_memory(state.inner())?;
    // 报告第 4 条末句:「一次拒绝后结束,界面还错误停留在“已暂停”」。SESSION-PAUSED 是
    // **会话**级的状态(消息原文就是 "Session paused after critical deny"),会话结束了它
    // 就没有意义;不清的话下一个会话所有事件都被拦成 SESSION-PAUSED。
    state.engine.lock().map_err(|e| e.to_string())?.resume();
    Ok(())
}

#[tauri::command]
fn inject_demo_threat(
    state: State<'_, AppState>,
    kind: String,
) -> Result<Vec<DecisionDto>, String> {
    require_protected_audit(state.inner())?;
    // 不经过 adapter 的两类演示先处理，避免为了一个早退分支持有 adapter 再取 engine。
    if kind == "domain" {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("url".into(), "https://evil.example/login".into());
        let event = GuardEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp_ms: 0,
            platform: "macos".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "Safari".into(),
            agent_context_id: None,
            metadata,
        };
        let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
        let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
        return Ok(vec![process_one(
            state.inner(),
            &mut engine,
            &event,
            approve,
        )?]);
    }
    if kind == "netmon" {
        let summary = FlowSummary {
            dest_host: "evil.example".into(),
            bytes_out: 2048,
            process: Some("AgentProxy".into()),
        };
        let intel = state
            .engine
            .lock()
            .map_err(|e| e.to_string())?
            .intel()
            .malicious_domains
            .clone();
        let finding = evaluate_flow(&summary, &intel)
            .ok_or_else(|| "netmon produced no finding".to_string())?;
        let event = GuardEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp_ms: 0,
            platform: "macos".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "AgentProxy".into(),
            agent_context_id: None,
            metadata: finding.metadata,
        };
        let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
        let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
        return Ok(vec![process_one(
            state.inner(),
            &mut engine,
            &event,
            approve,
        )?]);
    }

    let events = {
        let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
        match kind.as_str() {
            "payment" => adapter.ingest(SimObservation::UiText {
                app: "Safari".into(),
                text: "请确认支付 $299.00".into(),
            }),
            "fm" => adapter.ingest(SimObservation::FormFill {
                app: "Safari".into(),
                field_id: "dob".into(),
                profile_key: "date_of_birth".into(),
                required: false,
                value_filled: true,
                is_trap: false,
                probe_type: Some("form_minimization".into()),
            }),
            "overlay" => adapter.ingest(SimObservation::OverlayMarker {
                app: "Safari".into(),
                marker: "[AG_TRANSPARENT_OVERLAY]".into(),
            }),
            "trap" => adapter.ingest(SimObservation::FormFill {
                app: "Safari".into(),
                field_id: "priority_phone".into(),
                profile_key: "phone_number".into(),
                required: false,
                value_filled: true,
                is_trap: true,
                probe_type: Some("trap_resistance".into()),
            }),
            "inject" => adapter.ingest(SimObservation::UiText {
                app: "Safari".into(),
                text: "hidden <!-- agentguard:poison --> payload".into(),
            }),
            "capture" => {
                adapter.ingest_capture_frame(demo_transparent_overlay_frame(), "ScreenCapture");
            }
            other => return Err(format!("unknown threat kind: {other}")),
        }
        adapter.poll_events().map_err(|e| e.to_string())?
    };
    process_events(state.inner(), events)
}

#[tauri::command]
fn reload_intel(state: State<'_, AppState>) -> Result<String, String> {
    require_protected_audit(state.inner())?;
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let intel = load_intel().map_err(|error| error.to_string())?;
    let ver = intel.version.clone();
    engine.reload_intel(intel);
    Ok(ver)
}

#[tauri::command]
fn sck_probe_cmd() -> Result<SckProbeDto, String> {
    let caps = mac_capabilities();
    match sck_probe() {
        Ok(()) => Ok(SckProbeDto {
            ok: true,
            error: String::new(),
            screen_capture: caps.screen_capture,
        }),
        Err(e) => Ok(SckProbeDto {
            ok: false,
            error: e,
            screen_capture: caps.screen_capture,
        }),
    }
}

#[tauri::command]
async fn sck_start_cmd(app: AppHandle) -> Result<CaptureSessionDto, String> {
    let state = app
        .try_state::<AppState>()
        .ok_or_else(|| "app state unavailable".to_string())?;
    with_manual_session_control(&state.session_control, || {
        arm_sck_capture(app.clone(), None)
    })
    .await
}

#[tauri::command]
async fn sck_stop_cmd(app: AppHandle) -> Result<CaptureSessionDto, String> {
    let state = app
        .try_state::<AppState>()
        .ok_or_else(|| "app state unavailable".to_string())?;
    with_manual_session_control(&state.session_control, || async {
        let outcome = stop_sck_capture(app.clone()).await?;
        *state.sck_streaming.lock().map_err(|e| e.to_string())? = false;
        let message = format!("capture stopped ({outcome:?})");
        *state.sck_message.lock().map_err(|e| e.to_string())? = message.clone();
        Ok(CaptureSessionDto {
            native: false,
            message,
        })
    })
    .await
}

/// 开发者面板/托盘的手动观察器命令也属于会话生命周期转换。
///
/// 外层只拿异步 session 锁；具体操作随后按既定顺序拿 AX/SCK control。这样 end/start
/// 在释放 native control、尚未完成 adapter 会话提交的窗口里，手动 enable 不能把一个
/// 无会话观察器重新武装出来。会话自己的 start/end 已经持锁，因此直接调用内部 arm/stop，
/// 不经过这个 helper，避免重入。
async fn with_manual_session_control<T, F, Fut>(
    control: &tauri::async_runtime::Mutex<()>,
    operation: F,
) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let _session = control.lock().await;
    operation().await
}

#[tauri::command]
async fn sck_poll_cmd(app: AppHandle) -> Result<SckPollDto, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        require_protected_audit(state.inner())?;
        // 手动 tick 不属于常驻 poller 的 lifecycle worker；用与 start/end 相同的最外层
        // session 锁，再取 SCK control，保证旧会话 tick 不会在切换后抽走新会话事件。
        let _session = state.session_control.try_lock().map_err(|_| {
            "session transition in progress; retry the manual SCK poll afterwards".to_string()
        })?;
        let _control = state.sck_control.lock().map_err(|e| e.to_string())?;
        let Some(generation) = state.sck_lifecycle.active() else {
            return Ok(empty_sck_poll());
        };
        Ok(poll_sck_once(state.inner(), generation)?.unwrap_or_else(empty_sck_poll))
    })
    .await
    .map_err(|error| format!("SCK poll task failed: {error}"))?
}

fn start_sck_auto_poller(
    app: AppHandle,
    state: &AppState,
    generation: ObserverGeneration,
) -> Result<(), String> {
    let lifecycle = state.sck_lifecycle.clone();
    let worker = lifecycle
        .worker(generation)
        .ok_or_else(|| format!("SCK generation {generation} was cancelled before spawn"))?;
    let thread_lifecycle = lifecycle.clone();
    note_observer_started(state);
    std::thread::Builder::new()
        .name(format!("agentguard-sck-{generation}"))
        .spawn(move || {
            let _worker = worker.attach_current_thread();
            while thread_lifecycle.is_current(generation) {
                std::thread::park_timeout(Duration::from_millis(1500));
                if !thread_lifecycle.is_current(generation) {
                    break;
                }
                let Some(st) = app.try_state::<AppState>() else {
                    break;
                };
                match poll_sck_once(st.inner(), generation) {
                    Ok(Some(dto)) => {
                        let _ = thread_lifecycle.commit(generation, || {
                            let _ = app.emit("sck-poll", &dto);
                            if dto.decisions.iter().any(|d| d.require_confirm) {
                                let _ = app.emit("sck-confirm-needed", ());
                                bring_to_front(&app);
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        let _ = thread_lifecycle.commit(generation, || {
                            if let Ok(mut slot) = st.observer_error.lock() {
                                *slot = Some(format!("SCK observer stopped: {e}"));
                            }
                            let _ = app.emit("sck-poll-error", serde_json::json!({ "error": e }));
                        });
                        break;
                    }
                }
            }
            // 原生 stop 可等待数秒，但这是专用 poller，不是 Tauri UI 线程。generation-aware
            // stop 让迟到的旧 worker 无法停掉继任 stream，并在 worker guard 排空前完成清理。
            if let Err(error) = stop_capture_session_generation(generation.get()) {
                if let Some(st) = app.try_state::<AppState>() {
                    if let Ok(mut slot) = st.sck_stop_error.lock() {
                        *slot = Some(error.to_string());
                    }
                    if let Ok(mut slot) = st.observer_error.lock() {
                        *slot = Some(format!("SCK native stop failed: {error}"));
                    }
                    if let Ok(mut message) = st.sck_message.lock() {
                        *message = format!("SCK native stop failed: {error}");
                    }
                }
            }
            if let Some(st) = app.try_state::<AppState>() {
                if let Ok(mut streaming) = st.sck_streaming.lock() {
                    *streaming = false;
                }
            }
            thread_lifecycle.cancel(generation);
        })
        .map_err(|error| {
            lifecycle.cancel(generation);
            format!("spawn SCK poller: {error}")
        })?;
    Ok(())
}

fn empty_sck_poll() -> SckPollDto {
    SckPollDto {
        decisions: vec![],
        frames_drained: 0,
        suppressed: 0,
        summaries: vec![],
    }
}

fn poll_sck_once(
    state: &AppState,
    generation: ObserverGeneration,
) -> Result<Option<SckPollDto>, String> {
    if !state.sck_lifecycle.is_current(generation) {
        return Ok(None);
    }
    // 慢的原生队列提取放在 commit 锁外；返回的事件只存在当前栈中。取消发生后，下面的
    // commit 会丢弃整批结果，旧 generation 不会碰 heartbeat/engine/pending/UI。
    let (frames_drained, events) = {
        let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
        let frames = adapter.poll_sck_frames_generation(generation, "ScreenCapture");
        let events = adapter.poll_events().map_err(|e| e.to_string())?;
        (frames, events)
    };
    state
        .sck_lifecycle
        .commit(generation, || {
            let (decisions, suppressed, summaries) = process_observed_events(state, events)?;
            // 心跳 = 这一路观察器成功跑了一拍(流活着),不要求这一拍抓到东西。
            state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
            if state.trace.enabled()
                && (frames_drained > 0 || !decisions.is_empty() || suppressed > 0)
            {
                state.trace.write(&TraceLine {
                    source: Some("sck".into()),
                    events: Some(decisions.len() as u32),
                    suppressed: Some(suppressed as u32),
                    ..trace_line("observe_tick")
                });
            }
            Ok(SckPollDto {
                decisions,
                frames_drained,
                suppressed,
                summaries,
            })
        })
        .transpose()
}

#[derive(Serialize)]
struct AxProbeDto {
    ok: bool,
    error: String,
    accessibility: bool,
}

#[derive(Serialize)]
struct AxPollDto {
    decisions: Vec<DecisionDto>,
    source_app: String,
    message: String,
    suppressed: usize,
    summaries: Vec<String>,
}

const AX_CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const AX_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(2);

#[tauri::command]
async fn ax_probe_cmd(app: AppHandle) -> Result<AxProbeDto, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        let _session = state.session_control.try_lock().map_err(|_| {
            "session transition in progress; retry the AX probe afterwards".to_string()
        })?;
        let _control = state.ax_control.lock().map_err(|e| e.to_string())?;
        let caps = mac_capabilities();
        if state.ax_lifecycle.active().is_some() {
            // A diagnostic probe must not occupy the native single-flight gate and make the live
            // observer interpret Busy as a failed required capability.
            return Ok(AxProbeDto {
                ok: caps.accessibility,
                error: if caps.accessibility {
                    String::new()
                } else {
                    "AX realtime observation is active but Accessibility permission is missing"
                        .into()
                },
                accessibility: caps.accessibility,
            });
        }
        let result = state
            .ax_native_gate
            .call(None, None, "probe", AX_CONTROL_TIMEOUT, ax_probe);
        match result {
            Ok(()) => {
                *state.ax_message.lock().map_err(|e| e.to_string())? = "AX OK".into();
                Ok(AxProbeDto {
                    ok: true,
                    error: String::new(),
                    accessibility: caps.accessibility,
                })
            }
            Err(error) => {
                let error = error.to_string();
                *state.ax_message.lock().map_err(|e| e.to_string())? = error.clone();
                Ok(AxProbeDto {
                    ok: false,
                    error,
                    accessibility: caps.accessibility,
                })
            }
        }
    })
    .await
    .map_err(|error| format!("AX probe task failed: {error}"))?
}

#[tauri::command]
async fn ax_poll_cmd(app: AppHandle) -> Result<AxPollDto, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        require_protected_audit(state.inner())?;
        // Keep one manual snapshot entirely inside the current session epoch. The lock order is
        // identical to start_guard_session -> arm_ax_observer: session_control, then ax_control.
        let _session = state.session_control.try_lock().map_err(|_| {
            "session transition in progress; retry the manual AX capture afterwards".to_string()
        })?;
        let _control = state.ax_control.lock().map_err(|e| e.to_string())?;
        if state.ax_lifecycle.active().is_some() {
            return Err("AX realtime observation is active; use its latest result".into());
        }
        poll_ax_once(state.inner())
    })
    .await
    .map_err(|error| format!("AX poll task failed: {error}"))?
}

/// 前台是守卫自己时的说明——AX 主路径和一次性抓取都用它,壳子测试也认它。
const AX_SELF_SKIP_MESSAGE: &str =
    "frontmost app is AgentGuard itself — skipped (the guard does not observe its own window)";

fn poll_ax_once(state: &AppState) -> Result<AxPollDto, String> {
    let snapshot = match state.ax_native_gate.call(
        None,
        None,
        "snapshot",
        AX_SNAPSHOT_TIMEOUT,
        live_ax_snapshot,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let error = error.to_string();
            *state.ax_message.lock().map_err(|e| e.to_string())? = error.clone();
            if let Ok(mut slot) = state.observer_error.lock() {
                *slot = Some(format!("AX manual capture failed: {error}"));
            }
            return Err(error);
        }
    };
    let (capture, events) = {
        let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
        let capture = adapter.ingest_live_ax_snapshot(snapshot);
        let events = if capture == AxCapture::Captured {
            adapter.poll_events().map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        (capture, events)
    };
    match capture {
        AxCapture::SkippedSelf | AxCapture::NotDue => {
            // 守卫不观察自己。观察器是活的:更新心跳,不产事件、不过引擎。
            *state.ax_message.lock().map_err(|e| e.to_string())? = AX_SELF_SKIP_MESSAGE.into();
            state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
            Ok(AxPollDto {
                decisions: vec![],
                source_app: "AgentGuard".into(),
                message: AX_SELF_SKIP_MESSAGE.into(),
                suppressed: 0,
                summaries: vec![],
            })
        }
        AxCapture::Captured => {
            let (decisions, suppressed, summaries) = process_observed_events(state, events)?;
            let msg = if suppressed > 0 {
                format!(
                    "live AX ingested · {} decision(s) · {suppressed} duplicate(s) folded",
                    decisions.len()
                )
            } else {
                format!("live AX ingested · {} decision(s)", decisions.len())
            };
            *state.ax_message.lock().map_err(|e| e.to_string())? = msg.clone();
            state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
            if let Ok(mut slot) = state.observer_error.lock() {
                *slot = None;
            }
            state.trace.write(&TraceLine {
                source: Some("ax".into()),
                events: Some(decisions.len() as u32),
                suppressed: Some(suppressed as u32),
                ..trace_line("observe_tick")
            });
            Ok(AxPollDto {
                decisions,
                source_app: "frontmost".into(),
                message: msg,
                suppressed,
                summaries,
            })
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Drain AXObserver notifications through the adapter coalescer. `None` means the
/// current tick was inside the debounce window and intentionally did not capture.
fn poll_ax_push_once(
    state: &AppState,
    generation: ObserverGeneration,
) -> Result<Option<AxPollDto>, String> {
    if !state.ax_lifecycle.is_current(generation) {
        return Ok(None);
    }
    let now = now_ms();
    let refresh_due = state
        .adapter
        .lock()
        .map_err(|e| e.to_string())?
        .ax_observer_refresh_due(generation, now)?;
    if refresh_due {
        let native_lifecycle = state.ax_lifecycle.clone();
        let refresh = state.ax_native_gate.call(
            Some(generation),
            Some(&state.ax_lifecycle),
            "observer-refresh",
            AX_CONTROL_TIMEOUT,
            move || {
                let result = start_native_ax_observer(generation.get());
                if !native_lifecycle.is_current(generation) {
                    stop_native_ax_observer(generation.get());
                }
                result
            },
        );
        match refresh {
            Ok(()) | Err(AxNativeCallFailure::Native(_)) => {
                // 注册不支持时继续靠 3 秒兜底；但也要节流，不能每 50ms 重试。
                let noted = state.ax_lifecycle.commit(generation, || {
                    state
                        .adapter
                        .lock()
                        .map_err(|e| e.to_string())?
                        .note_ax_observer_refreshed(generation, now)
                });
                match noted {
                    Some(result) => result?,
                    None => return Ok(None),
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }

    // take 只读取原生回调计数，不进入目标应用 IPC；仍经过单飞槽，避免与 start/stop 的
    // Objective-C 全局状态并发。任何 Busy 都说明上一个有界调用真实尚未返回，应降级而非重试。
    let notifications = state
        .ax_native_gate
        .call_inline(Some(generation), "observer-take", || {
            Ok(take_ax_notifications(generation.get()))
        })
        .map_err(|error| error.to_string())?;
    let due = match state.ax_lifecycle.commit(generation, || {
        state
            .adapter
            .lock()
            .map_err(|e| e.to_string())?
            .ax_capture_due(generation, now, notifications)
    }) {
        Some(result) => result?,
        None => return Ok(None),
    };
    if !due {
        return Ok(None);
    }

    // 关键隔离边界：子线程只拿 generation 和 sender，不捕获 AppState。墙钟超时后 receiver
    // 被丢弃；迟到快照没有任何写状态的能力，并继续作为旧 lifecycle worker 阻止新代启动。
    let native_lifecycle = state.ax_lifecycle.clone();
    let snapshot = state
        .ax_native_gate
        .call(
            Some(generation),
            Some(&state.ax_lifecycle),
            "snapshot",
            AX_SNAPSHOT_TIMEOUT,
            move || {
                let result = live_ax_snapshot();
                if !native_lifecycle.is_current(generation) {
                    stop_native_ax_observer(generation.get());
                }
                result
            },
        )
        .map_err(|error| error.to_string())?;

    state
        .ax_lifecycle
        .commit(generation, || {
            // apply + drain 是短 adapter 临界区；引擎/待确认处理在 guard 已释放后才开始。
            let (capture, events) = {
                let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
                let capture = adapter.apply_ax_snapshot(generation, now, snapshot)?;
                let events = if capture == AxCapture::Captured {
                    adapter.poll_events().map_err(|e| e.to_string())?
                } else {
                    Vec::new()
                };
                (capture, events)
            };
            match capture {
                AxCapture::NotDue => Ok(None),
                AxCapture::SkippedSelf => {
                    state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
                    if let Ok(mut slot) = state.observer_error.lock() {
                        *slot = None;
                    }
                    *state.ax_message.lock().map_err(|e| e.to_string())? =
                        AX_SELF_SKIP_MESSAGE.into();
                    Ok(None)
                }
                AxCapture::Captured => {
                    let (decisions, suppressed, summaries) =
                        process_observed_events(state, events)?;
                    let msg = if suppressed > 0 {
                        format!(
                            "live AX ingested · {} decision(s) · {suppressed} duplicate(s) folded",
                            decisions.len()
                        )
                    } else {
                        format!("live AX ingested · {} decision(s)", decisions.len())
                    };
                    *state.ax_message.lock().map_err(|e| e.to_string())? = msg.clone();
                    state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
                    if let Ok(mut slot) = state.observer_error.lock() {
                        *slot = None;
                    }
                    state.trace.write(&TraceLine {
                        source: Some("ax".into()),
                        events: Some(decisions.len() as u32),
                        suppressed: Some(suppressed as u32),
                        ..trace_line("observe_tick")
                    });
                    Ok(Some(AxPollDto {
                        decisions,
                        source_app: "frontmost".into(),
                        message: msg,
                        suppressed,
                        summaries,
                    }))
                }
            }
        })
        .unwrap_or(Ok(None))
}

/// 打开 AX 树观察(AXObserver 推送 + 兜底轮询),返回写进状态行的那句话。
///
/// 从 `ax_auto_cmd` 抽出来,因为现在有两个调用方:开发者面板的手动开关,和
/// `start_guard_session` —— 会话开始就该开始看(见 `observers_for_session`)。
async fn arm_ax_observer(
    app: AppHandle,
    session_generation: Option<u64>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        require_protected_audit(state.inner())?;
        let _control = state.ax_control.lock().map_err(|e| e.to_string())?;
        let previous = stop_ax_locked(state.inner())?;
        ensure_drained("AX", previous)?;
        if !session_generation_matches(state.inner(), session_generation) {
            return Err("AX start superseded by a newer session transition".into());
        }

        let generation = state.ax_lifecycle.begin_if_drained().map_err(|remaining| {
            format!("AX cannot start while {remaining} old worker(s) are still draining")
        })?;
        *state.ax_stop_error.lock().map_err(|e| e.to_string())? = None;
        state
            .adapter
            .lock()
            .map_err(|e| e.to_string())?
            .begin_ax_push(generation);
        let native_lifecycle = state.ax_lifecycle.clone();
        let push_result = state.ax_native_gate.call(
            Some(generation),
            Some(&state.ax_lifecycle),
            "observer-start",
            AX_CONTROL_TIMEOUT,
            move || {
                let result = start_native_ax_observer(generation.get());
                if !native_lifecycle.is_current(generation) {
                    stop_native_ax_observer(generation.get());
                }
                result
            },
        );
        if let Err(error) = &push_result {
            if !error.is_native_error() {
                if let Ok(mut slot) = state.observer_error.lock() {
                    *slot = Some(format!("AX observer start failed: {error}"));
                }
                let outcome = stop_ax_locked(state.inner())?;
                return Err(format!("{error}; AX cleanup: {outcome:?}"));
            }
        }
        state
            .adapter
            .lock()
            .map_err(|e| e.to_string())?
            .note_ax_observer_refreshed(generation, now_ms())?;
        if let Err(error) = poll_ax_push_once(state.inner(), generation) {
            if let Ok(mut slot) = state.observer_error.lock() {
                *slot = Some(format!("AX observer start poll failed: {error}"));
            }
            let cleanup = stop_ax_locked(state.inner());
            return Err(match cleanup {
                Ok(outcome) => format!("{error}; AX cleanup: {outcome:?}"),
                Err(cleanup_error) => format!("{error}; AX cleanup failed: {cleanup_error}"),
            });
        }
        if !session_generation_matches(state.inner(), session_generation) {
            let _ = stop_ax_locked(state.inner());
            return Err("AX start completed after its session ended".into());
        }
        if let Err(error) = start_ax_auto_poller(app.clone(), state.inner(), generation) {
            let _ = stop_ax_locked(state.inner());
            return Err(error);
        }
        let message = match &push_result {
            Ok(()) => "AXObserver push on (150ms debounce, 800ms ceiling, 3s fallback)".to_string(),
            Err(e) => format!("AXObserver unavailable ({e}); 3s fallback polling on"),
        };
        *state.ax_message.lock().map_err(|e| e.to_string())? = message.clone();
        Ok(message)
    })
    .await
    .map_err(|error| format!("AX start task failed: {error}"))?
}

// SCK 原生 stop 自带 3 秒上限；给 worker 额外 1 秒完成 guard/状态清理。等待发生在
// spawn_blocking 中，UI 线程不被占用。
const OBSERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(4);

fn ensure_drained(kind: &str, outcome: StopOutcome) -> Result<(), String> {
    match outcome {
        StopOutcome::Drained => Ok(()),
        StopOutcome::Panicked => Ok(()),
        StopOutcome::TimedOut { remaining } => Err(format!(
            "{kind} stop timed out with {remaining} worker(s) still running; restart required"
        )),
    }
}

fn stop_ax_locked(state: &AppState) -> Result<StopOutcome, String> {
    let Some(generation) = state.ax_lifecycle.cancel_active_or_draining() else {
        require_confirmed_ax_stop(
            state
                .ax_stop_error
                .lock()
                .map_err(|e| e.to_string())?
                .as_deref(),
        )?;
        if state.ax_native_gate.is_busy() {
            return Err(
                "AX native call is still running with no drainable observer; restart required"
                    .into(),
            );
        }
        return Ok(StopOutcome::Drained);
    };
    let outcome = state.ax_lifecycle.wait(generation, OBSERVER_DRAIN_TIMEOUT);
    if matches!(outcome, StopOutcome::TimedOut { .. }) {
        let error =
            format!("AX generation {generation} cancelled but stop timed out; restart required");
        if let Ok(mut slot) = state.observer_error.lock() {
            *slot = Some(error.clone());
        }
        if let Ok(mut slot) = state.ax_stop_error.lock() {
            *slot = Some(error);
        }
        return Ok(outcome);
    }
    require_confirmed_ax_stop(
        state
            .ax_stop_error
            .lock()
            .map_err(|e| e.to_string())?
            .as_deref(),
    )?;
    let should_stop_native = state
        .adapter
        .lock()
        .map_err(|e| e.to_string())?
        .finish_ax_push(generation);
    if should_stop_native {
        stop_native_ax_bounded(state, generation)?;
    }
    if outcome == StopOutcome::Panicked {
        if let Ok(mut slot) = state.observer_error.lock() {
            *slot = Some(format!("AX generation {generation} poller panicked"));
        }
    }
    Ok(outcome)
}

fn stop_native_ax_bounded(state: &AppState, generation: ObserverGeneration) -> Result<(), String> {
    match state.ax_native_gate.call(
        Some(generation),
        None,
        "observer-stop",
        AX_CONTROL_TIMEOUT,
        move || {
            stop_native_ax_observer(generation.get());
            Ok(())
        },
    ) {
        Ok(()) => {
            *state.ax_stop_error.lock().map_err(|e| e.to_string())? = None;
            Ok(())
        }
        Err(error) => {
            let error = error.to_string();
            *state.ax_stop_error.lock().map_err(|e| e.to_string())? = Some(error.clone());
            if let Ok(mut slot) = state.observer_error.lock() {
                *slot = Some(format!("AX native stop unconfirmed: {error}"));
            }
            Err(format!(
                "AX native stop is unconfirmed ({error}); restart required"
            ))
        }
    }
}

fn require_confirmed_ax_stop(error: Option<&str>) -> Result<(), String> {
    match error {
        Some(error) => Err(format!(
            "AX native stop is still unconfirmed ({error}); restart required"
        )),
        None => Ok(()),
    }
}

async fn stop_ax_observer(app: AppHandle) -> Result<StopOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        let _control = state.ax_control.lock().map_err(|e| e.to_string())?;
        stop_ax_locked(state.inner())
    })
    .await
    .map_err(|error| format!("AX stop task failed: {error}"))?
}

/// 打开屏幕抓取(SCK)。最长 8 秒的系统调用只在 blocking worker 中执行。
async fn arm_sck_capture(
    app: AppHandle,
    session_generation: Option<u64>,
) -> Result<CaptureSessionDto, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        require_protected_audit(state.inner())?;
        let _control = state.sck_control.lock().map_err(|e| e.to_string())?;
        let previous = stop_sck_locked(state.inner())?;
        ensure_drained("SCK", previous)?;
        if !session_generation_matches(state.inner(), session_generation) {
            return Err("SCK start superseded by a newer session transition".into());
        }

        let generation = state
            .sck_lifecycle
            .begin_if_drained()
            .map_err(|remaining| {
                format!("SCK cannot start while {remaining} old worker(s) are still draining")
            })?;
        *state.sck_stop_error.lock().map_err(|e| e.to_string())? = None;
        let info = match start_capture_session_generation(generation.get()) {
            Ok(info) => info,
            Err(error) => {
                state.sck_lifecycle.cancel(generation);
                let _ = state.sck_lifecycle.wait(generation, OBSERVER_DRAIN_TIMEOUT);
                return Err(error.to_string());
            }
        };
        if !session_generation_matches(state.inner(), session_generation) {
            state.sck_lifecycle.cancel(generation);
            let _ = stop_capture_session_generation(generation.get());
            return Err("SCK start completed after its session ended".into());
        }
        *state.sck_streaming.lock().map_err(|e| e.to_string())? = info.native;
        *state.sck_native_ok.lock().map_err(|e| e.to_string())? = info.native;
        *state.sck_message.lock().map_err(|e| e.to_string())? = info.message.clone();
        if info.native {
            if let Err(error) = start_sck_auto_poller(app.clone(), state.inner(), generation) {
                state.sck_lifecycle.cancel(generation);
                let _ = state.sck_lifecycle.wait(generation, OBSERVER_DRAIN_TIMEOUT);
                let _ = stop_capture_session_generation(generation.get());
                return Err(error);
            }
        } else {
            state.sck_lifecycle.cancel(generation);
            let _ = state.sck_lifecycle.wait(generation, OBSERVER_DRAIN_TIMEOUT);
        }
        Ok(CaptureSessionDto {
            native: info.native,
            message: info.message,
        })
    })
    .await
    .map_err(|error| format!("SCK start task failed: {error}"))?
}

fn stop_sck_locked(state: &AppState) -> Result<StopOutcome, String> {
    let Some(generation) = state.sck_lifecycle.cancel_active_or_draining() else {
        let stop_error = state.sck_stop_error.lock().map_err(|e| e.to_string())?;
        require_confirmed_sck_stop(stop_error.as_deref())?;
        return Ok(StopOutcome::Drained);
    };
    let outcome = state.sck_lifecycle.wait(generation, OBSERVER_DRAIN_TIMEOUT);
    if matches!(outcome, StopOutcome::TimedOut { .. }) {
        if let Ok(mut slot) = state.observer_error.lock() {
            *slot = Some(format!(
                "SCK generation {generation} cancelled but stop timed out; restart required"
            ));
        }
        return Ok(outcome);
    }
    let direct_stop = stop_capture_session_generation(generation.get()).map_err(|e| e.to_string());
    let worker_stop = state
        .sck_stop_error
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    require_confirmed_sck_stop(worker_stop.as_deref())?;
    if let Err(error) = direct_stop {
        *state.sck_stop_error.lock().map_err(|e| e.to_string())? = Some(error.clone());
        if let Ok(mut slot) = state.observer_error.lock() {
            *slot = Some(format!("SCK native stop failed: {error}"));
        }
        return require_confirmed_sck_stop(Some(&error)).map(|()| outcome);
    }
    *state.sck_streaming.lock().map_err(|e| e.to_string())? = false;
    if outcome == StopOutcome::Panicked {
        if let Ok(mut slot) = state.observer_error.lock() {
            *slot = Some(format!("SCK generation {generation} poller panicked"));
        }
    }
    Ok(outcome)
}

fn require_confirmed_sck_stop(error: Option<&str>) -> Result<(), String> {
    match error {
        Some(error) => Err(format!(
            "SCK native stop is still unconfirmed ({error}); restart required"
        )),
        None => Ok(()),
    }
}

async fn stop_sck_capture(app: AppHandle) -> Result<StopOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app
            .try_state::<AppState>()
            .ok_or_else(|| "app state unavailable".to_string())?;
        let _control = state.sck_control.lock().map_err(|e| e.to_string())?;
        stop_sck_locked(state.inner())
    })
    .await
    .map_err(|error| format!("SCK stop task failed: {error}"))?
}

#[tauri::command]
async fn ax_auto_cmd(app: AppHandle, enable: bool) -> Result<AxAutoDto, String> {
    let state = app
        .try_state::<AppState>()
        .ok_or_else(|| "app state unavailable".to_string())?;
    with_manual_session_control(&state.session_control, || async {
        let message = if enable {
            arm_ax_observer(app.clone(), None).await?
        } else {
            let outcome = stop_ax_observer(app.clone()).await?;
            format!("AX realtime observation off ({outcome:?})")
        };
        Ok(AxAutoDto {
            enabled: enable,
            message,
        })
    })
    .await
}

#[derive(Serialize)]
struct AxAutoDto {
    enabled: bool,
    message: String,
}

type AxWorkerTask = Box<dyn FnOnce() + Send + 'static>;

/// 把 worker guard 放进将提交给系统线程 API 的闭包。测试可注入一个确定失败的 spawner，
/// 证明 `spawn` 返回错误时闭包会被丢弃、worker 计数会归零，而不依赖耗尽系统线程资源。
fn spawn_ax_worker_with(
    worker: ObserverWorker,
    spawn: impl FnOnce(AxWorkerTask) -> std::io::Result<()>,
    task: impl FnOnce() + Send + 'static,
) -> std::io::Result<()> {
    spawn(Box::new(move || {
        let _worker = worker.attach_current_thread();
        task();
    }))
}

fn cleanup_failed_ax_poller_start_with(
    lifecycle: &ObserverLifecycle,
    generation: ObserverGeneration,
    stop_push: impl FnOnce(),
) -> StopOutcome {
    lifecycle.cancel(generation);
    stop_push();
    lifecycle.wait(generation, OBSERVER_DRAIN_TIMEOUT)
}

fn start_ax_auto_poller(
    app: AppHandle,
    state: &AppState,
    generation: ObserverGeneration,
) -> Result<(), String> {
    let lifecycle = state.ax_lifecycle.clone();
    let worker = lifecycle
        .worker(generation)
        .ok_or_else(|| format!("AX generation {generation} was cancelled before spawn"))?;
    let thread_lifecycle = lifecycle.clone();
    let thread_name = format!("agentguard-ax-{generation}");
    let spawn_result = spawn_ax_worker_with(
        worker,
        move |task| {
            std::thread::Builder::new()
                .name(thread_name)
                .spawn(task)
                .map(|_| ())
        },
        move || {
            while thread_lifecycle.is_current(generation) {
                std::thread::park_timeout(Duration::from_millis(50));
                if !thread_lifecycle.is_current(generation) {
                    break;
                }
                let Some(st) = app.try_state::<AppState>() else {
                    break;
                };
                match poll_ax_push_once(st.inner(), generation) {
                    Ok(Some(dto)) => {
                        let _ = thread_lifecycle.commit(generation, || {
                            let _ = app.emit("ax-poll", &dto);
                            if dto.decisions.iter().any(|d| d.require_confirm) {
                                let _ = app.emit("sck-confirm-needed", ());
                                bring_to_front(&app);
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        let _ = thread_lifecycle.commit(generation, || {
                            let _ = app
                                .emit("ax-poll-error", serde_json::json!({ "error": e.clone() }));
                            if let Ok(mut slot) = st.observer_error.lock() {
                                *slot = Some(format!("AX observer stopped: {e}"));
                            }
                        });
                        // 先失效代际再做任何清理：get_status 会立即按 AX 必需能力降级，
                        // 迟到的 native child 也只能丢结果/自清理，不能再刷新心跳。
                        thread_lifecycle.cancel(generation);
                        break;
                    }
                }
            }
            thread_lifecycle.cancel(generation);
            if let Some(st) = app.try_state::<AppState>() {
                let should_stop_native = st
                    .adapter
                    .lock()
                    .map(|mut adapter| adapter.finish_ax_push(generation))
                    .unwrap_or(false);
                if should_stop_native && !st.ax_native_gate.is_busy() {
                    let _ = stop_native_ax_bounded(st.inner(), generation);
                }
            }
        },
    );
    match spawn_result {
        Ok(()) => {
            note_observer_started(state);
            Ok(())
        }
        Err(error) => {
            let outcome = cleanup_failed_ax_poller_start_with(&lifecycle, generation, || {
                state
                    .adapter
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .finish_ax_push(generation);
            });
            let native_cleanup = stop_native_ax_bounded(state, generation)
                .map(|()| "Drained".to_string())
                .unwrap_or_else(|cleanup_error| cleanup_error);
            Err(format!(
                "spawn AX poller: {error}; worker cleanup: {outcome:?}; native cleanup: {native_cleanup}"
            ))
        }
    }
}

#[tauri::command]
fn sync_device_policy(
    state: State<'_, AppState>,
    source: Option<String>,
) -> Result<String, String> {
    if !DEVELOPMENT_BUILD && source.is_none() {
        return Err("此发布版本未配置企业策略来源，无法同步".into());
    }
    require_protected_audit(state.inner())?;
    let src = source.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../policies/enterprise-poc.yaml")
            .to_string_lossy()
            .into_owned()
    });
    // P1-9:同步 = 验签 + 装进引擎(验过才装),不再只是下载缓存显示 ID。
    let st = load_device_policy(&state, &src)?;
    Ok(match (&st.last_error, st.enforced) {
        (None, true) => format!(
            "{}@{} verified (signer {}) — enforced",
            st.policy_id,
            st.version,
            st.signer.clone().unwrap_or_default()
        ),
        (Some(e), true) => format!("{}@{} still enforced; {e}", st.policy_id, st.version),
        (Some(e), false) => format!("{}@{} NOT enforced: {e}", st.policy_id, st.version),
        (None, false) => format!("{}@{} NOT enforced", st.policy_id, st.version),
    })
}

#[tauri::command]
fn set_tray_locale(app: AppHandle, locale: String) -> Result<(), String> {
    let labels = match locale.as_str() {
        "zh-Hans" => [
            "打开仪表盘",
            "抓取前台 AX 树",
            "AX 实时观测：开/关",
            "SCK 开始捕获",
            "SCK 停止",
            "退出 AgentGuard",
        ],
        "zh-Hant" => [
            "開啟儀表板",
            "擷取最上層 AX 樹",
            "AX 即時觀測：開/關",
            "SCK 開始擷取",
            "SCK 停止",
            "結束 AgentGuard",
        ],
        _ => [
            "Open dashboard",
            "Capture frontmost AX tree",
            "AX realtime observation: on/off",
            "Start SCK capture",
            "Stop SCK",
            "Quit AgentGuard",
        ],
    };
    let show = MenuItem::with_id(&app, "show", labels[0], true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let ax_poll = MenuItem::with_id(&app, "ax_poll", labels[1], true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let ax_auto = MenuItem::with_id(&app, "ax_auto", labels[2], true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let sck_start = MenuItem::with_id(&app, "sck_start", labels[3], true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let sck_stop = MenuItem::with_id(&app, "sck_stop", labels[4], true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let quit = MenuItem::with_id(&app, "quit", labels[5], true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let menu = Menu::with_items(
        &app,
        &[&show, &ax_poll, &ax_auto, &sck_start, &sck_stop, &quit],
    )
    .map_err(|e| e.to_string())?;
    let tray = app
        .tray_by_id("agentguard-tray")
        .ok_or_else(|| "tray icon not ready".to_string())?;
    tray.set_menu(Some(menu)).map_err(|e| e.to_string())
}

fn process_one(
    state: &AppState,
    engine: &mut Engine,
    event: &guard_schema::GuardEvent,
    approve: bool,
) -> Result<DecisionDto, String> {
    let is_ui = matches!(
        event.event_type,
        EventType::UiTreeDelta | EventType::ScreenFrame
    );

    if is_ui {
        // 只和**同一来源**的上一帧比:SCK 帧不和 AX 快照比,演示注入不和真机观察比。
        let before = state
            .last_ui_event
            .lock()
            .map_err(|e| e.to_string())?
            .get(&event.source_app)
            .cloned();
        if let Some(ref before) = before {
            let gate = engine.revalidate_ui(before, event);
            if gate.action != DecisionAction::Allow {
                if approve {
                    let d = engine
                        .process_with_revalidate(before, event, &AutoApprove)
                        .map_err(|e| e.to_string())?;
                    remember_ui_event(state, event)?;
                    return Ok(to_dto(&d));
                }
                // Mark UI so UI-REVALIDATE rule + pending confirm modal fire.
                let mut marked = event.clone();
                let ui = marked.metadata.get("ui_text").cloned().unwrap_or_default();
                marked.metadata.insert(
                    "ui_text".into(),
                    format!("{ui} [AG_UI_REVALIDATE]").trim().to_string(),
                );
                remember_ui_event(state, event)?;
                let d = engine.process(&marked).map_err(|e| e.to_string())?;
                if d.require_confirm
                    && matches!(d.action, DecisionAction::Block | DecisionAction::Alert)
                {
                    let req = ConfirmRequest::from_decision(
                        &d,
                        &marked.source_app,
                        engine.last_audit_id().map(|s| s.to_string()),
                        marked.metadata.get("ui_text").cloned(),
                    );
                    enqueue_confirm(state, engine, req)?;
                }
                return Ok(to_dto(&d));
            }
        }
        remember_ui_event(state, event)?;
    }

    if approve {
        let d = engine
            .process_gated(event, &AutoApprove)
            .map_err(|e| e.to_string())?;
        return Ok(to_dto(&d));
    }

    let d = engine.process(event).map_err(|e| e.to_string())?;
    if d.require_confirm && matches!(d.action, DecisionAction::Block | DecisionAction::Alert) {
        let req = ConfirmRequest::from_decision(
            &d,
            &event.source_app,
            engine.last_audit_id().map(|s| s.to_string()),
            event.metadata.get("ui_text").cloned(),
        );
        enqueue_confirm(state, engine, req)?;
    }
    Ok(to_dto(&d))
}

fn to_dto(d: &Decision) -> DecisionDto {
    DecisionDto {
        action: format!("{:?}", d.action),
        rule_id: d.rule_id.clone(),
        human_message: d.human_message.clone(),
        require_confirm: d.require_confirm,
        effect: OBSERVED_ONLY_EFFECT,
        external_action_blocked: EXTERNAL_ACTION_BLOCKED,
    }
}

fn remember_ui_event(state: &AppState, event: &GuardEvent) -> Result<(), String> {
    state
        .last_ui_event
        .lock()
        .map_err(|e| e.to_string())?
        .insert(event.source_app.clone(), event.clone());
    Ok(())
}

fn note_observer_started(state: &AppState) {
    state
        .observer_started_ms
        .store(now_epoch_ms(), Ordering::Relaxed);
    if let Ok(mut slot) = state.observer_error.lock() {
        *slot = None;
    }
}

/// 一次一条的路径(会话开始/结束、演示注入、SessionEnd 等):不聚合。
fn process_events(state: &AppState, events: Vec<GuardEvent>) -> Result<Vec<DecisionDto>, String> {
    require_protected_audit(state)?;
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for event in events {
        out.push(process_one(state, &mut engine, &event, approve)?);
    }
    Ok(out)
}

/// 观察器轮询路径(SCK / AX):先过聚合器,同一语义内容 30 s 内只过引擎一次(P2-3)。
///
/// 返回 (判决, 这一拍折叠掉的条数, 结束摘要)。折叠掉的事件**不**过引擎、不写审计、不入
/// 待确认队列——它们和上一条一字不差,过一遍只会多一行一样的记录和一个多余的弹窗。
/// 窗口过后同一内容仍在,放行一条并把折叠计数写进元数据 `repeat_count`,审计里就有
/// 「这 30 s 里同一画面出现了 N 次」的持续摘要,而不是 N 行。
fn process_observed_events(
    state: &AppState,
    events: Vec<GuardEvent>,
) -> Result<(Vec<DecisionDto>, usize, Vec<String>), String> {
    require_protected_audit(state)?;
    let now = now_epoch_ms();
    let mut aggregator = state.aggregator.lock().map_err(|e| e.to_string())?;
    let mut to_process = Vec::with_capacity(events.len());
    let mut suppressed = 0usize;
    for mut event in events {
        match aggregator.observe_event(&event, now) {
            Verdict::Emit { repeats } => {
                if repeats > 0 {
                    event
                        .metadata
                        .insert(REPEAT_COUNT_KEY.to_string(), repeats.to_string());
                }
                to_process.push(event);
            }
            Verdict::Suppress { .. } => suppressed += 1,
        }
    }
    let summaries: Vec<String> = aggregator
        .sweep(now)
        .into_iter()
        .filter(|e| e.total > 1)
        .map(|e| {
            format!(
                "repeated observation ended: seen {} time(s) over {:.1}s",
                e.total,
                e.last_ms.saturating_sub(e.first_ms) as f64 / 1000.0
            )
        })
        .collect();
    drop(aggregator);

    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(to_process.len());
    for event in &to_process {
        out.push(process_one(state, &mut engine, event, approve)?);
    }
    Ok((out, suppressed, summaries))
}

mod desktop_setup;
mod gateway_confirm;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 签名资源仍在首窗前同步验证；它们是本地文件，不会等待系统授权。Keychain、SQLCipher
    // 和签名器则由 setup 后的单飞 worker 初始化，避免 Security.framework 把 UI 主线程
    // 无限卡在 SecItemCopyMatching。审计 Ready 前所有会话/事件入口保持 fail-closed。
    let mut engine =
        build_engine_without_audit().expect("initialize signed runtime resources without audit");
    // P1-9:占位引擎先恢复可验证策略用于只读状态；受保护引擎就绪时会原子替换它。
    let policy_status = restore_device_policy_at_startup(&mut engine);
    let state = AppState {
        engine: Mutex::new(engine),
        audit_bootstrap: Mutex::new(AuditBootstrapState::Pending),
        audit_bootstrap_started: AtomicBool::new(false),
        audit_bootstrap_generation: AtomicU64::new(0),
        audit_recovery_running: AtomicBool::new(false),
        adapter: Mutex::new(MacAdapter::new()),
        auto_approve: Mutex::new(false),
        // cap 64:同时在等的高危确认上限。真正防止风暴撑爆它的是上层的事件聚合(P2-3);
        // 满了则挤出最旧的并把它判成 Stale(fail-safe:过期确认按未放行处理)。
        pending: Mutex::new(ConfirmQueue::new(64)),
        tcc_acknowledged: Mutex::new(false),
        sck_streaming: Mutex::new(false),
        sck_native_ok: Mutex::new(false),
        sck_message: Mutex::new(String::new()),
        sck_stop_error: Mutex::new(None),
        sck_lifecycle: ObserverLifecycle::new(),
        sck_control: Mutex::new(()),
        ax_lifecycle: ObserverLifecycle::new(),
        ax_native_gate: AxNativeGate::new(),
        ax_stop_error: Mutex::new(None),
        ax_control: Mutex::new(()),
        session_generation: AtomicU64::new(0),
        session_control: tauri::async_runtime::Mutex::new(()),
        last_ui_event: Mutex::new(HashMap::new()),
        ax_message: Mutex::new(String::new()),
        heartbeat_ms: AtomicU64::new(0),
        observer_started_ms: AtomicU64::new(0),
        observer_error: Mutex::new(None),
        aggregator: Mutex::new(Aggregator::for_observers()),
        confirms_timed_out: AtomicUsize::new(0),
        orphaned_confirms: AtomicUsize::new(0),
        policy_status: Mutex::new(policy_status),
        trace: TraceWriter::from_env(),
        last_shown_request: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .manage(gateway_confirm::GatewayConfirm::default())
        .setup(|app| {
            start_protected_audit_bootstrap(app.handle().clone());
            let tray_icon =
                tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))?;
            let show = MenuItem::with_id(app, "show", "Open dashboard", true, None::<&str>)?;
            let ax_poll = MenuItem::with_id(
                app,
                "ax_poll",
                "Capture frontmost AX tree",
                true,
                None::<&str>,
            )?;
            let ax_auto = MenuItem::with_id(
                app,
                "ax_auto",
                "AX realtime observation: on/off",
                true,
                None::<&str>,
            )?;
            let sck_start =
                MenuItem::with_id(app, "sck_start", "Start SCK capture", true, None::<&str>)?;
            let sck_stop = MenuItem::with_id(app, "sck_stop", "Stop SCK", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit AgentGuard", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&show, &ax_poll, &ax_auto, &sck_start, &sck_stop, &quit],
            )?;
            let _tray = TrayIconBuilder::with_id("agentguard-tray")
                .icon(tray_icon)
                .icon_as_template(true)
                .menu(&menu)
                .tooltip("AgentGuard")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "ax_poll" => {
                        let task_app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            match ax_poll_cmd(task_app.clone()).await {
                                Ok(dto) => {
                                    let _ = task_app.emit("ax-poll", &dto);
                                    if dto.decisions.iter().any(|d| d.require_confirm) {
                                        let _ = task_app.emit("sck-confirm-needed", ());
                                    }
                                }
                                Err(e) => {
                                    let _ = task_app
                                        .emit("ax-poll-error", serde_json::json!({ "error": e }));
                                }
                            }
                        });
                    }
                    "sck_start" => {
                        let task_app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(error) = sck_start_cmd(task_app.clone()).await {
                                let _ = task_app
                                    .emit("sck-poll-error", serde_json::json!({ "error": error }));
                            }
                        });
                    }
                    "sck_stop" => {
                        let task_app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(error) = sck_stop_cmd(task_app.clone()).await {
                                let _ = task_app
                                    .emit("sck-poll-error", serde_json::json!({ "error": error }));
                            }
                        });
                    }
                    "ax_auto" => {
                        if let Some(st) = app.try_state::<AppState>() {
                            let enable = st.ax_lifecycle.active().is_none();
                            let task_app = app.clone();
                            tauri::async_runtime::spawn(async move {
                                if let Err(error) = ax_auto_cmd(task_app.clone(), enable).await {
                                    let _ = task_app.emit(
                                        "ax-poll-error",
                                        serde_json::json!({ "error": error }),
                                    );
                                }
                            });
                        }
                    }
                    "quit" => {
                        if let Some(st) = app.try_state::<AppState>() {
                            advance_session_generation(st.inner());
                        }
                        let task_app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let _ = stop_ax_observer(task_app.clone()).await;
                            let _ = stop_sck_capture(task_app.clone()).await;
                            task_app.exit(0);
                        });
                    }
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            desktop_setup::get_installation_info,
            desktop_setup::open_setup_resource,
            desktop_setup::check_gateway_setup,
            gateway_confirm::connect_gateway_confirmation,
            gateway_confirm::poll_gateway_confirmation,
            gateway_confirm::disconnect_gateway_confirmation,
            gateway_confirm::answer_gateway_confirmation,
            get_status,
            get_tcc_status,
            acknowledge_tcc,
            probe_permissions,
            get_pending_confirm,
            resolve_confirm,
            list_audit,
            export_session_report,
            set_auto_approve,
            security_status,
            resume_session,
            start_guard_session,
            end_guard_session,
            inject_demo_threat,
            reload_intel,
            sync_device_policy,
            sck_probe_cmd,
            sck_start_cmd,
            sck_stop_cmd,
            sck_poll_cmd,
            ax_probe_cmd,
            ax_poll_cmd,
            ax_auto_cmd,
            open_privacy_settings,
            retry_audit_initialization,
            recover_legacy_audit,
            set_tray_locale,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod audit_bootstrap_tests {
    use super::AuditBootstrapState;

    #[test]
    fn timeout_keeps_protection_closed_but_late_success_can_recover() {
        let mut state = AuditBootstrapState::Pending;
        state.mark_timeout();
        assert_eq!(state.state_name(), "failed");
        assert!(state
            .blocking_reason()
            .unwrap()
            .contains("protection remains off"));

        state.complete_success();
        assert_eq!(state, AuditBootstrapState::Ready);
        assert!(state.blocking_reason().is_none());
    }

    #[test]
    fn watchdog_and_late_error_cannot_overwrite_ready() {
        let mut state = AuditBootstrapState::Ready;
        state.mark_timeout();
        state.complete_failure("late failure".into());
        assert_eq!(state, AuditBootstrapState::Ready);
    }

    #[test]
    fn release_startup_wires_keychain_off_the_main_thread_and_gates_sessions() {
        let source = include_str!("lib.rs");
        let product = source.split("\n#[cfg(test)]").next().unwrap();
        let run = product.split("pub fn run()").nth(1).unwrap();
        assert!(run.contains("build_engine_without_audit()"));
        assert!(run.contains("start_protected_audit_bootstrap(app.handle().clone())"));
        assert!(!run
            .split("tauri::Builder::default()")
            .next()
            .unwrap()
            .contains("build_engine()"));

        let start = product
            .split("async fn start_guard_session(")
            .nth(1)
            .unwrap();
        assert!(start.contains("require_protected_audit(state.inner())?"));
    }
}

#[cfg(test)]
mod pending_persistence_tests {
    use super::*;

    fn audit_record(id: &str) -> AuditRecord {
        AuditRecord {
            id: id.into(),
            timestamp_ms: 1,
            platform: "macos".into(),
            event_type: "ui_tree_delta".into(),
            source_app: "Safari".into(),
            agent_session_id: None,
            rule_id: "PAY-001".into(),
            severity: "critical".into(),
            action: "Block".into(),
            human_message: "需要确认".into(),
            evidence_ref: None,
            user_decision: None,
            event_json: "{}".into(),
            attributed_agent: None,
        }
    }

    fn pending(audit_id: &str) -> PersistedPending {
        PersistedPending {
            request_id: 7,
            generation: 2,
            enqueued_ms: 10,
            audit_id: Some(audit_id.into()),
            rule_id: "PAY-001".into(),
            severity: "Critical".into(),
            source_app: "Safari".into(),
        }
    }

    fn confirm(audit_id: &str) -> ConfirmRequest {
        ConfirmRequest {
            audit_id: Some(audit_id.into()),
            rule_id: "PAY-001".into(),
            severity: "Critical".into(),
            human_message: "需要确认".into(),
            source_app: "Safari".into(),
            ui_excerpt: None,
        }
    }

    fn engine_with(store: AuditStore) -> Engine {
        Engine::new(
            guard_schema::RuleSet {
                version: "test".into(),
                rules: vec![],
            },
            guard_schema::GuardContract::default(),
        )
        .with_audit(store)
    }

    #[test]
    fn 同库待确认在重启时写timeout并清理运行时状态() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-7")).unwrap();
        store
            .save_pending_confirmations_json(&serde_json::to_string(&[pending("audit-7")]).unwrap())
            .unwrap();

        assert_eq!(restore_orphaned_from_store(&store), 1);
        assert_eq!(store.pending_confirmations_json().unwrap(), None);
        assert_eq!(
            store.list_recent(1).unwrap()[0].user_decision.as_deref(),
            Some("timeout")
        );
        assert_eq!(store.head().unwrap().unwrap().receipt_count, 1);
    }

    #[test]
    fn 损坏的同库json保留且不铸造回执() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-7")).unwrap();
        store.save_pending_confirmations_json("{broken").unwrap();

        assert_eq!(restore_orphaned_from_store(&store), 0);
        assert_eq!(
            store.pending_confirmations_json().unwrap().as_deref(),
            Some("{broken")
        );
        assert_eq!(store.list_recent(1).unwrap()[0].user_decision, None);
        assert_eq!(store.head().unwrap().unwrap().receipt_count, 0);
    }

    #[test]
    fn 缺少审计id的同库状态保留且不铸造回执() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-7")).unwrap();
        let mut item = pending("audit-7");
        item.audit_id = None;
        let json = serde_json::to_string(&[item]).unwrap();
        store.save_pending_confirmations_json(&json).unwrap();

        assert_eq!(restore_orphaned_from_store(&store), 0);
        assert_eq!(
            store.pending_confirmations_json().unwrap().as_deref(),
            Some(json.as_str())
        );
        assert_eq!(store.list_recent(1).unwrap()[0].user_decision, None);
        assert_eq!(store.head().unwrap().unwrap().receipt_count, 0);
    }

    #[test]
    fn 确认回执失败时请求与引擎状态都保持不变() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-valid")).unwrap();
        let mut engine = engine_with(store);
        let mut queue = ConfirmQueue::new(4);
        let request_id = queue.enqueue_at(confirm("audit-missing"), 10);
        let before = queue.snapshot();
        engine
            .audit()
            .unwrap()
            .save_pending_confirmations_json(&serde_json::to_string(&before).unwrap())
            .unwrap();

        engine.pause();
        assert!(resolve_pending_with_engine(&mut engine, &mut queue, request_id, true).is_err());
        assert!(engine.is_paused(), "失败的同意不能恢复引擎");
        assert_eq!(queue.snapshot(), before);

        engine.resume();
        assert!(resolve_pending_with_engine(&mut engine, &mut queue, request_id, false).is_err());
        assert!(!engine.is_paused(), "失败的拒绝不能暂停引擎");
        assert_eq!(queue.snapshot(), before);
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .pending_confirmations_json()
                .unwrap(),
            Some(serde_json::to_string(&before).unwrap())
        );
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .head()
                .unwrap()
                .unwrap()
                .receipt_count,
            0
        );
    }

    #[test]
    fn 超时回执失败时请求仍在队列和同库快照中() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-valid")).unwrap();
        let mut engine = engine_with(store);
        let mut queue = ConfirmQueue::new(4);
        queue.enqueue_at(confirm("audit-missing"), 1);
        let before = queue.snapshot();
        let json = serde_json::to_string(&before).unwrap();
        engine
            .audit()
            .unwrap()
            .save_pending_confirmations_json(&json)
            .unwrap();

        assert!(
            expire_pending_with_engine(&mut engine, &mut queue, DEFAULT_CONFIRM_TTL_MS + 2)
                .is_err()
        );
        assert_eq!(queue.snapshot(), before);
        assert!(!engine.is_paused());
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .pending_confirmations_json()
                .unwrap(),
            Some(json)
        );
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .head()
                .unwrap()
                .unwrap()
                .receipt_count,
            0
        );
    }

    #[test]
    fn 会话切换给全部遗留项写timeout后才推进代际() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-a")).unwrap();
        store.append(&audit_record("audit-b")).unwrap();
        let engine = engine_with(store);
        let mut queue = ConfirmQueue::new(4);
        queue.enqueue_at(confirm("audit-a"), 1);
        queue.enqueue_at(confirm("audit-b"), 2);
        let generation = queue.generation();
        engine
            .audit()
            .unwrap()
            .save_pending_confirmations_json(&serde_json::to_string(&queue.snapshot()).unwrap())
            .unwrap();

        let removed = bump_pending_generation_with_engine(&engine, &mut queue).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(queue.is_empty());
        assert_eq!(queue.generation(), generation + 1);
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .pending_confirmations_json()
                .unwrap(),
            None
        );
        let records = engine.audit().unwrap().list_recent(10).unwrap();
        assert!(records
            .iter()
            .all(|record| record.user_decision.as_deref() == Some("timeout")));
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .head()
                .unwrap()
                .unwrap()
                .receipt_count,
            2
        );
    }

    #[test]
    fn 容量挤出先写timeout并把新项存入同库快照() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-a")).unwrap();
        store.append(&audit_record("audit-b")).unwrap();
        let engine = engine_with(store);
        let mut queue = ConfirmQueue::new(1);

        let (a, none) =
            enqueue_pending_with_engine(&mut queue, &engine, confirm("audit-a"), 1).unwrap();
        assert!(none.is_none());
        let (b, evicted) =
            enqueue_pending_with_engine(&mut queue, &engine, confirm("audit-b"), 2).unwrap();
        assert_eq!(b, a + 1);
        assert_eq!(evicted.unwrap().audit_id.as_deref(), Some("audit-a"));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.front().unwrap().request_id, b);
        let records = engine.audit().unwrap().list_recent(10).unwrap();
        assert_eq!(
            records
                .iter()
                .find(|record| record.id == "audit-a")
                .unwrap()
                .user_decision
                .as_deref(),
            Some("timeout")
        );
        assert_eq!(
            records
                .iter()
                .find(|record| record.id == "audit-b")
                .unwrap()
                .user_decision,
            None
        );
        let persisted: Vec<PersistedPending> = serde_json::from_str(
            &engine
                .audit()
                .unwrap()
                .pending_confirmations_json()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted, queue.snapshot());
        assert_eq!(
            engine
                .audit()
                .unwrap()
                .head()
                .unwrap()
                .unwrap()
                .receipt_count,
            1
        );
    }

    #[test]
    fn 遗留明文sidecar即使指向当前记录也不会被执行或删除() {
        let legacy = std::env::temp_dir().join(format!(
            "agentguard-legacy-pending-{}.json",
            uuid::Uuid::new_v4()
        ));
        let bytes = serde_json::to_vec(&[pending("audit-7")]).unwrap();
        std::fs::write(&legacy, &bytes).unwrap();
        let store = AuditStore::open_in_memory().unwrap();
        store.append(&audit_record("audit-7")).unwrap();

        warn_legacy_pending_sidecar_at(&legacy);

        assert_eq!(restore_orphaned_from_store(&store), 0);
        assert_eq!(std::fs::read(&legacy).unwrap(), bytes);
        assert_eq!(store.list_recent(1).unwrap()[0].user_decision, None);
        assert_eq!(store.head().unwrap().unwrap().receipt_count, 0);
        std::fs::remove_file(legacy).unwrap();
    }
}

#[cfg(test)]
mod observed_effect_tests {
    use super::*;
    use guard_schema::Severity;
    use std::collections::HashMap;

    fn block_record() -> AuditRecord {
        let event = GuardEvent {
            event_id: "observed-1".into(),
            timestamp_ms: 42,
            platform: "macos".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "Safari".into(),
            agent_context_id: Some("session-1".into()),
            metadata: HashMap::from([("ui_text".into(), "Pay $299".into())]),
        };
        let decision = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: "PAY-001".into(),
            human_message: "检测到高风险支付界面".into(),
            require_confirm: true,
        };
        AuditRecord::from_event_decision(&event, &decision)
    }

    #[test]
    fn realtime_and_confirm_dtos_disclose_observed_only_effect() {
        let decision = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: "PAY-001".into(),
            human_message: "检测到高风险支付界面".into(),
            require_confirm: true,
        };
        let decision_json = serde_json::to_value(to_dto(&decision)).unwrap();
        assert_eq!(decision_json["action"], "Block");
        assert_eq!(decision_json["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!decision_json["external_action_blocked"].as_bool().unwrap());

        let confirm_json = serde_json::to_value(ConfirmDto {
            request_id: 7,
            rule_id: "PAY-001".into(),
            severity: "Critical".into(),
            human_message: "检测到高风险支付界面".into(),
            source_app: "Safari".into(),
            ui_excerpt: None,
            effect: OBSERVED_ONLY_EFFECT,
            external_action_blocked: EXTERNAL_ACTION_BLOCKED,
        })
        .unwrap();
        assert_eq!(confirm_json["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!confirm_json["external_action_blocked"].as_bool().unwrap());
    }

    #[test]
    fn audit_rows_and_reports_never_claim_external_blocking() {
        let row = serde_json::to_value(ObservedAuditRecordDto::from(block_record())).unwrap();
        assert_eq!(row["action"], "Block", "签名审计的内部动作不能被改写");
        assert_eq!(row["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!row["external_action_blocked"].as_bool().unwrap());

        let report = ObservedSessionReport::from(SessionReport::from_records(&[block_record()]));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["risk_verdict_count"], 1);
        assert_eq!(json["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!json["external_action_blocked"].as_bool().unwrap());
        assert!(json.get("block_count").is_none());
        assert!(json.get("privacy_note").is_none());

        let markdown = report.to_markdown();
        assert!(markdown.contains("`effect=observed_only`"));
        assert!(markdown.contains("`external_action_blocked=false`"));
        assert!(markdown.contains("未阻止外部应用中已经发生的动作"));
        assert!(!markdown.contains("| Block |"));

        let completion = report.completion_message(
            std::path::Path::new("session.json"),
            std::path::Path::new("session.md"),
        );
        assert!(completion.contains("risk_verdicts=1"));
        assert!(completion.contains("effect=observed_only"));
        assert!(completion.contains("external_action_blocked=false"));
        assert!(!completion.contains("blocks="));
    }
}

#[cfg(test)]
mod packaging_tests {
    use super::{
        bundle_resources_from_executable, BUNDLED_DEVICE_POLICY, BUNDLED_INTEL,
        BUNDLED_INTEL_PUBKEY, BUNDLED_RULES, BUNDLED_TASK_PLANS,
    };

    /// The signing script's bundle identifier must equal `tauri.conf.json`'s.
    ///
    /// macOS keys Accessibility and Screen Recording grants to the signed identifier. If the
    /// signer stamps a different one than the bundle declares, every grant the user gave is
    /// attached to an identity the app no longer has: `AXIsProcessTrusted()` returns false
    /// while System Settings still shows the toggle on, which reads as a broken probe rather
    /// than as a packaging mistake. The two strings live in different files, in different
    /// languages, and nothing else would notice them drifting apart.
    #[test]
    fn the_signer_stamps_the_identifier_the_bundle_declares() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let conf: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("tauri.conf.json")).unwrap())
                .expect("tauri.conf.json parses");
        let declared = conf["identifier"].as_str().expect("bundle identifier");
        let script = std::fs::read_to_string(root.join("../scripts/sign-and-notarize.sh"))
            .expect("the signing script must exist; printed instructions are not a build step");
        assert!(
            script.contains(&format!("AGENTGUARD_BUNDLE_ID:-{declared}")),
            "sign-and-notarize.sh does not default to the declared identifier {declared:?}"
        );
        assert!(
            script.contains("--identifier \"$BUNDLE_ID\""),
            "the signer must pass --identifier, or codesign derives one from the binary name"
        );
    }

    /// Signing must be something the build *does*.
    #[test]
    fn the_release_build_signs_rather_than_printing_instructions() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let build = std::fs::read_to_string(root.join("../scripts/build-release.sh")).unwrap();
        assert!(
            build.contains("scripts/sign-and-notarize.sh"),
            "build-release.sh must invoke the signer"
        );
        assert!(
            !build.contains("==> Next steps: codesign"),
            "the old printed-instructions block is back; a printed step is not a step"
        );
        assert!(
            build.contains("--no-default-features --features audit-sqlcipher --locked"),
            "the canonical Release command must explicitly select locked SQLCipher"
        );
        assert!(
            build.contains("scripts/bootstrap-rust.sh"),
            "the Release command must use the repository-pinned cargo/rustc wrapper"
        );
        assert!(
            !build.contains("AGENTGUARD_AUDIT_PLAIN"),
            "a plaintext Release override reopens P1-5"
        );
    }

    #[test]
    fn notarization_uses_a_keychain_profile_and_pins_the_team() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let script = std::fs::read_to_string(root.join("../scripts/sign-and-notarize.sh")).unwrap();
        assert!(script.contains("--keychain-profile \"$NOTARYTOOL_PROFILE\""));
        assert!(script.contains("AGENTGUARD_EXPECTED_TEAM_ID"));
        assert!(script.contains("TeamIdentifier"));
        assert!(!script.contains("APPLE_APP_SPECIFIC_PASSWORD"));
        assert!(!script.contains("--password"));
        assert!(!script.contains("--apple-id"));
    }

    #[test]
    fn release_entitlements_do_not_disable_hardened_runtime_controls() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let entitlements = std::fs::read_to_string(root.join("entitlements.plist")).unwrap();
        for forbidden in [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-library-validation",
        ] {
            assert!(
                !entitlements.contains(forbidden),
                "unjustified hardened-runtime escape is present: {forbidden}"
            );
        }
    }

    /// Every icon the bundle configuration names has to exist.
    ///
    /// See the note on the Windows shell's copy of this test: the claim that these files were
    /// missing from the repository was the author's error, made from an incomplete working
    /// copy. The test is still worth having — `generate_context!` fails obscurely on a missing
    /// icon — but it did not fix a defect.
    #[test]
    fn every_declared_icon_is_present() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let conf: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("tauri.conf.json")).unwrap())
                .unwrap();
        let icons = conf["bundle"]["icon"].as_array().expect("bundle.icon list");
        assert!(!icons.is_empty());
        for i in icons {
            let rel = i.as_str().expect("icon path");
            let path = root.join(rel);
            assert!(
                path.is_file(),
                "declared icon {rel} does not exist at {}",
                path.display()
            );
        }
    }

    #[test]
    fn security_resources_are_mapped_into_the_app_bundle() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let conf: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("tauri.conf.json")).unwrap())
                .unwrap();
        let resources = conf["bundle"]["resources"]
            .as_object()
            .expect("bundle.resources map");
        let expected = [
            (
                "../../../crates/guard-schema/rules/p0_rules.yaml",
                BUNDLED_RULES,
            ),
            ("../../../policies/pro-trial.yaml", BUNDLED_DEVICE_POLICY),
            ("../../../policies/task-plans.yaml", BUNDLED_TASK_PLANS),
            ("../../../intel/bundle.json", BUNDLED_INTEL),
            ("../../../intel/keys/public.hex", BUNDLED_INTEL_PUBKEY),
        ];
        for (source, destination) in expected {
            assert_eq!(
                resources.get(source).and_then(|value| value.as_str()),
                Some(destination),
                "missing bundle resource mapping {source} -> {destination}"
            );
            assert!(
                root.join(source).is_file(),
                "source resource missing: {source}"
            );
        }
    }

    #[test]
    fn executable_resolves_only_a_real_macos_bundle_shape() {
        let bundled =
            std::path::Path::new("/Applications/AgentGuard.app/Contents/MacOS/AgentGuard");
        assert_eq!(
            bundle_resources_from_executable(bundled),
            Some(std::path::PathBuf::from(
                "/Applications/AgentGuard.app/Contents/Resources"
            ))
        );
        assert_eq!(
            bundle_resources_from_executable(std::path::Path::new("/tmp/AgentGuard")),
            None
        );
    }

    /// 菜单栏必须使用独立的单色模板图；彩色 App 图标在浅色/深色菜单栏都不可靠。
    #[test]
    fn tray_template_is_packaged_and_enabled() {
        let png = include_bytes!("../icons/tray-template.png");
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");

        let source = include_str!("lib.rs");
        assert!(source.contains(".icon(tray_icon)"));
        assert!(source.contains(".icon_as_template(true)"));
    }

    /// AXObserver 不能只停在适配器方法定义里；桌面产品路径必须实际启动、驱动并停止它。
    #[test]
    fn ax_observer_is_wired_into_desktop_driver() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = include_str!("lib.rs");
        let product = source
            .split("\n#[cfg(test)]")
            .next()
            .expect("product source before tests");
        assert!(
            product.contains(".begin_ax_push(generation)")
                && product.contains("start_native_ax_observer(generation.get())"),
            "启用时没有按状态/原生两阶段启动 AXObserver"
        );
        assert!(
            product.contains(".ax_capture_due(generation, now, notifications)")
                && product.contains(".apply_ax_snapshot(generation, now, snapshot)"),
            "后台驱动没有经过去抖/延迟上限合并器"
        );
        assert!(
            product.contains(".finish_ax_push(generation)")
                && product.contains("stop_native_ax_observer(generation.get())"),
            "停用/退出没有按状态/原生两阶段卸载 AXObserver"
        );
        assert!(
            product.contains("ax_native_gate")
                && product.contains("AX_SNAPSHOT_TIMEOUT")
                && !product.contains("adapter.capture_live_ax()")
                && !product.contains("adapter.maybe_capture_ax("),
            "阻塞 AX 快照必须经过单飞墙钟超时，不能在 adapter guard 下直接调用"
        );
        assert!(
            product.contains("park_timeout(Duration::from_millis(50))"),
            "驱动 tick 太慢，兑现不了 150ms 去抖"
        );
        assert!(
            !product.lines().any(|line| {
                line.trim_start()
                    .starts_with("std::thread::sleep(Duration::from_millis(2500))")
            }),
            "旧的 2.5s AX 纯轮询仍在产品路径"
        );

        let bridge = std::fs::read_to_string(
            root.join("../../../adapters/mac-adapter/native/AgentGuardAX.m"),
        )
        .expect("读取 AX 原生桥");
        assert!(
            bridge.contains("CFRunLoopAddSource(CFRunLoopGetMain()"),
            "AXObserver source 必须挂到持续运行的主 run loop"
        );
        assert!(
            !bridge.contains("CFRunLoopAddSource(CFRunLoopGetCurrent()"),
            "后台线程的 current run loop 不会自动运行"
        );
        assert!(
            bridge.contains("gAxGeneration")
                && bridge.contains("callback_generation")
                && bridge.contains("(void *)(uintptr_t)generation")
                && bridge.contains("gAxCallbackLock"),
            "AX callback 必须携带注册代际，并把代际校验与计数放进同一临界区"
        );
        assert!(
            bridge.contains("AXUIElementCreateSystemWide()")
                && bridge.contains("AXUIElementSetMessagingTimeout(")
                && bridge.contains("CLOCK_MONOTONIC")
                && bridge.contains("kAGAXSnapshotBudgetNs")
                && bridge.contains("AX snapshot timed out"),
            "AX 桥必须同时限制单次 Mach 消息和整棵树的总遍历时间"
        );
    }

    #[test]
    fn sck_callback按代际隔离且原生等待不在ui线程() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = include_str!("lib.rs");
        let product = source.split("\n#[cfg(test)]").next().unwrap();
        assert!(
            product.contains("tauri::async_runtime::spawn_blocking"),
            "SCK 的 8s start / 3s stop 不能留在同步 Tauri command"
        );
        assert!(
            product.contains("stop_capture_session_generation(generation.get())"),
            "停止必须带代际，旧 worker 不能停掉继任 stream"
        );

        let bridge = std::fs::read_to_string(
            root.join("../../../adapters/mac-adapter/native/AgentGuardSCK.m"),
        )
        .expect("读取 SCK 原生桥");
        assert!(
            bridge.contains("self.generation") && bridge.contains("gSckGeneration"),
            "每个 SCK output 必须保留自己的 callback generation"
        );
        assert!(
            bridge.contains("AG_SCK_TIMEOUT"),
            "原生 stop 超时不能静默返回成功"
        );
    }
}

#[cfg(test)]
mod session_observer_tests {
    use super::{
        cleanup_failed_ax_poller_start_with, mac_required_observation_state, observers_for_session,
        privacy_pane_anchor, require_confirmed_ax_stop, require_confirmed_sck_stop,
        spawn_ax_worker_with, with_manual_session_control,
    };
    use guard_core::observe_state::{derive, ProtectionState, Reason, StateInputs, Thresholds};
    use mac_adapter::{
        AxNativeCallFailure, AxNativeGate, MacAdapter, MacCapabilities, ObserverLifecycle,
        StopOutcome,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    /// 确定性复现 end/start 在 native stop 后尚未完成 adapter 提交时，手动 enable 试图
    /// 穿过转换锁的竞态。手动操作只有在转换释放 session_control 后才允许开始。
    #[test]
    fn 手动观察器命令不能穿过会话转换() {
        let control = Arc::new(tauri::async_runtime::Mutex::new(()));
        let (transition_entered_tx, transition_entered_rx) = mpsc::sync_channel(0);
        let (release_transition_tx, release_transition_rx) = mpsc::sync_channel(0);
        let transition_control = control.clone();
        let transition = std::thread::spawn(move || {
            tauri::async_runtime::block_on(async move {
                let _session = transition_control.lock().await;
                transition_entered_tx.send(()).unwrap();
                release_transition_rx.recv().unwrap();
            });
        });
        transition_entered_rx.recv().unwrap();

        let (manual_started_tx, manual_started_rx) = mpsc::sync_channel(0);
        let manual_control = control.clone();
        let manual = std::thread::spawn(move || {
            tauri::async_runtime::block_on(async move {
                with_manual_session_control(&manual_control, || async move {
                    manual_started_tx.send(()).unwrap();
                })
                .await;
            });
        });

        assert!(
            manual_started_rx
                .recv_timeout(Duration::from_millis(75))
                .is_err(),
            "manual enable crossed an in-progress session transition"
        );
        release_transition_tx.send(()).unwrap();
        manual_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("manual operation did not resume after the transition completed");
        transition.join().unwrap();
        manual.join().unwrap();
    }

    #[test]
    fn 三个手动观察器入口都接入会话转换锁() {
        let product = include_str!("lib.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap();
        for name in ["sck_start_cmd", "sck_stop_cmd", "ax_auto_cmd"] {
            let marker = format!("async fn {name}(");
            let start = product
                .find(&marker)
                .unwrap_or_else(|| panic!("missing manual command {name}"));
            let tail = &product[start..];
            let end = tail[marker.len()..]
                .find("\n#[tauri::command]")
                .map(|offset| marker.len() + offset)
                .unwrap_or(tail.len());
            assert!(
                tail[..end].contains("with_manual_session_control(&state.session_control"),
                "{name} bypasses session_control"
            );
        }
    }

    fn caps(accessibility: bool, screen_capture: bool) -> MacCapabilities {
        MacCapabilities {
            simulation: true,
            accessibility,
            screen_capture,
        }
    }

    /// 授权了什么就武装什么。
    ///
    /// 这条测试存在的原因是一个真实缺陷:`start_guard_session` 以前**不武装任何观察器**,
    /// 只有开发者面板里的两个按钮会。用户授权、点「开始守护」,状态灯停在"守护不完整",
    /// 而"打开监控"的唯一入口被标成开发者诊断——一个叫「开始守护」的按钮没做它名字承诺的事。
    #[test]
    fn 授权过的观察器随会话武装_没授权的不武装() {
        assert_eq!(observers_for_session(&caps(true, true)), (true, true));
        assert_eq!(observers_for_session(&caps(true, false)), (true, false));
        assert_eq!(observers_for_session(&caps(false, true)), (false, true));
    }

    /// 未授权矩阵不会武装观察器；桌面会话入口在任何会话写入前拒绝缺少 AX。
    #[test]
    fn 未授权时不武装观察器且桌面入口提前拒绝() {
        assert_eq!(observers_for_session(&caps(false, false)), (false, false));
        let source = include_str!("lib.rs");
        let start = source
            .split("async fn start_guard_session(")
            .nth(1)
            .unwrap();
        assert!(
            start.find("DESKTOP_ACCESSIBILITY_REQUIRED").unwrap()
                < start.find("advance_session_generation").unwrap()
        );
    }

    /// macOS 的首发合同不是「任意一个观察器活着就算完整」：AX 承担窗口语义主路径，
    /// SCK 只补像素覆盖。因此 AX-only 可以 Active，但 SCK-only 必须明确要求 AX 授权；
    /// 已授权的 AX 若没跑，也不能被 SCK 的健康心跳掩盖。
    #[test]
    fn mac首发以ax为必需路径_sck只作可选增强() {
        let thresholds = Thresholds::default();
        let derived =
            |accessibility: bool, ax_running: bool, screen_capture: bool, sck_running: bool| {
                let (required_observation_permission, required_capability_unavailable) =
                    mac_required_observation_state(accessibility, ax_running);
                derive(
                    &StateInputs {
                        session_active: true,
                        paused: false,
                        pending_confirm: false,
                        observers_available: accessibility as u32 + screen_capture as u32,
                        observers_running: ax_running as u32 + sck_running as u32,
                        required_observation_permission,
                        required_capability_unavailable,
                        observer_error: None,
                        audit_enabled: true,
                        audit_error: None,
                        observer_started_ms: Some(99_000),
                        last_heartbeat_ms: Some(99_500),
                        now_ms: 100_000,
                    },
                    &thresholds,
                )
            };

        assert_eq!(
            derived(true, true, false, false).state,
            ProtectionState::Active,
            "AX-only 是获准的核心桌面路径，缺少可选 SCK 不能单独熄灭绿灯"
        );

        let sck_only = derived(false, false, true, true);
        assert_eq!(sck_only.state, ProtectionState::PermissionRequired);
        assert_eq!(
            sck_only.reasons,
            vec![Reason::RequiredObservationPermission]
        );

        let ax_stopped = derived(true, false, true, true);
        assert_eq!(ax_stopped.state, ProtectionState::Degraded);
        assert!(
            ax_stopped
                .reasons
                .contains(&Reason::RequiredCapabilityUnavailable),
            "已授权但未运行的必需 AX 不能被 SCK 的心跳掩盖"
        );

        let ax_timeout = derive(
            &StateInputs {
                session_active: true,
                observers_available: 2,
                observers_running: 1,
                required_capability_unavailable: true,
                observer_error: Some("AX native snapshot timed out"),
                audit_enabled: true,
                last_heartbeat_ms: Some(99_999),
                now_ms: 100_000,
                ..StateInputs::default()
            },
            &thresholds,
        );
        assert_eq!(ax_timeout.state, ProtectionState::Degraded);
        assert!(ax_timeout
            .reasons
            .contains(&Reason::RequiredCapabilityUnavailable));
        assert!(ax_timeout.reasons.contains(&Reason::ObserverError));
    }

    /// 确定性复现真实事故的并发形状：原生闭包已进入且不返回时，三个共享状态锁仍都能
    /// 立即取得；墙钟 timeout 取消旧代，迟到 worker 继续计入 drain 且不能提交心跳。
    #[test]
    fn 阻塞ax原生调用不冻结共享锁_超时后旧代不能提交() {
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let gate = AxNativeGate::new();
        let adapter = Arc::new(Mutex::new(MacAdapter::new()));
        adapter.lock().unwrap().begin_ax_push(generation);
        let engine_lock = Arc::new(Mutex::new(()));
        let pending_lock = Arc::new(Mutex::new(()));
        let heartbeat = Arc::new(AtomicU64::new(41));
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let caller_gate = gate.clone();
        let caller_lifecycle = lifecycle.clone();
        let caller = std::thread::spawn(move || {
            let result = caller_gate.call(
                Some(generation),
                Some(&caller_lifecycle),
                "injected-blocking-snapshot",
                Duration::from_millis(25),
                move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                },
            );
            if matches!(result, Err(AxNativeCallFailure::TimedOut { .. })) {
                caller_lifecycle.cancel(generation);
            }
            result
        });

        entered_rx.recv().unwrap();
        assert!(adapter.try_lock().is_ok(), "AX IPC 不得持有 adapter");
        assert!(engine_lock.try_lock().is_ok(), "AX IPC 不得持有 engine");
        assert!(pending_lock.try_lock().is_ok(), "AX IPC 不得持有 pending");
        assert!(matches!(
            caller.join().unwrap(),
            Err(AxNativeCallFailure::TimedOut { .. })
        ));
        assert_eq!(heartbeat.load(Ordering::SeqCst), 41);
        assert!(lifecycle
            .commit(generation, || heartbeat.store(99, Ordering::SeqCst))
            .is_none());
        assert_eq!(heartbeat.load(Ordering::SeqCst), 41);
        assert_eq!(
            lifecycle.wait(generation, Duration::ZERO),
            StopOutcome::TimedOut { remaining: 1 }
        );
        assert_eq!(lifecycle.begin_if_drained(), Err(1));

        release_tx.send(()).unwrap();
        assert_eq!(
            lifecycle.wait(generation, Duration::from_secs(1)),
            StopOutcome::Drained
        );
        assert!(lifecycle.begin_if_drained().is_ok());
    }

    /// 上面的纯函数测试不能证明 `get_status` 真把分类结果喂进共享状态机；这条壳接线测试
    /// 防止以后又把两项 required_* 写回常量 false。
    #[test]
    fn get_status接入mac首发ax必需合同() {
        let source = include_str!("lib.rs");
        let start = source.find("fn get_status(").expect("get_status missing");
        let end = source[start..]
            .find("\n#[tauri::command]")
            .map(|i| start + i)
            .unwrap_or(source.len());
        let body = &source[start..end];
        assert!(
            body.contains("mac_required_observation_state(caps.accessibility, ax_auto_poll)"),
            "get_status 没有按 AX 授权与实际运行状态分类 macOS 必需能力"
        );
        assert!(
            body.contains("required_observation_permission,")
                && body.contains("required_capability_unavailable,"),
            "macOS 必需能力分类没有喂进共享状态机"
        );
        assert!(
            !body.contains("required_observation_permission: false")
                && !body.contains("required_capability_unavailable: false"),
            "get_status 又把 macOS 必需能力硬编码成永不缺失"
        );
    }

    #[test]
    fn sck_stop超时不能在下次操作里被冒充为已排空() {
        assert!(require_confirmed_sck_stop(None).is_ok());
        let error = require_confirmed_sck_stop(Some("stop timeout")).unwrap_err();
        assert!(error.contains("still unconfirmed"));
        assert!(error.contains("restart required"));
    }

    #[test]
    fn ax_stop超时不能在下次操作里被冒充为已排空() {
        assert!(require_confirmed_ax_stop(None).is_ok());
        let error = require_confirmed_ax_stop(Some("stop timeout")).unwrap_err();
        assert!(error.contains("still unconfirmed"));
        assert!(error.contains("restart required"));
    }

    #[test]
    fn ax_worker_spawn失败会停止push并清空生命周期状态() {
        let lifecycle = ObserverLifecycle::new();
        let generation = lifecycle.begin();
        let worker = lifecycle.worker(generation).unwrap();
        let task_ran = Arc::new(AtomicBool::new(false));
        let task_ran_in_worker = task_ran.clone();

        let spawn = spawn_ax_worker_with(
            worker,
            |task| {
                drop(task);
                Err(std::io::Error::other("injected spawn failure"))
            },
            move || task_ran_in_worker.store(true, Ordering::SeqCst),
        );
        assert!(spawn.is_err());
        assert!(!task_ran.load(Ordering::SeqCst));

        let push_stopped = AtomicBool::new(false);
        let outcome = cleanup_failed_ax_poller_start_with(&lifecycle, generation, || {
            push_stopped.store(true, Ordering::SeqCst);
        });
        assert!(push_stopped.load(Ordering::SeqCst));
        assert_eq!(outcome, StopOutcome::Drained);
        assert!(lifecycle.active().is_none());
        assert!(lifecycle.cancel_active_or_draining().is_none());
        assert!(lifecycle.begin_if_drained().is_ok());
    }

    /// 决策对了不等于被调用了:上面那条测试只钉"授权矩阵 → 该开什么",删掉
    /// `start_guard_session` 里的武装那一段它照样绿。这条按仓库既有的接线测试写法
    /// (见 `ax_observer_is_wired_into_desktop_driver`)对源码断言:会话开始真的调用了
    /// 两个武装函数,且**在放掉 adapter 锁之后**(它们内部要再锁 adapter —— 不放会死锁)。
    #[test]
    fn 会话开始真的武装观察器_且在放掉adapter锁之后() {
        let source = include_str!("lib.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap();
        let start = source
            .find("async fn start_guard_session(")
            .expect("找不到 start_guard_session —— 接线测试需要跟着改");
        let end = source[start..]
            .find("\n#[tauri::command]")
            .map(|i| start + i)
            .unwrap_or(source.len());
        let body = &source[start..end];
        assert!(
            body.contains("state.session_control.lock().await"),
            "并发 start/end 必须由异步会话锁串行化，不能跨 await 持有 std::sync::Mutex"
        );
        assert!(
            body.contains("observers_for_session(&caps)"),
            "会话开始没有按授权矩阵决定要开哪些观察器"
        );
        assert!(
            body.contains("arm_ax_observer("),
            "会话开始没有武装 AX 树观察 —— 「开始守护」又变回只登记会话不看任何东西"
        );
        assert!(
            body.contains("arm_sck_capture("),
            "会话开始没有武装屏幕抓取"
        );
        let sync_scope_end = body
            .find("process_events(state.inner(), session_events)?;")
            .expect("会话事件没有在释放 adapter 后交给引擎处理");
        let arm_at = body.find("arm_ax_observer(").unwrap();
        let old_ax_stop = body.find("stop_ax_observer(app.clone()).await").unwrap();
        let new_session = body.find("adapter.start_task_session(").unwrap();
        assert!(
            old_ax_stop < new_session
                && sync_scope_end < arm_at
                && body.contains("let session_events = {")
                && body.contains("adapter.poll_events()")
                && body.contains("arm_ax_observer(app.clone(), Some(session_generation)).await")
                && body.contains("arm_sck_capture(app, Some(session_generation)).await"),
            "必须先排空旧观察器，再创建新 session；随后结束 adapter 锁作用域再异步武装"
        );
        // 会话**结束**停观察器这一半一直是对的(P0-3),别在改开始的时候把它弄坏:
        // 开始与结束必须对称,否则又会出现"结束了还在采集"或"开始了没在看"。
        let end_start = source
            .find("fn end_guard_session(")
            .expect("找不到 end_guard_session");
        let end_body = &source[end_start..];
        assert!(
            end_body.contains("advance_session_generation(state.inner())")
                && end_body.contains("stop_ax_observer(app.clone()).await")
                && end_body.contains("stop_sck_capture(app).await"),
            "会话结束必须先失效异步 start，再异步取消并排空两个观察器"
        );
    }

    /// 两个隐私面板的 anchor 表:界面上的「打开系统设置」按钮靠它把用户直接送到该点的那一页,
    /// 而不是只印一行四层路径让人自己找。未知面板名必须是 None(而不是随便打开一个页面)。
    #[test]
    fn 隐私面板锚点只认那两个已知面板() {
        assert_eq!(
            privacy_pane_anchor("accessibility"),
            Some("Privacy_Accessibility")
        );
        assert_eq!(privacy_pane_anchor("screen"), Some("Privacy_ScreenCapture"));
        assert_eq!(privacy_pane_anchor("Privacy_AllFiles"), None);
        assert_eq!(privacy_pane_anchor(""), None);
    }
}

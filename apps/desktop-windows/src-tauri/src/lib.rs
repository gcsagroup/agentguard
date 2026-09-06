//! AgentGuard Tauri backend: engine + audit + confirm modal + win-adapter simulation.

// 发布壳会自动生成审计加密密钥，因此“Release 但明文”不是一个合法兼容模式。
// 只在 debug 允许 audit-sqlite；Release 少了显式 feature 时必须在产物生成前失败。
#[cfg(all(
    any(agentguard_release_profile, not(debug_assertions)),
    not(feature = "audit-sqlcipher")
))]
compile_error!(
    "desktop-windows Release requires SQLCipher; rebuild with \
     --no-default-features --features audit-sqlcipher"
);

#[cfg(all(feature = "audit-sqlite", feature = "audit-sqlcipher"))]
compile_error!(
    "audit-sqlite and audit-sqlcipher are mutually exclusive; use \
     --no-default-features --features audit-sqlcipher for Release"
);

use std::path::PathBuf;

// Cargo 的 Release 身份独立于 debug_assertions，诊断开关不能打开开发资源或明文审计。
const DEVELOPMENT_BUILD: bool = cfg!(all(debug_assertions, not(agentguard_release_profile)));

#[path = "../../../desktop-build-info.rs"]
mod build_info;

#[cfg(all(test, agentguard_release_profile))]
#[test]
fn release开启调试断言仍保持安全发布语义() {
    let status = security_status().unwrap();
    assert!(status.release_build && status.sqlcipher && status.intel_fail_closed);
    assert!(!status.auto_approve_allowed);
    assert_eq!(
        load_intel().unwrap().version,
        runtime_resources::intel().unwrap().version
    );
    assert!(load_task_plans().unwrap().is_some());
}
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use guard_audit::{
    auto_approve_allowed, default_audit_key_path, ensure_audit_key_file, sqlcipher_enabled,
    AuditRecord, AuditStore, SessionReport, UserDecision,
};
use guard_billing::load_or_free;
use guard_core::acceptance_trace::{TraceLine, TraceWriter};
use guard_core::confirm_queue::{
    ConfirmQueue, PendingItem, PersistedPending, ResolveOutcome, DEFAULT_CONFIRM_TTL_MS,
};
use guard_core::device_policy::EnforcedPolicy;
use guard_core::observe_state::{self, StateInputs, Thresholds};
use guard_core::{AutoApprove, ConfirmRequest, Engine};
use guard_intel::PublicKeyBytes;
use guard_netmon::{evaluate_flow, FlowSummary};
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent};
use guard_sync::{
    pull_policy_verified, signer_fingerprint, sync_to_cache, sync_to_cache_verified, DevicePolicy,
};
use serde::Serialize;
use tauri::{Emitter, Manager, State};
use win_adapter::{capabilities, AdapterCapabilities, PlatformAdapter, SimObservation, WinAdapter};

mod runtime_resources;

/// The live Windows observer, on Windows only.
///
/// Before this existed the shell's only ingress was seven demo threat buttons plus
/// start/end session: every rule that reads a UI tree or a frame was inert, and
/// `protection_mode` reported "full" from two compile flags. The observer is optional
/// because the shell must still build and run on a host where UI Automation cannot be
/// created — it then reports why, rather than reporting simulation as protection.
#[cfg(windows)]
type NativeObserver = win_adapter::NativeWinAdapter;

struct AppState {
    engine: Mutex<Engine>,
    audit_ready: AtomicBool,
    audit_operation_running: AtomicBool,
    audit_recovery_running: AtomicBool,
    audit_initialization_error: Mutex<String>,
    adapter: Mutex<WinAdapter>,
    auto_approve: Mutex<bool>,
    // P0-5:带不可变 request_id 的有界确认队列(与 macOS 壳子共用 guard_core::ConfirmQueue)。
    // 后台观察事件只能入队,不覆盖用户正在看的那条;确认按 request_id compare-and-swap。
    pending: Mutex<ConfirmQueue>,
    /// Startup snapshot from the dedicated native-probe thread.
    ///
    /// Re-probing from a Tauri command would re-enter the WinRT OCR factory cache from the
    /// UI/IPC thread. The exact Windows host crashed there with `0xC0000005`; later native
    /// observation still reports warnings through poll events and terminal errors in state.
    capabilities: AdapterCapabilities,
    /// The real observer. `None` on a non-Windows build, or when UI Automation could not
    /// be created — and [`AppState::observe_error`] then says which.
    #[cfg(windows)]
    observer: Mutex<Option<NativeObserver>>,
    observe_error: Mutex<Option<String>>,
    /// Set while the auto-poller thread should keep running.
    polling: Arc<AtomicBool>,
    /// P1-5:每次 start 递增;旧线程在下一拍看到自己的代际过期就退出——快速 stop/start
    /// 不再留下两个同时跑的轮询线程。
    poll_generation: Arc<AtomicU64>,
    /// P0-3:最近一次**成功**观察的时刻(ms since epoch,0 = 没有)。
    heartbeat_ms: AtomicU64,
    /// P0-3:观察循环最近一次启动的时刻(0 = 没启动过),给状态机判「启动宽限」。
    observer_started_ms: AtomicU64,
    /// P2-3:观察事件聚合器。只在原生观察路径上用;会话边界 reset。
    aggregator: Mutex<guard_core::event_dedup::Aggregator>,
    /// P1-4:本次运行里超时按拒绝处理的确认数;启动时发现上次遗留并按超时处理的确认数。
    confirms_timed_out: AtomicUsize,
    orphaned_confirms: AtomicUsize,
    /// P1-9:设备策略的对外状态(验证/执法/最近一次失败),与引擎里装的那份一致。
    policy_status: Mutex<PolicyStatusDto>,
    /// 阶段 D:验收 trace(AGENTGUARD_ACCEPTANCE_TRACE 设定时写,否则空转)。
    trace: TraceWriter,
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

#[derive(Serialize)]
struct StatusDto {
    rules_loaded: usize,
    policy_id: String,
    audit_enabled: bool,
    audit_ready: bool,
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
    uia_native: bool,
    graphics_capture: bool,
    /// Why a capability is unavailable. Empty strings when it is available; never empty
    /// when it is not, so the UI cannot render an unexplained red cross.
    uia_detail: String,
    frame_capture: bool,
    frame_capture_detail: String,
    /// Whether text can be read off a frame. Its own field because without it the AX↔screen
    /// cross-validation does not run and the subliminal sanitization loop cannot close — two
    /// published surfaces lost, which the user should see rather than infer.
    ocr: bool,
    ocr_detail: String,
    /// True while the auto-poller is running: the difference between "able to observe"
    /// and "currently observing", which the old status could not express.
    observing: bool,
    observe_error: String,
    privacy_composite: f32,
    pending_confirm: bool,
    intel_version: String,
    plan: String,
    pro_active: bool,
    device_policy_id: String,
    /// sim | partial | full — honest coverage level from native capabilities.
    protection_mode: String,
    protection_summary: String,
    /// P0-3:状态机输出(`guard_core::observe_state`)。前端只信这个字段来画状态灯。
    protection_state: String,
    /// 状态成因码(前端查 `reason.*` 词表)。Active 时为空。
    state_reasons: Vec<String>,
    observers_available: u32,
    observers_running: u32,
    heartbeat_age_ms: Option<u64>,
    /// 引擎最近一次审计写入失败的错误;空串 = 可写。
    audit_error: String,
    /// P2-3:本会话被聚合器折叠掉的重复观察条数。
    suppressed_events: u64,
    /// P1-4:本次运行超时默认拒绝的确认数;上次运行遗留、启动时按超时处理的确认数;当前等待数。
    confirms_timed_out: usize,
    orphaned_confirms: usize,
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
    /// Windows 桌面壳处理的是 UIA/GDI 已经看到的状态。内部 `DecisionAction::Block`
    /// 是风险判决，不是对外部应用动作的执行前拦截证明。
    effect: &'static str,
    external_action_blocked: bool,
}

#[derive(Serialize)]
struct ConfirmDto {
    /// P0-5:不可变请求 id,UI 回传给 resolve 做 compare-and-swap。
    request_id: u64,
    rule_id: String,
    severity: String,
    human_message: String,
    source_app: String,
    ui_excerpt: Option<String>,
    /// “暂不继续”只暂停 AgentGuard 本会话和后续观察，不能撤销已经观察到的动作。
    effect: &'static str,
    external_action_blocked: bool,
}

const OBSERVED_ONLY_EFFECT: &str = "observed_only";
const EXTERNAL_ACTION_BLOCKED: bool = false;

/// Windows 审计列表的展示契约。
///
/// `AuditRecord::action` 必须保留，因为规则、确认队列和签名链都依赖这个内部判决；
/// 展示层额外声明实际效果，避免把 `Block` 误读成外部动作已被阻止。
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

/// Windows 桌面报告只总结旁路观测效果。
///
/// 公共 `SessionReport` 继续使用 `block_count` 表达内部 `DecisionAction::Block`，因为
/// 执行前网关等消费者仍需要该语义。Windows 壳不能把它原样写给用户，因此这里使用
/// `risk_verdict_count`，并把实际效果作为机器可读字段写进 JSON 和 Markdown。
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
        let mut md = String::new();
        md.push_str("# AgentGuard Windows 会话摘要\n\n");
        md.push_str(&format!("生成时间 (ms): {}\n\n", self.generated_at_ms));
        md.push_str("## 效果边界\n\n");
        md.push_str(&format!(
            "- `effect={}`\n- `external_action_blocked={}`\n\n",
            self.effect, self.external_action_blocked
        ));
        md.push_str("Windows 桌面端在 UIA/GDI 呈现后进行旁路观察；风险确认只能暂停本会话和后续观察，不能撤销外部应用中已经发生的动作。\n\n");
        md.push_str("## 概览\n\n");
        md.push_str(&format!(
            "| 指标 | 值 |\n| --- | --- |\n| 记录数 | {} |\n| 风险判决（内部动作枚举） | {} |\n| Alert | {} |\n| Allow | {} |\n| LogOnly | {} |\n\n",
            self.record_count,
            self.risk_verdict_count,
            self.alert_count,
            self.allow_count,
            self.log_only_count
        ));
        md.push_str(&format!(
            "确认：approve={} deny={} timeout={} pending≈{}（来源：{}）\n\n",
            self.confirm_decisions.approve,
            self.confirm_decisions.deny,
            self.confirm_decisions.timeout,
            self.confirm_decisions.pending,
            self.confirm_source.label()
        ));
        md.push_str(&format!("> {}\n\n", self.summary_note));
        md.push_str("## 规则命中\n\n");
        for rule in &self.by_rule {
            md.push_str(&format!("- `{}`: {}\n", rule.rule_id, rule.count));
        }
        md.push_str("\n## 来源应用\n\n");
        for app in &self.by_source_app {
            md.push_str(&format!("- {}: {}\n", app.source_app, app.count));
        }
        if !self.top_messages.is_empty() {
            md.push_str("\n## 高危摘要\n\n");
            for message in &self.top_messages {
                md.push_str(&format!("- {message}\n"));
            }
        }
        md
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

/// Honest coverage level, from the **probed** capabilities.
///
/// The previous version took two booleans that were `cfg!(windows)`, so a Windows build
/// reported "full" on a machine where no UIA client could be created and no window could
/// be captured. It also called the top level "full" while the capture path was GDI, which
/// does not see another process's window composited on top — the (A)I Sees A3 overlay.
/// There is therefore no "full" any more: the best this platform offers is `partial`, and
/// the summary says what is missing.
fn protection_coverage(caps: &AdapterCapabilities, observing: bool) -> (String, String) {
    let tree = caps.uia_native.available;
    let frame = caps.frame_capture.available;
    let ocr = caps.ocr.available;
    let mode = match (tree, frame, observing) {
        (true, true, true) => "partial",
        (_, _, false) if tree || frame => "idle",
        (false, false, _) => "sim",
        _ => "degraded",
    };
    let summary = match mode {
        "partial" => format!(
            "防护范围：部分。UI 树与窗口像素都在观察中{}。但捕获走 GDI，看不到别的进程叠在上面的窗口（A3 钓鱼浮层）。",
            if ocr {
                "，屏幕文字识别可用，所以 AX↔屏幕交叉验证会运行"
            } else {
                "；但本机没有可用的 OCR 语言包，所以 AX↔屏幕交叉验证不运行——那是「没有结论」，不是「干净」"
            }
        ),
        "idle" => format!(
            "有观察能力但当前未在观察：开始会话后才会轮询。UI 树 {}，窗口捕获 {}。",
            if tree { "可用" } else { "不可用" },
            if frame { "可用" } else { "不可用" }
        ),
        "degraded" => format!(
            "防护范围：不完整。UI 树 {}；窗口捕获 {}。缺的那一半对应的规则不会产生任何结论——请不要读成没有风险。",
            cap_zh(&caps.uia_native.available, &caps.uia_native.detail),
            cap_zh(&caps.frame_capture.available, &caps.frame_capture.detail)
        ),
        _ => format!(
            "防护范围：仿真。原生观察不可用（{}），只能回放场景语料。请勿当作已在真实守护。",
            caps.uia_native.detail
        ),
    };
    (mode.into(), summary)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RequiredCapabilityGap {
    permission: bool,
    capability: bool,
}

/// Classify a failed probe as an access denial only when the native error says so.
/// Windows UIA/GDI do not normally have macOS-style permission grants, so a missing
/// component, language pack, foreground window, or an acceptance-forced failure is a
/// capability gap and must be shown as `degraded`, not as a made-up permission prompt.
fn probe_detail_is_access_denied(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    [
        "access is denied",
        "access denied",
        "permission denied",
        "permission required",
        "e_accessdenied",
        "0x80070005",
        "not authorized",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
}

/// The Windows first-release contract requires all three observation surfaces.
/// `graphics_capture` is deliberately excluded: this build truthfully uses GDI and
/// documents its cross-process-overlay limitation instead of claiming composed capture.
fn required_windows_capability_gap(caps: &AdapterCapabilities) -> RequiredCapabilityGap {
    let mut gap = RequiredCapabilityGap::default();
    for capability in [&caps.uia_native, &caps.frame_capture, &caps.ocr] {
        if capability.available {
            continue;
        }
        if probe_detail_is_access_denied(&capability.detail) {
            gap.permission = true;
        } else {
            gap.capability = true;
        }
    }
    gap
}

fn cap_zh(available: &bool, detail: &str) -> String {
    if *available {
        "可用".into()
    } else {
        format!("不可用（{detail}）")
    }
}

/// Form schemas for field classification, so `profile_key`, `required` and the trap flag
/// mean the same thing on Windows as on macOS.
///
/// An empty list is a real answer, not a failure: `classify_field` then falls back to its
/// heuristics. It is worth noticing though, because a missing schema directory turns a
/// trap field into an ordinary one.
#[cfg(windows)]
fn load_form_schemas() -> anyhow::Result<Vec<guard_privacy::AppFormSchema>> {
    if !DEVELOPMENT_BUILD {
        return runtime_resources::forms();
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        manifest.join("../../../policies/forms"),
        PathBuf::from("policies/forms"),
    ] {
        if candidate.is_dir() {
            return Ok(guard_privacy::load_form_schemas(candidate));
        }
    }
    Ok(Vec::new())
}

fn rules_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_RULES") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../../crates/guard-schema/rules/p0_rules.yaml"),
        PathBuf::from("crates/guard-schema/rules/p0_rules.yaml"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates[0].clone()
}

fn audit_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_AUDIT_DB") {
        return PathBuf::from(p);
    }
    let mut dir = dirs_next_data();
    dir.push(build_info::data_directory());
    let _ = std::fs::create_dir_all(&dir);
    dir.push("audit.db");
    dir
}

fn dirs_next_data() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Application Support");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(ad) = std::env::var_os("APPDATA") {
            return PathBuf::from(ad);
        }
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

fn device_policy_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_DEVICE_POLICY") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../../policies/device-cache.yaml"),
        manifest.join("../../../policies/pro-trial.yaml"),
        PathBuf::from("policies/pro-trial.yaml"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates[1].clone()
}

fn load_intel() -> anyhow::Result<guard_intel::ThreatBundle> {
    if !DEVELOPMENT_BUILD {
        return runtime_resources::intel();
    }
    let bundle = if let Ok(p) = std::env::var("AGENTGUARD_INTEL") {
        PathBuf::from(p)
    } else {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidates = [
            manifest.join("../../../intel/bundle.json"),
            PathBuf::from("intel/bundle.json"),
        ];
        candidates
            .into_iter()
            .find(|c| c.exists())
            .unwrap_or_else(|| PathBuf::from("intel/bundle.json"))
    };
    guard_intel::load_or_default(&bundle).context("加载开发环境情报")
}

/// Current-user DPAPI envelope for the device audit signing seed, next to the
/// audit DB (Aura §4.4.6 attribution). This protects the exportable software key
/// at rest; it is not a TPM-backed identity claim.
fn desktop_audit_key_path() -> PathBuf {
    if build_info::PROFILE.is_empty() {
        default_audit_key_path()
    } else {
        audit_db_path().with_file_name("audit.key")
    }
}

fn audit_signing_key_path() -> std::path::PathBuf {
    let mut p = desktop_audit_key_path();
    p.set_file_name("audit-signing.key");
    p
}

fn open_audit_store() -> anyhow::Result<AuditStore> {
    let path = audit_db_path();
    // Load/provision the signer before touching the DB. Release must never create
    // an encrypted database and then continue (or reopen it) unsigned when signer
    // attachment fails.
    #[cfg(target_os = "windows")]
    let signer = guard_audit::WindowsDpapiDeviceKey::load_or_create(audit_signing_key_path())
        .context("load or provision current-user DPAPI Windows audit signing key")?;
    // The Windows shell's source-level tests also compile on macOS/Linux. This
    // branch is test/development portability only and cannot enter a Windows build.
    #[cfg(not(target_os = "windows"))]
    let signer = guard_audit::FileDeviceKey::load_or_create(audit_signing_key_path())
        .context("load or provision non-Windows test audit signing key")?;
    if sqlcipher_enabled() {
        let key = ensure_audit_key_file(desktop_audit_key_path())
            .context("load or provision DPAPI-protected Windows audit encryption key")?;
        let path = guard_audit::resolve_recovered_audit(&path, &signer)?;
        AuditStore::open_protected(&path, &key, Box::new(signer))
            .context("open encrypted and signed Windows audit database")
    } else {
        // The compile_error above makes this branch debug-only. Keep local
        // development convenient, but do not weaken signer failure semantics.
        AuditStore::open(&path)
            .context("open debug plaintext audit database")?
            .with_signer(Box::new(signer))
            .context("attach debug audit signer")
    }
}

fn build_engine_without_audit() -> anyhow::Result<Engine> {
    // The task-plan library, so a session that names a `task_profile` gets its trajectory plan and
    // its Aura §4.4 resource ceiling. Neither shell loaded it, which meant the whole plan mechanism
    // was unreachable from the desktop apps however the session was opened.
    let rules = if DEVELOPMENT_BUILD {
        guard_schema::RuleSet::from_path(rules_path()).context("加载开发环境规则")?
    } else {
        runtime_resources::rules()?
    };
    // 所有必须资源先验证，再创建受保护审计库；损坏候选不得留下半初始化数据库。
    let intel = load_intel()?;
    let plans = load_task_plans()?;
    if !DEVELOPMENT_BUILD {
        runtime_resources::device_policy()?;
        #[cfg(windows)]
        runtime_resources::forms()?;
    }
    let mut engine = Engine::new(rules, guard_schema::GuardContract::default()).with_intel(intel);
    if let Some(plans) = plans {
        engine = engine.with_task_plans(plans);
    }
    Ok(engine)
}

fn build_engine() -> anyhow::Result<Engine> {
    Ok(build_engine_without_audit()?.with_audit(open_audit_store()?))
}

fn require_audit_ready(state: &AppState) -> Result<(), String> {
    if state.audit_ready.load(Ordering::Acquire)
        && !state.audit_operation_running.load(Ordering::Acquire)
    {
        Ok(())
    } else {
        Err("活动记录尚未就绪，请先完成记录设置；守护未启动".into())
    }
}

struct AuditOperationGuard<'a>(&'a AtomicBool);
impl Drop for AuditOperationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[tauri::command]
async fn retry_audit_initialization(app: tauri::AppHandle) -> Result<(), String> {
    {
        let state = app.state::<AppState>();
        if state.audit_ready.load(Ordering::Acquire) {
            return Err("加密记录已经就绪".into());
        }
        state
            .audit_operation_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "已有记录设置操作正在执行")?;
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _running = AuditOperationGuard(&state.audit_operation_running);
        let result = (|| -> anyhow::Result<()> {
            let mut engine = build_engine()?;
            let orphaned = restore_orphaned_confirms(&engine);
            let policy = restore_device_policy_at_startup(&mut engine);
            *state
                .engine
                .lock()
                .map_err(|_| anyhow::anyhow!("记录引擎锁不可用"))? = engine;
            *state
                .policy_status
                .lock()
                .map_err(|_| anyhow::anyhow!("策略状态锁不可用"))? = policy;
            state.orphaned_confirms.store(orphaned, Ordering::Relaxed);
            Ok(())
        })();
        *state
            .audit_initialization_error
            .lock()
            .map_err(|e| e.to_string())? = result
            .as_ref()
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        state.audit_ready.store(result.is_ok(), Ordering::Release);
        result.map_err(|error| format!("{error:#}"))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn recover_legacy_audit(
    app: tauri::AppHandle,
    approved: bool,
) -> Result<guard_audit::RecoveryReceipt, String> {
    if !approved {
        return Err("尚未确认保留历史并升级；未修改数据".into());
    }
    {
        let state = app.state::<AppState>();
        if state.audit_ready.load(Ordering::Acquire) {
            return Err("记录已就绪，不能重复迁移".into());
        }
        state
            .audit_operation_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "已有数据操作正在执行")?;
        state.audit_recovery_running.store(true, Ordering::Release);
    }
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<AppState>();
        let _running = AuditOperationGuard(&state.audit_operation_running);
        let _recovering = AuditOperationGuard(&state.audit_recovery_running);
        let result = (|| -> anyhow::Result<guard_audit::RecoveryReceipt> {
            #[cfg(windows)]
            let signer =
                guard_audit::WindowsDpapiDeviceKey::load_or_create(audit_signing_key_path())?;
            #[cfg(not(windows))]
            let signer = guard_audit::FileDeviceKey::load_or_create(audit_signing_key_path())?;
            let key = ensure_audit_key_file(desktop_audit_key_path())?;
            guard_audit::migrate_legacy_audit(&audit_db_path(), &key, &signer)
        })();
        if let Err(error) = &result {
            *state
                .audit_initialization_error
                .lock()
                .map_err(|e| e.to_string())? = format!("历史升级未完成：{error:#}");
        }
        result.map_err(|error| format!("{error:#}"))
    })
    .await
    .map_err(|error| error.to_string())?;
    if result.is_ok() {
        retry_audit_initialization(app).await?;
    }
    result
}

/// The operator's task-plan library, if it is where we expect it.
///
/// Absent is not an error: a deployment without plans runs exactly as it did, which is the same
/// `require_plan: false` reasoning the library itself documents.
fn load_task_plans() -> anyhow::Result<Option<guard_schema::TaskPlanLibrary>> {
    if !DEVELOPMENT_BUILD {
        return runtime_resources::plans().map(Some);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        std::env::var("AGENTGUARD_TASK_PLANS")
            .map(PathBuf::from)
            .unwrap_or_default(),
        manifest.join("../../../policies/task-plans.yaml"),
        PathBuf::from("policies/task-plans.yaml"),
    ];
    for c in &candidates {
        if c.as_os_str().is_empty() || !c.exists() {
            continue;
        }
        match std::fs::read_to_string(c)
            .ok()
            .and_then(|y| guard_schema::TaskPlanLibrary::from_yaml_str(&y).ok())
        {
            Some(lib) => return Ok(Some(lib)),
            None => continue,
        }
    }
    Ok(None)
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> Result<StatusDto, String> {
    // P1-4:每次有人看状态都先把超时的确认按拒绝处理掉。
    sweep_expired_confirms(&state)?;
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
    let st = engine.status();
    let caps = &state.capabilities;
    let score = engine.privacy_score();
    let ent = load_or_free(entitlement_path());
    let device_policy = if DEVELOPMENT_BUILD {
        DevicePolicy::from_path(device_policy_path()).unwrap_or_default()
    } else {
        runtime_resources::device_policy().map_err(|error| error.to_string())?
    };
    let audit_ready = state.audit_ready.load(Ordering::Acquire) && st.audit_enabled;
    let audit_error = st.audit_error.clone().unwrap_or_else(|| {
        state
            .audit_initialization_error
            .lock()
            .map(|error| error.clone())
            .unwrap_or_else(|_| "记录状态锁不可用".into())
    });
    let observing = state.polling.load(Ordering::Relaxed);
    let (protection_mode, protection_summary) = protection_coverage(caps, observing);
    let observe_error = state
        .observe_error
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
    let observers_available =
        caps.uia_native.available as u32 + caps.frame_capture.available as u32;
    let required_gap = required_windows_capability_gap(caps);
    // 一个轮询循环同时驱动 UI 树和窗口捕获,所以"在跑"是 0 或 1。
    let observers_running = observing as u32;
    let derived = observe_state::derive(
        &StateInputs {
            session_active: adapter.has_session(),
            paused: st.paused,
            pending_confirm: !pending.is_empty(),
            observers_available,
            observers_running,
            required_observation_permission: required_gap.permission,
            required_capability_unavailable: required_gap.capability,
            observer_error: observe_error.as_deref(),
            audit_enabled: audit_ready,
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
        audit_enabled: audit_ready,
        audit_ready,
        audit_bootstrap_state: if audit_ready {
            "ready"
        } else if state.audit_operation_running.load(Ordering::Acquire) {
            "pending"
        } else {
            "failed"
        },
        audit_operation_running: state.audit_operation_running.load(Ordering::Acquire),
        audit_recovery_running: state.audit_recovery_running.load(Ordering::Acquire),
        audit_data_path: audit_db_path().display().to_string(),
        build_version: env!("CARGO_PKG_VERSION"),
        build_revision: build_info::REVISION,
        build_time: build_info::TIME,
        build_profile: build_info::PROFILE,
        audit_legacy_available: !audit_ready
            && guard_audit::has_legacy_plaintext_audit(&audit_db_path()).unwrap_or(false),
        paused: st.paused,
        session_active: adapter.has_session(),
        uia_native: caps.uia_native.available,
        graphics_capture: caps.graphics_capture.available,
        uia_detail: caps.uia_native.detail.clone(),
        frame_capture: caps.frame_capture.available,
        frame_capture_detail: caps.frame_capture.detail.clone(),
        ocr: caps.ocr.available,
        ocr_detail: caps.ocr.detail.clone(),
        observing,
        observe_error: observe_error.unwrap_or_default(),
        privacy_composite: score.composite,
        pending_confirm: !pending.is_empty(),
        intel_version: st.intel_version,
        plan: format!("{:?}", ent.plan),
        pro_active: ent.is_active(),
        device_policy_id: device_policy.policy_id,
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
        suppressed_events,
        confirms_timed_out: state.confirms_timed_out.load(Ordering::Relaxed),
        orphaned_confirms: state.orphaned_confirms.load(Ordering::Relaxed),
        pending_count: pending.len(),
        policy: state
            .policy_status
            .lock()
            .map_err(|e| e.to_string())?
            .clone(),
    })
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

/// 从当前审计库恢复上次遗留的待确认。损坏 JSON 保留供诊断，且不会铸造回执。
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

/// P1-4:整批 Timeout 回执和剩余快照先原子提交；失败时请求仍在队列且可重试。
fn sweep_expired_confirms(state: &AppState) -> Result<Vec<u64>, String> {
    // 队列修改与快照写入都由同一 engine 锁排序，旧快照不能在等待锁后覆盖新快照。
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

/// P1-4:高危确认到了,把窗口拉到前面(Windows 壳子没有托盘,窗口是唯一的提醒面)。
fn bring_to_front(app: &tauri::AppHandle, pending: usize) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        let _ = w.set_title(&if pending > 0 {
            format!("AgentGuard — {pending} confirmation(s) waiting")
        } else {
            "AgentGuard".to_string()
        });
    }
}

#[tauri::command]
fn get_pending_confirm(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<ConfirmDto>, String> {
    sweep_expired_confirms(&state)?;
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
    if let Some(w) = app.get_webview_window("main") {
        let n = pending.len();
        let _ = w.set_title(&if n > 0 {
            format!("AgentGuard — {n} confirmation(s) waiting")
        } else {
            "AgentGuard".to_string()
        });
    }
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

/// resolve_confirm 的结果(与 macOS 壳子同形)。`resolved:false` = 这条已过期,前端应重看。
#[derive(Serialize)]
struct ResolveDto {
    resolved: bool,
    has_next: bool,
}

#[tauri::command]
fn resolve_confirm(
    state: State<'_, AppState>,
    request_id: u64,
    approve: bool,
) -> Result<ResolveDto, String> {
    // P0-5:按 request_id compare-and-swap,只解析用户看到的那条。
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let (outcome, has_next) = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        resolve_pending_with_engine(&mut engine, &mut q, request_id, approve)?
    };
    let ResolveOutcome::Resolved { approve, audit_id } = outcome else {
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

    // 两阶段 helper 已保证回执、新快照、内存移除和引擎状态按顺序完成；失败时请求仍在。
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
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let store = engine.audit().ok_or("audit disabled")?;
    store
        .list_recent(limit.unwrap_or(50))
        .map(|records| records.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn export_session_report(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<String, String> {
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
    report.write_json(&json_path).map_err(|e| e.to_string())?;
    report.write_markdown(&md_path).map_err(|e| e.to_string())?;
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
    require_audit_ready(state.inner())?;
    state.engine.lock().map_err(|e| e.to_string())?.resume();
    Ok(())
}

#[tauri::command]
fn start_guard_session(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    task_profile: Option<String>,
    task_apps: Option<Vec<String>>,
) -> Result<String, String> {
    require_audit_ready(state.inner())?;
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
    // 先把上一代待确认全部以系统 Timeout 结案；事务失败时不启动新会话。
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

    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    adapter.start_task_session(sid.clone(), "Claude", &task);
    state.trace.write(&TraceLine {
        session_id: Some(sid.clone()),
        ..trace_line("session_start")
    });
    reset_observation_memory(&state)?;
    drain_and_process(&state, &mut adapter)?;
    // Observation begins with the session and ends with it. Polling outside a session would
    // record a user's screen with no agent to attribute it to, which is the opposite of what
    // a session-scoped guard is for.
    drop(adapter);
    // P1-5:真实观察器绑到同一个会话 id——原生事件的 agent_context_id 不再是空。
    #[cfg(windows)]
    if let Ok(mut guard) = state.observer.lock() {
        if let Some(o) = guard.as_mut() {
            o.bind_session(Some(sid.clone()));
        }
    }
    if state.capabilities.can_observe() {
        state
            .observer_started_ms
            .store(now_epoch_ms(), Ordering::Relaxed);
        start_auto_poller(app, state.polling.clone(), state.poll_generation.clone());
    }
    Ok(sid)
}

/// 会话边界:清掉「上一段观察」的记忆——聚合器(上一会话见过的画面在新会话里要当首次记)
/// 和心跳/启动时刻(新会话从零起算,不拿旧会话的心跳冒充「在观察」)。
fn reset_observation_memory(state: &State<'_, AppState>) -> Result<(), String> {
    state.aggregator.lock().map_err(|e| e.to_string())?.reset();
    state.heartbeat_ms.store(0, Ordering::Relaxed);
    state.observer_started_ms.store(0, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
fn end_guard_session(state: State<'_, AppState>) -> Result<(), String> {
    // 审计事务先行；失败时会话、观察器、队列与引擎状态都保持原样，调用方可重试。
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

    state.polling.store(false, Ordering::Relaxed);
    state.trace.write(&trace_line("session_end"));
    #[cfg(windows)]
    if let Ok(mut guard) = state.observer.lock() {
        if let Some(o) = guard.as_mut() {
            o.bind_session(None);
        }
    }
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    adapter.end_session("Claude");
    drain_and_process(&state, &mut adapter)?;
    reset_observation_memory(&state)?;
    // SESSION-PAUSED 是会话级状态("Session paused after critical deny"),会话结束即失效;
    // 不清的话下一个会话所有事件都被拦成 SESSION-PAUSED,界面也一直停在「已暂停」。
    state.engine.lock().map_err(|e| e.to_string())?.resume();
    Ok(())
}

#[tauri::command]
fn inject_demo_threat(
    state: State<'_, AppState>,
    kind: String,
) -> Result<Vec<DecisionDto>, String> {
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    match kind.as_str() {
        "payment" => adapter.ingest(SimObservation::UiText {
            app: "Chrome".into(),
            text: "请确认支付 $299.00".into(),
        }),
        "fm" => adapter.ingest(SimObservation::FormFill {
            app: "Chrome".into(),
            field_id: "dob".into(),
            profile_key: "date_of_birth".into(),
            required: false,
            value_filled: true,
            is_trap: false,
            probe_type: Some("form_minimization".into()),
        }),
        "overlay" => adapter.ingest(SimObservation::OverlayMarker {
            app: "Chrome".into(),
            marker: "[AG_TRANSPARENT_OVERLAY]".into(),
        }),
        "trap" => adapter.ingest(SimObservation::FormFill {
            app: "Chrome".into(),
            field_id: "priority_phone".into(),
            profile_key: "phone_number".into(),
            required: false,
            value_filled: true,
            is_trap: true,
            probe_type: Some("trap_resistance".into()),
        }),
        "inject" => adapter.ingest(SimObservation::UiText {
            app: "Chrome".into(),
            text: "hidden <!-- agentguard:poison --> payload".into(),
        }),
        "domain" => {
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("url".into(), "https://evil.example/login".into());
            let event = GuardEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp_ms: 0,
                platform: "windows".into(),
                event_type: EventType::UiTreeDelta,
                source_app: "Chrome".into(),
                agent_context_id: None,
                metadata,
            };
            let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
            let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
            return Ok(vec![process_one(&state, &mut engine, &event, approve)?]);
        }
        "netmon" => {
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
                platform: "windows".into(),
                event_type: EventType::UiTreeDelta,
                source_app: "AgentProxy".into(),
                agent_context_id: None,
                metadata: finding.metadata,
            };
            let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
            let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
            return Ok(vec![process_one(&state, &mut engine, &event, approve)?]);
        }
        other => return Err(format!("unknown threat kind: {other}")),
    }
    drain_and_process(&state, &mut adapter)
}

#[tauri::command]
fn reload_intel(state: State<'_, AppState>) -> Result<String, String> {
    let intel = load_intel().map_err(|error| error.to_string())?;
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let ver = intel.version.clone();
    engine.reload_intel(intel);
    Ok(ver)
}

#[tauri::command]
fn sync_device_policy(
    state: State<'_, AppState>,
    source: Option<String>,
) -> Result<String, String> {
    if !DEVELOPMENT_BUILD && source.is_none() {
        return Err("此发布版本未配置企业策略来源，无法同步".into());
    }
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
fn ingest_browser_json(
    state: State<'_, AppState>,
    payload: String,
) -> Result<Vec<DecisionDto>, String> {
    use browser_adapter::BrowserAdapter;
    let mut browser = BrowserAdapter::new();
    browser.set_session(Some("browser-ext".into()));
    let events = browser
        .parse_envelope(&payload)
        .map_err(|e| e.to_string())?;
    let _adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    // Feed browser events through engine directly.
    drop(_adapter);
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for event in events {
        let d = process_one(&state, &mut engine, &event, approve)?;
        out.push(d);
    }
    Ok(out)
}

fn process_one(
    state: &State<'_, AppState>,
    engine: &mut Engine,
    event: &guard_schema::GuardEvent,
    approve: bool,
) -> Result<DecisionDto, String> {
    require_audit_ready(state.inner())?;
    if approve {
        let d = engine
            .process_gated(event, &AutoApprove)
            .map_err(|e| e.to_string())?;
        return Ok(to_dto(&d));
    }

    // Interactive path: process without auto-deny pause; queue confirm UI.
    let d = engine.process(event).map_err(|e| e.to_string())?;
    if d.require_confirm && matches!(d.action, DecisionAction::Block | DecisionAction::Alert) {
        let req = ConfirmRequest::from_decision(
            &d,
            &event.source_app,
            engine.last_audit_id().map(|s| s.to_string()),
            event.metadata.get("ui_text").cloned(),
        );
        let (audit_id, rule_id) = (req.audit_id.clone(), req.rule_id.clone());
        let (id, evicted) = {
            let mut queue = state.pending.lock().map_err(|e| e.to_string())?;
            enqueue_pending_with_engine(&mut queue, engine, req, now_epoch_ms())?
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

fn drain_and_process(
    state: &State<'_, AppState>,
    adapter: &mut WinAdapter,
) -> Result<Vec<DecisionDto>, String> {
    let events = adapter.poll_events().map_err(|e| e.to_string())?;
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for event in events {
        out.push(process_one(state, &mut engine, &event, approve)?);
    }
    Ok(out)
}

/// Observe the foreground window once and run every event through the engine.
///
/// Returns the decisions plus whatever the adapter could not do. The warnings are the point:
/// a poll that read no tree and captured no frame returns an empty decision list, which is
/// indistinguishable from a clean screen unless the reason travels alongside it.
#[cfg(windows)]
fn poll_native_once(
    state: &State<'_, AppState>,
) -> Result<(Vec<DecisionDto>, Vec<String>), String> {
    let mut guard = state.observer.lock().map_err(|e| e.to_string())?;
    let observer = match guard.as_mut() {
        Some(o) => o,
        None => {
            let why = state
                .observe_error
                .lock()
                .map_err(|e| e.to_string())?
                .clone()
                .unwrap_or_else(|| "no native observer on this host".into());
            return Ok((Vec::new(), vec![why]));
        }
    };
    let outcome = observer.poll_once();
    // 这个 cfg(windows) 函数在 Linux/macOS 上编不到(ring 也挡住了 msvc 目标的交叉 check),
    // 所以它只保留一行调用;所有逻辑在下面的平台无关函数里,cargo test 在任何机器上都盯着。
    let (to_process, warnings, suppressed) = aggregate_observed(
        &state.aggregator,
        &state.heartbeat_ms,
        outcome.events,
        outcome.warnings,
        now_epoch_ms(),
    )?;
    state.trace.write(&TraceLine {
        source: Some("uia".into()),
        events: Some(to_process.len() as u32),
        suppressed: Some(suppressed as u32),
        ..trace_line("observe_tick")
    });
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(to_process.len());
    for event in &to_process {
        out.push(process_one(state, &mut engine, event, approve)?);
    }
    Ok((out, warnings))
}

/// 观察器一拍的结果 → (该过引擎的事件, 警告)。平台无关,`#[cfg(windows)]` 之外。
///
/// - 心跳(P0-3):这一拍真的看到了东西,或者它没什么可抱怨的,才算。只带 warnings 回来
///   (树读不到、帧抓不到)的一拍**不**算心跳——那正是状态机要暴露的「没在观察」。
/// - 聚合(P2-3):同一语义内容 30 s 内只过引擎一次;折叠的不写审计、不入待确认队列。
///   窗口过后同一内容仍在,放行一条并把折叠计数写进 `repeat_count`,审计里就有持续摘要。
#[cfg_attr(not(windows), allow(dead_code))]
fn aggregate_observed(
    aggregator: &Mutex<guard_core::event_dedup::Aggregator>,
    heartbeat_ms: &AtomicU64,
    events: Vec<GuardEvent>,
    mut warnings: Vec<String>,
    now: u64,
) -> Result<(Vec<GuardEvent>, Vec<String>, usize), String> {
    use guard_core::event_dedup::{Verdict, REPEAT_COUNT_KEY};
    // 「前台是守卫自己,跳过」是观察器看了一眼之后的结论,算心跳;别的 warning(树读不到、
    // 帧抓不到)不算。
    let only_benign_skips = warnings.iter().all(|w| w == win_adapter::SELF_SKIP_NOTE);
    if !events.is_empty() || only_benign_skips {
        heartbeat_ms.store(now, Ordering::Relaxed);
    }
    let mut aggregator = aggregator.lock().map_err(|e| e.to_string())?;
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
    for ended in aggregator.sweep(now).into_iter().filter(|e| e.total > 1) {
        warnings.push(format!(
            "repeated observation ended: seen {} time(s) over {:.1}s",
            ended.total,
            ended.last_ms.saturating_sub(ended.first_ms) as f64 / 1000.0
        ));
    }
    if suppressed > 0 {
        warnings.push(format!("{suppressed} duplicate observation(s) folded"));
    }
    Ok((to_process, warnings, suppressed))
}

#[cfg(not(windows))]
fn poll_native_once(
    _state: &State<'_, AppState>,
) -> Result<(Vec<DecisionDto>, Vec<String>), String> {
    Ok((
        Vec::new(),
        vec![format!(
            "this build targets {}; UI Automation and window capture are Win32 APIs",
            std::env::consts::OS
        )],
    ))
}

/// One-shot observation, for a UI button and for tests.
#[tauri::command]
fn poll_native(state: State<'_, AppState>) -> Result<PollDto, String> {
    require_audit_ready(state.inner())?;
    let (decisions, warnings) = poll_native_once(&state)?;
    Ok(PollDto {
        decisions,
        warnings,
    })
}

#[derive(Serialize)]
struct PollDto {
    decisions: Vec<DecisionDto>,
    warnings: Vec<String>,
}

/// Poll interval.
///
/// Matched to the macOS AX poller rather than chosen independently: two platforms observing
/// the same agent at different cadences would produce incomparable trajectories, and the
/// plan-budget rules count events.
const POLL_INTERVAL: Duration = Duration::from_millis(2500);

/// Start the observation loop. Stops itself on repeated failure rather than emitting an
/// error twice a second forever.
/// P1-5:连续失败后的退避——2.5s、5s、10s … 上限 60s。不再"三次失败就永久停"。
fn poll_backoff(consecutive_failures: u32) -> Duration {
    let n = consecutive_failures.min(5);
    let ms = (POLL_INTERVAL.as_millis() as u64) << n;
    Duration::from_millis(ms.min(60_000))
}

fn start_auto_poller(app: tauri::AppHandle, flag: Arc<AtomicBool>, generation: Arc<AtomicU64>) {
    flag.store(true, Ordering::Relaxed);
    let my_generation = generation.fetch_add(1, Ordering::SeqCst) + 1;
    std::thread::spawn(move || {
        let mut consecutive_failures = 0u32;
        let alive = |flag: &AtomicBool, generation: &AtomicU64| {
            flag.load(Ordering::Relaxed) && generation.load(Ordering::SeqCst) == my_generation
        };
        while alive(&flag, &generation) {
            std::thread::sleep(poll_backoff(consecutive_failures));
            if !alive(&flag, &generation) {
                break;
            }
            let Some(state) = app.try_state::<AppState>() else {
                break;
            };
            match poll_native_once(&state) {
                Ok((decisions, warnings)) => {
                    if consecutive_failures > 0 {
                        // 恢复了:清掉 degraded 原因。
                        if let Ok(mut slot) = state.observe_error.lock() {
                            *slot = None;
                        }
                    }
                    consecutive_failures = 0;
                    if decisions.iter().any(|d| d.require_confirm) {
                        let _ = app.emit("confirm-needed", ());
                        let n = state.pending.lock().map(|q| q.len()).unwrap_or(1);
                        bring_to_front(&app, n);
                    }
                    let _ = app.emit(
                        "native-poll",
                        serde_json::json!({ "decisions": decisions, "warnings": warnings }),
                    );
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let _ = app.emit("native-poll-error", serde_json::json!({ "error": e }));
                    // P1-5:以前三次失败就永久停,且没有恢复路径——用户要重开会话才会再观察。
                    // 现在:进入 degraded(原因留在 observe_error,状态灯据此变橙),按指数退避
                    // 继续尝试;成功一次即清掉原因回到 active。
                    if let Ok(mut slot) = state.observe_error.lock() {
                        *slot = Some(format!(
                            "observation failing ({consecutive_failures}×, retrying in {:?}): {e}",
                            poll_backoff(consecutive_failures)
                        ));
                    }
                }
            }
        }
    });
}

/// Run a probe away from the caller's thread.
///
/// On Windows, `capabilities()` creates a UI Automation client and therefore initialises COM
/// as MTA on the calling thread. Tauri/tao later calls `OleInitialize` (STA) on its main thread
/// while creating the native file-drop handler; doing both on the same thread panics with
/// `RPC_E_CHANGED_MODE` before the first window appears.
#[cfg(any(windows, test))]
fn on_dedicated_thread<T, F>(name: &str, probe: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(probe)
        .unwrap_or_else(|e| panic!("failed to start {name}: {e}"))
        .join()
        .unwrap_or_else(|_| panic!("{name} panicked"))
}

/// Keep the process-wide multithreaded apartment alive for cached WinRT factories.
///
/// `windows-core` caches an agile OCR activation factory for the process. The exact Windows
/// host crashed in that cache after the short-lived startup probe thread exited and a later
/// observation thread reused it. `CoIncrementMTAUsage` exists for this case: the cookie keeps
/// MTA support alive even when no MTA-initialised worker is currently running. The cookie stays
/// in a static for the process lifetime and Windows releases it when the process terminates.
#[cfg(windows)]
fn retain_process_mta() -> Result<(), String> {
    use std::ffi::c_void;
    use std::sync::OnceLock;

    #[link(name = "ole32")]
    extern "system" {
        fn CoIncrementMTAUsage(cookie: *mut *mut c_void) -> i32;
    }

    static MTA_USAGE: OnceLock<Result<usize, String>> = OnceLock::new();
    MTA_USAGE
        .get_or_init(|| {
            let mut cookie = std::ptr::null_mut();
            let result = unsafe { CoIncrementMTAUsage(&mut cookie) };
            if result < 0 {
                Err(format!(
                    "CoIncrementMTAUsage failed: HRESULT 0x{:08X}",
                    result as u32
                ))
            } else if cookie.is_null() {
                Err("CoIncrementMTAUsage returned a null cookie".into())
            } else {
                Ok(cookie as usize)
            }
        })
        .as_ref()
        .map(|_| ())
        .map_err(Clone::clone)
}

fn startup_capabilities() -> AdapterCapabilities {
    // `.honoring_env()`:验收开关 AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia,frame,ocr 把探测成功的
    // 能力强制标成不可用(只此一个方向),让 W6「能力不可用分支」在一台好机器上也能走到。
    // 探测本身仍在专用线程上做(COM apartment 见 on_dedicated_thread)。
    #[cfg(windows)]
    {
        on_dedicated_thread("agentguard-capability-probe", || {
            retain_process_mta().unwrap_or_else(|e| panic!("cannot retain the Windows MTA: {e}"));
            capabilities().honoring_env()
        })
    }
    #[cfg(not(windows))]
    {
        capabilities().honoring_env()
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let caps = startup_capabilities();
    // Construct the observer once. Its absence is recorded with a reason, because a shell
    // that silently falls back to simulation is the failure this whole iteration is about.
    let observe_error = if caps.can_observe() {
        None
    } else {
        Some(format!(
            "native observation unavailable — UI tree: {}; window capture: {}",
            caps.uia_native, caps.frame_capture
        ))
    };
    let engine = build_engine_without_audit().expect("Windows 必需规则资源无效，拒绝启动");
    let (engine, audit_initialization_error) = match open_audit_store() {
        Ok(audit) => (engine.with_audit(audit), String::new()),
        Err(error) => (engine, format!("{error:#}")),
    };
    let audit_ready = audit_initialization_error.is_empty();
    // P1-4:上次运行没处理完的确认——逐条写 Timeout 回执。
    let orphaned = restore_orphaned_confirms(&engine);
    // P1-9:只恢复能再验过签的缓存策略;没公钥就只显示、不执法。
    let mut engine = engine;
    let policy_status = restore_device_policy_at_startup(&mut engine);
    let state = AppState {
        engine: Mutex::new(engine),
        audit_ready: AtomicBool::new(audit_ready),
        audit_operation_running: AtomicBool::new(false),
        audit_recovery_running: AtomicBool::new(false),
        audit_initialization_error: Mutex::new(audit_initialization_error),
        adapter: Mutex::new(WinAdapter::new()),
        auto_approve: Mutex::new(false),
        pending: Mutex::new(ConfirmQueue::new(64)),
        capabilities: caps.clone(),
        #[cfg(windows)]
        observer: Mutex::new(
            if caps.uia_native.available || caps.frame_capture.available {
                Some(
                    NativeObserver::new()
                        .with_schemas(load_form_schemas().unwrap_or_else(|error| {
                            panic!("Windows 表单规则加载失败，拒绝启动观察: {error:#}")
                        }))
                        .with_observation_capabilities(
                            caps.uia_native.available,
                            caps.frame_capture.available,
                            caps.ocr.available,
                        ),
                )
            } else {
                None
            },
        ),
        observe_error: Mutex::new(observe_error),
        polling: Arc::new(AtomicBool::new(false)),
        poll_generation: Arc::new(AtomicU64::new(0)),
        heartbeat_ms: AtomicU64::new(0),
        observer_started_ms: AtomicU64::new(0),
        aggregator: Mutex::new(guard_core::event_dedup::Aggregator::for_observers()),
        confirms_timed_out: AtomicUsize::new(0),
        orphaned_confirms: AtomicUsize::new(orphaned),
        policy_status: Mutex::new(policy_status),
        trace: TraceWriter::from_env(),
        last_shown_request: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_pending_confirm,
            resolve_confirm,
            list_audit,
            export_session_report,
            set_auto_approve,
            security_status,
            retry_audit_initialization,
            recover_legacy_audit,
            resume_session,
            start_guard_session,
            end_guard_session,
            inject_demo_threat,
            reload_intel,
            sync_device_policy,
            ingest_browser_json,
            poll_native,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod pending_persistence_tests {
    use super::*;

    fn audit_record(id: &str) -> AuditRecord {
        AuditRecord {
            id: id.into(),
            timestamp_ms: 1,
            platform: "windows".into(),
            event_type: "ui_tree_delta".into(),
            source_app: "Chrome".into(),
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
            source_app: "Chrome".into(),
        }
    }

    fn confirm(audit_id: &str) -> ConfirmRequest {
        ConfirmRequest {
            audit_id: Some(audit_id.into()),
            rule_id: "PAY-001".into(),
            severity: "Critical".into(),
            human_message: "需要确认".into(),
            source_app: "Chrome".into(),
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
mod observation_tests {
    use super::*;
    use std::collections::HashMap;

    fn ev(source: &str, ui_text: &str, digest: &str) -> GuardEvent {
        let mut metadata = HashMap::new();
        metadata.insert("ui_text".to_string(), ui_text.to_string());
        metadata.insert("frame_digest".to_string(), digest.to_string());
        GuardEvent {
            event_id: "e".into(),
            timestamp_ms: 0,
            platform: "windows".into(),
            event_type: EventType::UiTreeDelta,
            source_app: source.into(),
            agent_context_id: None,
            metadata,
        }
    }

    /// P0-3:只带 warnings、没有事件的一拍不算心跳;有事件或无警告才算。
    /// 例外:「前台是守卫自己,跳过」——观察器看过了,算心跳。
    #[test]
    fn 只有警告没有事件的一拍不更新心跳() {
        let agg = Mutex::new(guard_core::event_dedup::Aggregator::for_observers());
        let hb = AtomicU64::new(0);
        aggregate_observed(&agg, &hb, vec![], vec!["UIA: no tree".into()], 1_000).unwrap();
        assert_eq!(hb.load(Ordering::Relaxed), 0, "树读不到的一拍冒充了心跳");
        aggregate_observed(
            &agg,
            &hb,
            vec![],
            vec![win_adapter::SELF_SKIP_NOTE.to_string()],
            1_500,
        )
        .unwrap();
        assert_eq!(
            hb.load(Ordering::Relaxed),
            1_500,
            "跳过自己那一拍观察器是活的,该算心跳"
        );
        aggregate_observed(
            &agg,
            &hb,
            vec![],
            vec![
                win_adapter::SELF_SKIP_NOTE.to_string(),
                "UIA: no tree".into(),
            ],
            1_700,
        )
        .unwrap();
        assert_eq!(hb.load(Ordering::Relaxed), 1_500, "夹着真警告就不算");
        aggregate_observed(&agg, &hb, vec![], vec![], 2_000).unwrap();
        assert_eq!(hb.load(Ordering::Relaxed), 2_000);
        aggregate_observed(
            &agg,
            &hb,
            vec![ev("Chrome", "x", "a")],
            vec!["w".into()],
            3_000,
        )
        .unwrap();
        assert_eq!(hb.load(Ordering::Relaxed), 3_000);
    }

    /// P2-3:静止画面 30 s 内只放行一条;窗口过后放行的那条带 repeat_count;折叠数进 warnings。
    #[test]
    fn 重复观察被折叠_周期摘要带repeat_count() {
        let agg = Mutex::new(guard_core::event_dedup::Aggregator::for_observers());
        let hb = AtomicU64::new(0);
        let (first, w, _) =
            aggregate_observed(&agg, &hb, vec![ev("Chrome", "Pay now", "d1")], vec![], 0).unwrap();
        assert_eq!(first.len(), 1);
        assert!(w.is_empty());
        let mut folded = 0;
        for t in (2_500..30_000).step_by(2_500) {
            let (out, w, folded_n) = aggregate_observed(
                &agg,
                &hb,
                vec![ev("Chrome", "Pay now", &format!("d{t}"))],
                vec![],
                t,
            )
            .unwrap();
            assert!(out.is_empty(), "t={t} 同一画面又过了引擎");
            assert!(w.iter().any(|m| m.contains("folded")), "折叠没有报出来");
            assert_eq!(folded_n, 1);
            folded += 1;
        }
        assert_eq!(folded, 11);
        let (summary, _, _) = aggregate_observed(
            &agg,
            &hb,
            vec![ev("Chrome", "Pay now", "dz")],
            vec![],
            30_000,
        )
        .unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(
            summary[0]
                .metadata
                .get(guard_core::event_dedup::REPEAT_COUNT_KEY)
                .map(String::as_str),
            Some("11")
        );
    }

    /// P1-5:失败退避 2.5s → 5s → 10s → 20s → 40s → 60s 封顶;成功后回到 2.5s(调用方传 0)。
    #[test]
    fn 轮询失败指数退避封顶60秒() {
        assert_eq!(poll_backoff(0), POLL_INTERVAL);
        assert_eq!(poll_backoff(1), Duration::from_millis(5_000));
        assert_eq!(poll_backoff(2), Duration::from_millis(10_000));
        assert_eq!(poll_backoff(4), Duration::from_millis(40_000));
        assert_eq!(poll_backoff(5), Duration::from_millis(60_000));
        assert_eq!(poll_backoff(50), Duration::from_millis(60_000));
    }

    /// 内容变了立刻放行,不等窗口——去重不能变成漏看。
    #[test]
    fn 内容变化立即放行() {
        let agg = Mutex::new(guard_core::event_dedup::Aggregator::for_observers());
        let hb = AtomicU64::new(0);
        aggregate_observed(&agg, &hb, vec![ev("Chrome", "Total $10", "a")], vec![], 0).unwrap();
        let (out, _, _) = aggregate_observed(
            &agg,
            &hb,
            vec![ev("Chrome", "Total $299", "b")],
            vec![],
            2_500,
        )
        .unwrap();
        assert_eq!(out.len(), 1);
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
            platform: "windows".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "Chrome".into(),
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
    fn realtime_and_confirm_dtos_keep_internal_action_but_disclose_observed_effect() {
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
            source_app: "Chrome".into(),
            ui_excerpt: None,
            effect: OBSERVED_ONLY_EFFECT,
            external_action_blocked: EXTERNAL_ACTION_BLOCKED,
        })
        .unwrap();
        assert_eq!(confirm_json["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!confirm_json["external_action_blocked"].as_bool().unwrap());
    }

    #[test]
    fn audit_list_rows_disclose_that_external_action_was_not_blocked() {
        let row = serde_json::to_value(ObservedAuditRecordDto::from(block_record())).unwrap();
        assert_eq!(row["action"], "Block", "签名审计的内部动作不能被改写");
        assert_eq!(row["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!row["external_action_blocked"].as_bool().unwrap());
    }

    #[test]
    fn exported_report_uses_risk_verdicts_and_never_claims_external_blocking() {
        let report = ObservedSessionReport::from(SessionReport::from_records(&[block_record()]));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["risk_verdict_count"], 1);
        assert_eq!(json["effect"], OBSERVED_ONLY_EFFECT);
        assert!(!json["external_action_blocked"].as_bool().unwrap());
        assert!(
            json.get("block_count").is_none(),
            "Windows 对外报告不能把内部 Block 统计成拦截次数"
        );
        assert!(
            json.get("privacy_note").is_none(),
            "公共报告里的旧‘拦截/告警’说明不能泄漏到 Windows 导出"
        );

        let markdown = report.to_markdown();
        assert!(markdown.contains("`effect=observed_only`"));
        assert!(markdown.contains("`external_action_blocked=false`"));
        assert!(markdown.contains("风险判决（内部动作枚举）"));
        assert!(!markdown.contains("| Block |"));
        assert!(markdown.contains("未阻止外部应用中已经发生的动作"));

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
mod windows_required_capability_tests {
    use super::*;
    use guard_core::observe_state::{ProtectionState, Reason};
    use win_adapter::Capability;

    fn all_available() -> AdapterCapabilities {
        AdapterCapabilities {
            simulation: true,
            uia_native: Capability::yes("UI Automation ready"),
            frame_capture: Capability::yes("GDI ready"),
            graphics_capture: Capability::no("GDI is the documented release path"),
            ocr: Capability::yes("OCR engine ready (English)"),
        }
    }

    fn release_state(caps: &AdapterCapabilities) -> observe_state::Derived {
        let gap = required_windows_capability_gap(caps);
        observe_state::derive(
            &StateInputs {
                session_active: true,
                paused: false,
                pending_confirm: false,
                observers_available: caps.uia_native.available as u32
                    + caps.frame_capture.available as u32,
                observers_running: 1,
                required_observation_permission: gap.permission,
                required_capability_unavailable: gap.capability,
                observer_error: None,
                audit_enabled: true,
                audit_error: None,
                observer_started_ms: Some(1_000),
                last_heartbeat_ms: Some(9_500),
                now_ms: 10_000,
            },
            &Thresholds::default(),
        )
    }

    #[test]
    fn w10_missing_uia_or_ocr_stays_degraded_despite_a_healthy_frame_heartbeat() {
        for forced in ["uia", "frame", "ocr"] {
            let caps = all_available().with_forced_unavailable(forced);
            let state = release_state(&caps);
            assert_eq!(state.state, ProtectionState::Degraded, "forced={forced}");
            assert!(
                state
                    .reasons
                    .contains(&Reason::RequiredCapabilityUnavailable),
                "forced={forced} reasons={:?}",
                state.reasons
            );
        }
    }

    #[test]
    fn access_denial_is_permission_required_but_missing_language_engine_is_capability_gap() {
        let mut denied = all_available();
        denied.uia_native = Capability::no("CUIAutomation failed: E_ACCESSDENIED 0x80070005");
        let denied_state = release_state(&denied);
        assert_eq!(denied_state.state, ProtectionState::PermissionRequired);
        assert_eq!(
            denied_state.reasons,
            vec![Reason::RequiredObservationPermission]
        );

        let mut no_ocr = all_available();
        no_ocr.ocr = Capability::no("no OCR recognizer available; install a language pack");
        let no_ocr_state = release_state(&no_ocr);
        assert_eq!(no_ocr_state.state, ProtectionState::Degraded);
        assert_eq!(
            no_ocr_state.reasons,
            vec![Reason::RequiredCapabilityUnavailable]
        );
    }

    #[test]
    fn all_windows_release_capabilities_available_can_be_active() {
        let state = release_state(&all_available());
        assert_eq!(state.state, ProtectionState::Active);
        assert!(state.reasons.is_empty());
    }
}

#[cfg(test)]
mod packaging_tests {
    /// Every icon the bundle configuration names has to exist.
    ///
    /// `tauri::generate_context!` reads these files at compile time and panics if one is
    /// missing, so a dropped icon is a build failure with a confusing message. This test names
    /// the cause instead.
    ///
    /// It exists because of a mistake worth recording: the author of this test worked from an
    /// incomplete copy of the repository in which these PNGs were absent, concluded the app
    /// "could never be built", and wrote that in three documents. The files were present all
    /// along. What was true — and is the reason nobody would have noticed a real absence — is
    /// that neither desktop shell was ever *compiled* by CI; the repository verified them with
    /// `rustfmt --check`, which parses and does not resolve. That is now fixed by the
    /// `windows` and `macos-shell` jobs, and this test makes the icon dependency explicit.
    #[test]
    fn every_declared_icon_is_present() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let conf: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("tauri.conf.json")).unwrap())
                .expect("tauri.conf.json parses");
        let icons = conf["bundle"]["icon"].as_array().expect("bundle.icon list");
        assert!(!icons.is_empty(), "a bundle with no icons cannot be built");
        for i in icons {
            let rel = i.as_str().expect("icon path");
            let path = root.join(rel);
            assert!(
                path.is_file(),
                "declared icon {rel} does not exist at {}",
                path.display()
            );
        }

        let release = std::fs::read_to_string(root.join("../scripts/build-release.sh"))
            .expect("Windows must have one reproducible secure Release entry");
        assert!(
            release.contains("--no-default-features --features audit-sqlcipher --locked"),
            "the canonical Release command must explicitly select locked SQLCipher"
        );
        assert!(
            release.contains("scripts/bootstrap-rust.sh"),
            "the Release command must use the repository-pinned cargo/rustc wrapper"
        );
    }

    #[test]
    fn release_audit_has_no_unsigned_fallback_and_preflights_signer_first() {
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        )
        .unwrap();
        assert!(
            !src.contains(concat!("open_audit_store_", "unsigned")),
            "an unsigned reopen path reintroduced the encrypted-but-unsigned state"
        );
        assert!(
            !src.contains(concat!("records will be ", "unsigned")),
            "signer failure must stop startup, not downgrade"
        );
        let signer = src
            .find("WindowsDpapiDeviceKey::load_or_create(audit_signing_key_path())")
            .expect("the Windows signer seed is provisioned through current-user DPAPI");
        let database = src
            .find("AuditStore::open_protected")
            .expect("Release uses the protected audit constructor");
        assert!(
            signer < database,
            "the database was opened before signer provisioning could fail"
        );
        assert!(
            src.contains("DPAPI-protected Windows audit encryption key"),
            "Windows encryption key provisioning must remain DPAPI-backed"
        );
        assert!(
            src.contains(
                "#[cfg(not(target_os = \"windows\"))]\n    let signer = guard_audit::FileDeviceKey::load_or_create(audit_signing_key_path())"
            ),
            "the plaintext file signer may exist only in the non-Windows test portability branch"
        );
    }

    /// The observation path must be reachable from the shell.
    ///
    /// The whole point of this iteration on Windows: before it, the only ingress was seven
    /// demo threat buttons plus start/end session, and `NativeWinAdapter` was constructed
    /// nowhere. A registered command is the difference between an adapter that exists and one
    /// that runs.
    #[test]
    fn the_native_poll_command_is_registered() {
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        )
        .unwrap();
        let handler = src
            .split("generate_handler![")
            .nth(1)
            .expect("an invoke_handler must exist");
        assert!(
            handler.contains("poll_native"),
            "poll_native is not in the invoke handler, so the front end cannot reach the observer"
        );
        assert!(
            src.contains("start_auto_poller"),
            "nothing starts the observation loop"
        );
        assert!(
            src.contains("state.polling.store(false"),
            "the observation loop is never stopped, so it would outlive the session"
        );
    }

    /// The startup capability probe must not initialise COM on Tauri's main thread.
    #[test]
    fn startup_probe_uses_a_different_thread() {
        let caller = std::thread::current().id();
        let worker =
            super::on_dedicated_thread("agentguard-test-probe", || std::thread::current().id());
        assert_ne!(
            caller, worker,
            "running the probe on Tauri's main thread reintroduces RPC_E_CHANGED_MODE"
        );
    }

    /// The real capability probe must leave Tauri's thread free for OLE's STA setup.
    #[cfg(windows)]
    #[test]
    fn startup_probe_does_not_change_the_callers_com_apartment() {
        use std::ffi::c_void;

        #[link(name = "ole32")]
        extern "system" {
            fn OleInitialize(reserved: *mut c_void) -> i32;
            fn OleUninitialize();
        }

        let _ = super::startup_capabilities();
        let result = unsafe { OleInitialize(std::ptr::null_mut()) };
        assert!(
            result >= 0,
            "OleInitialize failed after the startup probe: HRESULT 0x{:08X}",
            result as u32
        );
        unsafe { OleUninitialize() };
    }

    /// A process-wide WinRT factory cached by the startup worker must remain valid when a
    /// later observation worker uses it. The old lifetime crashed here with `0xC0000005`.
    #[cfg(windows)]
    #[test]
    fn winrt_factory_survives_the_startup_probe_thread() {
        let _ = super::startup_capabilities();
        let later = super::on_dedicated_thread("agentguard-later-probe", super::capabilities);
        assert!(later.simulation);
    }
}

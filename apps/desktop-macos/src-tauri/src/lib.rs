//! AgentGuard macOS shell: Menu Bar tray + TCC onboarding + MacAdapter simulation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_audit::{
    auto_approve_allowed, default_audit_key_path, ensure_audit_key_file, sqlcipher_enabled,
    AuditRecord, AuditStore, SessionReport, UserDecision,
};
use guard_billing::load_or_free;
use guard_core::acceptance_trace::{TraceLine, TraceWriter};
use guard_core::confirm_queue::{
    ConfirmQueue, PersistedPending, ResolveOutcome, DEFAULT_CONFIRM_TTL_MS,
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
    ax_probe, demo_transparent_overlay_frame, mac_capabilities, sck_probe, start_capture_session,
    stop_capture_session, AxCapture, MacAdapter,
};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State};
use win_adapter::{PlatformAdapter, SimObservation};

struct AppState {
    engine: Mutex<Engine>,
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
    /// Background Menu Bar SCK poller (1.5s). Cleared on stop.
    sck_auto_poll: Arc<AtomicBool>,
    /// Background AXObserver driver. A 50ms tick drains notifications; the adapter
    /// coalesces captures to 150ms debounce / 800ms max latency / 3s fallback.
    ax_auto_poll: Arc<AtomicBool>,
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

#[derive(Serialize)]
struct StatusDto {
    rules_loaded: usize,
    policy_id: String,
    audit_enabled: bool,
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
    dir.push("agentguard");
    let _ = std::fs::create_dir_all(&dir);
    dir.push("audit-macos.db");
    dir
}

/// A release build must not try to open a legacy plaintext SQLite audit DB with a
/// SQLCipher key: SQLCipher correctly reports "file is not a database" and the app
/// would crash before showing a window. Keep the legacy file untouched and start a
/// sibling encrypted store. Existing encrypted stores keep their original path.
fn sqlcipher_audit_db_path(path: &std::path::Path) -> PathBuf {
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
    let mut header = [0_u8; 16];
    let is_plaintext = std::fs::File::open(path)
        .and_then(|mut file| {
            use std::io::Read;
            file.read_exact(&mut header)
        })
        .map(|_| &header == SQLITE_HEADER)
        .unwrap_or(false);
    if !is_plaintext {
        return path.to_path_buf();
    }

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("audit-macos");
    path.with_file_name(format!("{stem}.sqlcipher.db"))
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
    dir.push("agentguard");
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

fn intel_pubkey_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_INTEL_PUBKEY") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../../intel/keys/public.hex"),
        PathBuf::from("intel/keys/public.hex"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates[0].clone()
}

fn load_intel() -> guard_intel::ThreatBundle {
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
    let pk = intel_pubkey_path();
    if cfg!(debug_assertions) {
        return guard_intel::load_or_default(&bundle).unwrap_or_default();
    }
    match load_release(&bundle, &pk) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("intel load_release failed ({e}); using empty bundle (fail-closed)");
            guard_intel::ThreatBundle::default()
        }
    }
}

/// Device audit signing key next to the audit DB (Aura §4.4.6 attribution).
/// Generated on first run; see docs/audit-signing.md for the threat model —
/// a key on the same disk stops DB tampering, not a compromised host.
fn audit_signing_key_path() -> std::path::PathBuf {
    let mut p = default_audit_key_path();
    p.set_file_name("audit-signing.key");
    p
}

fn open_audit_store() -> AuditStore {
    let store = open_audit_store_unsigned();
    let key = match guard_audit::FileDeviceKey::load_or_create(audit_signing_key_path()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("audit signing key unavailable ({e}); records will be unsigned");
            return store;
        }
    };
    match store.with_signer(Box::new(key)) {
        Ok(signed) => signed,
        Err(e) => {
            // with_signer consumed the store; reopen through the same path so an
            // encrypted DB stays encrypted.
            eprintln!("audit signer attach failed ({e}); records will be unsigned");
            open_audit_store_unsigned()
        }
    }
}

fn open_audit_store_unsigned() -> AuditStore {
    let path = audit_db_path();
    if sqlcipher_enabled() {
        let key = ensure_audit_key_file(default_audit_key_path()).expect("audit key");
        let encrypted_path = sqlcipher_audit_db_path(&path);
        if encrypted_path != path {
            eprintln!(
                "legacy plaintext audit db retained at {}; using encrypted store {}",
                path.display(),
                encrypted_path.display()
            );
        }
        AuditStore::open_with_key(&encrypted_path, Some(&key)).expect("open encrypted audit db")
    } else {
        if !cfg!(debug_assertions) {
            eprintln!(
                "warning: release build without sqlcipher — rebuild with --features audit-sqlcipher"
            );
        }
        AuditStore::open(&path).expect("open audit db")
    }
}

fn build_engine() -> Engine {
    // The task-plan library, so a session that names a `task_profile` gets its trajectory plan and
    // its Aura §4.4 resource ceiling. Neither shell loaded it, which meant the whole plan mechanism
    // was unreachable from the desktop apps however the session was opened.
    let mut engine = Engine::from_paths(rules_path(), None::<PathBuf>)
        .expect("load rules")
        .with_intel(load_intel())
        .with_audit(open_audit_store());
    if let Some(plans) = load_task_plans() {
        engine = engine.with_task_plans(plans);
    }
    engine
}

/// The operator's task-plan library, if it is where we expect it.
///
/// Absent is not an error: a deployment without plans runs exactly as it did, which is the same
/// `require_plan: false` reasoning the library itself documents.
fn load_task_plans() -> Option<guard_schema::TaskPlanLibrary> {
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
            Some(lib) => return Some(lib),
            None => continue,
        }
    }
    None
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> Result<StatusDto, String> {
    // P1-4:每次有人看状态都先把超时的确认按拒绝处理掉——不然它们会一直「等着」。
    sweep_expired_confirms(state.inner())?;
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
    let tcc = *state.tcc_acknowledged.lock().map_err(|e| e.to_string())?;
    let st = engine.status();
    let caps = mac_capabilities();
    let score = engine.privacy_score();
    let ent = load_or_free(entitlement_path());
    let device_policy = DevicePolicy::from_path(device_policy_path()).unwrap_or_default();
    let sck_streaming = *state.sck_streaming.lock().map_err(|e| e.to_string())?;
    let sck_native_ok = *state.sck_native_ok.lock().map_err(|e| e.to_string())?;
    let sck_message = state.sck_message.lock().map_err(|e| e.to_string())?.clone();
    let sck_auto_poll = state.sck_auto_poll.load(Ordering::Relaxed);
    let ax_message = state.ax_message.lock().map_err(|e| e.to_string())?.clone();
    let (protection_mode, protection_summary, _) =
        protection_coverage(caps.accessibility, caps.screen_capture);
    let ax_auto_poll = state.ax_auto_poll.load(Ordering::Relaxed);
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
    let derived = observe_state::derive(
        &StateInputs {
            session_active: adapter.has_session(),
            paused: st.paused,
            pending_confirm: !pending.is_empty(),
            observers_available,
            observers_running,
            observer_error: observer_error.as_deref(),
            audit_enabled: st.audit_enabled,
            audit_error: st.audit_error.as_deref(),
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
        audit_enabled: st.audit_enabled,
        paused: st.paused,
        session_active: adapter.has_session(),
        accessibility: caps.accessibility,
        screen_capture: caps.screen_capture,
        privacy_composite: score.composite,
        pending_confirm: !pending.is_empty(),
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
        audit_error: st.audit_error.unwrap_or_default(),
        observer_error: observer_error.unwrap_or_default(),
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
/// 但**绝不因为没授权而拒绝开会话**(未授权时仿真与浏览器扩展路径仍然有效,那正是
/// 「防护范围:部分 / 仿真」的含义)。
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
fn open_privacy_settings(which: String) -> Result<(), String> {
    let anchor = privacy_pane_anchor(&which).ok_or_else(|| format!("unknown pane: {which}"))?;
    open_settings_pane(anchor)
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
fn enqueue_confirm(state: &AppState, req: ConfirmRequest) -> Result<u64, String> {
    let (audit_id, rule_id) = (req.audit_id.clone(), req.rule_id.clone());
    let id = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        q.enqueue_at(req, now_epoch_ms())
    };
    persist_pending(state);
    state.trace.write(&TraceLine {
        request_id: Some(id),
        audit_id,
        rule_id: Some(rule_id),
        ..trace_line("confirm_enqueued")
    });
    Ok(id)
}

/// P1-4:待确认落盘(不含观测文本摘录),重启后不静默丢。写失败只记 stderr——落盘是给
/// 重启兜底的,不该反过来让当前这次确认失败。
fn pending_confirms_path() -> PathBuf {
    let mut p = dirs_next_data();
    p.push("agentguard");
    let _ = std::fs::create_dir_all(&p);
    p.push("pending-confirms.json");
    p
}

fn persist_pending(state: &AppState) {
    let snapshot = match state.pending.lock() {
        Ok(q) => q.snapshot(),
        Err(_) => return,
    };
    let path = pending_confirms_path();
    if snapshot.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let tmp = path.with_extension("json.tmp");
    let write = serde_json::to_vec(&snapshot)
        .map_err(|e| e.to_string())
        .and_then(|bytes| std::fs::write(&tmp, bytes).map_err(|e| e.to_string()))
        .and_then(|_| std::fs::rename(&tmp, &path).map_err(|e| e.to_string()));
    if let Err(e) = write {
        eprintln!("agentguard: pending-confirms persist failed: {e}");
    }
}

/// P1-4:启动时处理上次运行遗留的待确认——逐条写 Timeout 回执,然后删文件。
/// 返回处理条数。任何一条回执写不进就**保留文件**(下次启动再试),不假装处理完了。
fn restore_orphaned_confirms(engine: &Engine) -> usize {
    let path = pending_confirms_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return 0;
    };
    let items: Vec<PersistedPending> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("agentguard: pending-confirms.json unreadable ({e}); leaving it in place");
            return 0;
        }
    };
    let mut done = 0usize;
    let mut failed = false;
    if let Some(store) = engine.audit() {
        for it in &items {
            if let Some(id) = &it.audit_id {
                match store.set_user_decision(id, UserDecision::Timeout) {
                    Ok(()) => done += 1,
                    Err(e) => {
                        failed = true;
                        eprintln!(
                            "agentguard: orphaned confirm {} receipt failed: {e}",
                            it.request_id
                        );
                    }
                }
            } else {
                done += 1;
            }
        }
    } else {
        failed = !items.is_empty();
    }
    if !failed {
        let _ = std::fs::remove_file(&path);
    }
    done
}

/// P1-4:把等了超过 TTL 的确认按拒绝处理:写 Timeout 回执、引擎保持/进入暂停、落盘、计数。
/// 返回本次处理的 request_id。回执写不进的那条**留在计数外**并记 stderr——它已从队列移出
/// (再点是 Stale),但审计里没有它的回执,这是要暴露而不是吞掉的。
fn sweep_expired_confirms(state: &AppState) -> Result<Vec<u64>, String> {
    let expired = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        q.expire(now_epoch_ms(), DEFAULT_CONFIRM_TTL_MS)
    };
    if expired.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::with_capacity(expired.len());
    {
        let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
        for it in &expired {
            if let (Some(store), Some(id)) = (engine.audit(), it.request.audit_id.as_ref()) {
                if let Err(e) = store.set_user_decision(id, UserDecision::Timeout) {
                    eprintln!(
                        "agentguard: timeout receipt for {} failed: {e}",
                        it.request_id
                    );
                    continue;
                }
            }
            ids.push(it.request_id);
            state.trace.write(&TraceLine {
                request_id: Some(it.request_id),
                audit_id: it.request.audit_id.clone(),
                rule_id: Some(it.request.rule_id.clone()),
                ..trace_line("confirm_expired")
            });
        }
        // 超时 = 默认拒绝:和用户点「不」一样,引擎暂停,等用户回来点「恢复」。
        engine.pause();
    }
    state
        .confirms_timed_out
        .fetch_add(ids.len(), Ordering::Relaxed);
    persist_pending(state);
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
    let (outcome, has_next) = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        let outcome = q.resolve(request_id, approve);
        (outcome, !q.is_empty())
    };
    persist_pending(state.inner());
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

    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    // 审计落库失败 = 确认失败。以前这里是 `let _ = ...`(报告 P0-5 点名):回执没写进签名
    // 审计,却照样告诉调用方成功了。现在写不进就报错、不动引擎状态 —— 一次没有留痕的高危
    // 确认,和没确认没有区别。
    if let (Some(store), Some(id)) = (engine.audit(), audit_id.as_ref()) {
        let ud = if approve {
            UserDecision::Approve
        } else {
            UserDecision::Deny
        };
        store
            .set_user_decision(id, ud)
            .map_err(|e| format!("确认回执写入签名审计失败,确认未生效:{e}"))?;
    }
    if approve {
        engine.resume();
    } else {
        engine.pause();
    }
    Ok(ResolveDto {
        resolved: true,
        has_next,
    })
}

#[tauri::command]
fn list_audit(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<AuditRecord>, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let store = engine.audit().ok_or("audit disabled")?;
    store
        .list_recent(limit.unwrap_or(50))
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
    let report = SessionReport::from_records(&records);
    let mut dir = dirs_next_data();
    dir.push("agentguard");
    dir.push("reports");
    let _ = std::fs::create_dir_all(&dir);
    let stamp = report.generated_at_ms;
    let json_path = dir.join(format!("session-{stamp}.json"));
    let md_path = dir.join(format!("session-{stamp}.md"));
    report.write_json(&json_path).map_err(|e| e.to_string())?;
    report.write_markdown(&md_path).map_err(|e| e.to_string())?;
    Ok(format!(
        "{} · blocks={} alerts={} → {} / {}",
        report.privacy_note,
        report.block_count,
        report.alert_count,
        json_path.display(),
        md_path.display()
    ))
}

#[tauri::command]
fn set_auto_approve(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if enabled && !auto_approve_allowed() {
        return Err(
            "auto-approve disabled in release builds (set AGENTGUARD_ALLOW_AUTO_APPROVE=1 to override)"
                .into(),
        );
    }
    *state.auto_approve.lock().map_err(|e| e.to_string())? = enabled;
    Ok(())
}

#[tauri::command]
fn security_status() -> Result<SecurityStatusDto, String> {
    Ok(SecurityStatusDto {
        release_build: !cfg!(debug_assertions),
        sqlcipher: sqlcipher_enabled(),
        auto_approve_allowed: auto_approve_allowed(),
        intel_fail_closed: !cfg!(debug_assertions),
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
fn start_guard_session(
    app: AppHandle,
    state: State<'_, AppState>,
    task_profile: Option<String>,
    task_apps: Option<Vec<String>>,
) -> Result<String, String> {
    let sid = uuid::Uuid::new_v4().to_string();
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
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
    adapter.start_task_session(sid.clone(), "Claude", &task);
    state.trace.write(&TraceLine {
        session_id: Some(sid.clone()),
        ..trace_line("session_start")
    });
    // P0-3/P0-5:新会话推进 generation 并清空上一会话遗留的待确认。一个新会话不继承
    // 悬空的确认;上一会话的 request_id 从此解析为 Stale。
    state
        .pending
        .lock()
        .map_err(|e| e.to_string())?
        .bump_generation();
    persist_pending(state.inner());
    reset_observation_memory(state.inner())?;
    drain_and_process(state.inner(), &mut adapter)?;
    // 下面要用到 state.adapter(arm_ax_observer 会锁它),先放掉这把锁。
    drop(adapter);

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
        if let Err(e) = arm_ax_observer(app.clone(), &state) {
            *state.ax_message.lock().map_err(|le| le.to_string())? =
                format!("AX observation could not start: {e}");
        }
    }
    if arm_sck {
        if let Err(e) = arm_sck_capture(app, &state) {
            *state.sck_message.lock().map_err(|le| le.to_string())? =
                format!("screen capture could not start: {e}");
        }
    }
    if state.ax_auto_poll.load(Ordering::Relaxed) || state.sck_auto_poll.load(Ordering::Relaxed) {
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
fn end_guard_session(state: State<'_, AppState>) -> Result<(), String> {
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    adapter.end_session("Claude");
    state.trace.write(&trace_line("session_end"));
    // P0-3:会话结束停掉后台观察器(不再"结束了还在采集"),并清空待确认队列。
    // 观察器由这两个 AtomicBool 驱动,置 false 让 SCK/AX 轮询线程在下一拍退出。
    state.sck_auto_poll.store(false, Ordering::SeqCst);
    state.ax_auto_poll.store(false, Ordering::SeqCst);
    if let Ok(mut s) = state.sck_streaming.lock() {
        *s = false;
    }
    let _ = stop_capture_session();
    state
        .pending
        .lock()
        .map_err(|e| e.to_string())?
        .bump_generation();
    persist_pending(state.inner());
    drain_and_process(state.inner(), &mut adapter)?;
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
        "domain" => {
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
        "capture" => {
            adapter.ingest_capture_frame(demo_transparent_overlay_frame(), "ScreenCapture");
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
        other => return Err(format!("unknown threat kind: {other}")),
    }
    drain_and_process(state.inner(), &mut adapter)
}

#[tauri::command]
fn reload_intel(state: State<'_, AppState>) -> Result<String, String> {
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let intel = load_intel();
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
fn sck_start_cmd(app: AppHandle, state: State<'_, AppState>) -> Result<CaptureSessionDto, String> {
    arm_sck_capture(app, &state)
}

#[tauri::command]
fn sck_stop_cmd(state: State<'_, AppState>) -> Result<CaptureSessionDto, String> {
    state.sck_auto_poll.store(false, Ordering::Relaxed);
    let info = stop_capture_session().map_err(|e| e.to_string())?;
    *state.sck_streaming.lock().map_err(|e| e.to_string())? = false;
    *state.sck_message.lock().map_err(|e| e.to_string())? = info.message.clone();
    Ok(CaptureSessionDto {
        native: info.native,
        message: info.message,
    })
}

#[tauri::command]
fn sck_poll_cmd(state: State<'_, AppState>) -> Result<SckPollDto, String> {
    poll_sck_once(&state)
}

fn start_sck_auto_poller(app: AppHandle, state: &AppState) {
    // Stop any previous loop, then enable a new one.
    state.sck_auto_poll.store(false, Ordering::Relaxed);
    let flag = state.sck_auto_poll.clone();
    flag.store(true, Ordering::Relaxed);
    note_observer_started(state);
    std::thread::spawn(move || {
        while flag.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1500));
            if !flag.load(Ordering::Relaxed) {
                break;
            }
            let Some(st) = app.try_state::<AppState>() else {
                break;
            };
            match poll_sck_once(st.inner()) {
                Ok(dto) => {
                    let _ = app.emit("sck-poll", &dto);
                    if dto.decisions.iter().any(|d| d.require_confirm) {
                        let _ = app.emit("sck-confirm-needed", ());
                        bring_to_front(&app);
                    }
                }
                Err(e) => {
                    let _ = app.emit("sck-poll-error", serde_json::json!({ "error": e }));
                }
            }
        }
    });
}

fn poll_sck_once(state: &AppState) -> Result<SckPollDto, String> {
    let streaming = *state.sck_streaming.lock().map_err(|e| e.to_string())?;
    if !streaming {
        return Ok(SckPollDto {
            decisions: vec![],
            frames_drained: 0,
            suppressed: 0,
            summaries: vec![],
        });
    }
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    let frames_drained = adapter.poll_sck_frames("ScreenCapture");
    let (decisions, suppressed, summaries) = drain_and_process_observed(state, &mut adapter)?;
    // 心跳 = 这一路观察器成功跑了一拍(流活着),不要求这一拍抓到东西:静止画面 SCK 可能
    // 一帧都不交,那不是观察器死了。
    state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
    if state.trace.enabled() && (frames_drained > 0 || !decisions.is_empty() || suppressed > 0) {
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

#[tauri::command]
fn ax_probe_cmd(state: State<'_, AppState>) -> Result<AxProbeDto, String> {
    let caps = mac_capabilities();
    match ax_probe() {
        Ok(()) => {
            *state.ax_message.lock().map_err(|e| e.to_string())? = "AX OK".into();
            Ok(AxProbeDto {
                ok: true,
                error: String::new(),
                accessibility: caps.accessibility,
            })
        }
        Err(e) => {
            *state.ax_message.lock().map_err(|e| e.to_string())? = e.clone();
            Ok(AxProbeDto {
                ok: false,
                error: e,
                accessibility: caps.accessibility,
            })
        }
    }
}

#[tauri::command]
fn ax_poll_cmd(state: State<'_, AppState>) -> Result<AxPollDto, String> {
    poll_ax_once(state.inner())
}

/// 前台是守卫自己时的说明——AX 主路径和一次性抓取都用它,壳子测试也认它。
const AX_SELF_SKIP_MESSAGE: &str =
    "frontmost app is AgentGuard itself — skipped (the guard does not observe its own window)";

fn poll_ax_once(state: &AppState) -> Result<AxPollDto, String> {
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    match adapter.capture_live_ax() {
        // capture_live_ax 不经过合并器,不会返回 NotDue;放在同一臂只是为了穷尽枚举。
        Ok(AxCapture::SkippedSelf) | Ok(AxCapture::NotDue) => {
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
        Ok(AxCapture::Captured) => {
            let (decisions, suppressed, summaries) =
                drain_and_process_observed(state, &mut adapter)?;
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
        Err(e) => {
            *state.ax_message.lock().map_err(|e| e.to_string())? = e.clone();
            Err(e)
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
fn poll_ax_push_once(state: &AppState) -> Result<Option<AxPollDto>, String> {
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    match adapter.maybe_capture_ax(now_ms())? {
        AxCapture::NotDue => return Ok(None),
        AxCapture::SkippedSelf => {
            // 用户正停在 AgentGuard 自己的窗口上(比如刚点了「开始会话」):观察器活着,
            // 心跳照常;不产事件。没有这一笔,状态灯会在用户看着仪表盘 10 秒后转成
            // 「守护不完整 / 观察没有汇报」——那是对着自己误报。
            state.heartbeat_ms.store(now_epoch_ms(), Ordering::Relaxed);
            if let Ok(mut slot) = state.observer_error.lock() {
                *slot = None;
            }
            *state.ax_message.lock().map_err(|e| e.to_string())? = AX_SELF_SKIP_MESSAGE.into();
            return Ok(None);
        }
        AxCapture::Captured => {}
    }
    // 这条是 AX 实时观测的**主路径**(E3 推送 + 兜底),所以 P0-3 心跳 / P2-3 折叠都在这里:
    // 抓到一次快照 = 观察器活着;快照内容一字不差 = 折叠,不过引擎。
    let (decisions, suppressed, summaries) = drain_and_process_observed(state, &mut adapter)?;
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

/// 打开 AX 树观察(AXObserver 推送 + 兜底轮询),返回写进状态行的那句话。
///
/// 从 `ax_auto_cmd` 抽出来,因为现在有两个调用方:开发者面板的手动开关,和
/// `start_guard_session` —— 会话开始就该开始看(见 `observers_for_session`)。
fn arm_ax_observer(app: AppHandle, state: &AppState) -> Result<String, String> {
    // Start the real observer before the driver. If registration itself is unavailable,
    // keep the 3s fallback alive; capture permission errors still surface immediately.
    let push_result = state
        .adapter
        .lock()
        .map_err(|e| e.to_string())?
        .start_ax_push();
    if let Err(e) = poll_ax_push_once(state) {
        state
            .adapter
            .lock()
            .map_err(|lock_err| lock_err.to_string())?
            .stop_ax_push();
        return Err(e);
    }
    start_ax_auto_poller(app, state);
    let message = match &push_result {
        Ok(()) => "AXObserver push on (150ms debounce, 800ms ceiling, 3s fallback)".to_string(),
        Err(e) => format!("AXObserver unavailable ({e}); 3s fallback polling on"),
    };
    *state.ax_message.lock().map_err(|e| e.to_string())? = message.clone();
    Ok(message)
}

/// 打开屏幕抓取(SCK)。同样有两个调用方:开发者面板与会话开始。
fn arm_sck_capture(app: AppHandle, state: &AppState) -> Result<CaptureSessionDto, String> {
    let info = start_capture_session().map_err(|e| e.to_string())?;
    *state.sck_streaming.lock().map_err(|e| e.to_string())? = info.native;
    *state.sck_native_ok.lock().map_err(|e| e.to_string())? = info.native;
    *state.sck_message.lock().map_err(|e| e.to_string())? = info.message.clone();
    if info.native {
        start_sck_auto_poller(app, state);
    } else {
        state.sck_auto_poll.store(false, Ordering::Relaxed);
    }
    Ok(CaptureSessionDto {
        native: info.native,
        message: info.message,
    })
}

#[tauri::command]
fn ax_auto_cmd(
    app: AppHandle,
    state: State<'_, AppState>,
    enable: bool,
) -> Result<AxAutoDto, String> {
    if enable {
        arm_ax_observer(app, &state)?;
    } else {
        state.ax_auto_poll.store(false, Ordering::Relaxed);
        state
            .adapter
            .lock()
            .map_err(|e| e.to_string())?
            .stop_ax_push();
    }
    Ok(AxAutoDto {
        enabled: enable,
        message: if enable {
            state.ax_message.lock().map_err(|e| e.to_string())?.clone()
        } else {
            "AX realtime observation off".into()
        },
    })
}

#[derive(Serialize)]
struct AxAutoDto {
    enabled: bool,
    message: String,
}

fn start_ax_auto_poller(app: AppHandle, state: &AppState) {
    let flag = state.ax_auto_poll.clone();
    if flag.swap(true, Ordering::Relaxed) {
        return;
    }
    note_observer_started(state);
    std::thread::spawn(move || {
        while flag.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
            if !flag.load(Ordering::Relaxed) {
                break;
            }
            let Some(st) = app.try_state::<AppState>() else {
                break;
            };
            match poll_ax_push_once(st.inner()) {
                Ok(Some(dto)) => {
                    let _ = app.emit("ax-poll", &dto);
                    if dto.decisions.iter().any(|d| d.require_confirm) {
                        let _ = app.emit("sck-confirm-needed", ());
                        bring_to_front(&app);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = app.emit("ax-poll-error", serde_json::json!({ "error": e }));
                    // Permission lost mid-run: stop the loop instead of spamming — and leave
                    // the reason where the state machine reads it (P0-3),so the pill goes to
                    // Degraded with `observer_error` instead of staying green.
                    if let Ok(mut slot) = st.observer_error.lock() {
                        *slot = Some(format!("AX observer stopped: {e}"));
                    }
                    flag.store(false, Ordering::Relaxed);
                }
            }
        }
        if let Some(st) = app.try_state::<AppState>() {
            if let Ok(mut adapter) = st.adapter.lock() {
                adapter.stop_ax_push();
            }
        }
    });
}

#[tauri::command]
fn sync_device_policy(
    state: State<'_, AppState>,
    source: Option<String>,
) -> Result<String, String> {
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
                    enqueue_confirm(state, req)?;
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
        enqueue_confirm(state, req)?;
    }
    Ok(to_dto(&d))
}

fn to_dto(d: &Decision) -> DecisionDto {
    DecisionDto {
        action: format!("{:?}", d.action),
        rule_id: d.rule_id.clone(),
        human_message: d.human_message.clone(),
        require_confirm: d.require_confirm,
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
fn drain_and_process(
    state: &AppState,
    adapter: &mut MacAdapter,
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

/// 观察器轮询路径(SCK / AX):先过聚合器,同一语义内容 30 s 内只过引擎一次(P2-3)。
///
/// 返回 (判决, 这一拍折叠掉的条数, 结束摘要)。折叠掉的事件**不**过引擎、不写审计、不入
/// 待确认队列——它们和上一条一字不差,过一遍只会多一行一样的记录和一个多余的弹窗。
/// 窗口过后同一内容仍在,放行一条并把折叠计数写进元数据 `repeat_count`,审计里就有
/// 「这 30 s 里同一画面出现了 N 次」的持续摘要,而不是 N 行。
fn drain_and_process_observed(
    state: &AppState,
    adapter: &mut MacAdapter,
) -> Result<(Vec<DecisionDto>, usize, Vec<String>), String> {
    let events = adapter.poll_events().map_err(|e| e.to_string())?;
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let engine = build_engine();
    // P1-4:上次运行没处理完的确认——逐条写 Timeout 回执。重启不是「悄悄清空」的理由。
    let orphaned = restore_orphaned_confirms(&engine);
    // P1-9:只恢复能再验过签的缓存策略;没公钥就只显示、不执法。
    let mut engine = engine;
    let policy_status = restore_device_policy_at_startup(&mut engine);
    let state = AppState {
        engine: Mutex::new(engine),
        adapter: Mutex::new(MacAdapter::new()),
        auto_approve: Mutex::new(false),
        // cap 64:同时在等的高危确认上限。真正防止风暴撑爆它的是上层的事件聚合(P2-3);
        // 满了则挤出最旧的并把它判成 Stale(fail-safe:过期确认按未放行处理)。
        pending: Mutex::new(ConfirmQueue::new(64)),
        tcc_acknowledged: Mutex::new(false),
        sck_streaming: Mutex::new(false),
        sck_native_ok: Mutex::new(false),
        sck_message: Mutex::new(String::new()),
        sck_auto_poll: Arc::new(AtomicBool::new(false)),
        ax_auto_poll: Arc::new(AtomicBool::new(false)),
        last_ui_event: Mutex::new(HashMap::new()),
        ax_message: Mutex::new(String::new()),
        heartbeat_ms: AtomicU64::new(0),
        observer_started_ms: AtomicU64::new(0),
        observer_error: Mutex::new(None),
        aggregator: Mutex::new(Aggregator::for_observers()),
        confirms_timed_out: AtomicUsize::new(0),
        orphaned_confirms: AtomicUsize::new(orphaned),
        policy_status: Mutex::new(policy_status),
        trace: TraceWriter::from_env(),
        last_shown_request: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .setup(|app| {
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
                        if let Some(st) = app.try_state::<AppState>() {
                            match ax_poll_cmd(st) {
                                Ok(dto) => {
                                    let _ = app.emit("ax-poll", &dto);
                                    if dto.decisions.iter().any(|d| d.require_confirm) {
                                        let _ = app.emit("sck-confirm-needed", ());
                                    }
                                }
                                Err(e) => {
                                    let _ = app
                                        .emit("ax-poll-error", serde_json::json!({ "error": e }));
                                }
                            }
                        }
                    }
                    "sck_start" => {
                        if let Some(st) = app.try_state::<AppState>() {
                            let _ = sck_start_cmd(app.clone(), st);
                        }
                    }
                    "sck_stop" => {
                        if let Some(st) = app.try_state::<AppState>() {
                            let _ = sck_stop_cmd(st);
                        }
                    }
                    "ax_auto" => {
                        if let Some(st) = app.try_state::<AppState>() {
                            let enable = !st.ax_auto_poll.load(Ordering::Relaxed);
                            let _ = ax_auto_cmd(app.clone(), st, enable);
                        }
                    }
                    "quit" => {
                        if let Some(st) = app.try_state::<AppState>() {
                            st.sck_auto_poll.store(false, Ordering::Relaxed);
                            st.ax_auto_poll.store(false, Ordering::Relaxed);
                            if let Ok(mut adapter) = st.adapter.lock() {
                                adapter.stop_ax_push();
                            }
                        }
                        let _ = stop_capture_session();
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
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
            set_tray_locale,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod packaging_tests {
    use super::sqlcipher_audit_db_path;

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
        assert!(
            source.contains(".start_ax_push()"),
            "启用时没有启动 AXObserver"
        );
        assert!(
            source.contains("adapter.maybe_capture_ax(now_ms())"),
            "后台驱动没有经过去抖/延迟上限合并器"
        );
        assert!(
            source.contains("adapter.stop_ax_push()"),
            "停用/退出没有卸载 AXObserver"
        );
        assert!(
            source.contains("Duration::from_millis(50)"),
            "驱动 tick 太慢，兑现不了 150ms 去抖"
        );
        assert!(
            !source.lines().any(|line| {
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
    }

    #[test]
    fn sqlcipher_upgrade_preserves_a_legacy_plaintext_database() {
        let dir =
            std::env::temp_dir().join(format!("agentguard-audit-path-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("audit-macos.db");
        std::fs::write(&legacy, b"SQLite format 3\0legacy-audit-data").unwrap();

        let encrypted = sqlcipher_audit_db_path(&legacy);
        assert_eq!(encrypted, dir.join("audit-macos.sqlcipher.db"));
        assert_eq!(
            std::fs::read(&legacy).unwrap(),
            b"SQLite format 3\0legacy-audit-data",
            "不得改写或删除旧审计库"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sqlcipher_upgrade_keeps_an_existing_encrypted_path() {
        let dir =
            std::env::temp_dir().join(format!("agentguard-audit-path-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let encrypted = dir.join("audit-macos.db");
        std::fs::write(&encrypted, b"encrypted-bytes-without-sqlite-header").unwrap();

        assert_eq!(sqlcipher_audit_db_path(&encrypted), encrypted);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod session_observer_tests {
    use super::{observers_for_session, privacy_pane_anchor};
    use mac_adapter::MacCapabilities;

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

    /// 一个权限都没有时:不武装任何观察器,但**这不是拒绝开会话的理由**。
    ///
    /// 未授权时仿真与浏览器扩展路径仍然有效(这正是"防护范围:仿真"的含义),而会话本身是
    /// 策略与审计的边界。这条钉住的是"什么都不开"而不是"什么都不做":调用方
    /// (`start_guard_session`)据此不设 `observer_started_ms`,状态机于是如实报
    /// permission_required / degraded,而不是绿灯。
    #[test]
    fn 未授权时不武装任何观察器_但会话仍可开始() {
        assert_eq!(observers_for_session(&caps(false, false)), (false, false));
    }

    /// 决策对了不等于被调用了:上面那条测试只钉"授权矩阵 → 该开什么",删掉
    /// `start_guard_session` 里的武装那一段它照样绿。这条按仓库既有的接线测试写法
    /// (见 `ax_observer_is_wired_into_desktop_driver`)对源码断言:会话开始真的调用了
    /// 两个武装函数,且**在放掉 adapter 锁之后**(它们内部要再锁 adapter —— 不放会死锁)。
    #[test]
    fn 会话开始真的武装观察器_且在放掉adapter锁之后() {
        let source = include_str!("lib.rs");
        let start = source
            .find("fn start_guard_session(")
            .expect("找不到 start_guard_session —— 接线测试需要跟着改");
        let end = source[start..]
            .find("\n#[tauri::command]")
            .map(|i| start + i)
            .unwrap_or(source.len());
        let body = &source[start..end];
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
        let drop_at = body
            .find("drop(adapter);")
            .expect("会话开始没有显式放掉 adapter 锁");
        let arm_at = body.find("arm_ax_observer(").unwrap();
        assert!(
            drop_at < arm_at,
            "必须先 drop(adapter) 再武装:两个武装函数内部会重新锁 state.adapter,不放会死锁"
        );
        // 会话**结束**停观察器这一半一直是对的(P0-3),别在改开始的时候把它弄坏:
        // 开始与结束必须对称,否则又会出现"结束了还在采集"或"开始了没在看"。
        let end_start = source
            .find("fn end_guard_session(")
            .expect("找不到 end_guard_session");
        let end_body = &source[end_start..];
        assert!(
            end_body.contains("state.ax_auto_poll.store(false, Ordering::SeqCst)")
                && end_body.contains("state.sck_auto_poll.store(false, Ordering::SeqCst)"),
            "会话结束没有停掉两个观察器"
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

//! AgentGuard macOS shell: Menu Bar tray + TCC onboarding + MacAdapter simulation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_audit::{
    auto_approve_allowed, default_audit_key_path, ensure_audit_key_file, sqlcipher_enabled,
    AuditRecord, AuditStore, SessionReport, UserDecision,
};
use guard_billing::load_or_free;
use guard_core::confirm_queue::{ConfirmQueue, ResolveOutcome};
use guard_core::event_dedup::{Aggregator, Verdict, REPEAT_COUNT_KEY};
use guard_core::observe_state::{self, StateInputs, Thresholds};
use guard_core::{AutoApprove, ConfirmRequest, Engine};
use guard_intel::load_release;
use guard_netmon::{evaluate_flow, FlowSummary};
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent};
use guard_sync::{sync_to_cache, DevicePolicy};
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
    let mut q = state.pending.lock().map_err(|e| e.to_string())?;
    Ok(q.enqueue(req))
}

#[tauri::command]
fn get_pending_confirm(state: State<'_, AppState>) -> Result<Option<ConfirmDto>, String> {
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
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
    let ResolveOutcome::Resolved { approve, audit_id } = outcome else {
        // Stale:用户看到的请求已经不在了(新会话清掉 / 被挤出 / 已解析过)。不改引擎状态,
        // 让前端重新拉 pending —— 绝不把一个过期的"同意"当作对当前请求的同意。
        return Ok(ResolveDto {
            resolved: false,
            has_next,
        });
    };

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
    // P0-3/P0-5:新会话推进 generation 并清空上一会话遗留的待确认。一个新会话不继承
    // 悬空的确认;上一会话的 request_id 从此解析为 Stale。
    state
        .pending
        .lock()
        .map_err(|e| e.to_string())?
        .bump_generation();
    reset_observation_memory(state.inner())?;
    // 观察器若已在跑(用户先开了 AX 自动轮询再开会话),从现在起算启动宽限;心跳很快会来。
    if state.ax_auto_poll.load(Ordering::Relaxed) || state.sck_auto_poll.load(Ordering::Relaxed) {
        state
            .observer_started_ms
            .store(now_epoch_ms(), Ordering::Relaxed);
    }
    drain_and_process(state.inner(), &mut adapter)?;
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
    let info = start_capture_session().map_err(|e| e.to_string())?;
    *state.sck_streaming.lock().map_err(|e| e.to_string())? = info.native;
    *state.sck_native_ok.lock().map_err(|e| e.to_string())? = info.native;
    *state.sck_message.lock().map_err(|e| e.to_string())? = info.message.clone();
    if info.native {
        start_sck_auto_poller(app, &state);
    } else {
        state.sck_auto_poll.store(false, Ordering::Relaxed);
    }
    Ok(CaptureSessionDto {
        native: info.native,
        message: info.message,
    })
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
    Ok(Some(AxPollDto {
        decisions,
        source_app: "frontmost".into(),
        message: msg,
        suppressed,
        summaries,
    }))
}

#[tauri::command]
fn ax_auto_cmd(
    app: AppHandle,
    state: State<'_, AppState>,
    enable: bool,
) -> Result<AxAutoDto, String> {
    if enable {
        // Start the real observer before the driver. If registration itself is unavailable,
        // keep the 3s fallback alive; capture permission errors still surface immediately.
        let push_result = state
            .adapter
            .lock()
            .map_err(|e| e.to_string())?
            .start_ax_push();
        if let Err(e) = poll_ax_push_once(state.inner()) {
            state
                .adapter
                .lock()
                .map_err(|lock_err| lock_err.to_string())?
                .stop_ax_push();
            return Err(e);
        }
        start_ax_auto_poller(app, &state);
        *state.ax_message.lock().map_err(|e| e.to_string())? = match &push_result {
            Ok(()) => "AXObserver push on (150ms debounce, 800ms ceiling, 3s fallback)".into(),
            Err(e) => format!("AXObserver unavailable ({e}); 3s fallback polling on"),
        };
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
fn sync_device_policy(source: Option<String>) -> Result<String, String> {
    let src = source.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../policies/enterprise-poc.yaml")
            .to_string_lossy()
            .into_owned()
    });
    let cache = {
        let mut p = dirs_next_data();
        p.push("agentguard");
        let _ = std::fs::create_dir_all(&p);
        p.push("device-cache.yaml");
        p
    };
    let policy = sync_to_cache(&src, &cache).map_err(|e| e.to_string())?;
    Ok(format!("{}@{}", policy.policy_id, policy.version))
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
    let state = AppState {
        engine: Mutex::new(build_engine()),
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

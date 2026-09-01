//! AgentGuard Tauri backend: engine + audit + confirm modal + win-adapter simulation.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use guard_audit::{
    auto_approve_allowed, default_audit_key_path, ensure_audit_key_file, sqlcipher_enabled,
    AuditRecord, AuditStore, SessionReport, UserDecision,
};
use guard_billing::load_or_free;
use guard_core::{AutoApprove, ConfirmRequest, Engine};
use guard_intel::load_release;
use guard_netmon::{evaluate_flow, FlowSummary};
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent};
use guard_sync::{sync_to_cache, DevicePolicy};
use serde::Serialize;
use tauri::{Emitter, Manager, State};
use win_adapter::{capabilities, AdapterCapabilities, PlatformAdapter, SimObservation, WinAdapter};

/// The live Windows observer, on Windows only.
///
/// Before this existed the shell's only ingress was seven demo threat buttons plus
/// start/end session: every rule that reads a UI tree or a frame was inert, and
/// `protection_mode` reported "full" from two compile flags. The observer is optional
/// because the shell must still build and run on a host where UI Automation cannot be
/// created — it then reports why, rather than reporting simulation as protection.
#[cfg(windows)]
type NativeObserver = win_adapter::NativeWinAdapter;

struct PendingConfirm {
    audit_id: Option<String>,
    request: ConfirmRequest,
}

struct AppState {
    engine: Mutex<Engine>,
    adapter: Mutex<WinAdapter>,
    auto_approve: Mutex<bool>,
    pending: Mutex<Option<PendingConfirm>>,
    /// The real observer. `None` on a non-Windows build, or when UI Automation could not
    /// be created — and [`AppState::observe_error`] then says which.
    #[cfg(windows)]
    observer: Mutex<Option<NativeObserver>>,
    observe_error: Mutex<Option<String>>,
    /// Set while the auto-poller thread should keep running.
    polling: Arc<AtomicBool>,
}

#[derive(Serialize)]
struct StatusDto {
    rules_loaded: usize,
    policy_id: String,
    audit_enabled: bool,
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
    rule_id: String,
    severity: String,
    human_message: String,
    source_app: String,
    ui_excerpt: Option<String>,
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
fn load_form_schemas() -> Vec<guard_privacy::AppFormSchema> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        manifest.join("../../../policies/forms"),
        PathBuf::from("policies/forms"),
    ] {
        if candidate.is_dir() {
            return guard_privacy::load_form_schemas(candidate);
        }
    }
    Vec::new()
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
        AuditStore::open_with_key(&path, Some(&key)).expect("open encrypted audit db")
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
        std::env::var("AGENTGUARD_TASK_PLANS").map(PathBuf::from).unwrap_or_default(),
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
    let st = engine.status();
    let caps = capabilities();
    let score = engine.privacy_score();
    let ent = load_or_free(entitlement_path());
    let device_policy = DevicePolicy::from_path(device_policy_path()).unwrap_or_default();
    let observing = state.polling.load(Ordering::Relaxed);
    let (protection_mode, protection_summary) = protection_coverage(&caps, observing);
    Ok(StatusDto {
        rules_loaded: st.rules_loaded,
        policy_id: st.policy_id,
        audit_enabled: st.audit_enabled,
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
        observe_error: state
            .observe_error
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .unwrap_or_default(),
        privacy_composite: score.composite,
        pending_confirm: pending.is_some(),
        intel_version: st.intel_version,
        plan: format!("{:?}", ent.plan),
        pro_active: ent.is_active(),
        device_policy_id: device_policy.policy_id,
        protection_mode,
        protection_summary,
    })
}

#[tauri::command]
fn get_pending_confirm(state: State<'_, AppState>) -> Result<Option<ConfirmDto>, String> {
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
    Ok(pending.as_ref().map(|p| ConfirmDto {
        rule_id: p.request.rule_id.clone(),
        severity: p.request.severity.clone(),
        human_message: p.request.human_message.clone(),
        source_app: p.request.source_app.clone(),
        ui_excerpt: p.request.ui_excerpt.clone(),
    }))
}

#[tauri::command]
fn resolve_confirm(state: State<'_, AppState>, approve: bool) -> Result<(), String> {
    let mut pending_guard = state.pending.lock().map_err(|e| e.to_string())?;
    let Some(pending) = pending_guard.take() else {
        return Ok(());
    };
    drop(pending_guard);

    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    if let (Some(store), Some(id)) = (engine.audit(), pending.audit_id.as_ref()) {
        let ud = if approve {
            UserDecision::Approve
        } else {
            UserDecision::Deny
        };
        let _ = store.set_user_decision(id, ud);
    }
    if approve {
        // Allow once: stay unpaused.
        engine.resume();
    } else {
        // Mirror AutoDeny: pause session.
        // process_gated would set paused; we expose via a follow-up event.
        // Use a tiny synthetic path: process_gated with AutoDeny already paused —
        // here we set pause by processing a no-op through deny semantics.
        // Engine::paused is private via resume only — add force_pause via public API.
        drop(engine);
        force_pause(&state)?;
    }
    Ok(())
}

fn force_pause(state: &State<'_, AppState>) -> Result<(), String> {
    // Engine lacks force_pause; approximate by gated deny on a payment marker once.
    // Prefer calling resume-only API: add pause() on Engine.
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    // Use internal: process_gated already has pause — call a helper method.
    engine.pause();
    Ok(())
}

#[tauri::command]
fn list_audit(state: State<'_, AppState>, limit: Option<usize>) -> Result<Vec<AuditRecord>, String> {
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
    app: tauri::AppHandle,
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
        profile: task_profile.map(|p| p.trim().to_string()).filter(|p| !p.is_empty()),
        apps: task_apps.unwrap_or_default(),
        ..Default::default()
    };
    adapter.start_task_session(sid.clone(), "Claude", &task);
    drain_and_process(&state, &mut adapter)?;
    // Observation begins with the session and ends with it. Polling outside a session would
    // record a user's screen with no agent to attribute it to, which is the opposite of what
    // a session-scoped guard is for.
    drop(adapter);
    if capabilities().can_observe() {
        start_auto_poller(app, state.polling.clone());
    }
    Ok(sid)
}

#[tauri::command]
fn end_guard_session(state: State<'_, AppState>) -> Result<(), String> {
    state.polling.store(false, Ordering::Relaxed);
    let mut adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    adapter.end_session("Claude");
    drain_and_process(&state, &mut adapter)?;
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
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let intel = load_intel();
    let ver = intel.version.clone();
    engine.reload_intel(intel);
    Ok(ver)
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
fn ingest_browser_json(state: State<'_, AppState>, payload: String) -> Result<Vec<DecisionDto>, String> {
    use browser_adapter::BrowserAdapter;
    let mut browser = BrowserAdapter::new();
    browser.set_session(Some("browser-ext".into()));
    let events = browser.parse_envelope(&payload).map_err(|e| e.to_string())?;
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
    if approve {
        let d = engine
            .process_gated(event, &AutoApprove)
            .map_err(|e| e.to_string())?;
        return Ok(to_dto(&d));
    }

    // Interactive path: process without auto-deny pause; queue confirm UI.
    let d = engine.process(event).map_err(|e| e.to_string())?;
    if d.require_confirm
        && matches!(d.action, DecisionAction::Block | DecisionAction::Alert)
    {
        let req = ConfirmRequest::from_decision(
            &d,
            &event.source_app,
            engine.last_audit_id().map(|s| s.to_string()),
            event.metadata.get("ui_text").cloned(),
        );
        *state.pending.lock().map_err(|e| e.to_string())? = Some(PendingConfirm {
            audit_id: engine.last_audit_id().map(|s| s.to_string()),
            request: req,
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
fn poll_native_once(state: &State<'_, AppState>) -> Result<(Vec<DecisionDto>, Vec<String>), String> {
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
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let approve = *state.auto_approve.lock().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for event in &outcome.events {
        out.push(process_one(state, &mut engine, event, approve)?);
    }
    Ok((out, outcome.warnings))
}

#[cfg(not(windows))]
fn poll_native_once(_state: &State<'_, AppState>) -> Result<(Vec<DecisionDto>, Vec<String>), String> {
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
    let (decisions, warnings) = poll_native_once(&state)?;
    Ok(PollDto { decisions, warnings })
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
fn start_auto_poller(app: tauri::AppHandle, flag: Arc<AtomicBool>) {
    flag.store(true, Ordering::Relaxed);
    std::thread::spawn(move || {
        let mut consecutive_failures = 0u32;
        while flag.load(Ordering::Relaxed) {
            std::thread::sleep(POLL_INTERVAL);
            if !flag.load(Ordering::Relaxed) {
                break;
            }
            let Some(state) = app.try_state::<AppState>() else {
                break;
            };
            match poll_native_once(&state) {
                Ok((decisions, warnings)) => {
                    consecutive_failures = 0;
                    if decisions.iter().any(|d| d.require_confirm) {
                        let _ = app.emit("confirm-needed", ());
                    }
                    let _ = app.emit(
                        "native-poll",
                        serde_json::json!({ "decisions": decisions, "warnings": warnings }),
                    );
                }
                Err(e) => {
                    consecutive_failures += 1;
                    let _ = app.emit("native-poll-error", serde_json::json!({ "error": e }));
                    // Three in a row is a broken host, not a transient miss. Keep the reason
                    // where the UI can still read it after the loop stops.
                    if consecutive_failures >= 3 {
                        if let Ok(mut slot) = state.observe_error.lock() {
                            *slot = Some(format!("observation stopped after 3 failures: {e}"));
                        }
                        flag.store(false, Ordering::Relaxed);
                        break;
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

fn startup_capabilities() -> AdapterCapabilities {
    #[cfg(windows)]
    {
        on_dedicated_thread("agentguard-capability-probe", capabilities)
    }
    #[cfg(not(windows))]
    {
        capabilities()
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
    let state = AppState {
        engine: Mutex::new(build_engine()),
        adapter: Mutex::new(WinAdapter::new()),
        auto_approve: Mutex::new(false),
        pending: Mutex::new(None),
        #[cfg(windows)]
        observer: Mutex::new(if caps.uia_native.available || caps.frame_capture.available {
            Some(NativeObserver::new().with_schemas(load_form_schemas()))
        } else {
            None
        }),
        observe_error: Mutex::new(observe_error),
        polling: Arc::new(AtomicBool::new(false)),
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
            assert!(path.is_file(), "declared icon {rel} does not exist at {}", path.display());
        }
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
        let worker = super::on_dedicated_thread("agentguard-test-probe", || {
            std::thread::current().id()
        });
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
}

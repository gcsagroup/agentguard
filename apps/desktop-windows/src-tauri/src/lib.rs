//! AgentGuard Tauri backend: engine + audit + confirm modal + win-adapter simulation.

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
use guard_core::observe_state::{self, StateInputs, Thresholds};
use guard_core::{AutoApprove, ConfirmRequest, Engine};
use guard_intel::load_release;
use guard_intel::PublicKeyBytes;
use guard_netmon::{evaluate_flow, FlowSummary};
use guard_schema::{Decision, DecisionAction, EventType, GuardEvent};
use guard_sync::{
    pull_policy_verified, signer_fingerprint, sync_to_cache, sync_to_cache_verified, DevicePolicy,
};
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

struct AppState {
    engine: Mutex<Engine>,
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
    // P1-4:每次有人看状态都先把超时的确认按拒绝处理掉。
    sweep_expired_confirms(&state)?;
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let adapter = state.adapter.lock().map_err(|e| e.to_string())?;
    let pending = state.pending.lock().map_err(|e| e.to_string())?;
    let st = engine.status();
    let caps = &state.capabilities;
    let score = engine.privacy_score();
    let ent = load_or_free(entitlement_path());
    let device_policy = DevicePolicy::from_path(device_policy_path()).unwrap_or_default();
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
    // 一个轮询循环同时驱动 UI 树和窗口捕获,所以"在跑"是 0 或 1。
    let observers_running = observing as u32;
    let derived = observe_state::derive(
        &StateInputs {
            session_active: adapter.has_session(),
            paused: st.paused,
            pending_confirm: !pending.is_empty(),
            observers_available,
            observers_running,
            observer_error: observe_error.as_deref(),
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
        audit_error: st.audit_error.unwrap_or_default(),
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

/// P1-4:待确认落盘(不含观测文本摘录),重启后不静默丢。与 macOS 壳子同形。
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

/// P1-4:启动时处理上次遗留的待确认——逐条写 Timeout 回执再删文件;有一条写不进就保留文件。
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

/// P1-4:超时的确认按拒绝处理:Timeout 回执、引擎暂停、落盘、计数。
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
        engine.pause();
    }
    state
        .confirms_timed_out
        .fetch_add(ids.len(), Ordering::Relaxed);
    persist_pending(state);
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
    let (outcome, has_next) = {
        let mut q = state.pending.lock().map_err(|e| e.to_string())?;
        let outcome = q.resolve(request_id, approve);
        (outcome, !q.is_empty())
    };
    persist_pending(&state);
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

    {
        let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
        // 审计落库失败 = 确认失败(报告 P0-5:以前是 `let _ = ...`,回执没写却报成功)。
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
        }
    }
    if !approve {
        force_pause(&state)?;
    }
    Ok(ResolveDto {
        resolved: true,
        has_next,
    })
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
    // P0-3/P0-5:新会话推进 generation 并清空上一会话遗留的待确认。
    state
        .pending
        .lock()
        .map_err(|e| e.to_string())?
        .bump_generation();
    persist_pending(&state);
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
    // P0-3:会话结束清空待确认队列(观察器已由 polling=false 停掉)。
    state
        .pending
        .lock()
        .map_err(|e| e.to_string())?
        .bump_generation();
    persist_pending(&state);
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
    let mut engine = state.engine.lock().map_err(|e| e.to_string())?;
    let intel = load_intel();
    let ver = intel.version.clone();
    engine.reload_intel(intel);
    Ok(ver)
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
        let id = state
            .pending
            .lock()
            .map_err(|e| e.to_string())?
            .enqueue_at(req, now_epoch_ms());
        persist_pending(state);
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
    let engine = build_engine();
    // P1-4:上次运行没处理完的确认——逐条写 Timeout 回执。
    let orphaned = restore_orphaned_confirms(&engine);
    // P1-9:只恢复能再验过签的缓存策略;没公钥就只显示、不执法。
    let mut engine = engine;
    let policy_status = restore_device_policy_at_startup(&mut engine);
    let state = AppState {
        engine: Mutex::new(engine),
        adapter: Mutex::new(WinAdapter::new()),
        auto_approve: Mutex::new(false),
        pending: Mutex::new(ConfirmQueue::new(64)),
        capabilities: caps.clone(),
        #[cfg(windows)]
        observer: Mutex::new(
            if caps.uia_native.available || caps.frame_capture.available {
                Some(NativeObserver::new().with_schemas(load_form_schemas()))
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

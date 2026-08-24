//! C ABI surface for Swift / macOS hosts.
//!
//! ```text
//! ag_engine_new(rules_path, policy_path) -> *mut EngineHandle
//! ag_engine_free(handle)
//! ag_engine_process_json(handle, event_json) -> *mut c_char  // caller frees via ag_string_free
//! ag_string_free(s)
//! ```

use guard_core::Engine;
use guard_schema::GuardEvent;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// Opaque engine handle for C callers.
pub struct EngineHandle {
    engine: Engine,
}

fn cstr_to_path<'a>(path: *const c_char) -> Option<&'a std::path::Path> {
    if path.is_null() {
        return None;
    }
    // SAFETY: caller must pass a valid NUL-terminated C string when non-null.
    let s = unsafe { CStr::from_ptr(path) }.to_str().ok()?;
    Some(std::path::Path::new(s))
}

/// Create a new engine. Returns null on failure.
///
/// `policy_path` may be null to use the default GuardContract.
///
/// Equivalent to [`ag_engine_new_with_registry`] with no registry, which means **no
/// app-identity verification**: a registered app's deeplink allow-list and HIGH-tier
/// flow clearance then rest on its name, the field AgentScan's package-name forgery
/// targets. Kept for ABI compatibility; new hosts should pass a registry.
#[no_mangle]
pub extern "C" fn ag_engine_new(
    rules_path: *const c_char,
    policy_path: *const c_char,
) -> *mut EngineHandle {
    ag_engine_new_with_registry(rules_path, policy_path, ptr::null())
}

/// Create a new engine with a known-app registry for verified app identity
/// (AgentScan §3.5 package-name forgery).
///
/// `known_apps_path` may be null. A path that exists but does not parse is a hard
/// failure (null return) rather than a silent fallback: a host that asked for
/// identity verification and did not get it would run with the checks quietly off.
#[no_mangle]
pub extern "C" fn ag_engine_new_with_registry(
    rules_path: *const c_char,
    policy_path: *const c_char,
    known_apps_path: *const c_char,
) -> *mut EngineHandle {
    let rules = match cstr_to_path(rules_path) {
        Some(p) => p,
        None => return ptr::null_mut(),
    };

    let mut engine = match Engine::from_paths(rules, cstr_to_path(policy_path)) {
        Ok(e) => e,
        Err(_) => return ptr::null_mut(),
    };

    // Task plans live beside the registry: an operator who ships one ships both, and
    // a separate FFI entry point per policy file would guarantee some host wires only
    // one of them.
    if let Some(dir) = cstr_to_path(known_apps_path).and_then(|p| p.parent()) {
        let plans = dir.join("task-plans.yaml");
        if plans.exists() {
            match std::fs::read_to_string(&plans)
                .ok()
                .and_then(|raw| guard_schema::TaskPlanLibrary::from_yaml_str(&raw).ok())
            {
                Some(lib) => engine = engine.with_task_plans(lib),
                None => return ptr::null_mut(),
            }
        }
        let agents = dir.join("agent-registry.yaml");
        if agents.exists() {
            match std::fs::read_to_string(&agents)
                .ok()
                .and_then(|raw| guard_schema::AgentRegistry::from_yaml_str(&raw).ok())
            {
                Some(reg) => engine = engine.with_agents(reg),
                None => return ptr::null_mut(),
            }
        }
    }
    if let Some(p) = cstr_to_path(known_apps_path) {
        let policy = match std::fs::read_to_string(p)
            .ok()
            .and_then(|raw| guard_schema::KnownAppsPolicy::from_yaml_str(&raw).ok())
        {
            Some(policy) => policy,
            None => return ptr::null_mut(),
        };
        engine = engine.with_known_apps(policy);
    }

    Box::into_raw(Box::new(EngineHandle { engine }))
}

/// Destroy an engine handle created by [`ag_engine_new`].
///
/// # Safety
///
/// `handle` must be null, or a pointer returned by [`ag_engine_new`] /
/// [`ag_engine_new_with_registry`] that has not already been passed here. The pointer is
/// reboxed and dropped, so it dangles afterwards: freeing it twice, using it after this
/// call, or handing over a pointer this library did not allocate is undefined behaviour.
/// The engine is not internally synchronised, so no other thread may be inside
/// [`ag_engine_process_json`] with the same handle when this runs.
#[no_mangle]
pub unsafe extern "C" fn ag_engine_free(handle: *mut EngineHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Process a JSON-serialized [`GuardEvent`]; returns Decision JSON or null on error.
///
/// # Safety
///
/// `handle` must be null, or a live handle from [`ag_engine_new`] /
/// [`ag_engine_new_with_registry`] that has not been freed. The call takes a unique
/// `&mut` borrow of that engine and the engine carries per-session state, so the same
/// handle must not be in use on another thread for the duration.
///
/// `json` must be null, or point to a NUL-terminated string that stays allocated and
/// unmodified until this function returns; bytes that are not valid UTF-8 or not valid
/// event JSON are handled, and only produce a null return.
///
/// A non-null return is an owned, heap-allocated C string: release it with
/// [`ag_string_free`] and with nothing else.
#[no_mangle]
pub unsafe extern "C" fn ag_engine_process_json(
    handle: *mut EngineHandle,
    json: *const c_char,
) -> *mut c_char {
    if handle.is_null() || json.is_null() {
        return ptr::null_mut();
    }

    let json_str = match CStr::from_ptr(json).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let event: GuardEvent = match serde_json::from_str(json_str) {
        Ok(e) => e,
        Err(_) => return ptr::null_mut(),
    };

    let handle = &mut *handle;
    let decision = match handle.engine.process(&event) {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    match serde_json::to_string(&decision)
        .ok()
        .and_then(|s| CString::new(s).ok())
    {
        Some(c) => c.into_raw(),
        None => ptr::null_mut(),
    }
}

/// Free strings returned by [`ag_engine_process_json`].
///
/// # Safety
///
/// `s` must be null, or exactly a pointer returned by [`ag_engine_process_json`] and not
/// yet freed. The allocation's length is recovered by scanning to the NUL terminator, so
/// the buffer must still hold the string this library wrote — a caller that overwrote
/// bytes, moved the terminator, or reallocated the block makes this undefined behaviour,
/// as does freeing it twice or releasing it through the C allocator's `free`.
#[no_mangle]
pub unsafe extern "C" fn ag_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::{DecisionAction, EventType, Severity};
    use std::collections::HashMap;
    use std::ffi::CString;

    fn rules_yaml_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../guard-schema/rules/p0_rules.yaml")
    }

    #[test]
    fn smoke_process_json_via_ffi_logic() {
        let rules = rules_yaml_path();
        if !rules.exists() {
            return;
        }

        let rules_c = CString::new(rules.to_string_lossy().as_bytes()).unwrap();
        let handle = ag_engine_new(rules_c.as_ptr(), ptr::null());
        assert!(!handle.is_null());

        let mut meta = HashMap::new();
        meta.insert("ui_text".into(), "请确认支付 $99".into());
        let event = GuardEvent {
            event_id: "ffi-1".into(),
            timestamp_ms: 1,
            platform: "macos".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "Claude".into(),
            agent_context_id: None,
            metadata: meta,
        };
        let event_json = serde_json::to_string(&event).unwrap();
        let event_c = CString::new(event_json).unwrap();

        let out = unsafe { ag_engine_process_json(handle, event_c.as_ptr()) };
        assert!(!out.is_null());

        let decision_json = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        let decision: guard_schema::Decision = serde_json::from_str(decision_json).unwrap();
        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.severity, Severity::Critical);

        unsafe {
            ag_string_free(out);
            ag_engine_free(handle);
        }
    }
}

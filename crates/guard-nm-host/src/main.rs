//! Chrome Native Messaging host.
//! Protocol: u32 LE length + UTF-8 JSON on stdin/stdout.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use browser_adapter::BrowserAdapter;
use guard_audit::AuditStore;
use guard_core::{AutoDeny, Engine};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
struct HostResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    processed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decisions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn read_message() -> Result<Option<Value>> {
    let mut stdin = std::io::stdin().lock();
    let mut len_buf = [0u8; 4];
    match stdin.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 10_000_000 {
        anyhow::bail!("native message too large: {len}");
    }
    let mut buf = vec![0u8; len];
    stdin.read_exact(&mut buf)?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

fn write_message(value: &Value) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    let len = (data.len() as u32).to_le_bytes();
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&len)?;
    stdout.write_all(&data)?;
    stdout.flush()?;
    Ok(())
}

fn rules_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_RULES") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = manifest.join("../guard-schema/rules/p0_rules.yaml");
    if p.exists() {
        p
    } else {
        PathBuf::from("crates/guard-schema/rules/p0_rules.yaml")
    }
}

fn audit_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTGUARD_AUDIT_DB") {
        return PathBuf::from(p);
    }
    std::env::temp_dir().join("agentguard-nm-audit.db")
}

/// Known-app registry, for verified app identity (AgentScan §3.5).
///
/// The browser host cannot attest anything — a page has no signing certificate —
/// so this only ever yields the name-based deeplink allow-list here. It is loaded
/// anyway because *not* loading it silently disabled the allow-list entirely, and
/// because the registry is where a deployment expresses which apps it knows.
fn known_apps_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AGENTGUARD_KNOWN_APPS") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = manifest.join("../../policies/known-apps.yaml");
    p.exists().then_some(p)
}

/// Task plan library path, same resolution shape as the registry.
fn task_plans_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AGENTGUARD_TASK_PLANS") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = manifest.join("../../policies/task-plans.yaml");
    p.exists().then_some(p)
}

fn load_task_plans(engine: Engine) -> Engine {
    let Some(path) = task_plans_path() else {
        return engine;
    };
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| guard_schema::TaskPlanLibrary::from_yaml_str(&raw).ok())
    {
        Some(plans) => engine.with_task_plans(plans),
        None => {
            eprintln!(
                "agentguard: could not load task plan library {}",
                path.display()
            );
            engine
        }
    }
}

fn agent_registry_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AGENTGUARD_AGENT_REGISTRY") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = manifest.join("../../policies/agent-registry.yaml");
    p.exists().then_some(p)
}

fn load_agents(engine: Engine) -> Engine {
    let Some(path) = agent_registry_path() else {
        return engine;
    };
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| guard_schema::AgentRegistry::from_yaml_str(&raw).ok())
    {
        Some(reg) => engine.with_agents(reg),
        None => {
            eprintln!(
                "agentguard: could not load agent registry {}",
                path.display()
            );
            engine
        }
    }
}

fn load_known_apps(engine: Engine) -> Engine {
    let Some(path) = known_apps_path() else {
        return engine;
    };
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| guard_schema::KnownAppsPolicy::from_yaml_str(&raw).ok())
    {
        Some(policy) => engine.with_known_apps(policy),
        None => {
            // stderr, not silence: an unparseable registry means every app is
            // unregistered and nobody would notice.
            eprintln!(
                "agentguard: could not load known-apps registry {}",
                path.display()
            );
            engine
        }
    }
}

fn process_payload(
    engine: &mut Engine,
    adapter: &mut BrowserAdapter,
    msg: &Value,
) -> Result<HostResponse> {
    let raw = serde_json::to_string(msg)?;
    let events = adapter.parse_envelope(&raw).unwrap_or_default();
    if events.is_empty() && msg.get("type").and_then(|t| t.as_str()) != Some("browser_events") {
        // ping / handshake
        return Ok(HostResponse {
            ok: true,
            processed: Some(0),
            decisions: None,
            error: None,
        });
    }
    let mut decisions = Vec::new();
    for event in &events {
        let d = engine.process_gated(event, &AutoDeny)?;
        decisions.push(format!("{}:{:?}", d.rule_id, d.action));
    }
    Ok(HostResponse {
        ok: true,
        processed: Some(events.len()),
        decisions: Some(decisions),
        error: None,
    })
}

fn main() -> Result<()> {
    let store = AuditStore::open(audit_path()).context("open audit db")?;
    let mut engine = load_agents(load_task_plans(load_known_apps(
        Engine::from_paths(rules_path(), None::<PathBuf>)?.with_audit(store),
    )));
    let mut adapter = BrowserAdapter::new();
    adapter.set_session(Some("native-messaging".into()));

    while let Some(msg) = read_message()? {
        let resp = match process_payload(&mut engine, &mut adapter, &msg) {
            Ok(r) => r,
            Err(e) => HostResponse {
                ok: false,
                processed: None,
                decisions: None,
                error: Some(e.to_string()),
            },
        };
        write_message(&serde_json::to_value(resp)?)?;
    }
    Ok(())
}

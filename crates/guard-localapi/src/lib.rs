//! Local loopback HTTP API for AgentGuard status / audit / confirm hooks.
//!
//! Intended for first-party agents and desktop companions on `127.0.0.1` only.
//! All `/v1/*` routes require `Authorization: Bearer <token>` (`/health` is open).

use anyhow::{bail, Context, Result};
use guard_audit::{AuditStore, SessionReport};
use guard_core::Engine;
use guard_schema::RuleSet;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, StatusCode};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub rules_loaded: usize,
    pub policy_id: String,
    pub paused: bool,
    pub audit_enabled: bool,
    pub intel_version: String,
    pub privacy_composite: f32,
    pub sqlcipher: bool,
    /// 当前锁存的环境风险是不是由一次**完整**调查确定的。
    ///
    /// `false` 意味着"不知道",而不是"干净" —— 这两个答案只有第一个是好消息。
    pub env_surveyed: bool,
    /// 设备上有东西能看到智能体输入的内容。
    pub env_input_observed: bool,
    /// 设备上有东西能读日志。
    pub env_log_readable: bool,
    /// 具体是哪些 —— 四张风险清单的并集。
    ///
    /// 放进状态里的理由不只是给测试用:一个运维要能从外面看到"这台设备现在
    /// 站着一个什么风险",否则那个锁存状态只存在于进程内存里,谁也看不见。
    /// 这也让"伪造的干净调查清不掉锁存风险"这件事从**外部**可验证。
    pub env_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmBody {
    pub approve: bool,
}

pub struct ApiState {
    pub engine: Mutex<Engine>,
    pub audit_db: PathBuf,
    /// Envelope ingress from the Android companion (over `adb reverse`).
    pub android: Mutex<android_adapter::AndroidAdapter>,
}

pub struct ApiConfig {
    pub bind: SocketAddr,
    pub rules: PathBuf,
    pub audit_db: PathBuf,
    pub intel: Option<PathBuf>,
    /// Bearer token required for `/v1/*`. Generated if empty at serve time.
    pub token: String,
    /// Permit non-loopback bind (Android↔desktop over Wi-Fi). Still requires
    /// the bearer token on every route; plain HTTP, so keep to trusted LANs.
    pub allow_lan: bool,
    /// Device audit signing key (Aura §4.4.6 attribution). When set, every audit
    /// record and decision receipt written by this server is signed. `None` =
    /// hash chain only: tamper-evident, but not attributed to anyone.
    pub audit_signing_key: Option<PathBuf>,
    /// Known-app registry for verified app identity (AgentScan §3.5 package-name
    /// forgery). `None` = no identity verification at all: a registered app's
    /// deeplink allow-list and HIGH-tier flow clearance then rest on a name, which
    /// is the field the attack forges.
    ///
    /// This server is what the Android companion relays into, so it is the one place
    /// the registry has to be loadable — the mechanism existed for a full iteration
    /// while being reachable from nothing but the eval harness.
    pub known_apps: Option<PathBuf>,
    /// Task plan library for trajectory alignment (Aura §4.3.2). `None` = the label
    /// comparison only, which cannot see a sequence that drifts while keeping its
    /// task label.
    pub task_plans: Option<PathBuf>,
    /// Agent identity registry (Aura pillar i). `None` = no action is attributable to
    /// a particular agent; `agent_context_id` is whatever the agent said.
    pub agent_registry: Option<PathBuf>,
    /// 适配器身份注册表。`None` 表示**没有任何**适配器断言能移除风险 ——
    /// 比配了注册表更保守,不是更宽松。
    ///
    /// 这条路才是这个机制真正要保护的入口:`/v1/events` 之前只有一道 bearer 令牌,
    /// 于是本机任何拿到令牌的进程都能伪造一份"干净"的环境调查,把一个已锁存的
    /// Critical 风险清掉。
    pub adapter_registry: Option<PathBuf>,
    /// 明确允许一个弱令牌启动。
    ///
    /// 默认 `false`,而且**没有**默认构造 —— 每个调用点都必须自己写出这个选择。
    /// 一个能被猜到的 bearer 令牌在这个 API 上不是小事:`/v1/pause` 能把守卫
    /// 停掉,`/v1/confirm` 能替人回答确认框。也就是说,猜到令牌 = 绕过整个产品。
    pub insecure_token: bool,
}

/// bearer 令牌的最小长度。
///
/// 24 个字符不是密码学下限,是**在线猜测**下限:这个服务器没有速率限制,
/// 一个本机进程可以按网络速度试。自动生成的令牌是 `ag_` + 32 个十六进制字符,
/// 远在这条线之上;这条线管的是人手输入的那些。
pub const MIN_API_TOKEN_LEN: usize = 24;

/// 明显可猜的令牌,逐字命中即拒。
///
/// 第一个就是 `dev-secret` —— 它曾经是本仓库 `make api-serve` 的默认值,
/// 也印在 docs/local-api.md 里。也就是说,任何按文档跑起来的部署,
/// 令牌都是一个写在公开文档里的字符串。长度检查其实已经能拦住它,
/// 这张表存在的意义是让**错误信息**能指名道姓:
/// "dev-secret 是本项目文档里的示例值",比"令牌太短"有用得多。
const WELL_KNOWN_API_TOKENS: &[&str] = &[
    "dev-secret",
    "devsecret",
    "secret",
    "changeme",
    "change-me",
    "password",
    "token",
    "test",
    "testing",
    "agentguard",
    "admin",
    "letmein",
];

/// 为什么一个令牌不能用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenWeakness {
    /// 短于 [`MIN_API_TOKEN_LEN`]。
    TooShort { len: usize },
    /// 在 [`WELL_KNOWN_API_TOKENS`] 里(不区分大小写)。
    WellKnown { token: String },
}

impl std::fmt::Display for TokenWeakness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { len } => write!(
                f,
                "bearer 令牌只有 {len} 个字符,至少需要 {MIN_API_TOKEN_LEN} 个"
            ),
            Self::WellKnown { token } => write!(
                f,
                "bearer 令牌 '{token}' 是公开的示例值(本仓库的文档里就有这个字符串)"
            ),
        }
    }
}

/// 令牌是否弱到不该用来守 `/v1/*`。
///
/// 大小写不敏感、去首尾空白后再比:`Dev-Secret ` 和 `dev-secret` 是同一个令牌。
pub fn api_token_weakness(token: &str) -> Option<TokenWeakness> {
    let t = token.trim();
    let lower = t.to_ascii_lowercase();
    if WELL_KNOWN_API_TOKENS.contains(&lower.as_str()) {
        return Some(TokenWeakness::WellKnown {
            token: t.to_string(),
        });
    }
    if t.chars().count() < MIN_API_TOKEN_LEN {
        return Some(TokenWeakness::TooShort {
            len: t.chars().count(),
        });
    }
    None
}

/// Resolve API token: explicit > `AGENTGUARD_API_TOKEN` > random UUID.
///
/// 自动生成的那条路一定是强的;弱令牌只可能来自前两条 —— 命令行和环境变量,
/// 也就是人手写的地方。强度检查在 [`serve`] 里,因为那才是**唯一**必经之路:
/// 放在这里的话,任何直接构造 `ApiConfig` 的嵌入方都绕过去了。
pub fn resolve_api_token(explicit: Option<String>) -> String {
    if let Some(t) = explicit.filter(|s| !s.is_empty()) {
        return t;
    }
    if let Ok(t) = std::env::var("AGENTGUARD_API_TOKEN") {
        if !t.is_empty() {
            return t;
        }
    }
    format!("ag_{}", Uuid::new_v4().simple())
}

impl ApiState {
    pub fn from_config(cfg: &ApiConfig) -> Result<Self> {
        let rules = RuleSet::from_path(&cfg.rules)
            .with_context(|| format!("load rules {}", cfg.rules.display()))?;
        let store = AuditStore::open(&cfg.audit_db)?;
        let store = match &cfg.audit_signing_key {
            Some(path) => {
                // load_existing, not load_or_create: generating a key here would
                // start signing with a key whose public half exists nowhere, which
                // then "verifies" against the DB-embedded copy while proving nothing.
                let key = guard_audit::FileDeviceKey::load_existing(path)
                    .with_context(|| format!("load audit signing key {}", path.display()))?;
                store.with_signer(Box::new(key))?
            }
            None => store,
        };
        let mut engine =
            Engine::new(rules, guard_schema::GuardContract::default()).with_audit(store);
        if let Some(p) = &cfg.intel {
            let intel = guard_intel::load_or_default(p).unwrap_or_default();
            engine = engine.with_intel(intel);
        }
        if let Some(p) = &cfg.known_apps {
            // Loud failure, not a silent fallback: a registry the operator asked for
            // and did not get would leave identity checks quietly disabled.
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("read known-apps registry {}", p.display()))?;
            let policy = guard_schema::KnownAppsPolicy::from_yaml_str(&raw)
                .with_context(|| format!("parse known-apps registry {}", p.display()))?;
            engine = engine.with_known_apps(policy);
        }
        if let Some(p) = &cfg.task_plans {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("read task plan library {}", p.display()))?;
            let plans = guard_schema::TaskPlanLibrary::from_yaml_str(&raw)
                .with_context(|| format!("parse task plan library {}", p.display()))?;
            engine = engine.with_task_plans(plans);
        }
        if let Some(p) = &cfg.agent_registry {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("read agent registry {}", p.display()))?;
            let reg = guard_schema::AgentRegistry::from_yaml_str(&raw)
                .with_context(|| format!("parse agent registry {}", p.display()))?;
            engine = engine.with_agents(reg);
        }
        if let Some(p) = &cfg.adapter_registry {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("read adapter registry {}", p.display()))?;
            let reg = guard_schema::AdapterRegistry::from_yaml_str(&raw)
                .with_context(|| format!("parse adapter registry {}", p.display()))?;
            engine = engine.with_adapters(reg);
        }
        Ok(Self {
            engine: Mutex::new(engine),
            audit_db: cfg.audit_db.clone(),
            android: Mutex::new(android_adapter::AndroidAdapter::new()),
        })
    }

    pub fn snapshot(&self) -> Result<StatusSnapshot> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine lock"))?;
        let st = engine.status();
        let score = engine.privacy_score();
        let er = engine.env_risk().clone();
        Ok(StatusSnapshot {
            rules_loaded: st.rules_loaded,
            policy_id: st.policy_id,
            paused: st.paused,
            audit_enabled: st.audit_enabled,
            intel_version: st.intel_version,
            privacy_composite: score.composite,
            sqlcipher: guard_audit::sqlcipher_enabled(),
            env_surveyed: er.surveyed,
            env_input_observed: er.input_is_observed(),
            env_log_readable: er.log_is_readable(),
            env_findings: {
                let mut v: Vec<String> = er
                    .broadcast_input_receivers
                    .iter()
                    .chain(er.foreign_a11y_services.iter())
                    .chain(er.text_capturing_services.iter())
                    .chain(er.log_readers.iter())
                    .cloned()
                    .collect();
                v.sort_unstable();
                v.dedup();
                v
            },
        })
    }
}

/// 取一个请求头的值(名字不区分大小写)。
fn header(req: &tiny_http::Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().trim().to_string())
        .filter(|v| !v.is_empty())
}

fn bearer_ok(request: &Request, expected: &str) -> bool {
    for h in request.headers() {
        if h.field.equiv("Authorization") {
            let v = h.value.as_str().trim();
            let prefix = "Bearer ";
            if let Some(tok) = v.strip_prefix(prefix) {
                return constant_time_eq(tok.as_bytes(), expected.as_bytes());
            }
            return false;
        }
    }
    false
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Serve loopback API until `shutdown` is set (or forever if None).
pub fn serve(cfg: ApiConfig, shutdown: Option<Arc<AtomicBool>>) -> Result<()> {
    if !cfg.bind.ip().is_loopback() && !cfg.allow_lan {
        bail!(
            "refusing non-loopback bind {} (pass --allow-lan to opt in; bearer token still required)",
            cfg.bind
        );
    }
    if !cfg.bind.ip().is_loopback() {
        eprintln!(
            "warning: serving on non-loopback {}; token auth required on all /v1/* routes (plain HTTP — trusted LANs only)",
            cfg.bind
        );
    }
    if cfg.token.is_empty() {
        bail!("api token must not be empty");
    }
    // 弱令牌默认不让启动。这个 API 上 `/v1/pause` 能停掉守卫、`/v1/confirm` 能
    // 替人回答确认框,所以猜到令牌等于绕过整个产品 —— 拒绝的门槛应该和这个
    // 后果相称,而不是打印一行警告然后照样开。
    if let Some(weak) = api_token_weakness(&cfg.token) {
        if !cfg.insecure_token {
            bail!(
                "拒绝启动:{weak}。\n\
                 换一个:AGENTGUARD_API_TOKEN=$(agentguard api-token) 或任意 {MIN_API_TOKEN_LEN} 字符以上的随机串。\n\
                 确实只是本机临时调试,可以加 --insecure-token 明确覆盖。"
            );
        }
        eprintln!("warning: {weak};已被 --insecure-token 明确覆盖");
    }
    let token = cfg.token.clone();
    let state = Arc::new(ApiState::from_config(&cfg)?);
    let server = tiny_http::Server::http(cfg.bind).map_err(|e| anyhow::anyhow!("bind: {e}"))?;
    eprintln!("guard local API on http://{}/v1/status", cfg.bind);
    eprintln!("auth: Authorization: Bearer <token>  (token printed once below)");
    eprintln!("AGENTGUARD_API_TOKEN={token}");

    loop {
        if shutdown
            .as_ref()
            .map(|s| s.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            break;
        }
        let mut request = match server.recv_timeout(std::time::Duration::from_millis(400)) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("recv: {e}");
                continue;
            }
        };
        let url = request.url().to_string();
        let method = request.method().clone();
        let path = url.split('?').next().unwrap_or(&url);

        if path.starts_with("/v1/") && !bearer_ok(&request, &token) {
            let _ = request.respond(json_error(401, "unauthorized"));
            continue;
        }

        let response = match (&method, path) {
            (Method::Get, "/health") | (Method::Get, "/health/") => json_response(
                200,
                r#"{"ok":true,"service":"agentguard-localapi","auth":"bearer"}"#,
            ),
            (Method::Get, "/v1/status") | (Method::Get, "/v1/status/") => match state.snapshot() {
                Ok(s) => json_response(200, &serde_json::to_string(&s).unwrap_or_default()),
                Err(e) => json_error(500, &e.to_string()),
            },
            (Method::Get, "/v1/audit/recent") | (Method::Get, "/v1/audit/recent/") => {
                let limit = query_usize(&url, "limit").unwrap_or(50);
                match state.engine.lock() {
                    Ok(engine) => match engine.audit() {
                        Some(store) => match store.list_recent(limit) {
                            Ok(rows) => json_response(
                                200,
                                &serde_json::to_string(&rows).unwrap_or_default(),
                            ),
                            Err(e) => json_error(500, &e.to_string()),
                        },
                        None => json_error(503, "audit disabled"),
                    },
                    Err(_) => json_error(500, "engine lock"),
                }
            }
            (Method::Get, "/v1/audit/report") | (Method::Get, "/v1/audit/report/") => {
                let limit = query_usize(&url, "limit").unwrap_or(500);
                match state.engine.lock() {
                    Ok(engine) => match engine.audit() {
                        Some(store) => match store.list_recent(limit) {
                            Ok(rows) => {
                                let report = SessionReport::from_records(&rows);
                                json_response(
                                    200,
                                    &serde_json::to_string(&report).unwrap_or_default(),
                                )
                            }
                            Err(e) => json_error(500, &e.to_string()),
                        },
                        None => json_error(503, "audit disabled"),
                    },
                    Err(_) => json_error(500, "engine lock"),
                }
            }
            (Method::Post, "/v1/resume") | (Method::Post, "/v1/resume/") => {
                match state.engine.lock() {
                    Ok(mut engine) => {
                        engine.resume();
                        json_response(200, r#"{"ok":true,"paused":false}"#)
                    }
                    Err(_) => json_error(500, "engine lock"),
                }
            }
            (Method::Post, "/v1/pause") | (Method::Post, "/v1/pause/") => {
                match state.engine.lock() {
                    Ok(mut engine) => {
                        engine.pause();
                        json_response(200, r#"{"ok":true,"paused":true}"#)
                    }
                    Err(_) => json_error(500, "engine lock"),
                }
            }
            (Method::Post, "/v1/confirm") | (Method::Post, "/v1/confirm/") => {
                match read_json::<ConfirmBody>(&mut request) {
                    Ok(body) => match state.engine.lock() {
                        Ok(mut engine) => {
                            if body.approve {
                                engine.resume();
                            } else {
                                engine.pause();
                            }
                            json_response(
                                200,
                                &format!(
                                    r#"{{"ok":true,"approve":{},"paused":{}}}"#,
                                    body.approve, !body.approve
                                ),
                            )
                        }
                        Err(_) => json_error(500, "engine lock"),
                    },
                    Err(e) => json_error(400, &e.to_string()),
                }
            }
            (Method::Post, "/v1/events") | (Method::Post, "/v1/events/") => {
                // Android companion envelope ingress (companion → desktop over
                // `adb reverse tcp:8788 tcp:8788`, stays loopback on the host).
                // 适配器签名走**请求头**,不进 body。签名要签的就是 body 的原始字节,
                // 把签名塞进它自己要签的 JSON 里就必须先规范化那个 JSON ——
                // 而那正是这个设计刻意绕开的陷阱。
                let sig_adapter = header(&request, guard_schema::ADAPTER_HEADER_ID);
                let sig_value = header(&request, guard_schema::ADAPTER_HEADER_SIGNATURE);
                let sig_ts = header(&request, guard_schema::ADAPTER_HEADER_TIMESTAMP)
                    .and_then(|v| v.parse::<i64>().ok());

                let mut body = String::new();
                if let Err(e) = std::io::Read::read_to_string(&mut request.as_reader(), &mut body) {
                    json_error(400, &e.to_string())
                } else {
                    let parsed = match state.android.lock() {
                        Ok(mut adapter) => adapter.parse_envelope(&body),
                        Err(_) => {
                            let _ = request.respond(json_error(500, "adapter lock"));
                            continue;
                        }
                    };
                    match parsed {
                        Err(e) => json_error(400, &format!("bad envelope: {e}")),
                        Ok(events) => match state.engine.lock() {
                            Err(_) => json_error(500, "engine lock"),
                            Ok(mut engine) => {
                                // 验的是**线上那串字节**,在解析之前就已经拿到了。
                                // 验不过一律退化成"未签名"(可以加风险、不能清风险),
                                // 而不是拒掉这个请求:适配器时钟偏了、注册表还没配、
                                // 旧版本适配器,都不该让守卫瞎掉。
                                let adapter_identity = match (&sig_adapter, &sig_value, sig_ts) {
                                    (Some(id), Some(sig), Some(ts)) => engine.verify_adapter_body(
                                        id,
                                        guard_schema::ANDROID_ENVELOPE_FORMAT,
                                        "android",
                                        ts,
                                        body.as_bytes(),
                                        sig,
                                    ),
                                    _ => guard_schema::AdapterIdentity::Unsigned,
                                };
                                let mut outcomes = Vec::new();
                                let mut failed = None;
                                for ev in &events {
                                    match engine.process_from_adapter(ev, &adapter_identity) {
                                        // `require_confirm` and the message are part of the
                                        // response because otherwise a companion cannot
                                        // implement confirmation at all: the phone posted an
                                        // event, learned the action was a Block, and had
                                        // nothing to show the user and nothing to wait for.
                                        // A one-way relay makes Aura's Critical Node gate a
                                        // desktop-only feature while the matrix counts it as
                                        // covered on Android.
                                        Ok(d) => outcomes.push(serde_json::json!({
                                            "event_id": ev.event_id,
                                            "action": format!("{:?}", d.action),
                                            "rule_id": d.rule_id,
                                            "severity": format!("{:?}", d.severity),
                                            "require_confirm": d.require_confirm,
                                            "human_message": d.human_message,
                                        })),
                                        Err(e) => {
                                            failed = Some(e.to_string());
                                            break;
                                        }
                                    }
                                }
                                if let Some(e) = failed {
                                    json_error(500, &e)
                                } else {
                                    json_response(
                                        200,
                                        &serde_json::json!({
                                            "ok": true,
                                            "ingested": outcomes.len(),
                                            "decisions": outcomes,
                                        })
                                        .to_string(),
                                    )
                                }
                            }
                        },
                    }
                }
            }
            _ => json_error(404, "not found"),
        };
        let _ = request.respond(response);
    }
    Ok(())
}

fn query_usize(url: &str, key: &str) -> Option<usize> {
    let q = url.split_once('?')?.1;
    for part in q.split('&') {
        let mut it = part.splitn(2, '=');
        if it.next()? == key {
            return it.next()?.parse().ok();
        }
    }
    None
}

fn read_json<T: for<'de> Deserialize<'de>>(request: &mut tiny_http::Request) -> Result<T> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(request.as_reader(), &mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn json_response(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(body.as_bytes().to_vec())
        .with_status_code(StatusCode::from(status))
        .with_header(json_header())
}

fn json_error(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = format!(
        r#"{{"error":"{}"}}"#,
        msg.replace('\\', "\\\\").replace('"', "\\\"")
    );
    json_response(status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn health_open_status_requires_token() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("a.db");
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        // 32 位以上:强度门槛默认开着,测试也得过。
        let token = "test-token-rc1-0123456789abcdef".to_string();
        let handle = thread::spawn(move || {
            let _ = serve(
                ApiConfig {
                    bind: "127.0.0.1:18766".parse().unwrap(),
                    rules,
                    audit_db: audit,
                    intel: None,
                    token: token.clone(),
                    allow_lan: false,
                    audit_signing_key: None,
                    known_apps: None,
                    task_plans: None,
                    agent_registry: None,
                    adapter_registry: None,
                    insecure_token: false,
                },
                Some(flag),
            );
        });
        thread::sleep(Duration::from_millis(300));
        let health = ureq::get("http://127.0.0.1:18766/health").call().unwrap();
        assert_eq!(health.status(), 200);

        let denied = ureq::get("http://127.0.0.1:18766/v1/status").call();
        match denied {
            Err(ureq::Error::Status(code, _)) => assert_eq!(code, 401),
            Ok(r) => assert_eq!(r.status(), 401),
            Err(e) => panic!("unexpected: {e}"),
        }

        let st = ureq::get("http://127.0.0.1:18766/v1/status")
            .set("Authorization", "Bearer test-token-rc1-0123456789abcdef")
            .call()
            .unwrap();
        assert_eq!(st.status(), 200);
        assert!(st.into_string().unwrap().contains("rules_loaded"));

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    #[test]
    fn events_endpoint_ingests_android_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("a.db");
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let handle = thread::spawn(move || {
            let _ = serve(
                ApiConfig {
                    bind: "127.0.0.1:18767".parse().unwrap(),
                    rules,
                    audit_db: audit,
                    intel: None,
                    token: "tok-0123456789abcdef0123456789".into(),
                    allow_lan: false,
                    audit_signing_key: None,
                    known_apps: None,
                    task_plans: None,
                    agent_registry: None,
                    adapter_registry: None,
                    insecure_token: false,
                },
                Some(flag),
            );
        });
        thread::sleep(Duration::from_millis(300));

        // Unauthenticated → 401.
        let denied = ureq::post("http://127.0.0.1:18767/v1/events")
            .send_string(r#"{"type":"batch","events":[]}"#);
        match denied {
            Err(ureq::Error::Status(code, _)) => assert_eq!(code, 401),
            other => panic!("expected 401, got {other:?}"),
        }

        // Envelope carrying a payment ui_text → CRIT-001 Block decision echoed.
        let envelope = r#"{
            "type": "batch",
            "session_id": "phone-sess-1",
            "events": [
                {"type": "ui_text", "app": "com.evil.overlay", "text": "确认支付 ￥99"}
            ]
        }"#;
        let resp = ureq::post("http://127.0.0.1:18767/v1/events")
            .set("Authorization", "Bearer tok-0123456789abcdef0123456789")
            .send_string(envelope)
            .unwrap();
        let body: serde_json::Value = serde_json::from_str(&resp.into_string().unwrap()).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["ingested"], 1);
        assert_eq!(body["decisions"][0]["rule_id"], "CRIT-001");
        assert_eq!(body["decisions"][0]["action"], "Block");

        // Malformed envelope → 400.
        let bad = ureq::post("http://127.0.0.1:18767/v1/events")
            .set("Authorization", "Bearer tok-0123456789abcdef0123456789")
            .send_string("not json");
        match bad {
            Err(ureq::Error::Status(code, _)) => assert_eq!(code, 400),
            other => panic!("expected 400, got {other:?}"),
        }

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    #[test]
    fn rejects_non_loopback() {
        let err = serve(
            ApiConfig {
                bind: "0.0.0.0:9".parse().unwrap(),
                rules: PathBuf::from("x"),
                audit_db: PathBuf::from("y"),
                intel: None,
                // 故意留一个弱令牌:loopback 检查在强度检查**之前**,
                // 所以这条测试同时钉住了两者的顺序。
                token: "x".into(),
                allow_lan: false,
                insecure_token: false,
                audit_signing_key: None,
                known_apps: None,
                task_plans: None,
                agent_registry: None,
                adapter_registry: None,
            },
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn lan_bind_allowed_with_opt_in() {
        // 0.0.0.0 with --allow-lan must bind (port 0 = ephemeral); we only
        // check that serve() gets past the guard and binds, then shut down.
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let dir = tempfile::tempdir().unwrap();
        let shutdown = Arc::new(AtomicBool::new(true)); // stop after first loop tick
                                                        // Bind on an ephemeral port on all interfaces; serve returns once the
                                                        // shutdown flag is observed (recv_timeout ≤ 400ms).
        let res = serve(
            ApiConfig {
                bind: "0.0.0.0:0".parse().unwrap(),
                rules,
                audit_db: dir.path().join("a.db"),
                intel: None,
                token: "tok-0123456789abcdef0123456789".into(),
                allow_lan: true,
                audit_signing_key: None,
                known_apps: None,
                task_plans: None,
                agent_registry: None,
                adapter_registry: None,
                insecure_token: false,
            },
            Some(shutdown),
        );
        assert!(res.is_ok(), "{res:?}");
    }

    // -----------------------------------------------------------------------
    // 适配器断言签名:端到端,走真的 HTTP 服务器
    // -----------------------------------------------------------------------

    /// 测试用适配器密钥(种子 0x5d 重复),和 guard-core 的测试同一把。
    const AD_SECRET: &str = "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";
    const AD_PUBLIC: &str = "5e449ad6fa4b2d65746e8cd4f968e38c5a9679f8495db114ee06317f72f717db";

    /// 一个"完整且干净"的环境调查信封 —— 也就是那次攻击的载荷。
    fn clean_survey_envelope() -> String {
        serde_json::json!({
            // 信封自己也有一个必填的 "type" —— 漏了会得到 400,
            // 而 400 的报错指向的是**事件**里缺 type,很容易看错地方。
            "type": "batch",
            "session_id": "s-e2e",
            "events": [{
                "type": "env_survey",
                "app": "AgentGuard Companion",
                "foreign_a11y_services": [],
                "broadcast_input_receivers": [],
                "log_readers": []
            }]
        })
        .to_string()
    }

    fn risky_survey_envelope() -> String {
        serde_json::json!({
            // 信封自己也有一个必填的 "type" —— 漏了会得到 400,
            // 而 400 的报错指向的是**事件**里缺 type,很容易看错地方。
            "type": "batch",
            "session_id": "s-e2e",
            "events": [{
                "type": "env_survey",
                "app": "AgentGuard Companion",
                "foreign_a11y_services": ["com.evil.keylog/.Sniffer"],
                "broadcast_input_receivers": []
            }]
        })
        .to_string()
    }

    /// 端到端:一个拿到 bearer 令牌的本机进程,伪造不出"环境是干净的"。
    ///
    /// # 为什么这条测试必须走真的 HTTP
    ///
    /// 要证的不是"引擎有这个能力",那已经在 guard-core 里证过了。要证的是
    /// **这条真实入口真的接上了** —— 本项目反复抓到的第二种缺陷形状就是
    /// "机制存在、被直接测过、然后没接到任何一个发布出去的入口上"。
    /// `CRIT-*` 曾经完全没接到网关上;`guard-jail` 的后端探测从别的二进制调用时
    /// 一直报假阴性。所以这里起一个真的 `serve()`,发真的请求。
    ///
    /// 断言查的是**效果**:先制造一个锁存的风险,再发伪造的干净调查,然后从
    /// `/v1/status` 读回引擎的状态,确认风险还在。一个返回 200 却把锁存清掉的
    /// 实现能过一条只看状态码的测试。
    #[test]
    fn 端到端_伪造的干净调查清不掉锁存的风险() {
        let dir = tempfile::tempdir().unwrap();
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        // 注册表钉了密钥,所以"签名过就能清"这条路是通的 —— 于是这条测试
        // 测的是签名验证,而不是"注册表没配所以谁都清不掉"。
        let reg = dir.path().join("adapters.yaml");
        std::fs::write(
            &reg,
            format!(
                "adapters:\n  - adapter_id: companion\n    public_key: \"{AD_PUBLIC}\"\n    platforms: [android]\n"
            ),
        )
        .unwrap();

        let token = "e2e-adapter-token-0123456789ab".to_string();
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let audit = dir.path().join("a.db");
        let t2 = token.clone();
        let handle = thread::spawn(move || {
            let _ = serve(
                ApiConfig {
                    bind: "127.0.0.1:18781".parse().unwrap(),
                    rules,
                    audit_db: audit,
                    intel: None,
                    token: t2,
                    allow_lan: false,
                    audit_signing_key: None,
                    known_apps: None,
                    task_plans: None,
                    agent_registry: None,
                    adapter_registry: Some(reg),
                    insecure_token: false,
                },
                Some(flag),
            );
        });
        thread::sleep(Duration::from_millis(400));

        // 返回 `bool` 而不是 `Result`:ureq 的错误类型很大(clippy 的
        // `result_large_err` 会说),而这条测试只关心这次 POST 有没有被接受。
        let post = |body: String, headers: Vec<(&str, String)>| -> bool {
            let mut r = ureq::post("http://127.0.0.1:18781/v1/events")
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json");
            for (k, v) in headers {
                r = r.set(k, &v);
            }
            r.send_string(&body).is_ok()
        };
        let risk_latched = || -> bool {
            let s: String = ureq::get("http://127.0.0.1:18781/v1/status")
                .set("Authorization", &format!("Bearer {token}"))
                .call()
                .unwrap()
                .into_string()
                .unwrap();
            s.contains("com.evil.keylog")
        };

        // 1. 制造一个锁存的风险。
        assert!(post(risky_survey_envelope(), vec![]), "POST 被拒了");
        assert!(risk_latched(), "前置条件没成立:风险没有锁存");

        // 2. 攻击:拿着令牌,发一份没有签名的"完整且干净"的调查。
        assert!(post(clean_survey_envelope(), vec![]), "POST 被拒了");
        assert!(
            risk_latched(),
            "未签名的干净调查通过 /v1/events 清掉了锁存的风险"
        );

        // 3. 带一个**乱造的**签名 —— 同样清不掉。
        assert!(post(
            clean_survey_envelope(),
            vec![
                ("X-AgentGuard-Adapter", "companion".into()),
                ("X-AgentGuard-Timestamp", "1".into()),
                ("X-AgentGuard-Signature", "0".repeat(128)),
            ],
        ));
        assert!(risk_latched(), "乱造的签名清掉了锁存的风险");

        // 4. 真正签过的干净调查 —— 这次必须清掉,否则守卫会永远悲观下去。
        let body = clean_survey_envelope();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let msg = guard_schema::adapter_body_message(
            "companion",
            guard_schema::ANDROID_ENVELOPE_FORMAT,
            ts,
            body.as_bytes(),
        );
        let key = guard_audit::FileDeviceKey::from_secret_hex(AD_SECRET).unwrap();
        let sig = guard_audit::AuditSigner::sign_message(&key, &msg).unwrap();
        assert!(post(
            body,
            vec![
                ("X-AgentGuard-Adapter", "companion".into()),
                ("X-AgentGuard-Timestamp", ts.to_string()),
                ("X-AgentGuard-Signature", sig.clone()),
            ],
        ));
        assert!(
            !risk_latched(),
            "签名过的干净调查也没能清掉风险 —— 那这个机制就只是把功能关掉了"
        );

        // 5. **同一个签名换一种十六进制写法重放 —— 必须清不掉。**
        //
        // 这一步是一次独立对抗性复核用 curl 跑出来的洞:重放键以前是签名的那串
        // header 文本,而 `hex::decode` 不分大小写。于是把同一个签名的十六进制
        // 改成大写重放,风险又被清掉一次,判决还报 `ADAPTER-VERIFIED`(不是
        // `ADAPTER-REPLAY`),`is_impersonation()` 为假 —— **静默**。
        //
        // 上面第 4 步只证明"签名过的能清掉",证明不了"只能清掉一次"。
        // 那正是复核指出的:这条端到端链路从来没测过重放。
        let body2 = risky_survey_envelope();
        assert!(post(body2, vec![]));
        assert!(risk_latched(), "重新锁存失败,后面的断言没有意义");
        assert!(post(
            clean_survey_envelope(),
            vec![
                (guard_schema::ADAPTER_HEADER_ID, "companion".into()),
                (guard_schema::ADAPTER_HEADER_TIMESTAMP, ts.to_string()),
                // 同样的字节,大写的写法。
                (guard_schema::ADAPTER_HEADER_SIGNATURE, sig.to_uppercase()),
            ],
        ));
        assert!(
            risk_latched(),
            "把签名的十六进制改成大写重放,风险被清掉了 —— 重放防御在中继路径上是可绕的"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    #[test]
    fn resolve_token_prefers_explicit() {
        assert_eq!(resolve_api_token(Some("abc".into())), "abc");
    }

    // -----------------------------------------------------------------------
    // 发布阻塞项:bearer 令牌强度
    // -----------------------------------------------------------------------

    /// `dev-secret` 必须被点名,而不是只报"太短"。
    ///
    /// 它是本仓库 `make api-serve` 曾经的默认值,也印在 docs/local-api.md 里。
    /// 运维看到"令牌太短"会去加长它;看到"这是本项目文档里的示例值"才会明白
    /// 问题不在长度,而在这个字符串是公开的。
    #[test]
    fn 文档里的示例令牌被点名拒绝() {
        for t in ["dev-secret", "DEV-SECRET", " dev-secret "] {
            match api_token_weakness(t) {
                Some(TokenWeakness::WellKnown { token }) => {
                    assert_eq!(token.trim(), token, "出错信息里不该带首尾空白");
                }
                other => panic!("{t:?} 应该被认成公开示例值,实际:{other:?}"),
            }
        }
        assert!(api_token_weakness("dev-secret")
            .unwrap()
            .to_string()
            .contains("dev-secret"));
    }

    /// 自动生成的令牌一定过得了自己的强度检查。
    ///
    /// 这两件事在代码里是分开的两段(生成 / 校验),一旦 `MIN_API_TOKEN_LEN`
    /// 被调高到超过 `ag_` + 32 位十六进制的长度,不带 `--token` 启动就会
    /// **永远启动不了**,而且只在运行时才炸。
    #[test]
    fn 自动生成的令牌过得了强度检查() {
        std::env::remove_var("AGENTGUARD_API_TOKEN");
        for _ in 0..8 {
            let t = resolve_api_token(None);
            assert!(
                api_token_weakness(&t).is_none(),
                "自动生成的令牌 {t:?} 过不了强度检查"
            );
        }
    }

    /// 弱令牌让 `serve` 直接拒绝启动 —— 而且是在 bind 之前。
    ///
    /// 断言查的是效果而不是返回值:如果只看 `Err`,一个先监听端口、再返回错误的
    /// 实现也能过。所以这里同时确认那个端口**没有**被占。
    #[test]
    fn 弱令牌不让服务器起来() {
        let dir = tempfile::tempdir().unwrap();
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let err = serve(
            ApiConfig {
                bind: "127.0.0.1:18771".parse().unwrap(),
                rules: rules.clone(),
                audit_db: dir.path().join("a.db"),
                intel: None,
                token: "dev-secret".into(),
                allow_lan: false,
                audit_signing_key: None,
                known_apps: None,
                task_plans: None,
                agent_registry: None,
                adapter_registry: None,
                insecure_token: false,
            },
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dev-secret"), "{msg}");
        assert!(
            msg.contains("--insecure-token"),
            "要告诉运维怎么覆盖: {msg}"
        );
        // 端口必须是空的:拒绝发生在 bind 之前。
        assert!(
            std::net::TcpListener::bind("127.0.0.1:18771").is_ok(),
            "serve 在拒绝之前就把端口占了"
        );
    }

    /// `--insecure-token` 真的能覆盖 —— 否则本机调试就没路可走,
    /// 而没路可走的检查最终会被整个删掉。
    #[test]
    fn 显式覆盖之后弱令牌可以启动() {
        let dir = tempfile::tempdir().unwrap();
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let res = serve(
            ApiConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                rules,
                audit_db: dir.path().join("a.db"),
                intel: None,
                token: "dev-secret".into(),
                allow_lan: false,
                audit_signing_key: None,
                known_apps: None,
                task_plans: None,
                agent_registry: None,
                adapter_registry: None,
                insecure_token: true,
            },
            Some(Arc::new(AtomicBool::new(true))),
        );
        assert!(res.is_ok(), "{res:?}");
    }
}

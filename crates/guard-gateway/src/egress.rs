//! 宿主登记的本机服务出口。任务容器保持断网，客户端不能登记服务或签发授权。
//! 本版仅支持准确 IPv4 回环 HTTP 地址；不进行 DNS、代理、重定向或协议升级。
//! 审计接收者必须在返回成功前完成持久化。记录失败会关闭整个代理实例。

use guard_schema::ExecutionOutcome;
use guard_trust::constant_time_eq;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_SESSIONS: usize = 128;
const MAX_GRANTS: usize = 1024;
const MAX_SESSION_TIME: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_GRANT_TIME: Duration = Duration::from_secs(60);
const IO_POLL: Duration = Duration::from_millis(100);

/// 标签只能由可信读取入口赋予；它的格式有效不代表客户端自报值可信。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Workspace,
    Sensitive,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}
impl HttpMethod {
    fn text(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsePolicy {
    /// 有凭据服务必须采用此模式，不把正文或响应头交给任务。
    StatusOnly,
    Json,
}

/// 固定错误码。网络错误、响应正文、凭据以及审计实现的错误详情均不外传。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EgressError {
    pub code: &'static str,
}
impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for EgressError {}
fn error(code: &'static str) -> EgressError {
    EgressError { code }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn opaque_id() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
}
fn now_ms() -> Result<u64, EgressError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .map_err(|_| error("EGRESS_CLOCK"))
}

/// 字段私有，防止构造后跳过目标与凭据规则。它不实现 Debug 或 Serialize。
pub struct LocalService {
    id: String,
    port: u16,
    path: String,
    method: HttpMethod,
    purpose: String,
    max_data: DataClass,
    response: ResponsePolicy,
    bearer: Option<String>,
    timeout: Duration,
}
impl LocalService {
    pub fn new(
        id: &str,
        http_url: &str,
        method: HttpMethod,
        purpose: &str,
        max_data: DataClass,
        response: ResponsePolicy,
    ) -> Result<Self, EgressError> {
        // 只解析这一种规范写法；域名、IPv6、user-info、其它数字IP写法均不接受。
        let rest = http_url
            .strip_prefix("http://127.0.0.1:")
            .ok_or_else(|| error("EGRESS_TARGET"))?;
        let (port, suffix) = rest.split_once('/').ok_or_else(|| error("EGRESS_TARGET"))?;
        let parsed = port.parse::<u16>().map_err(|_| error("EGRESS_TARGET"))?;
        if parsed == 0 || parsed.to_string() != port {
            return Err(error("EGRESS_TARGET"));
        }
        let path = format!("/{suffix}");
        if !valid_id(id)
            || !valid_id(purpose)
            || !matches!(max_data, DataClass::Public | DataClass::Workspace)
            || path.len() > 512
            || path.contains("//")
            || path.split('/').any(|part| matches!(part, "." | ".."))
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            return Err(error("EGRESS_POLICY"));
        }
        Ok(Self {
            id: id.into(),
            port: parsed,
            path,
            method,
            purpose: purpose.into(),
            max_data,
            response,
            bearer: None,
            timeout: MAX_GRANT_TIME,
        })
    }

    /// 只接受标准 Bearer token 字符。凭据始终保存在可信代理内存，不进入请求对象。
    pub fn with_bearer(mut self, value: String) -> Result<Self, EgressError> {
        if self.response != ResponsePolicy::StatusOnly
            || value.len() < 16
            || value.len() > 4096
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(error("EGRESS_CREDENTIAL_POLICY"));
        }
        self.bearer = Some(value);
        Ok(self)
    }

    /// 宿主可以收紧期限，不能超过本版 60 秒上限。
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, EgressError> {
        if timeout.is_zero() || timeout > MAX_GRANT_TIME {
            return Err(error("EGRESS_POLICY"));
        }
        self.timeout = timeout;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub session_id: String,
    pub epoch: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRequest {
    pub service_id: String,
    pub purpose: String,
    pub data_class: DataClass,
    pub body: Option<Value>,
}
/// 授权是内存中的不透明宿主对象，不提供从客户端 JSON 恢复的入口。
#[derive(Clone)]
pub struct EgressGrant {
    id: String,
    nonce: String,
}
impl fmt::Debug for EgressGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EgressGrant([已隐藏])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStage {
    BeforeDispatch,
    Completed,
}
#[derive(Debug, Clone, Serialize)]
pub struct EgressAudit {
    pub version: u16,
    pub event_id: String,
    pub stage: AuditStage,
    pub session_sha256: String,
    pub service_sha256: String,
    pub purpose_sha256: String,
    pub epoch: u64,
    pub request_sha256: String,
    pub request_bytes: usize,
    pub outcome: ExecutionOutcome,
    pub dispatched: bool,
    pub code: &'static str,
    /// 只限无凭据、成功且格式已核对的 JSON 响应。
    pub response_sha256: Option<String>,
}
pub trait EgressJournal: Send + Sync {
    /// 必须持久化后才返回成功。错误详情不会写入响应，也不会包含在代理日志中。
    fn record(&self, event: &EgressAudit) -> Result<(), String>;
}
#[derive(Debug, Clone, Serialize)]
pub struct EgressResult {
    pub outcome: ExecutionOutcome,
    pub dispatched: bool,
    pub code: &'static str,
    /// 仅无凭据服务返回 HTTP 状态；有凭据服务只给固定结果，避免响应回显秘密。
    pub http_status: Option<u16>,
    pub body: Option<Value>,
}
impl EgressResult {
    fn refused(code: &'static str) -> Self {
        Self {
            outcome: ExecutionOutcome::Refused,
            dispatched: false,
            code,
            http_status: None,
            body: None,
        }
    }
}

struct SessionLease {
    context: SessionContext,
    expires_at_ms: u64,
    deadline: Instant,
    revoked: AtomicBool,
    dispatch: Mutex<()>,
}
impl SessionLease {
    fn valid(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && now_ms().is_ok_and(|now| now < self.expires_at_ms)
    }
}
struct Permit {
    nonce: String,
    context: SessionContext,
    request_digest: String,
    deadline: Instant,
    lease: Arc<SessionLease>,
}
#[derive(Default)]
struct State {
    sessions: HashMap<String, Arc<SessionLease>>,
    used_sessions: HashSet<String>,
    grants: HashMap<String, Permit>,
}
pub struct EgressBroker {
    services: HashMap<String, LocalService>,
    state: Mutex<State>,
    journal: Arc<dyn EgressJournal>,
    faulted: AtomicBool,
}
impl EgressBroker {
    pub fn new(
        services: Vec<LocalService>,
        blocked_control_ports: Vec<u16>,
        journal: Arc<dyn EgressJournal>,
    ) -> Result<Self, EgressError> {
        if services.is_empty() || services.len() > 64 || blocked_control_ports.contains(&0) {
            return Err(error("EGRESS_POLICY"));
        }
        let mut registered = HashMap::new();
        for service in services {
            if blocked_control_ports.contains(&service.port) {
                return Err(error("EGRESS_CONTROL_TARGET"));
            }
            if registered.insert(service.id.clone(), service).is_some() {
                return Err(error("EGRESS_DUPLICATE_SERVICE"));
            }
        }
        Ok(Self {
            services: registered,
            state: Mutex::new(State::default()),
            journal,
            faulted: AtomicBool::new(false),
        })
    }
    pub fn is_faulted(&self) -> bool {
        self.faulted.load(Ordering::Acquire)
    }
    pub fn register_session(
        &self,
        context: SessionContext,
        expires_at_ms: u64,
    ) -> Result<(), EgressError> {
        let now = now_ms()?;
        if self.is_faulted()
            || !valid_id(&context.session_id)
            || expires_at_ms <= now
            || expires_at_ms - now > MAX_SESSION_TIME.as_millis() as u64
        {
            return Err(error("EGRESS_SESSION"));
        }
        let mut state = self.state.lock().map_err(|_| error("EGRESS_STATE"))?;
        state.sessions.retain(|_, lease| lease.valid());
        // 同一会话编号不得复活。换代需要宿主新建编号；旧授权仍按旧 lease 撤销。
        if state.used_sessions.contains(&context.session_id)
            || state.used_sessions.len() >= MAX_SESSIONS
        {
            return Err(error("EGRESS_SESSION"));
        }
        let lease = Arc::new(SessionLease {
            context: context.clone(),
            expires_at_ms,
            deadline: Instant::now() + Duration::from_millis(expires_at_ms - now),
            revoked: AtomicBool::new(false),
            dispatch: Mutex::new(()),
        });
        state.used_sessions.insert(context.session_id.clone());
        state.sessions.insert(context.session_id.clone(), lease);
        Ok(())
    }
    pub fn revoke_session(&self, session_id: &str) {
        let lease = if let Ok(mut state) = self.state.lock() {
            let lease = state.sessions.get(session_id).cloned();
            if let Some(lease) = &lease {
                lease.revoked.store(true, Ordering::Release);
            }
            state
                .grants
                .retain(|_, permit| permit.context.session_id != session_id);
            lease
        } else {
            self.faulted.store(true, Ordering::Release);
            None
        };
        if let Some(lease) = lease {
            // 先撤权，再等当前一次有界 connect/write 返回；不能在撤销返回后继续写入。
            // 不持有全局 state 等待，避免阻塞其它会话登记和结果收尾。
            if lease.dispatch.lock().is_err() {
                self.faulted.store(true, Ordering::Release);
            }
        }
    }
    fn prepare_request(&self, request: &EgressRequest) -> Result<(Vec<u8>, String), EgressError> {
        let service = self
            .services
            .get(&request.service_id)
            .ok_or_else(|| error("EGRESS_SERVICE"))?;
        if request.purpose != service.purpose {
            return Err(error("EGRESS_PURPOSE"));
        }
        if !matches!(
            (request.data_class, service.max_data),
            (DataClass::Public, DataClass::Public | DataClass::Workspace)
                | (DataClass::Workspace, DataClass::Workspace)
        ) {
            return Err(error("EGRESS_DATA_SCOPE"));
        }
        if matches!(
            (service.method, &request.body),
            (HttpMethod::Get, Some(_)) | (HttpMethod::Post, None)
        ) {
            return Err(error("EGRESS_BODY"));
        }
        let body = request
            .body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| error("EGRESS_BODY"))?
            .unwrap_or_default();
        if body.len() > MAX_REQUEST_BYTES - MAX_HEADER_BYTES {
            return Err(error("EGRESS_REQUEST_LIMIT"));
        }
        // 正文也不能携带代理已知凭据。响应的 StatusOnly 另行阻止编码回显。
        let body_text = std::str::from_utf8(&body).map_err(|_| error("EGRESS_BODY"))?;
        // 这是内容检索，不是令牌认证；使用有界字符串搜索，避免逐窗口认证造成计算放大。
        if self
            .services
            .values()
            .filter_map(|s| s.bearer.as_ref())
            .any(|secret| body_text.contains(secret.as_str()))
        {
            return Err(error("EGRESS_CREDENTIAL_IN_BODY"));
        }
        // 审计摘要同时绑定不可变登记项，不能仅凭同一个service_id掩盖目标或方法变更。
        let canonical = serde_json::to_vec(&serde_json::json!({
            "schema":"egress_request_v1", "request":request,
            "target":format!("http://127.0.0.1:{}{}", service.port, service.path),
            "method":service.method.text(), "max_data":service.max_data,
            "response":match service.response { ResponsePolicy::StatusOnly=>"status_only", ResponsePolicy::Json=>"json" },
            "credential_present":service.bearer.is_some(),
        })).map_err(|_| error("EGRESS_BODY"))?;
        Ok((body, digest(&canonical)))
    }
    /// 纯宿主入口。客户端不能凭自报的 data_class 或会话编号取得授权。
    pub fn issue(
        &self,
        context: &SessionContext,
        request: &EgressRequest,
        ttl: Duration,
    ) -> Result<EgressGrant, EgressError> {
        if self.is_faulted() || ttl.is_zero() || ttl > MAX_GRANT_TIME {
            return Err(error("EGRESS_CLOSED"));
        }
        let (_, request_digest) = self.prepare_request(request)?;
        let mut state = self.state.lock().map_err(|_| error("EGRESS_STATE"))?;
        state
            .grants
            .retain(|_, permit| permit.lease.valid() && Instant::now() < permit.deadline);
        if state.grants.len() >= MAX_GRANTS {
            return Err(error("EGRESS_GRANT_LIMIT"));
        }
        let lease = state
            .sessions
            .get(&context.session_id)
            .filter(|lease| lease.context == *context && lease.valid())
            .cloned()
            .ok_or_else(|| error("EGRESS_SESSION"))?;
        let grant = EgressGrant {
            id: opaque_id(),
            nonce: opaque_id(),
        };
        state.grants.insert(
            grant.id.clone(),
            Permit {
                nonce: grant.nonce.clone(),
                context: context.clone(),
                request_digest,
                deadline: (Instant::now() + ttl).min(lease.deadline),
                lease,
            },
        );
        Ok(grant)
    }
    pub fn execute(
        &self,
        context: &SessionContext,
        grant: EgressGrant,
        request: EgressRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> EgressResult {
        if self.is_faulted() {
            return EgressResult::refused("EGRESS_CLOSED");
        }
        // 提取即消费：失败、错绑与网络状态未知都不能复用这份授权。
        let permit = match self.state.lock() {
            Ok(mut state) => state.grants.remove(&grant.id),
            Err(_) => {
                self.faulted.store(true, Ordering::Release);
                None
            }
        };
        let Some(permit) = permit else {
            return EgressResult::refused("EGRESS_GRANT");
        };
        let (body, request_digest) = match self.prepare_request(&request) {
            Ok(prepared) => prepared,
            Err(e) => return EgressResult::refused(e.code),
        };
        if permit.context != *context
            || !constant_time_eq(permit.nonce.as_bytes(), grant.nonce.as_bytes())
            || !constant_time_eq(permit.request_digest.as_bytes(), request_digest.as_bytes())
            || !permit.lease.valid()
            || Instant::now() >= permit.deadline
        {
            return EgressResult::refused("EGRESS_BINDING");
        }
        let service = &self.services[&request.service_id];
        let mut audit = EgressAudit {
            version: 1,
            event_id: opaque_id(),
            stage: AuditStage::BeforeDispatch,
            session_sha256: digest(context.session_id.as_bytes()),
            service_sha256: digest(service.id.as_bytes()),
            purpose_sha256: digest(service.purpose.as_bytes()),
            epoch: context.epoch,
            request_sha256: request_digest,
            request_bytes: body.len(),
            outcome: ExecutionOutcome::Unknown,
            dispatched: false,
            code: "EGRESS_DISPATCH_INTENT",
            response_sha256: None,
        };
        if cancelled() || !permit.lease.valid() {
            return EgressResult::refused("EGRESS_CANCELLED");
        }
        if self.journal.record(&audit).is_err() {
            self.faulted.store(true, Ordering::Release);
            return EgressResult::refused("EGRESS_AUDIT_BEFORE");
        }
        let deadline = (Instant::now() + service.timeout).min(permit.deadline);
        let active = || !self.is_faulted() && permit.lease.valid() && !cancelled();
        let mut result = transport(
            service,
            &body,
            deadline,
            &active,
            &permit.lease,
            &self.faulted,
        );
        audit.stage = AuditStage::Completed;
        audit.outcome = result.outcome;
        audit.dispatched = result.dispatched;
        audit.code = result.code;
        audit.response_sha256 = result
            .body
            .as_ref()
            .and_then(|value| serde_json::to_vec(value).ok())
            .map(|bytes| digest(&bytes));
        if self.journal.record(&audit).is_err() {
            self.faulted.store(true, Ordering::Release);
            result.outcome = if result.dispatched {
                ExecutionOutcome::Unknown
            } else {
                ExecutionOutcome::Refused
            };
            result.code = "EGRESS_AUDIT_AFTER";
            result.body = None;
            result.http_status = None;
        }
        result
    }
}

fn io_retry(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}
fn transport(
    service: &LocalService,
    body: &[u8],
    deadline: Instant,
    active: &dyn Fn() -> bool,
    lease: &SessionLease,
    faulted: &AtomicBool,
) -> EgressResult {
    let mut dispatched = false;
    let failure = |code, dispatched| EgressResult {
        outcome: if dispatched {
            ExecutionOutcome::Unknown
        } else {
            ExecutionOutcome::Refused
        },
        dispatched,
        code,
        http_status: None,
        body: None,
    };
    let check = || {
        if !active() {
            Err(error("EGRESS_CANCELLED"))
        } else if Instant::now() >= deadline {
            Err(error("EGRESS_TIMEOUT"))
        } else {
            Ok(())
        }
    };
    let exchange = (|| -> Result<DecodedResponse, EgressError> {
        check()?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, service.port));
        // 自定义取消回调在锁外调用；锁内只检查宿主 lease，避免回调撤销时重入死锁。
        let dispatch_guard = || {
            let guard = lease.dispatch.lock().map_err(|_| error("EGRESS_STATE"))?;
            if !lease.valid() || faulted.load(Ordering::Acquire) {
                return Err(error("EGRESS_CANCELLED"));
            }
            if Instant::now() >= deadline {
                return Err(error("EGRESS_TIMEOUT"));
            }
            Ok(guard)
        };
        let mut stream = {
            let _dispatch = dispatch_guard()?;
            TcpStream::connect_timeout(&address, IO_POLL).map_err(|_| error("EGRESS_CONNECT"))?
        };
        stream
            .set_read_timeout(Some(IO_POLL))
            .map_err(|_| error("EGRESS_IO"))?;
        stream
            .set_write_timeout(Some(IO_POLL))
            .map_err(|_| error("EGRESS_IO"))?;
        check()?;
        let mut header = format!("{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n", service.method.text(), service.path, service.port, body.len());
        if let Some(secret) = &service.bearer {
            header.push_str("Authorization: Bearer ");
            header.push_str(secret);
            header.push_str("\r\n");
        }
        header.push_str("\r\n");
        for part in [header.as_bytes(), body] {
            let mut rest = part;
            while !rest.is_empty() {
                check()?;
                let write = {
                    let _dispatch = dispatch_guard()?;
                    stream.write(rest)
                };
                match write {
                    Ok(0) => return Err(error("EGRESS_IO")),
                    Ok(count) => {
                        dispatched = true;
                        rest = &rest[count..];
                    }
                    Err(e) if io_retry(&e) => {}
                    Err(_) => return Err(error("EGRESS_IO")),
                }
            }
        }
        let mut raw = Vec::new();
        let mut buffer = [0; 8192];
        let mut body_start = None;
        loop {
            check()?;
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    raw.extend_from_slice(&buffer[..count]);
                    if body_start.is_none() {
                        body_start = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
                    }
                    if body_start.is_some_and(|at| {
                        at > MAX_HEADER_BYTES || raw.len() - at > MAX_RESPONSE_BYTES
                    }) || body_start.is_none() && raw.len() > MAX_HEADER_BYTES
                    {
                        return Err(error("EGRESS_RESPONSE_LIMIT"));
                    }
                }
                Err(e) if io_retry(&e) => {}
                Err(_) => return Err(error("EGRESS_IO")),
            }
        }
        check()?;
        decode_response(&raw)
    })();
    let response = match exchange {
        Ok(response) => response,
        Err(e) => return failure(e.code, dispatched),
    };
    if (300..400).contains(&response.status) {
        return EgressResult {
            outcome: ExecutionOutcome::Failed,
            dispatched,
            code: "EGRESS_REDIRECT",
            http_status: None,
            body: None,
        };
    }
    let success = (200..300).contains(&response.status);
    if service.response == ResponsePolicy::StatusOnly {
        return EgressResult {
            outcome: if success {
                ExecutionOutcome::Success
            } else {
                ExecutionOutcome::Failed
            },
            dispatched,
            code: if success {
                "EGRESS_OK"
            } else {
                "EGRESS_HTTP_STATUS"
            },
            http_status: None,
            body: None,
        };
    }
    if !success {
        return EgressResult {
            outcome: ExecutionOutcome::Failed,
            dispatched,
            code: "EGRESS_HTTP_STATUS",
            http_status: Some(response.status),
            body: None,
        };
    }
    if !response.json {
        return failure("EGRESS_JSON_TYPE", dispatched);
    }
    match serde_json::from_slice::<Value>(&response.body) {
        Ok(body) => EgressResult {
            outcome: ExecutionOutcome::Success,
            dispatched,
            code: "EGRESS_OK",
            http_status: Some(response.status),
            body: Some(body),
        },
        Err(_) => failure("EGRESS_JSON_FORMAT", dispatched),
    }
}
struct DecodedResponse {
    status: u16,
    body: Vec<u8>,
    json: bool,
}
fn decode_response(raw: &[u8]) -> Result<DecodedResponse, EgressError> {
    let invalid = || error("EGRESS_HTTP_FORMAT");
    let boundary = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?;
    if boundary + 4 > MAX_HEADER_BYTES || raw.len() - boundary - 4 > MAX_RESPONSE_BYTES {
        return Err(error("EGRESS_RESPONSE_LIMIT"));
    }
    let header = std::str::from_utf8(&raw[..boundary]).map_err(|_| invalid())?;
    let mut lines = header.split("\r\n");
    let mut status_line = lines.next().ok_or_else(invalid)?.splitn(3, ' ');
    if !matches!(status_line.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(invalid());
    }
    let code = status_line.next().ok_or_else(invalid)?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let status = code.parse::<u16>().map_err(|_| invalid())?;
    if status_line
        .next()
        .is_some_and(|reason| reason.bytes().any(|b| !(32..127).contains(&b)))
    {
        return Err(invalid());
    }
    if !(200..600).contains(&status) {
        return Err(invalid());
    }
    let mut length = None;
    let mut chunked = false;
    let mut json = false;
    let mut seen = HashSet::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or_else(invalid)?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(invalid());
        }
        let key = key.to_ascii_lowercase();
        let value = value.trim();
        if [
            "content-length",
            "transfer-encoding",
            "content-type",
            "content-encoding",
            "location",
        ]
        .contains(&key.as_str())
            && !seen.insert(key.clone())
        {
            return Err(invalid());
        }
        match key.as_str() {
            "upgrade" => return Err(invalid()),
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let size = value
                    .parse::<usize>()
                    .map_err(|_| error("EGRESS_RESPONSE_LIMIT"))?;
                if size > MAX_RESPONSE_BYTES {
                    return Err(error("EGRESS_RESPONSE_LIMIT"));
                }
                length = Some(size);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(invalid());
                }
                chunked = true;
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => return Err(invalid()),
            "content-type" => {
                json = value
                    .split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
            }
            _ => {}
        }
    }
    if chunked == length.is_some() {
        return Err(invalid());
    }
    let body = &raw[boundary + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        if length != Some(body.len()) {
            return Err(invalid());
        }
        body.to_vec()
    };
    Ok(DecodedResponse { status, body, json })
}
fn decode_chunked(mut bytes: &[u8]) -> Result<Vec<u8>, EgressError> {
    let invalid = || error("EGRESS_HTTP_FORMAT");
    let mut body = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(invalid)?;
        if end == 0 || end > 16 || !bytes[..end].iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid());
        }
        let length = usize::from_str_radix(
            std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?,
            16,
        )
        .map_err(|_| invalid())?;
        bytes = &bytes[end + 2..];
        if length == 0 {
            return if bytes == b"\r\n" {
                Ok(body)
            } else {
                Err(invalid())
            };
        }
        if length > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(error("EGRESS_RESPONSE_LIMIT"));
        }
        if length > bytes.len().saturating_sub(2) || bytes.get(length..length + 2) != Some(b"\r\n")
        {
            return Err(invalid());
        }
        body.extend_from_slice(&bytes[..length]);
        bytes = &bytes[length + 2..];
    }
}

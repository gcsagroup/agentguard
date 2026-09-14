//! 网关确认通道：只连 IPv4 环回，不使用代理、重定向或持久化令牌。
use guard_schema::ApprovalBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// 状态可能包含多份正文；这是独立展示上限，超限整条拒绝，不截断后继续批准。
const LIMIT: usize = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_FILE_LIMIT: usize = 8192;
const WORKSPACE_TIMEOUT: Duration = Duration::from_secs(15);

/// 文件内容只存在 Rust；不实现 Serialize，避免意外作为 WebView 回执返回。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlFile {
    service: String,
    confirm_protocol: u32,
    url: String,
    port: u16,
    instance_id: String,
    token: String,
}

impl ControlFile {
    fn validate(&self) -> Result<(), String> {
        if self.service != "agentguard-mcp"
            || self.confirm_protocol != 2
            || self.port == 0
            || self.url != format!("http://127.0.0.1:{}", self.port)
            || !hex_id(&self.instance_id)
            || !hex_id(&self.token)
        {
            return Err("GATEWAY_FILE_FORMAT".into());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_control_file(path: &Path) -> Result<ControlFile, String> {
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("GATEWAY_FILE_PATH".into());
    }
    let parts: Vec<_> = path
        .components()
        .filter_map(|c| {
            if let Component::Normal(name) = c {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    if parts.is_empty() {
        return Err("GATEWAY_FILE_PATH".into());
    }
    let mut directory = File::open("/").map_err(|_| "GATEWAY_FILE_OPEN")?;
    for (index, part) in parts.iter().enumerate() {
        let name = CString::new(part.as_bytes()).map_err(|_| "GATEWAY_FILE_PATH")?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if last {
                libc::O_NONBLOCK
            } else {
                libc::O_DIRECTORY
            };
        let raw = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if raw < 0 {
            return Err("GATEWAY_FILE_OPEN".into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        if !last {
            directory = file;
            continue;
        }
        let metadata = file.metadata().map_err(|_| "GATEWAY_FILE_OPEN")?;
        let safe = |m: &std::fs::Metadata| {
            m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o600
        };
        if !safe(&metadata) {
            return Err("GATEWAY_FILE_PERMISSIONS".into());
        }
        if metadata.len() > CONTROL_FILE_LIMIT as u64 {
            return Err("GATEWAY_FILE_TOO_LARGE".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(CONTROL_FILE_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "GATEWAY_FILE_READ")?;
        let after = file.metadata().map_err(|_| "GATEWAY_FILE_READ")?;
        if bytes.len() > CONTROL_FILE_LIMIT {
            return Err("GATEWAY_FILE_TOO_LARGE".into());
        }
        if !safe(&after)
            || metadata.len() != bytes.len() as u64
            || metadata.len() != after.len()
            || metadata.mtime() != after.mtime()
            || metadata.mtime_nsec() != after.mtime_nsec()
            || metadata.ctime() != after.ctime()
            || metadata.ctime_nsec() != after.ctime_nsec()
        {
            return Err("GATEWAY_FILE_CHANGED".into());
        }
        let value: ControlFile =
            serde_json::from_slice(&bytes).map_err(|_| "GATEWAY_FILE_FORMAT")?;
        value.validate()?;
        return Ok(value);
    }
    Err("GATEWAY_FILE_PATH".into())
}

#[cfg(not(unix))]
fn read_control_file(_: &Path) -> Result<ControlFile, String> {
    Err("GATEWAY_FILE_UNSUPPORTED".into())
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Request {
    id: String,
    what: String,
    findings: Vec<Finding>,
    action: ActionView,
    action_sha256: String,
}
/// 只把用户需要核对的动作发给 WebView，批准随机值保留在 Rust 控制面。
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct ActionView {
    session_id: String,
    target: String,
    tool_service: String,
    tool_name: String,
    tool_version: String,
    policy_version: String,
    parameters: serde_json::Value,
    expires_at_ms: i64,
}
#[derive(Clone, Deserialize, PartialEq)]
struct RemoteRequest {
    id: String,
    what: String,
    findings: Vec<Finding>,
    binding: ApprovalBinding,
    action_sha256: String,
}
impl RemoteRequest {
    fn validate(&self, now_ms: i64) -> Result<(), String> {
        if self.id != self.binding.approval_id().as_str()
            || self.action_sha256
                != format!(
                    "{:x}",
                    Sha256::digest(self.binding.action().canonical_bytes())
                )
        {
            return Err("GATEWAY_BINDING".into());
        }
        self.binding
            .validate_for_action(self.binding.action(), now_ms)
            .map_err(|_| "GATEWAY_STALE".into())
    }
    fn view(&self) -> Request {
        let action = self.binding.action().spec();
        Request {
            id: self.id.clone(),
            what: self.what.clone(),
            findings: self.findings.clone(),
            action_sha256: self.action_sha256.clone(),
            action: ActionView {
                session_id: action.session_id.to_string(),
                target: action.target.clone(),
                tool_service: action.tool.service.clone(),
                tool_name: action.tool.name.clone(),
                tool_version: action.tool.version.clone(),
                policy_version: action.policy_version.to_string(),
                parameters: action.parameters.clone(),
                expires_at_ms: self.binding.expires_at_ms(),
            },
        }
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Finding {
    rule_id: String,
    layer: String,
    severity: String,
    message: String,
}
#[derive(Deserialize)]
struct RemoteStatus {
    service: String,
    confirm_protocol: u32,
    instance_id: String,
    pending: Option<RemoteRequest>,
    remaining_ms: Option<u64>,
}
#[derive(Clone, Serialize)]
pub struct View {
    pub(crate) connection_id: String,
    pub(crate) port: u16,
    instance_id: String,
    pending: Option<Request>,
    remaining_ms: u64,
    supports_workspace: bool,
}
#[derive(Clone)]
struct Connection {
    id: String,
    port: u16,
    token: String,
    instance_id: String,
    displayed: Option<RemoteRequest>,
    supports_workspace: bool,
    workspace: Option<WorkspaceStatus>,
    review: Option<RemoteReview>,
    workspace_epoch: u64,
}
#[derive(Clone, Default)]
pub struct GatewayConfirm(Arc<Mutex<Option<Connection>>>);

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct WorkspaceEntry {
    workspace_id: String,
    target: String,
    snapshot: String,
    writable: bool,
    writeback_available: bool,
    writeback_reason: Option<String>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct ReviewIdentity {
    review_id: String,
    review_sha256: String,
    expires_at_ms: i64,
    workspace_id: String,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct WorkspaceStatus {
    service: String,
    workspace_protocol: u32,
    instance_id: String,
    pub(crate) session_id: String,
    task_profile: String,
    pub(crate) session_state: String,
    busy: bool,
    last_client_message_ms: u64,
    workspaces: Vec<WorkspaceEntry>,
    pub(crate) pending_review: Option<ReviewIdentity>,
    last_result: Option<ApplyReport>,
    // 浏览器回执由 Rust 模型调度器消费，不把控制面完整状态透传给 WebView。
    #[serde(default, skip_serializing)]
    pub(crate) browser: Option<BrowserProgress>,
}
#[derive(Clone, Deserialize)]
pub(crate) struct BrowserProgress {
    service: String,
    browser_protocol: u32,
    pub(crate) session_id: String,
    pub(crate) state: String,
    #[serde(default)]
    pub(crate) pending_http_requests: Option<usize>,
    pub(crate) receipts: Vec<BrowserHttpReceipt>,
}
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BrowserHttpReceipt {
    pub(crate) action_sha256: String,
    pub(crate) session_id: String,
    pub(crate) outcome: String,
    dispatched: bool,
    http_status: Option<u16>,
    automatic_retry: bool,
}
impl BrowserProgress {
    fn validate(&self, session_id: &str) -> Result<(), String> {
        if self.service != "agentguard-browser-host"
            || self.browser_protocol != 1
            || self.session_id != session_id
            || !["active", "paused", "stopped", "failed"].contains(&self.state.as_str())
            || self.pending_http_requests.is_some_and(|count| count > 8)
            || self.receipts.len() > 50
            || self.receipts.iter().any(|r| {
                r.automatic_retry
                    || !safe_identifier(&r.session_id)
                    || r.action_sha256.len() != 64
                    || !r.action_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    || !matches!(
                        (r.outcome.as_str(), r.dispatched, r.http_status),
                        ("success", true, Some(200..=299))
                            | ("failed", true, Some(300..=599))
                            | ("refused" | "cancelled" | "timed_out", false, None)
                            | ("unknown", true, None | Some(200..=599))
                    )
            })
        {
            return Err("WORKSPACE_PROTOCOL".into());
        }
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub struct FileVersion {
    sha256: String,
    bytes: u64,
    mode: u32,
    text: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct FileChange {
    path: String,
    kind: String,
    before: Option<FileVersion>,
    after: Option<FileVersion>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Preview {
    digest: String,
    workspace_root: String,
    recovery_directory: String,
    changes: Vec<FileChange>,
    total_body_bytes: u64,
    atomic: bool,
    limitations: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct FileResult {
    path: String,
    state: String,
    detail: String,
    recovery_file: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct ApplyReport {
    outcome: String,
    files: Vec<FileResult>,
    recovery_directory: Option<String>,
    detail: String,
}
/// 批准凭据只留 Rust；WebView 得到下方显式构造的安全视图。
#[derive(Clone, Deserialize)]
struct RemoteReview {
    service: String,
    workspace_protocol: u32,
    instance_id: String,
    session_id: String,
    workspace_id: String,
    review_id: String,
    review_sha256: String,
    review_nonce: String,
    expires_at_ms: i64,
    preview: Preview,
    binding: ApprovalBinding,
}
#[derive(Serialize)]
pub struct WorkspaceReview {
    session_id: String,
    workspace_id: String,
    review_id: String,
    review_sha256: String,
    expires_at_ms: i64,
    preview: Preview,
}
#[derive(Deserialize)]
struct WorkspaceEnvelope {
    service: String,
    workspace_protocol: u32,
    instance_id: String,
    session_id: String,
}
#[derive(Deserialize)]
struct RemoteApply {
    service: String,
    workspace_protocol: u32,
    instance_id: String,
    session_id: String,
    result: ApplyReport,
}
fn sha_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn safe_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn workspace_identity(
    connection: &Connection,
    service: &str,
    protocol: u32,
    instance: &str,
    session: &str,
) -> Result<(), String> {
    if service != "agentguard-mcp"
        || protocol != 1
        || instance != connection.instance_id
        || !safe_identifier(session)
    {
        return Err("WORKSPACE_PROTOCOL".into());
    }
    Ok(())
}
impl ApplyReport {
    fn validate(&self) -> Result<(), String> {
        if !["applied", "conflict", "partial", "unknown"].contains(&self.outcome.as_str())
            || self.files.iter().any(|f| {
                !["applied", "conflict", "not_applied", "unknown"].contains(&f.state.as_str())
            })
        {
            return Err("WORKSPACE_PROTOCOL".into());
        }
        Ok(())
    }
}
impl RemoteReview {
    fn identity(&self) -> ReviewIdentity {
        ReviewIdentity {
            review_id: self.review_id.clone(),
            review_sha256: self.review_sha256.clone(),
            expires_at_ms: self.expires_at_ms,
            workspace_id: self.workspace_id.clone(),
        }
    }
    fn view(&self) -> WorkspaceReview {
        WorkspaceReview {
            session_id: self.session_id.clone(),
            workspace_id: self.workspace_id.clone(),
            review_id: self.review_id.clone(),
            review_sha256: self.review_sha256.clone(),
            expires_at_ms: self.expires_at_ms,
            preview: self.preview.clone(),
        }
    }
    fn validate(&self, connection: &Connection, current: &WorkspaceStatus) -> Result<(), String> {
        workspace_identity(
            connection,
            &self.service,
            self.workspace_protocol,
            &self.instance_id,
            &self.session_id,
        )?;
        let action = self.binding.action().spec();
        self.binding
            .validate_for_action(self.binding.action(), now_ms()?)
            .map_err(|_| "WORKSPACE_STALE")?;
        let entry = current
            .workspaces
            .iter()
            .find(|w| w.workspace_id == self.workspace_id)
            .ok_or("WORKSPACE_STALE")?;
        if current.session_state != "active"
            || current.busy
            || current.session_id != self.session_id
            || !entry.writable
            || !entry.writeback_available
            || entry.target != self.preview.workspace_root
            || self.binding.approval_id().as_str() != self.review_id
            || self.binding.nonce() != self.review_nonce
            || self.binding.expires_at_ms() != self.expires_at_ms
            || action.session_id.as_str() != self.session_id
            || action.target != self.preview.workspace_root
            || action.tool.service != "agentguard-host-control"
            || action.tool.name != "workspace_apply"
            || !sha_id(&self.review_nonce)
            || self.review_sha256
                != format!(
                    "{:x}",
                    Sha256::digest(self.binding.action().canonical_bytes())
                )
            || action.parameters
                != serde_json::json!({"workspace_id":self.workspace_id,"preview":self.preview})
            || !sha_id(&self.preview.digest)
            || self.preview.atomic
            || !Path::new(&self.preview.recovery_directory).is_absolute()
        {
            return Err("WORKSPACE_BINDING".into());
        }
        let mut paths = std::collections::BTreeSet::new();
        let mut total: u64 = 0;
        for change in &self.preview.changes {
            if change.path.is_empty()
                || Path::new(&change.path).is_absolute()
                || Path::new(&change.path)
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
                || !paths.insert(&change.path)
                || !matches!(
                    (
                        change.kind.as_str(),
                        change.before.is_some(),
                        change.after.is_some()
                    ),
                    ("create", false, true) | ("modify", true, true) | ("delete", true, false)
                )
            {
                return Err("WORKSPACE_PROTOCOL".into());
            }
            for version in [&change.before, &change.after].into_iter().flatten() {
                if !sha_id(&version.sha256) || version.mode > 0o7777 {
                    return Err("WORKSPACE_PROTOCOL".into());
                }
                if let Some(body) = &version.text {
                    if body.len() as u64 != version.bytes
                        || format!("{:x}", Sha256::digest(body.as_bytes())) != version.sha256
                    {
                        return Err("WORKSPACE_BINDING".into());
                    }
                }
                total = total
                    .checked_add(version.bytes)
                    .ok_or("WORKSPACE_PROTOCOL")?;
            }
        }
        if total != self.preview.total_body_bytes {
            return Err("WORKSPACE_PROTOCOL".into());
        }
        Ok(())
    }
}
fn workspace_http(
    connection: &Connection,
    method: &str,
    path: &str,
    body: &str,
) -> Result<Vec<u8>, String> {
    let (code, bytes) = http_response(
        connection.port,
        &connection.token,
        method,
        path,
        body,
        WORKSPACE_TIMEOUT,
    )?;
    if code == 200 {
        return Ok(bytes);
    }
    if code == 403 {
        return Err("GATEWAY_AUTH".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_PROTOCOL")?;
    let code = value
        .get("error")
        .and_then(|v| v.as_str())
        .ok_or("WORKSPACE_PROTOCOL")?;
    if [
        "WORKSPACE_ARGUMENTS",
        "WORKSPACE_BUSY",
        "WORKSPACE_REPLY_UNKNOWN",
        "WORKSPACE_STALE",
        "WORKSPACE_UNAVAILABLE",
        "WORKSPACE_FAILED",
        "WORKSPACE_DENIED",
    ]
    .contains(&code)
    {
        Err(code.to_owned())
    } else {
        Err("WORKSPACE_PROTOCOL".into())
    }
}
fn workspace_status(connection: &mut Connection) -> Result<WorkspaceStatus, String> {
    if !connection.supports_workspace {
        return Err("WORKSPACE_UNAVAILABLE".into());
    }
    let bytes = workspace_http(connection, "GET", "/workspace/status", "")?;
    let remote: WorkspaceStatus =
        serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_PROTOCOL")?;
    workspace_identity(
        connection,
        &remote.service,
        remote.workspace_protocol,
        &remote.instance_id,
        &remote.session_id,
    )?;
    if !["active", "paused", "stopped", "failed"].contains(&remote.session_state.as_str())
        || remote.workspaces.iter().any(|w| {
            !safe_identifier(&w.workspace_id)
                || !Path::new(&w.target).is_absolute()
                || !Path::new(&w.snapshot).is_absolute()
        })
        || remote
            .workspaces
            .iter()
            .map(|w| &w.workspace_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != remote.workspaces.len()
    {
        return Err("WORKSPACE_PROTOCOL".into());
    }
    if let Some(report) = &remote.last_result {
        report.validate()?;
    }
    if let Some(browser) = &remote.browser {
        browser.validate(&remote.session_id)?;
    }
    if connection.review.as_ref().is_some_and(|r| {
        r.session_id != remote.session_id
            || remote.session_state != "active"
            || remote.pending_review.as_ref() != Some(&r.identity())
            || r.expires_at_ms <= now_ms().unwrap_or(i64::MAX)
    }) {
        connection.review = None;
    }
    connection.workspace = Some(remote.clone());
    Ok(remote)
}

fn hex_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 固定路径、精确 Content-Length、总期限和大小上限；错误不包含响应正文或凭据。
fn http(port: u16, token: &str, method: &str, path: &str, body: &str) -> Result<Vec<u8>, String> {
    let (code, bytes) = http_response(port, token, method, path, body, TIMEOUT)?;
    match code {
        200 => Ok(bytes),
        409 => Err("GATEWAY_STALE".into()),
        403 => Err("GATEWAY_AUTH".into()),
        _ => Err("GATEWAY_PROTOCOL".into()),
    }
}

fn http_response(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), String> {
    let started = Instant::now();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream =
        TcpStream::connect_timeout(&address, timeout).map_err(|_| "GATEWAY_UNAVAILABLE")?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| "GATEWAY_IO")?;
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).map_err(|_| "GATEWAY_IO")?;
    let mut bytes = Vec::new();
    let mut header_end = None;
    let mut expected = None;
    let mut response_code = 0;
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err("GATEWAY_TIMEOUT".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "GATEWAY_IO")?;
        let mut buffer = [0; 4096];
        let count = stream.read(&mut buffer).map_err(|_| "GATEWAY_IO")?;
        if count == 0 {
            return Err("GATEWAY_TRUNCATED".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > LIMIT + 8192 {
            return Err("GATEWAY_TOO_LARGE".into());
        }
        if header_end.is_none() {
            if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                if at > 8192 {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                let headers = std::str::from_utf8(&bytes[..at]).map_err(|_| "GATEWAY_PROTOCOL")?;
                let mut lines = headers.split("\r\n");
                let first = lines.next().ok_or("GATEWAY_PROTOCOL")?;
                let code = first.split_whitespace().nth(1).ok_or("GATEWAY_PROTOCOL")?;
                if !(first.starts_with("HTTP/1.1 ") || first.starts_with("HTTP/1.0 ")) {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                response_code = code.parse::<u16>().map_err(|_| "GATEWAY_PROTOCOL")?;
                if !(100..600).contains(&response_code) {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                let mut length = None;
                let mut json = false;
                for line in lines {
                    let (name, value) = line.split_once(':').ok_or("GATEWAY_PROTOCOL")?;
                    if name.eq_ignore_ascii_case("transfer-encoding") {
                        return Err("GATEWAY_PROTOCOL".into());
                    }
                    if name.eq_ignore_ascii_case("content-type") {
                        json = value.trim().split(';').next() == Some("application/json");
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        if length.is_some() {
                            return Err("GATEWAY_PROTOCOL".into());
                        }
                        length = Some(
                            value
                                .trim()
                                .parse::<usize>()
                                .map_err(|_| "GATEWAY_PROTOCOL")?,
                        );
                    }
                }
                let length = length
                    .filter(|len| *len <= LIMIT)
                    .ok_or("GATEWAY_TOO_LARGE")?;
                if !json {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                header_end = Some(at + 4);
                expected = Some(at + 4 + length);
            } else if bytes.len() > 8192 {
                return Err("GATEWAY_PROTOCOL".into());
            }
        }
        if let Some(end) = expected {
            if bytes.len() >= end {
                if bytes.len() != end {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                return Ok((response_code, bytes[header_end.unwrap()..end].to_vec()));
            }
        }
    }
}

fn status(connection: &mut Connection) -> Result<View, String> {
    let started = Instant::now();
    let bytes = http(connection.port, &connection.token, "GET", "/status", "")?;
    let remote: RemoteStatus = serde_json::from_slice(&bytes).map_err(|_| "GATEWAY_PROTOCOL")?;
    if remote.service != "agentguard-mcp"
        || remote.confirm_protocol != 2
        || !hex_id(&remote.instance_id)
        || (!connection.instance_id.is_empty() && connection.instance_id != remote.instance_id)
    {
        return Err("GATEWAY_INSTANCE_CHANGED".into());
    }
    if let Some(request) = &remote.pending {
        if request.what.len() > 2 * 1024 * 1024 {
            return Err("GATEWAY_TOO_LARGE".into());
        }
        if request.id.is_empty()
            || request.id.len() > 128
            || request.findings.len() > 64
            || remote.remaining_ms.is_none()
        {
            return Err("GATEWAY_PROTOCOL".into());
        }
        request.validate(now_ms()?)?;
    }
    connection.instance_id = remote.instance_id;
    // 减去整个往返耗时，宁早过期，不在前端扩大批准窗口。
    let remaining = remote
        .remaining_ms
        .unwrap_or(0)
        .saturating_sub(started.elapsed().as_millis() as u64);
    let remaining = if let Some(request) = &remote.pending {
        remaining.min(
            request
                .binding
                .expires_at_ms()
                .saturating_sub(now_ms()?)
                .max(0) as u64,
        )
    } else {
        remaining
    };
    connection.displayed = remote.pending.filter(|_| remaining > 0);
    Ok(View {
        connection_id: connection.id.clone(),
        port: connection.port,
        instance_id: connection.instance_id.clone(),
        pending: connection.displayed.as_ref().map(RemoteRequest::view),
        remaining_ms: remaining,
        supports_workspace: connection.supports_workspace,
    })
}

fn now_ms() -> Result<i64, String> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "GATEWAY_CLOCK")?
            .as_millis(),
    )
    .map_err(|_| "GATEWAY_CLOCK".into())
}

impl GatewayConfirm {
    pub(crate) fn control_port(&self) -> Option<u16> {
        self.0
            .lock()
            .ok()
            .and_then(|state| state.as_ref().map(|connection| connection.port))
    }

    pub(crate) fn connected(&self) -> bool {
        self.0.lock().map(|slot| slot.is_some()).unwrap_or(true)
    }
    pub(crate) fn import_file(&self, path: &Path) -> Result<View, String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        *slot = None;
        let file = read_control_file(path)?;
        let mut connection = Connection {
            id: uuid::Uuid::new_v4().to_string(),
            port: file.port,
            token: file.token,
            instance_id: file.instance_id,
            displayed: None,
            supports_workspace: true,
            workspace: None,
            review: None,
            workspace_epoch: 0,
        };
        let view = status(&mut connection)?;
        *slot = Some(connection);
        Ok(view)
    }
    fn connect(&self, port: u16, token: String) -> Result<View, String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        *slot = None;
        if port == 0 || !hex_id(&token) {
            return Err("GATEWAY_INPUT".into());
        }
        let mut connection = Connection {
            id: uuid::Uuid::new_v4().to_string(),
            port,
            token,
            instance_id: String::new(),
            displayed: None,
            supports_workspace: false,
            workspace: None,
            review: None,
            workspace_epoch: 0,
        };
        let view = status(&mut connection)?;
        *slot = Some(connection);
        Ok(view)
    }
    pub(crate) fn poll(&self, id: &str) -> Result<View, String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let connection = slot
            .as_mut()
            .filter(|c| c.id == id)
            .ok_or("GATEWAY_DISCONNECTED")?;
        let result = status(connection);
        if result.is_err() {
            *slot = None;
        }
        result
    }
    pub(crate) fn disconnect(&self, id: &str) -> Result<(), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        if slot.as_ref().is_some_and(|c| c.id == id) {
            *slot = None;
        }
        Ok(())
    }
    fn answer(&self, id: &str, request_id: &str, approve: bool) -> Result<(), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let connection = slot
            .as_mut()
            .filter(|c| c.id == id)
            .ok_or("GATEWAY_DISCONNECTED")?;
        let displayed = connection
            .displayed
            .take()
            .filter(|r| r.id == request_id)
            .ok_or("GATEWAY_STALE")?;
        let result = (|| {
            let current = status(connection)?;
            if current.pending.as_ref() != Some(&displayed.view())
                || connection.displayed.as_ref() != Some(&displayed)
            {
                return Err("GATEWAY_STALE".into());
            }
            displayed.validate(now_ms()?)?;
            let body =
                serde_json::json!({"id": request_id, "action_sha256": displayed.action_sha256,
                "approval_nonce": displayed.binding.nonce()})
                .to_string();
            let bytes = http(
                connection.port,
                &connection.token,
                "POST",
                if approve { "/approve" } else { "/deny" },
                &body,
            )?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| "GATEWAY_PROTOCOL")?;
            if value.get("answered").and_then(|v| v.as_bool()) != Some(true) {
                return Err("GATEWAY_STALE".into());
            }
            Ok(())
        })();
        connection.displayed = None;
        // 回执不明时不重试批准；断开后由网关端期限兜底。
        if result.as_ref().is_err_and(|e| e != "GATEWAY_STALE") {
            *slot = None;
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn approve_test_action(&self, id: &str, request_id: &str) -> Result<(), String> {
        // 验收调用方先核对合成任务的完整动作；仍使用正式的单次批准绑定与重校验。
        self.answer(id, request_id, true)
    }

    #[cfg(test)]
    pub(crate) fn deny_test_action(&self, id: &str, request_id: &str) -> Result<(), String> {
        self.answer(id, request_id, false)
    }
}

impl GatewayConfirm {
    // 工作区慢操作不占用连接锁；暂停/停止可以并发撤权，旧回包不能覆盖新状态。
    fn workspace_snapshot(&self, id: &str, mutate: bool) -> Result<(Connection, u64), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let current = slot
            .as_mut()
            .filter(|c| c.id == id && c.supports_workspace)
            .ok_or("WORKSPACE_UNAVAILABLE")?;
        if mutate {
            current.workspace_epoch = current.workspace_epoch.wrapping_add(1);
        }
        let snapshot = current.clone();
        if mutate {
            current.review = None;
        }
        Ok((snapshot, current.workspace_epoch))
    }
    fn workspace_commit(&self, id: &str, epoch: u64, snapshot: &Connection) -> Result<(), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let current = slot
            .as_mut()
            .filter(|c| c.id == id && c.workspace_epoch == epoch)
            .ok_or("WORKSPACE_STALE")?;
        current.workspace = snapshot.workspace.clone();
        current.review = snapshot.review.clone();
        Ok(())
    }
    pub(crate) fn workspace_poll(&self, id: &str) -> Result<WorkspaceStatus, String> {
        let (mut connection, epoch) = self.workspace_snapshot(id, false)?;
        let result = workspace_status(&mut connection);
        if result.is_err() {
            connection.workspace = None;
            connection.review = None;
        }
        self.workspace_commit(id, epoch, &connection)?;
        result
    }
    fn workspace_preview(&self, id: &str, workspace_id: &str) -> Result<WorkspaceReview, String> {
        let (mut connection, epoch) = self.workspace_snapshot(id, true)?;
        connection.review = None;
        let current = workspace_status(&mut connection)?;
        if current.session_state != "active" || current.busy {
            return Err("WORKSPACE_BUSY".into());
        }
        if !current
            .workspaces
            .iter()
            .any(|w| w.workspace_id == workspace_id && w.writable && w.writeback_available)
        {
            return Err("WORKSPACE_UNAVAILABLE".into());
        }
        let bytes = workspace_http(
            &connection,
            "POST",
            "/workspace/preview",
            &serde_json::json!({"workspace_id":workspace_id}).to_string(),
        )?;
        let review: RemoteReview =
            serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_PROTOCOL")?;
        if review.workspace_id != workspace_id {
            return Err("WORKSPACE_BINDING".into());
        }
        review.validate(&connection, &current)?;
        let after = workspace_status(&mut connection)?;
        review.validate(&connection, &after)?;
        if after.pending_review.as_ref() != Some(&review.identity()) {
            return Err("WORKSPACE_STALE".into());
        }
        let view = review.view();
        connection.review = Some(review);
        self.workspace_commit(id, epoch, &connection)?;
        Ok(view)
    }
    fn workspace_apply(
        &self,
        id: &str,
        review_id: &str,
        review_sha256: &str,
    ) -> Result<ApplyReport, String> {
        let (mut connection, epoch) = self.workspace_snapshot(id, true)?;
        let review = connection
            .review
            .take()
            .filter(|r| r.review_id == review_id && r.review_sha256 == review_sha256)
            .ok_or("WORKSPACE_STALE")?;
        let current = workspace_status(&mut connection)?;
        review.validate(&connection, &current)?;
        if current.pending_review.as_ref() != Some(&review.identity())
            || review.preview.changes.is_empty()
        {
            return Err("WORKSPACE_STALE".into());
        }
        // 再检查本地控制动作；旧连接/并发暂停后不派发。
        self.workspace_commit(id, epoch, &connection)?;
        let body = serde_json::json!({"review_id":review.review_id,"review_sha256":review.review_sha256,"review_nonce":review.review_nonce}).to_string();
        let bytes =
            workspace_http(&connection, "POST", "/workspace/apply", &body).map_err(|e| {
                if [
                    "WORKSPACE_ARGUMENTS",
                    "WORKSPACE_BUSY",
                    "WORKSPACE_STALE",
                    "WORKSPACE_UNAVAILABLE",
                    "WORKSPACE_FAILED",
                    "WORKSPACE_DENIED",
                    "WORKSPACE_REPLY_UNKNOWN",
                ]
                .contains(&e.as_str())
                {
                    e
                } else {
                    "WORKSPACE_REPLY_UNKNOWN".into()
                }
            })?;
        let remote: RemoteApply =
            serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_REPLY_UNKNOWN")?;
        workspace_identity(
            &connection,
            &remote.service,
            remote.workspace_protocol,
            &remote.instance_id,
            &remote.session_id,
        )
        .map_err(|_| "WORKSPACE_REPLY_UNKNOWN")?;
        if remote.session_id != review.session_id {
            return Err("WORKSPACE_REPLY_UNKNOWN".into());
        }
        remote
            .result
            .validate()
            .map_err(|_| "WORKSPACE_REPLY_UNKNOWN")?;
        if let Some(state) = connection.workspace.as_mut() {
            state.last_result = Some(remote.result.clone());
            state.pending_review = None;
        }
        self.workspace_commit(id, epoch, &connection)
            .map_err(|_| "WORKSPACE_REPLY_UNKNOWN")?;
        Ok(remote.result)
    }
    fn workspace_discard(
        &self,
        id: &str,
        review_id: &str,
        review_sha256: &str,
    ) -> Result<WorkspaceStatus, String> {
        let (mut connection, epoch) = self.workspace_snapshot(id, true)?;
        let review = connection
            .review
            .take()
            .filter(|r| r.review_id == review_id && r.review_sha256 == review_sha256)
            .ok_or("WORKSPACE_STALE")?;
        let current = workspace_status(&mut connection)?;
        review.validate(&connection, &current)?;
        if current.pending_review.as_ref() != Some(&review.identity()) {
            return Err("WORKSPACE_STALE".into());
        }
        self.workspace_commit(id, epoch, &connection)?;
        let body = serde_json::json!({"review_id":review.review_id,"review_sha256":review.review_sha256,"review_nonce":review.review_nonce}).to_string();
        let bytes = workspace_http(&connection, "POST", "/workspace/discard", &body)?;
        let remote: WorkspaceEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_PROTOCOL")?;
        workspace_identity(
            &connection,
            &remote.service,
            remote.workspace_protocol,
            &remote.instance_id,
            &remote.session_id,
        )?;
        if remote.session_id != review.session_id {
            return Err("WORKSPACE_STALE".into());
        }
        let fresh = workspace_status(&mut connection)?;
        if fresh.session_id != remote.session_id
            || fresh
                .pending_review
                .as_ref()
                .is_some_and(|r| r.review_id == review.review_id)
        {
            return Err("WORKSPACE_STALE".into());
        }
        self.workspace_commit(id, epoch, &connection)?;
        Ok(fresh)
    }
    pub(crate) fn workspace_lifecycle(
        &self,
        id: &str,
        action: &str,
    ) -> Result<WorkspaceStatus, String> {
        if !["pause", "resume", "stop"].contains(&action) {
            return Err("WORKSPACE_ARGUMENTS".into());
        }
        let (mut connection, epoch) = self.workspace_snapshot(id, true)?;
        connection.review = None;
        let bytes = workspace_http(&connection, "POST", &format!("/workspace/{action}"), "{}")?;
        let remote: WorkspaceEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_PROTOCOL")?;
        workspace_identity(
            &connection,
            &remote.service,
            remote.workspace_protocol,
            &remote.instance_id,
            &remote.session_id,
        )?;
        let fresh = workspace_status(&mut connection)?;
        if fresh.session_id != remote.session_id {
            return Err("WORKSPACE_STALE".into());
        }
        self.workspace_commit(id, epoch, &connection)?;
        Ok(fresh)
    }
}
#[tauri::command]
pub async fn poll_gateway_workspace(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
) -> Result<WorkspaceStatus, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.workspace_poll(&connection_id))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn preview_gateway_workspace(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
    workspace_id: String,
) -> Result<WorkspaceReview, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        state.workspace_preview(&connection_id, &workspace_id)
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn apply_gateway_workspace(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
    review_id: String,
    review_sha256: String,
) -> Result<ApplyReport, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        state.workspace_apply(&connection_id, &review_id, &review_sha256)
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn discard_gateway_workspace(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
    review_id: String,
    review_sha256: String,
) -> Result<WorkspaceStatus, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        state.workspace_discard(&connection_id, &review_id, &review_sha256)
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn control_gateway_workspace(
    state: tauri::State<'_, GatewayConfirm>,
    manager: tauri::State<'_, crate::local_agent::AgentManager>,
    connection_id: String,
    action: String,
) -> Result<WorkspaceStatus, String> {
    let state = state.inner().clone();
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if manager.owns_connection(&connection_id) {
            manager
                .control_connection(&connection_id, &action)?
                .ok_or_else(|| "LOCAL_AGENT_CONNECTION".into())
        } else {
            state.workspace_lifecycle(&connection_id, &action)
        }
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}

#[tauri::command]
pub async fn import_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    manager: tauri::State<'_, crate::local_agent::AgentManager>,
    path: String,
) -> Result<View, String> {
    let state = state.inner().clone();
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager.external_connection(|| state.import_file(Path::new(&path)))
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}

#[tauri::command]
pub async fn pick_gateway_control_file() -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            rfd::FileDialog::new()
                .add_filter("JSON", &["json"])
                .pick_file()
                .map(|path| {
                    path.to_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "GATEWAY_FILE_PATH".to_owned())
                })
                .transpose()
        })
        .await
        .map_err(|_| "GATEWAY_WORKER")?
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("GATEWAY_FILE_UNSUPPORTED".into())
    }
}

#[tauri::command]
pub async fn connect_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    manager: tauri::State<'_, crate::local_agent::AgentManager>,
    port: u16,
    token: String,
) -> Result<View, String> {
    let state = state.inner().clone();
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager.external_connection(|| state.connect(port, token))
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn poll_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
) -> Result<View, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.poll(&connection_id))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn disconnect_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    manager: tauri::State<'_, crate::local_agent::AgentManager>,
    connection_id: String,
) -> Result<(), String> {
    let state = state.inner().clone();
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if manager.owns_connection(&connection_id) {
            manager
                .control_connection(&connection_id, "stop")
                .map(|_| ())
        } else {
            state.disconnect(&connection_id)
        }
    })
    .await
    .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn answer_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
    request_id: String,
    approve: bool,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.answer(&connection_id, &request_id, approve))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;

    #[cfg(unix)]
    fn control_fixture(port: u16, instance: &str) -> (std::path::PathBuf, serde_json::Value) {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("ag-control-import-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let path = directory.join("control.json");
        let value = serde_json::json!({"service":"agentguard-mcp", "confirm_protocol":2,
            "url":format!("http://127.0.0.1:{port}"), "port":port, "instance_id":instance, "token":"a".repeat(32)});
        std::fs::write(&path, value.to_string()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (path, value)
    }

    #[cfg(unix)]
    #[test]
    fn 连接文件严格核对协议地址字段与大小() {
        let (path, value) = control_fixture(8790, &"b".repeat(32));
        read_control_file(&path).unwrap();
        for key in [
            "service",
            "confirm_protocol",
            "url",
            "port",
            "instance_id",
            "token",
        ] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(key);
            std::fs::write(&path, bad.to_string()).unwrap();
            assert!(read_control_file(&path).is_err(), "{key}");
        }
        for (key, bad_value) in [
            ("service", serde_json::json!("other")),
            ("confirm_protocol", serde_json::json!(1)),
            ("url", serde_json::json!("http://localhost:8790")),
            ("url", serde_json::json!("http://127.0.0.1:8791")),
            ("url", serde_json::json!("http://127.0.0.1:8790/redirect")),
            ("url", serde_json::json!("http://example.test:8790")),
            ("port", serde_json::json!(0)),
            ("instance_id", serde_json::json!("bad")),
            ("token", serde_json::json!("a".repeat(64))),
            ("extra", serde_json::json!(true)),
        ] {
            let mut bad = value.clone();
            bad[key] = bad_value;
            std::fs::write(&path, bad.to_string()).unwrap();
            assert!(read_control_file(&path).is_err());
        }
        std::fs::write(&path, " ".repeat(CONTROL_FILE_LIMIT + 1)).unwrap();
        assert!(matches!(read_control_file(&path), Err(code) if code == "GATEWAY_FILE_TOO_LARGE"));
        assert!(read_control_file(Path::new("relative/control.json")).is_err());
        assert!(read_control_file(&path.parent().unwrap().join("../control.json")).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn 连接文件拒绝宽权限父链接末端链接目录与管道() {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        let (path, _) = control_fixture(8790, &"b".repeat(32));
        let directory = path.parent().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            matches!(read_control_file(&path), Err(code) if code == "GATEWAY_FILE_PERMISSIONS")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file_link = directory.join("file-link.json");
        std::os::unix::fs::symlink(&path, &file_link).unwrap();
        assert!(read_control_file(&file_link).is_err());
        let parent_link = directory.join("parent-link");
        std::os::unix::fs::symlink(directory, &parent_link).unwrap();
        assert!(read_control_file(&parent_link.join("control.json")).is_err());
        assert!(read_control_file(directory).is_err());
        let fifo = directory.join("pipe.json");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_control_file(&fifo).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn 导入文件需匹配实时实例且只向网页返回安全视图() {
        for matching in [true, false] {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (path, _) = control_fixture(port, &"b".repeat(32));
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut input = Vec::new();
                while !input.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut buffer = [0; 4096];
                    let len = socket.read(&mut buffer).unwrap();
                    assert!(len > 0);
                    input.extend_from_slice(&buffer[..len]);
                }
                assert!(std::str::from_utf8(&input)
                    .unwrap()
                    .contains(&format!("Authorization: Bearer {}", "a".repeat(32))));
                let body = serde_json::json!({"service":"agentguard-mcp", "confirm_protocol":2,
                    "instance_id":if matching { "b".repeat(32) } else { "c".repeat(32) }, "pending":null, "remaining_ms":0}).to_string();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            });
            let manager = GatewayConfirm::default();
            let result = manager.import_file(&path);
            if matching {
                let view = serde_json::to_string(&result.unwrap()).unwrap();
                assert!(!view.contains(&"a".repeat(32)) && !view.contains("token"));
                assert!(view.contains(&"b".repeat(32)));
            } else {
                assert!(matches!(result, Err(code) if code == "GATEWAY_INSTANCE_CHANGED"));
                assert!(manager.0.lock().unwrap().is_none());
            }
            worker.join().unwrap();
            std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    #[ignore = "需显式提供真实合成宿主的 AGENTGUARD_WORKSPACE_CONTROL_FILE"]
    fn 真实宿主工作区预览与绑定核验() {
        let path = std::env::var("AGENTGUARD_WORKSPACE_CONTROL_FILE")
            .expect("需要本次合成宿主连接文件路径");
        let manager = GatewayConfirm::default();
        let view = manager.import_file(Path::new(&path)).unwrap();
        let state = manager.workspace_poll(&view.connection_id).unwrap();
        let entry = state.workspaces.first().expect("需要合成工作区");
        let result = manager.workspace_preview(&view.connection_id, &entry.workspace_id);
        if std::env::var("AGENTGUARD_WORKSPACE_EXPECT_DENIED").as_deref() == Ok("1") {
            assert!(matches!(result, Err(code) if code == "WORKSPACE_DENIED"));
            assert!(manager.0.lock().unwrap().as_ref().unwrap().review.is_none());
            let current = manager.workspace_poll(&view.connection_id).unwrap();
            assert!(current.pending_review.is_none() && current.last_result.is_none());
            println!("真实敏感副产物预览明确拒绝，无批准与回写回执");
            return;
        }
        if let Err(code) = &result {
            println!("真实预览失败码：{code}");
        }
        let review = result.unwrap();
        assert!(!review.preview.changes.is_empty());
        println!(
            "真实预览验证通过，文件数={}，目标={}，session={}",
            review.preview.changes.len(),
            review.preview.workspace_root,
            review.session_id
        );
    }

    fn workspace_fixture() -> (Connection, WorkspaceStatus, RemoteReview) {
        use guard_schema::{
            ActionSnapshot, ActionSpec, ToolIdentity, ValidatedId, EXECUTION_CONTRACT_VERSION,
        };
        let id = |s: &str| ValidatedId::new(s).unwrap();
        let now = now_ms().unwrap();
        let version = |text: &str| FileVersion {
            sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
            bytes: text.len() as u64,
            mode: 0o644,
            text: Some(text.into()),
        };
        let preview = Preview {
            digest: "e".repeat(64),
            workspace_root: "/fixture/original".into(),
            recovery_directory: "/fixture/recovery".into(),
            changes: vec![FileChange {
                path: "report.txt".into(),
                kind: "modify".into(),
                before: Some(version("旧")),
                after: Some(version("新")),
            }],
            total_body_bytes: 6,
            atomic: false,
            limitations: vec!["不是多文件原子事务".into()],
        };
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("workspace-session"),
            action_id: id("workspace-action"),
            request_id: id("workspace-request"),
            tool: ToolIdentity { registration: None,
                service: "agentguard-host-control".into(),
                name: "workspace_apply".into(),
                version: "fixture".into(),
            },
            target: preview.workspace_root.clone(),
            parameters: serde_json::json!({"workspace_id":"workspace-0","preview":preview}),
            policy_version: id("workspace-policy"),
            issued_at_ms: now - 1000,
            expires_at_ms: now + 60000,
            nonce: "b".repeat(64),
            sources: vec![],
        })
        .unwrap();
        let binding = ApprovalBinding::new(
            id("workspace-review"),
            action,
            "c".repeat(64),
            now - 500,
            now + 59000,
        )
        .unwrap();
        let review = RemoteReview {
            service: "agentguard-mcp".into(),
            workspace_protocol: 1,
            instance_id: "d".repeat(32),
            session_id: "workspace-session".into(),
            workspace_id: "workspace-0".into(),
            review_id: "workspace-review".into(),
            review_sha256: format!("{:x}", Sha256::digest(binding.action().canonical_bytes())),
            review_nonce: binding.nonce().into(),
            expires_at_ms: binding.expires_at_ms(),
            preview,
            binding,
        };
        let status = WorkspaceStatus {
            service: "agentguard-mcp".into(),
            workspace_protocol: 1,
            instance_id: review.instance_id.clone(),
            session_id: review.session_id.clone(),
            task_profile: "fixture".into(),
            session_state: "active".into(),
            busy: false,
            last_client_message_ms: 0,
            workspaces: vec![WorkspaceEntry {
                workspace_id: "workspace-0".into(),
                target: "/fixture/original".into(),
                snapshot: "/fixture/snapshot".into(),
                writable: true,
                writeback_available: true,
                writeback_reason: None,
            }],
            pending_review: Some(review.identity()),
            last_result: None,
            browser: None,
        };
        let connection = Connection {
            id: "fixture-connection".into(),
            port: 1,
            token: "a".repeat(32),
            instance_id: review.instance_id.clone(),
            displayed: None,
            supports_workspace: true,
            workspace: Some(status.clone()),
            review: Some(review.clone()),
            workspace_epoch: 0,
        };
        (connection, status, review)
    }

    #[test]
    fn 工作区批准逐值绑定全文恢复目录会话且不向网页泄漏随机值() {
        let (connection, status, review) = workspace_fixture();
        review.validate(&connection, &status).unwrap();
        let view = serde_json::to_string(&review.view()).unwrap();
        assert!(view.contains("旧") && view.contains("新") && view.contains("/fixture/recovery"));
        assert!(
            !view.contains("nonce")
                && !view.contains("binding")
                && !view.contains(&review.review_nonce)
                && !view.contains(&connection.token)
        );
        type ReviewMutation = Box<dyn Fn(&mut RemoteReview)>;
        let mutations: Vec<ReviewMutation> = vec![
            Box::new(|r| {
                r.preview.changes[0].after.as_mut().unwrap().text = Some("被替换正文".into())
            }),
            Box::new(|r| r.preview.recovery_directory = "/different/recovery".into()),
            Box::new(|r| r.preview.workspace_root = "/different/target".into()),
            Box::new(|r| r.session_id = "session-changed".into()),
            Box::new(|r| r.review_nonce = "9".repeat(64)),
            Box::new(|r| r.review_sha256 = "9".repeat(64)),
            Box::new(|r| r.expires_at_ms += 1),
            Box::new(|r| r.preview.changes[0].after.as_mut().unwrap().sha256 = "9".repeat(64)),
            Box::new(|r| r.workspace_id = "other".into()),
        ];
        for mutate in mutations {
            let mut bad = review.clone();
            mutate(&mut bad);
            assert!(bad.validate(&connection, &status).is_err());
        }
        let mut paused = status.clone();
        paused.session_state = "paused".into();
        assert!(review.validate(&connection, &paused).is_err());
    }

    fn mock_workspace(
        responses: Vec<(&'static str, u16, serde_json::Value)>,
    ) -> (u16, std::thread::JoinHandle<Vec<serde_json::Value>>) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            let mut received = Vec::new();
            for (path, code, value) in responses {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut data = Vec::new();
                loop {
                    let mut buf = [0; 4096];
                    let count = socket.read(&mut buf).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buf[..count]);
                    if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = std::str::from_utf8(&data[..at]).unwrap();
                        let length: usize = header
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if data.len() >= at + 4 + length {
                            assert!(header.lines().next().unwrap().contains(path));
                            assert!(header
                                .contains(&format!("Authorization: Bearer {}", "a".repeat(32))));
                            received.push(if length == 0 {
                                serde_json::Value::Null
                            } else {
                                serde_json::from_slice(&data[at + 4..]).unwrap()
                            });
                            break;
                        }
                    }
                }
                let body = value.to_string();
                write!(socket,"HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).unwrap();
            }
            received
        });
        (port, thread)
    }

    #[test]
    fn 工作区回写一次消费绑定成功硬拒绝与未知回执均不重发() {
        for error in [
            None,
            Some("WORKSPACE_DENIED"),
            Some("WORKSPACE_REPLY_UNKNOWN"),
        ] {
            let (mut connection, status, review) = workspace_fixture();
            let response = if let Some(code) = error {
                serde_json::json!({"error":code,"detail":"受控错误夹具"})
            } else {
                serde_json::json!({"service":"agentguard-mcp","workspace_protocol":1,"instance_id":connection.instance_id,"session_id":review.session_id,
                "result":{"outcome":"partial","files":[{"path":"report.txt","state":"applied","detail":"已应用","recovery_file":"/fixture/recovery/report.txt"}],"recovery_directory":"/fixture/recovery","detail":"逐项回执"}})
            };
            let (port, server) = mock_workspace(vec![
                (
                    "/workspace/status",
                    200,
                    serde_json::to_value(status).unwrap(),
                ),
                (
                    "/workspace/apply",
                    match error {
                        Some("WORKSPACE_DENIED") => 409,
                        Some(_) => 504,
                        None => 200,
                    },
                    response,
                ),
            ]);
            connection.port = port;
            let manager = GatewayConfirm::default();
            *manager.0.lock().unwrap() = Some(connection);
            let result = manager.workspace_apply(
                "fixture-connection",
                &review.review_id,
                &review.review_sha256,
            );
            if let Some(expected) = error {
                assert!(matches!(result,Err(code) if code == expected));
            } else {
                assert_eq!(result.unwrap().outcome, "partial");
            }
            assert!(manager
                .workspace_apply(
                    "fixture-connection",
                    &review.review_id,
                    &review.review_sha256
                )
                .is_err());
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[1],
                serde_json::json!({"review_id":review.review_id,"review_sha256":review.review_sha256,"review_nonce":review.review_nonce})
            );
            assert!(manager.0.lock().unwrap().as_ref().unwrap().review.is_none());
        }
    }

    #[test]
    fn 工作区预览硬拒绝保持明确拒绝且无批准() {
        let (mut connection, status, _) = workspace_fixture();
        connection.review = None;
        let (port, server) = mock_workspace(vec![
            (
                "/workspace/status",
                200,
                serde_json::to_value(status).unwrap(),
            ),
            (
                "/workspace/preview",
                409,
                serde_json::json!({"error":"WORKSPACE_DENIED","detail":"合成敏感路径不可回写"}),
            ),
        ]);
        connection.port = port;
        let manager = GatewayConfirm::default();
        *manager.0.lock().unwrap() = Some(connection);
        assert!(
            matches!(manager.workspace_preview("fixture-connection", "workspace-0"), Err(code) if code == "WORKSPACE_DENIED")
        );
        assert!(manager.0.lock().unwrap().as_ref().unwrap().review.is_none());
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn 工作区恢复换会话后旧预览在提交前被拒绝() {
        let (mut connection, mut status, review) = workspace_fixture();
        status.session_id = "session-resumed".into();
        status.pending_review = None;
        let (port, server) = mock_workspace(vec![(
            "/workspace/status",
            200,
            serde_json::to_value(status).unwrap(),
        )]);
        connection.port = port;
        let manager = GatewayConfirm::default();
        *manager.0.lock().unwrap() = Some(connection);
        assert!(manager
            .workspace_apply(
                "fixture-connection",
                &review.review_id,
                &review.review_sha256
            )
            .is_err());
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn 放弃回写消费当前预览且保持会话允许重新预览() {
        let (mut connection, status, review) = workspace_fixture();
        let mut after = status.clone();
        after.pending_review = None;
        let envelope = serde_json::json!({"service":"agentguard-mcp","workspace_protocol":1,"instance_id":connection.instance_id,"session_id":review.session_id});
        let (port, server) = mock_workspace(vec![
            (
                "/workspace/status",
                200,
                serde_json::to_value(status).unwrap(),
            ),
            ("/workspace/discard", 200, envelope),
            (
                "/workspace/status",
                200,
                serde_json::to_value(after).unwrap(),
            ),
        ]);
        connection.port = port;
        let manager = GatewayConfirm::default();
        *manager.0.lock().unwrap() = Some(connection);
        let result = manager
            .workspace_discard(
                "fixture-connection",
                &review.review_id,
                &review.review_sha256,
            )
            .unwrap();
        assert_eq!(result.session_state, "active");
        assert!(result.pending_review.is_none());
        assert!(manager
            .workspace_apply(
                "fixture-connection",
                &review.review_id,
                &review.review_sha256
            )
            .is_err());
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[1],
            serde_json::json!({"review_id":review.review_id,"review_sha256":review.review_sha256,"review_nonce":review.review_nonce})
        );
    }
    #[test]
    fn 生命周期先核对回包身份再以完整状态展示结果() {
        for action in ["pause", "resume", "stop"] {
            let (mut connection, mut status, _) = workspace_fixture();
            status.session_state = match action {
                "pause" => "paused",
                "resume" => "active",
                _ => "stopped",
            }
            .into();
            status.pending_review = None;
            if action == "resume" {
                status.session_id = "session-resumed".into();
            }
            let envelope = serde_json::json!({"service":"agentguard-mcp","workspace_protocol":1,"instance_id":status.instance_id,"session_id":status.session_id});
            let route = match action {
                "pause" => "/workspace/pause",
                "resume" => "/workspace/resume",
                _ => "/workspace/stop",
            };
            let (port, server) = mock_workspace(vec![
                (route, 200, envelope),
                (
                    "/workspace/status",
                    200,
                    serde_json::to_value(&status).unwrap(),
                ),
            ]);
            connection.port = port;
            let manager = GatewayConfirm::default();
            *manager.0.lock().unwrap() = Some(connection);
            let actual = manager
                .workspace_lifecycle("fixture-connection", action)
                .unwrap();
            assert_eq!(actual.session_state, status.session_state);
            assert_eq!(actual.session_id, status.session_id);
            assert_eq!(server.join().unwrap().len(), 2);
        }
    }

    #[test]
    fn 控制操作使迟到预览失效且旧连接无法恢复批准() {
        let (connection, _, _) = workspace_fixture();
        let manager = GatewayConfirm::default();
        *manager.0.lock().unwrap() = Some(connection);
        let (slow, epoch) = manager
            .workspace_snapshot("fixture-connection", true)
            .unwrap();
        let (_, new_epoch) = manager
            .workspace_snapshot("fixture-connection", true)
            .unwrap();
        assert_ne!(epoch, new_epoch);
        assert!(manager
            .workspace_commit("fixture-connection", epoch, &slow)
            .is_err());
        assert!(manager.0.lock().unwrap().as_ref().unwrap().review.is_none());
        manager.disconnect("fixture-connection").unwrap();
        assert!(manager
            .workspace_commit("fixture-connection", new_epoch, &slow)
            .is_err());
    }

    fn bound_request() -> RemoteRequest {
        use guard_schema::{
            ActionSnapshot, ActionSpec, ToolIdentity, ValidatedId, EXECUTION_CONTRACT_VERSION,
        };
        let id = |value: &str| ValidatedId::new(value).unwrap();
        let now = now_ms().unwrap();
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("desktop-fixture-session"), action_id: id("desktop-action-1"),
            request_id: id("request-1"), tool: ToolIdentity { registration: None, service: "gateway".into(), name: "write_file".into(), version: "test-1".into() },
            target: "/workspace/fixture.txt".into(),
            parameters: serde_json::json!({"path":"/workspace/fixture.txt", "contents":"完整写入正文 <script>仅文字</script>"}),
            policy_version: id("fixture-policy"), issued_at_ms: now - 1000, expires_at_ms: now + 10000,
            nonce: "c".repeat(32), sources: vec![],
        }).unwrap();
        let digest = format!("{:x}", Sha256::digest(action.canonical_bytes()));
        RemoteRequest {
            id: "confirm-fixture-1".into(),
            what: "写入测试文件".into(),
            findings: vec![],
            binding: ApprovalBinding::new(
                id("confirm-fixture-1"),
                action,
                "d".repeat(32),
                now - 500,
                now + 9000,
            )
            .unwrap(),
            action_sha256: digest,
        }
    }

    #[test]
    fn 绑定摘要编号与期限必须匹配且随机值不交给网页() {
        let request = bound_request();
        request.validate(now_ms().unwrap()).unwrap();
        let view = serde_json::to_string(&request.view()).unwrap();
        assert!(view.contains("完整写入正文") && view.contains(&request.action_sha256));
        assert!(
            !view.contains(&"c".repeat(32))
                && !view.contains(&"d".repeat(32))
                && !view.contains("nonce")
        );
        let mut bad = request.clone();
        bad.action_sha256 = "0".repeat(64);
        assert!(bad.validate(now_ms().unwrap()).is_err());
        let mut bad = request.clone();
        bad.id = "confirm-other".into();
        assert!(bad.validate(now_ms().unwrap()).is_err());
        assert!(request.validate(request.binding.expires_at_ms()).is_err());
    }

    #[test]
    fn 旧协议无绑定请求不可被桌面解析成可批准动作() {
        assert!(serde_json::from_value::<RemoteRequest>(
            serde_json::json!({"id":"old", "what":"旧无绑定请求", "findings":[]})
        )
        .is_err());
    }

    struct GatewayProcess {
        child: Child,
        lines: mpsc::Receiver<String>,
        port: u16,
        token: String,
    }
    impl Drop for GatewayProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl GatewayProcess {
        fn start(binary: &str, directory: &std::path::Path) -> Self {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
            let plans = directory.join("desktop-fixture-plans.json");
            std::fs::write(
                &plans,
                serde_json::json!({"plans":[{"task_profile":"desktop-confirm-test",
                "allow":["run_shell"],"scope":{"paths":{"read":[directory],"write":[directory]}}}]})
                .to_string(),
            )
            .unwrap();
            // 正常范围内写入已由宿主事前授权；本用例显式加测试规则验证逐次确认链路。
            let rules = directory.join("desktop-fixture-rules.json");
            std::fs::write(&rules, serde_json::json!({"version":"1.0","rules":[{
                "id":"DESKTOP-FIXTURE-WRITE-CONFIRM","name":"桌面逐次确认夹具","severity":"high",
                "action":"alert","require_confirm":true,"platforms":["gateway"],
                "match_any_text":["write_file"],"description":"仅本次临时目录测试使用的逐次确认规则"}]}).to_string()).unwrap();
            let child = Command::new(binary)
                .arg("--rules")
                .arg(rules)
                .arg("--shell-policy")
                .arg(root.join("crates/guard-shell/policies/default.yaml"))
                .arg("--plans")
                .arg(plans)
                .args(["--task", "desktop-confirm-test"])
                .args(["--confirm-port", "0", "--confirm-timeout-secs", "2"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let (tx, rx) = mpsc::channel();
            let mut process = Self {
                child,
                lines: rx,
                port: 0,
                token: String::new(),
            };
            let stderr = process.child.stderr.take().unwrap();
            let (metadata_tx, metadata_rx) = mpsc::channel();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stderr)
                    .lines()
                    .map_while(Result::ok)
                {
                    // 测试令牌只沿内存通道传递，不输出完整进程日志。
                    if metadata_tx.send(line).is_err() {
                        break;
                    }
                }
            });
            while process.port == 0 || process.token.is_empty() {
                let line = metadata_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("网关未就绪");
                if let Some(value) = line.trim().strip_prefix("确认令牌 ") {
                    process.token = value.to_owned();
                }
                if let Some(value) = line.split("http://127.0.0.1:").nth(1) {
                    process.port = value.split_whitespace().next().unwrap().parse().unwrap();
                }
            }
            let stdout = process.child.stdout.take().unwrap();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            process
        }
        fn send(&mut self, id: u64, name: &str, arguments: serde_json::Value) {
            let request = serde_json::json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{"name":name,"arguments":arguments}});
            writeln!(self.child.stdin.as_mut().unwrap(), "{request}").unwrap();
        }
        fn response(&self) -> serde_json::Value {
            serde_json::from_str(
                &self
                    .lines
                    .recv_timeout(Duration::from_secs(5))
                    .expect("MCP 未返回"),
            )
            .unwrap()
        }
        fn pending(&self, state: &GatewayConfirm, id: &str) -> Request {
            let until = Instant::now() + Duration::from_secs(1);
            while Instant::now() < until {
                if let Some(request) = state.poll(id).unwrap().pending {
                    return request;
                }
                if let Ok(response) = self.lines.try_recv() {
                    // stdout 仅含本用例的合成文件请求回执；确认令牌始终在独立内存通道。
                    panic!("待确认前 MCP 已返回：{response}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("未出现待确认请求")
        }
    }
    #[test]
    fn 拒绝任意地址与头部注入() {
        let state = GatewayConfirm::default();
        for token in [
            "",
            "x\r\nOrigin: x",
            "http://localhost",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(state.connect(8790, token.into()).is_err());
        }
        assert!(state.connect(0, "a".repeat(32)).is_err());
    }
    #[test]
    fn 旧连接不能批准或断开新连接() {
        let state = GatewayConfirm::default();
        *state.0.lock().unwrap() = Some(Connection {
            id: "new".into(),
            port: 1,
            token: "a".repeat(32),
            instance_id: "b".repeat(32),
            displayed: None,
            supports_workspace: false,
            workspace: None,
            review: None,
            workspace_epoch: 0,
        });
        assert!(state.answer("old", "confirm-1", true).is_err());
        assert!(state.poll("old").is_err());
        state.disconnect("old").unwrap();
        assert!(state.0.lock().unwrap().is_some());
        state.disconnect("new").unwrap();
        assert!(state.0.lock().unwrap().is_none());
    }

    #[test]
    fn 响应拒绝重定向分块超大与截断() {
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: http://example.com\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut input = [0; 4096];
                let _ = socket.read(&mut input);
                let _ = socket.write_all(response.as_bytes());
            });
            assert!(http(port, &"a".repeat(32), "GET", "/status", "").is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    #[ignore = "需显式提供刚构建的 AGENTGUARD_GATEWAY_TEST_BIN；独立运行真实进程验收"]
    fn 真实网关允许拒绝批准超时与断连的文件副作用() {
        let binary = std::env::var("AGENTGUARD_GATEWAY_TEST_BIN").expect("缺少真实网关路径");
        let directory =
            std::env::temp_dir().join(format!("ag-desktop-confirm-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let denied = directory.join("denied.txt");
        let approved = directory.join("approved.txt");
        let timed_out = directory.join("timed-out.txt");
        let disconnected = directory.join("disconnected.txt");
        let mut gateway = GatewayProcess::start(&binary, &directory);
        let state = GatewayConfirm::default();
        assert!(state.connect(gateway.port, "0".repeat(32)).is_err());
        let view = state.connect(gateway.port, gateway.token.clone()).unwrap();
        let connection_id = view.connection_id;
        assert!(view.pending.is_none());

        gateway.send(
            1,
            "write_file",
            serde_json::json!({"path":denied,"contents":"拒绝不得写入"}),
        );
        let request = gateway.pending(&state, &connection_id);
        assert!(!denied.exists());
        assert!(state.answer(&connection_id, "wrong-id", true).is_err());
        // 不带令牌、跨站与错误请求编号均不能批准。
        for auth in ["", "Origin: https://example.com\r\n"] {
            let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, gateway.port)).unwrap();
            socket.set_read_timeout(Some(TIMEOUT)).unwrap();
            let bearer = if auth.is_empty() {
                String::new()
            } else {
                format!("Authorization: Bearer {}\r\n", gateway.token)
            };
            write!(socket, "GET /status HTTP/1.1\r\nHost: localhost\r\n{auth}{bearer}Connection: close\r\n\r\n").unwrap();
            let mut buffer = [0; 1024];
            let n = socket.read(&mut buffer).unwrap();
            assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("HTTP/1.1 403"));
        }
        state.poll(&connection_id).unwrap();
        state.answer(&connection_id, &request.id, false).unwrap();
        assert_eq!(gateway.response()["result"]["isError"], true);
        assert!(!denied.exists());
        assert!(state.answer(&connection_id, &request.id, true).is_err());

        gateway.send(
            2,
            "write_file",
            serde_json::json!({"path":approved,"contents":"仅本次批准"}),
        );
        let request = gateway.pending(&state, &connection_id);
        assert!(!approved.exists());
        state.answer(&connection_id, &request.id, true).unwrap();
        assert_eq!(gateway.response()["result"]["isError"], false);
        assert_eq!(std::fs::read_to_string(&approved).unwrap(), "仅本次批准");
        assert!(state.answer(&connection_id, &request.id, true).is_err());
        gateway.send(3, "read_file", serde_json::json!({"path":approved}));
        assert_eq!(gateway.response()["result"]["isError"], false);

        gateway.send(
            4,
            "write_file",
            serde_json::json!({"path":timed_out,"contents":"不得超时放行"}),
        );
        let old = gateway.pending(&state, &connection_id);
        assert_eq!(gateway.response()["result"]["isError"], true);
        assert!(!timed_out.exists());
        assert!(state.answer(&connection_id, &old.id, true).is_err());

        gateway.send(
            5,
            "write_file",
            serde_json::json!({"path":disconnected,"contents":"不得断连放行"}),
        );
        gateway.pending(&state, &connection_id);
        state.disconnect(&connection_id).unwrap();
        assert_eq!(gateway.response()["result"]["isError"], true);
        assert!(!disconnected.exists());
        let view = state.connect(gateway.port, gateway.token.clone()).unwrap();
        assert_ne!(view.connection_id, connection_id);
        assert!(state.answer(&connection_id, &old.id, true).is_err());
        gateway.child.kill().unwrap();
        gateway.child.wait().unwrap();
        assert!(state.poll(&view.connection_id).is_err());
        assert!(state.0.lock().unwrap().is_none());
        // 留存唯一测试目录与批准文件，便于独立核对；不删除任何用户文件。
        println!(
            "真实网关文件副作用验收通过，测试目录：{}",
            directory.display()
        );
    }
}

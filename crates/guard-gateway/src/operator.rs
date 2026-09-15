//! 独立操作者控制通道。HTTP 线程只排队，文件差异与回写在主执行线程中串行运行。
//! 调用者必须先通过独立 Bearer 认证；这些操作不暴露为 MCP 工具。

use crate::PendingConfirm;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub const WORKSPACE_PROTOCOL: u16 = 1;
pub const MAX_REVIEW_BYTES: usize = 4 * 1024 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(12);
pub type OperatorReply = (u16, Value);

#[derive(Debug, Clone)]
pub enum OperatorCommand {
    Memory {
        route: String,
        body: Value,
    },
    Preview {
        workspace_id: String,
    },
    Apply {
        review_id: String,
        review_sha256: String,
        review_nonce: String,
    },
    Discard {
        review_id: String,
        review_sha256: String,
        review_nonce: String,
    },
    Pause,
    Resume,
    Stop,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewBody {
    workspace_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
    review_id: String,
    review_sha256: String,
    review_nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}

pub fn failure(code: &str, detail: &str, status: u16) -> OperatorReply {
    (status, json!({"error":code,"detail":detail}))
}

fn parse_command(path: &str, body: &str) -> Result<OperatorCommand, OperatorReply> {
    let invalid = || failure("WORKSPACE_ARGUMENTS", "操作者请求格式无效", 400);
    match path {
        "/memory/list" | "/memory/history" | "/memory/preview" | "/memory/apply"
        | "/memory/discard" => {
            let body: Value = serde_json::from_str(body).map_err(|_| invalid())?;
            if !body.is_object() {
                return Err(invalid());
            }
            Ok(OperatorCommand::Memory {
                route: path.to_owned(),
                body,
            })
        }
        "/workspace/preview" => {
            let b: PreviewBody = serde_json::from_str(body).map_err(|_| invalid())?;
            if b.workspace_id.len() > 128 {
                return Err(invalid());
            }
            Ok(OperatorCommand::Preview {
                workspace_id: b.workspace_id,
            })
        }
        "/workspace/apply" | "/workspace/discard" => {
            let b: ApplyBody = serde_json::from_str(body).map_err(|_| invalid())?;
            if b.review_id.len() > 128 || b.review_sha256.len() != 64 || b.review_nonce.len() != 64
            {
                return Err(invalid());
            }
            Ok(if path == "/workspace/discard" {
                OperatorCommand::Discard {
                    review_id: b.review_id,
                    review_sha256: b.review_sha256,
                    review_nonce: b.review_nonce,
                }
            } else {
                OperatorCommand::Apply {
                    review_id: b.review_id,
                    review_sha256: b.review_sha256,
                    review_nonce: b.review_nonce,
                }
            })
        }
        "/workspace/pause" | "/workspace/resume" | "/workspace/stop" => {
            serde_json::from_str::<EmptyBody>(body).map_err(|_| invalid())?;
            Ok(match path {
                "/workspace/pause" => OperatorCommand::Pause,
                "/workspace/resume" => OperatorCommand::Resume,
                _ => OperatorCommand::Stop,
            })
        }
        _ => Err(failure("WORKSPACE_ROUTE", "不存在此操作者操作", 404)),
    }
}

pub struct OperatorJob {
    pub command: OperatorCommand,
    pub epoch: u64,
    pub cancellation_epoch: u64,
    response: mpsc::Sender<OperatorReply>,
    state: Arc<AtomicU8>,
    deadline: Instant,
}
impl OperatorJob {
    /// 超时尚未开始的操作永远不能在操作者离开后才执行。
    pub fn begin(&self) -> bool {
        Instant::now() < self.deadline
            && self
                .state
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
    }
    pub fn finish(self, reply: OperatorReply) {
        self.state.store(3, Ordering::SeqCst);
        let _ = self.response.send(reply);
    }
}

#[derive(Clone)]
pub struct OperatorEndpoint {
    queue: mpsc::SyncSender<OperatorJob>,
    state: Arc<Mutex<Value>>,
    pending: PendingConfirm,
    epoch: Arc<AtomicU64>,
    submission: Arc<Mutex<()>>,
    workers: Arc<AtomicUsize>,
    last_client_message_ms: Arc<AtomicU64>,
    registry: Option<crate::tool_registry::SharedRegistry>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    delegation: Option<crate::delegation_governance::DelegationOperator>,
}
impl OperatorEndpoint {
    pub fn new(pending: PendingConfirm) -> (Self, mpsc::Receiver<OperatorJob>) {
        let (queue, receiver) = mpsc::sync_channel(8);
        (
            Self {
                queue,
                state: Arc::new(Mutex::new(json!({}))),
                pending,
                epoch: Arc::new(AtomicU64::new(0)),
                submission: Arc::new(Mutex::new(())),
                workers: Arc::new(AtomicUsize::new(0)),
                last_client_message_ms: Arc::new(AtomicU64::new(0)),
                registry: None,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                delegation: None,
            },
            receiver,
        )
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
    pub fn with_registry(mut self, registry: crate::tool_registry::SharedRegistry) -> Self {
        self.registry = Some(registry);
        self
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn with_delegation(
        mut self,
        delegation: Option<crate::delegation_governance::DelegationOperator>,
    ) -> Self {
        self.delegation = delegation;
        self
    }
    pub fn advance_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
    pub fn note_client_message(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        self.last_client_message_ms.store(now, Ordering::SeqCst);
    }
    pub fn publish(&self, mut state: Value) {
        state["control_epoch"] = json!(self.epoch());
        if let Ok(mut current) = self.state.lock() {
            *current = state;
        }
    }
    pub fn set_busy(&self, busy: bool) {
        if let Ok(mut current) = self.state.lock() {
            current["busy"] = json!(busy);
        }
    }
    pub fn snapshot(&self) -> Value {
        let mut state = self
            .state
            .lock()
            .map(|v| v.clone())
            .unwrap_or(json!({"session_state":"failed"}));
        state["last_client_message_ms"] = json!(self.last_client_message_ms.load(Ordering::SeqCst));
        // 权限撤销立即可见；已派发动作的清理状态仍由 busy 与最终回执表示。
        if state["control_epoch"].as_u64() != Some(self.epoch()) || self.pending.is_closed() {
            state["pending_review"] = Value::Null;
        }
        if state["session_state"] != "failed" {
            if self.pending.is_closed() {
                state["session_state"] = json!("stopped");
            } else if self.pending.is_paused() {
                state["session_state"] = json!("paused");
            }
        }
        state
    }

    fn request(&self, command: OperatorCommand) -> OperatorReply {
        // 将撤权、代次与入队作为一个顺序，防止线程调度把较早恢复放到较晚暂停之后。
        let submission = self.submission.lock().expect("操作者提交互斥锁");
        match command {
            OperatorCommand::Pause => {
                self.advance_epoch();
                self.pending.pause();
            }
            OperatorCommand::Stop => {
                self.advance_epoch();
                self.pending.close();
            }
            _ => {}
        }
        let (response, receiver) = mpsc::channel();
        let state = Arc::new(AtomicU8::new(0));
        let job = OperatorJob {
            command,
            epoch: self.epoch(),
            cancellation_epoch: self.pending.cancellation_epoch(),
            response,
            state: state.clone(),
            deadline: Instant::now() + CONTROL_TIMEOUT,
        };
        if self.queue.try_send(job).is_err() {
            return failure(
                "WORKSPACE_BUSY",
                "操作者操作队列繁忙；暂停或停止的撤权已生效",
                503,
            );
        }
        drop(submission);
        match receiver.recv_timeout(CONTROL_TIMEOUT) {
            Ok(reply) => reply,
            Err(_) => {
                if state
                    .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    failure(
                        "WORKSPACE_BUSY",
                        "本次操作未开始；网关仍在处理当前动作",
                        503,
                    )
                } else {
                    failure(
                        "WORKSPACE_REPLY_UNKNOWN",
                        "未能取得本次操作结果；请查看最近回执，不要重复回写",
                        504,
                    )
                }
            }
        }
    }

    /// 入口已完成有界读取和Bearer/Origin验证。当前HTTP工作线程等待业务队列，额外并发受限。
    pub fn serve_authenticated(
        &self,
        request: &crate::control_http::ControlRequest,
    ) -> OperatorReply {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if request.url().starts_with("/delegation/") {
            return match &self.delegation {
                Some(operator) => operator.serve(request),
                None => failure("DELEGATION_UNAVAILABLE", "委托控制未启用", 404),
            };
        }
        if request.url().starts_with("/registry/") {
            return self.serve_registry(request);
        }
        if request.method() == "GET" && request.url() == "/workspace/status" {
            return (200, self.snapshot());
        }
        if request.method() != "POST" {
            return failure("WORKSPACE_ROUTE", "不支持此操作者请求", 404);
        }
        if self.workers.fetch_add(1, Ordering::SeqCst) >= 8 {
            self.workers.fetch_sub(1, Ordering::SeqCst);
            return failure("WORKSPACE_BUSY", "操作者连接过多", 503);
        }
        struct Worker(Arc<AtomicUsize>);
        impl Drop for Worker {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _worker = Worker(self.workers.clone());
        let body = match std::str::from_utf8(request.body()) {
            Ok(body) if body.len() <= 4096 => body,
            _ => return failure("WORKSPACE_ARGUMENTS", "操作者请求超过上限或不是UTF-8", 400),
        };
        match parse_command(request.url(), body) {
            Ok(command) => self.request(command),
            Err(reply) => reply,
        }
    }

    fn serve_registry(&self, request: &crate::control_http::ControlRequest) -> OperatorReply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Observe {
            manifest: guard_schema::ToolServiceManifest,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Service {
            service_id: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Decide {
            service_id: String,
            review_id: String,
            review_nonce: String,
            manifest_sha256: String,
            approve: bool,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Revoke {
            service_id: String,
            registration_id: String,
        }
        let Some(shared) = &self.registry else {
            return failure("REGISTRY_UNAVAILABLE", "宿主没有工具登记通道", 404);
        };
        let Ok(_submission) = self.submission.try_lock() else {
            return failure("REGISTRY_BUSY", "操作者正在提交另一操作", 503);
        };
        let Ok(mut registry) = shared.try_lock() else {
            return failure("REGISTRY_BUSY", "工具登记正在处理另一操作", 503);
        };
        let result = (|| -> anyhow::Result<Value> {
            match (request.method(), request.url()) {
                ("GET", "/registry/status") => Ok(registry.status()),
                ("POST", "/registry/observe") => {
                    let b: Observe = serde_json::from_slice(request.body())?;
                    b.manifest.validate()?;
                    if registry.approved_change(&b.manifest) {
                        // HTTP 派发持有撤权锁时会检查登记。此处先释放登记锁，
                        // 避免相反的锁顺序；提交锁仍串行化所有操作者变更。
                        drop(registry);
                        self.advance_epoch();
                        self.pending.pause();
                        registry = shared
                            .try_lock()
                            .map_err(|_| anyhow::anyhow!("登记繁忙，撤权已生效"))?;
                    }
                    registry.observe(b.manifest)
                }
                ("POST", "/registry/review") => {
                    let b: Service = serde_json::from_slice(request.body())?;
                    registry.review(&b.service_id)
                }
                ("POST", "/registry/refresh") => {
                    let b: Service = serde_json::from_slice(request.body())?;
                    registry.refresh(&b.service_id)
                }
                ("POST", "/registry/decide") => {
                    let b: Decide = serde_json::from_slice(request.body())?;
                    registry.decide(
                        &b.service_id,
                        &b.review_id,
                        &b.review_nonce,
                        &b.manifest_sha256,
                        b.approve,
                    )
                }
                ("POST", "/registry/revoke") => {
                    let b: Revoke = serde_json::from_slice(request.body())?;
                    drop(registry);
                    self.advance_epoch();
                    self.pending.pause();
                    registry = shared
                        .try_lock()
                        .map_err(|_| anyhow::anyhow!("登记繁忙，撤权已生效"))?;
                    registry.revoke(&b.service_id, &b.registration_id)
                }
                _ => anyhow::bail!("不支持此工具登记请求"),
            }
        })();
        match result {
            Ok(value) => (200, value),
            Err(_) => failure(
                "REGISTRY_REFUSED",
                "工具登记请求无效、过期、冲突或存储不可用；未授予新的工具认可",
                409,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 撤销登记与正在派发的请求没有相反锁顺序() {
        use crate::control_http::{ControlHttp, ControlResponse, HttpLimits};
        use std::io::{Read, Write};
        // Windows 不发布文件工具；用两种平台都发布的会话工具验证同一撤销锁顺序。
        for mode in [
            crate::exec::ExecutionMode::Native,
            crate::exec::ExecutionMode::WindowsFailClosed,
        ] {
            let pending = PendingConfirm::new();
            let registry = Arc::new(Mutex::new(crate::tool_registry::ToolRegistry::builtins(
                mode,
            )));
            let registration = registry
                .lock()
                .unwrap()
                .binding("agentguard-gateway", "start_session")
                .unwrap()
                .registration_id;
            let (endpoint, _receiver) = OperatorEndpoint::new(pending.clone());
            let endpoint = endpoint.with_registry(registry.clone());
            let handler = endpoint.clone();
            let mut http = ControlHttp::bind(0, HttpLimits::default()).unwrap();
            http.start(Arc::new(move |request| {
                let (code, body) = handler.serve_authenticated(&request);
                ControlResponse::json(code, body)
            }))
            .unwrap();
            let address = http.address();
            let mut worker = None;
            let released = pending.with_active_epoch(pending.cancellation_epoch(), || {
            worker = Some(std::thread::spawn(move || {
                let body = json!({"service_id":"agentguard-gateway","registration_id":registration}).to_string();
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                write!(stream, "POST /registry/revoke HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                let mut response = String::new(); stream.read_to_string(&mut response).unwrap(); response
            }));
            let deadline = Instant::now() + Duration::from_secs(3);
            while endpoint.epoch() == 0 && Instant::now() < deadline { std::thread::yield_now(); }
            // 控制面正在等待撤权锁，登记锁必须已释放；旧实现会在这里得到 WouldBlock。
            endpoint.epoch() > 0 && registry.try_lock().is_ok()
        });
            let response = worker.unwrap().join().unwrap();
            assert_eq!(released, Some(true));
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(registry
                .lock()
                .unwrap()
                .binding("agentguard-gateway", "start_session")
                .is_err());
        }
    }
    #[test]
    fn 操作者参数不接受附带授权或旧批准() {
        assert!(parse_command(
            "/workspace/preview",
            r#"{"workspace_id":"workspace-0","allow":true}"#
        )
        .is_err());
        assert!(parse_command("/workspace/resume", r#"{"task_profile":"other"}"#).is_err());
        assert!(parse_command("/workspace/apply", r#"{"review_id":"old"}"#).is_err());
        assert!(parse_command("/workspace/pause", "{}").is_ok());
    }
    #[test]
    fn 超时尚未开始的操作者动作不执行() {
        let (endpoint, receiver) = OperatorEndpoint::new(PendingConfirm::new());
        let (response, _reply) = mpsc::channel();
        endpoint
            .queue
            .send(OperatorJob {
                command: OperatorCommand::Pause,
                epoch: 0,
                cancellation_epoch: 0,
                response,
                state: Arc::new(AtomicU8::new(2)),
                deadline: Instant::now() + Duration::from_secs(1),
            })
            .unwrap();
        assert!(!receiver.recv().unwrap().begin());
    }
}

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
            },
            receiver,
        )
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
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
}

#[cfg(test)]
mod tests {
    use super::*;
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

//! 确认挂起：把一次 MCP 调用按住，等人回答。
//!
//! # 为什么 MCP 让这件事变得自然
//!
//! 一个 MCP 工具调用是**请求/响应**，而智能体在等。按住响应，就是按住动作——不需要任何
//! 内核机制，不需要抢输入焦点，也不会把人一起拦住。Aura 的 Critical Node 闸门在这里几乎是
//! 免费的，因为协议本身就是这个形状。
//!
//! 这是网关比观察器强的地方，也是唯一一处它强得毫无争议：观察器看到无障碍事件时点击已经
//! 发生了，而这里动作还没开始。
//!
//! # 超时必须是拒绝
//!
//! 这是整个网关唯一不能搞错方向的地方。一个"等不到答案就放行"的闸门，被攻击的方法是等——
//! 而等待是免费的。所以 [`PendingConfirm::wait`] 超时返回 [`Answer::Denied`]，并且理由里
//! 写明是超时而不是有人拒绝，因为这两件事在审计里不该长得一样。

use guard_schema::ApprovalBinding;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// 默认等人回答的时长。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// 一次待确认的请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub id: String,
    /// 这次调用会做什么，人话。
    pub what: String,
    /// 触发确认的判据。
    pub findings: Vec<crate::gate::Finding>,
    /// 新网关请求绑定完整不可变动作；旧本地确认测试可显式不带绑定。
    #[serde(default)]
    pub binding: Option<ApprovalBinding>,
    /// 对 `binding.action().canonical_bytes()` 的 SHA-256，供独立控制面回传核对。
    #[serde(default)]
    pub action_sha256: Option<String>,
}

/// 人的回答。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Approved,
    Denied,
}

/// 超时时的结论及其理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub answer: Answer,
    /// `human`（人答的）、`timeout`（超时）、`disconnected`（连接已关闭）或 `busy`（槽位占用）。
    /// 除人工批准以外均按拒绝处理；审计中需区分这些原因。
    pub source: &'static str,
}

#[derive(Default)]
struct Slot {
    closed: bool,
    paused: bool,
    cancellation_epoch: u64,
    pending: Option<ConfirmRequest>,
    answer: Option<Answer>,
    deadline: Option<Instant>,
}

impl Slot {
    /// 单调时钟限制最长等待，批准的绝对期限限制可用授权；两者都不能扩大另一方。
    fn remaining(&self) -> Duration {
        let remaining = self
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let Some(binding) = self
            .pending
            .as_ref()
            .and_then(|request| request.binding.as_ref())
        else {
            return remaining;
        };
        let now = now_ms();
        if binding.validate_for_action(binding.action(), now).is_err() {
            return Duration::ZERO;
        }
        remaining.min(Duration::from_millis(
            binding.expires_at_ms().saturating_sub(now).max(0) as u64,
        ))
    }
}

/// 待确认槽位。同一时刻只有一个——网关是单线程处理 MCP 调用的，第二个待确认意味着
/// 有一次调用被跳过了。
#[derive(Clone, Default)]
pub struct PendingConfirm {
    inner: Arc<(Mutex<Slot>, Condvar)>,
}

impl PendingConfirm {
    /// 撤权和实际派发使用同一把锁。闭包只允许有界的执行开始记录及首次发送，不能等待响应。
    pub fn with_active_epoch<T>(&self, epoch: u64, dispatch: impl FnOnce() -> T) -> Option<T> {
        let slot = self.inner.0.lock().ok()?;
        if slot.closed || slot.paused || slot.cancellation_epoch != epoch {
            return None;
        }
        Some(dispatch())
    }

    /// 浏览器页面失效时只取消属于该请求的确认，不影响另一条工具确认。
    pub fn cancel_request(&self, id: &str) -> bool {
        let (lock, cv) = &*self.inner;
        let Ok(mut slot) = lock.lock() else {
            return false;
        };
        if slot
            .pending
            .as_ref()
            .is_some_and(|request| request.id == id)
        {
            slot.answer = Some(Answer::Denied);
            cv.notify_all();
            true
        } else {
            false
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// stdio 生命周期结束后不可重新打开；已等待及尚未进入等待的请求都失效。
    pub fn close(&self) {
        let (lock, cv) = &*self.inner;
        let mut slot = lock.lock().expect("确认槽位互斥锁");
        slot.closed = true;
        slot.cancellation_epoch = slot.cancellation_epoch.wrapping_add(1);
        slot.pending = None;
        slot.answer = None;
        slot.deadline = None;
        cv.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.inner.0.lock().map(|slot| slot.closed).unwrap_or(true)
    }

    /// 只有宿主控制面使用；暂停撤销当前批准，但不把仍存活的 stdio 连接变成新连接。
    pub fn pause(&self) {
        let (lock, cv) = &*self.inner;
        let mut slot = lock.lock().expect("确认槽位互斥锁");
        slot.paused = true;
        slot.cancellation_epoch = slot.cancellation_epoch.wrapping_add(1);
        slot.pending = None;
        slot.answer = None;
        slot.deadline = None;
        cv.notify_all();
    }

    /// 只允许在执行线程已结束上一动作后调用；EOF 和永久停止不能恢复。
    pub(crate) fn resume_from_host(&self, expected_epoch: u64) -> bool {
        let mut slot = self.inner.0.lock().expect("确认槽位互斥锁");
        if slot.closed
            || !slot.paused
            || slot.pending.is_some()
            || slot.cancellation_epoch != expected_epoch
        {
            return false;
        }
        slot.paused = false;
        true
    }

    pub fn is_paused(&self) -> bool {
        self.inner.0.lock().map(|slot| slot.paused).unwrap_or(true)
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner
            .0
            .lock()
            .map(|slot| slot.closed || slot.paused)
            .unwrap_or(true)
    }

    pub fn cancellation_epoch(&self) -> u64 {
        self.inner
            .0
            .lock()
            .map(|slot| slot.cancellation_epoch)
            .unwrap_or(u64::MAX)
    }

    /// 提出一个确认请求并**阻塞**等答案。
    ///
    /// 超时返回 `Denied` + `source: "timeout"`。
    pub fn wait(&self, request: ConfirmRequest, timeout: Duration) -> Resolution {
        let (lock, cv) = &*self.inner;
        {
            let mut slot = lock.lock().expect("确认槽位互斥锁");
            if slot.closed || slot.paused || slot.pending.is_some() {
                return Resolution {
                    answer: Answer::Denied,
                    source: if slot.closed {
                        "disconnected"
                    } else if slot.paused {
                        "paused"
                    } else {
                        "busy"
                    },
                };
            }
            slot.pending = Some(request);
            slot.answer = None;
            slot.deadline = Instant::now().checked_add(timeout);
        }
        cv.notify_all();

        let mut slot = lock.lock().expect("确认槽位互斥锁");
        loop {
            if slot.closed {
                return Resolution {
                    answer: Answer::Denied,
                    source: "disconnected",
                };
            }
            if slot.paused {
                return Resolution {
                    answer: Answer::Denied,
                    source: "paused",
                };
            }
            let remaining = slot.remaining();
            if remaining.is_zero() {
                slot.pending = None;
                slot.answer = None;
                slot.deadline = None;
                // 超时 = 拒绝。等待是免费的，所以"等不到就放行"的闸门等于没有闸门。
                return Resolution {
                    answer: Answer::Denied,
                    source: "timeout",
                };
            }
            if let Some(a) = slot.answer.take() {
                slot.pending = None;
                slot.deadline = None;
                return Resolution {
                    answer: a,
                    source: "human",
                };
            }
            // 定期重读绝对期限，恢复运行或时钟变化后不再等待剩余的整段单调计时。
            let (guard, _) = cv
                .wait_timeout(slot, remaining.min(Duration::from_millis(250)))
                .expect("确认槽位条件变量");
            slot = guard;
        }
    }

    /// 当前待确认的请求，给 UI / 环回接口读。
    pub fn peek(&self) -> Option<ConfirmRequest> {
        self.snapshot().map(|(request, _)| request)
    }

    /// 同一把锁下读取请求与剩余期限，不返回已应答或过期的请求。
    pub fn snapshot(&self) -> Option<(ConfirmRequest, u64)> {
        let slot = self.inner.0.lock().ok()?;
        let remaining = slot.remaining();
        if slot.closed || slot.paused || slot.answer.is_some() || remaining.is_zero() {
            return None;
        }
        Some((
            slot.pending.clone()?,
            remaining.as_millis().min(u64::MAX as u128) as u64,
        ))
    }

    /// 回答**指定 id** 的待确认请求。
    ///
    /// `id` 不是装饰。旧签名是 `answer(&self, answer)`,批准落在"当下恰好挂着的那一个"
    /// 上,而 `ConfirmRequest` 一直带着 `id`、`/pending` 也一直把它返回了 —— 只是没人核
    /// 对。配合"超时按拒绝",一个读得慢一点的操作员就够了:复核实测,屏幕上显示的是
    /// `confirm-1`(`run ["echo","harmless"]`),它超时消失,`confirm-2`
    /// (`delete important.txt`)挂上来,操作员在显示着第一条的界面上点了批准,被删掉的
    /// 是第二条的目标。人以为自己在批准 A,系统执行的是 B。
    ///
    /// 返回 `false` 表示当时没有待确认的东西,或者 id 对不上 —— 一个回答不能凭空预先
    /// 批准下一次调用,也不能替另一次调用作答。
    pub fn answer_id(&self, id: &str, answer: Answer) -> bool {
        self.answer_checked(id, None, answer)
    }

    /// 绑定请求必须核对独立通道回传的动作摘要和批准随机值；本函数不认证 HTTP 调用者。
    pub fn answer_bound(
        &self,
        id: &str,
        action_sha256: &str,
        approval_nonce: &str,
        answer: Answer,
    ) -> bool {
        self.answer_checked(id, Some((action_sha256, approval_nonce)), answer)
    }

    fn answer_checked(&self, id: &str, binding_echo: Option<(&str, &str)>, answer: Answer) -> bool {
        let (lock, cv) = &*self.inner;
        let mut slot = lock.lock().expect("确认槽位互斥锁");
        if slot.closed || slot.paused || slot.answer.is_some() || slot.remaining().is_zero() {
            return false;
        }
        match &slot.pending {
            Some(p) if p.id == id => match (&p.binding, p.action_sha256.as_deref(), binding_echo) {
                (Some(binding), Some(digest), Some((got_digest, got_nonce)))
                    if binding.approval_id().as_str() == id
                        && digest == got_digest
                        && binding.nonce() == got_nonce
                        && binding
                            .validate_for_action(binding.action(), now_ms())
                            .is_ok() => {}
                (None, None, None) => {}
                _ => return false,
            },
            _ => return false,
        }
        slot.answer = Some(answer);
        cv.notify_all();
        true
    }

    /// 不带 id 的回答,只给测试和确实无法读到 id 的本地 UI 用。
    ///
    /// 生产的环回接口走 `answer_id`。保留这个入口是因为 `StdinConfirm` 这类交互式确认
    /// 器就在同一个线程里看着同一个请求,不存在"批准落到别的请求上"的窗口。
    pub fn answer(&self, answer: Answer) -> bool {
        self.peek()
            .is_some_and(|request| match (request.binding, request.action_sha256) {
                (Some(binding), Some(digest)) => {
                    self.answer_bound(&request.id, &digest, binding.nonce(), answer)
                }
                (None, None) => self.answer_id(&request.id, answer),
                _ => false,
            })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound_request(expires_in_ms: i64) -> ConfirmRequest {
        use guard_schema::{
            ActionSnapshot, ActionSpec, ToolIdentity, ValidatedId, EXECUTION_CONTRACT_VERSION,
        };
        use sha2::{Digest, Sha256};
        let id = |value: &str| ValidatedId::new(value).unwrap();
        let now = now_ms();
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("expiry-session"),
            action_id: id("expiry-action"),
            request_id: id("expiry-request"),
            tool: ToolIdentity {
                service: "agentguard-gateway".into(),
                name: "run_shell".into(),
                version: "test-1".into(),
            },
            target: "python3".into(),
            parameters: serde_json::json!({"argv":["python3", "-m", "probe"]}),
            policy_version: id("expiry-policy"),
            issued_at_ms: now - 2000,
            expires_at_ms: now + 60000,
            nonce: "a".repeat(32),
            sources: vec![],
        })
        .unwrap();
        let digest = format!("{:x}", Sha256::digest(action.canonical_bytes()));
        ConfirmRequest {
            id: "confirm-expiry".into(),
            what: "仅用于期限回归的合成命令".into(),
            findings: vec![],
            binding: Some(
                ApprovalBinding::new(
                    id("confirm-expiry"),
                    action,
                    "b".repeat(32),
                    now - 1000,
                    now + expires_in_ms,
                )
                .unwrap(),
            ),
            action_sha256: Some(digest),
        }
    }

    #[test]
    fn 批准绝对期限已过时不能继续显示等待() {
        let pending = pending_slot(Instant::now() + Duration::from_secs(30), None);
        let request = bound_request(-1);
        pending.inner.0.lock().unwrap().pending = Some(request.clone());
        assert!(!pending.answer_bound(
            &request.id,
            request.action_sha256.as_deref().unwrap(),
            request.binding.as_ref().unwrap().nonce(),
            Answer::Approved,
        ));
        assert!(
            pending.snapshot().is_none(),
            "不可执行的过期批准不能继续显示为待确认"
        );
    }

    #[test]
    fn 待确认剩余时间不能超过批准绝对期限() {
        let pending = pending_slot(Instant::now() + Duration::from_secs(30), None);
        pending.inner.0.lock().unwrap().pending = Some(bound_request(1000));
        let (_, remaining_ms) = pending.snapshot().unwrap();
        assert!(remaining_ms <= 1000, "显示期限不能从一秒扩展到三十秒");
    }

    #[test]
    fn 批准绝对期限先到时等待必须及时拒绝() {
        let pending = PendingConfirm::new();
        let worker_pending = pending.clone();
        let request = bound_request(100);
        let (sent, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sent.send(worker_pending.wait(request, Duration::from_secs(30)))
                .unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(2));
        // 失败也结束本测试创建的等待线程，不能把三十秒后台等待留给其它用例。
        pending.close();
        worker.join().unwrap();
        assert_eq!(
            result.unwrap(),
            Resolution {
                answer: Answer::Denied,
                source: "timeout"
            },
        );
    }

    fn pending_slot(deadline: Instant, answer: Option<Answer>) -> PendingConfirm {
        PendingConfirm {
            inner: Arc::new((
                Mutex::new(Slot {
                    closed: false,
                    paused: false,
                    cancellation_epoch: 0,
                    pending: Some(ConfirmRequest {
                        id: "one".into(),
                        what: "测试".into(),
                        findings: vec![],
                        binding: None,
                        action_sha256: None,
                    }),
                    deadline: Some(deadline),
                    answer,
                }),
                Condvar::new(),
            )),
        }
    }
    #[test]
    fn 首次选择不能被重复回答覆盖() {
        let p = pending_slot(Instant::now() + Duration::from_secs(1), None);
        assert!(!p.answer_id("other", Answer::Approved));
        assert!(p.answer_id("one", Answer::Denied));
        assert!(!p.answer_id("one", Answer::Approved));
        assert_eq!(p.inner.0.lock().unwrap().answer, Some(Answer::Denied));
        assert!(p.peek().is_none());
    }
    #[test]
    fn 截止时刻后拒绝批准并隐藏过期请求() {
        let p = pending_slot(Instant::now(), None);
        assert!(!p.answer_id("one", Answer::Approved));
        assert!(!p.answer(Answer::Approved));
        assert!(p.snapshot().is_none());
    }
    #[test]
    fn 第二个等待不能覆盖原请求() {
        let p = pending_slot(Instant::now() + Duration::from_secs(1), None);
        let result = p.wait(
            ConfirmRequest {
                id: "two".into(),
                what: "第二条".into(),
                findings: vec![],
                binding: None,
                action_sha256: None,
            },
            Duration::from_secs(1),
        );
        assert_eq!(result.answer, Answer::Denied);
        assert_eq!(p.peek().unwrap().id, "one");
    }

    #[test]
    fn 断连清除已有批准且后续等待立即拒绝() {
        let p = pending_slot(
            Instant::now() + Duration::from_secs(30),
            Some(Answer::Approved),
        );
        p.close();
        assert!(p.is_closed());
        assert!(p.peek().is_none());
        assert!(!p.answer_id("one", Answer::Approved));
        let result = p.wait(
            ConfirmRequest {
                id: "new".into(),
                what: "新请求".into(),
                findings: vec![],
                binding: None,
                action_sha256: None,
            },
            Duration::from_secs(30),
        );
        assert_eq!(
            result,
            Resolution {
                answer: Answer::Denied,
                source: "disconnected"
            }
        );
    }

    #[test]
    fn 宿主暂停撤销批准且只有活连接可以恢复() {
        let p = pending_slot(
            Instant::now() + Duration::from_secs(30),
            Some(Answer::Approved),
        );
        p.pause();
        assert!(!p.is_closed());
        assert!(p.is_cancelled());
        assert!(!p.answer_id("one", Answer::Approved));
        assert!(p.peek().is_none());
        assert!(p.resume_from_host(p.cancellation_epoch()));
        assert!(!p.is_cancelled());
        assert!(!p.answer_id("one", Answer::Approved));
        p.close();
        p.pause();
        assert!(!p.resume_from_host(p.cancellation_epoch()));
        assert!(p.is_closed());
    }

    #[test]
    fn 旧恢复请求不能清除后来发出的暂停() {
        let p = PendingConfirm::new();
        p.pause();
        let previous = p.cancellation_epoch();
        p.pause();
        assert!(!p.resume_from_host(previous));
        assert!(p.is_paused());
        assert!(p.resume_from_host(p.cancellation_epoch()));
    }
}

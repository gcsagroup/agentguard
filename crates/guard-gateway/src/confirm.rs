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
    /// `human`（人答的）或 `timeout`（超时按拒绝处理）。审计里这两者必须能分开：
    /// "人拒绝了"和"没人在"是不同的事实。
    pub source: &'static str,
}

#[derive(Default)]
struct Slot {
    pending: Option<ConfirmRequest>,
    answer: Option<Answer>,
    deadline: Option<Instant>,
}

/// 待确认槽位。同一时刻只有一个——网关是单线程处理 MCP 调用的，第二个待确认意味着
/// 有一次调用被跳过了。
#[derive(Clone, Default)]
pub struct PendingConfirm {
    inner: Arc<(Mutex<Slot>, Condvar)>,
}

impl PendingConfirm {
    pub fn new() -> Self {
        Self::default()
    }

    /// 提出一个确认请求并**阻塞**等答案。
    ///
    /// 超时返回 `Denied` + `source: "timeout"`。
    pub fn wait(&self, request: ConfirmRequest, timeout: Duration) -> Resolution {
        let (lock, cv) = &*self.inner;
        {
            let mut slot = lock.lock().expect("确认槽位互斥锁");
            if slot.pending.is_some() {
                return Resolution {
                    answer: Answer::Denied,
                    source: "busy",
                };
            }
            slot.pending = Some(request);
            slot.answer = None;
            slot.deadline = Instant::now().checked_add(timeout);
        }
        cv.notify_all();

        let mut slot = lock.lock().expect("确认槽位互斥锁");
        loop {
            if let Some(a) = slot.answer.take() {
                slot.pending = None;
                slot.deadline = None;
                return Resolution {
                    answer: a,
                    source: "human",
                };
            }
            let remaining = slot
                .deadline
                .map(|d| d.saturating_duration_since(Instant::now()))
                .unwrap_or_default();
            if remaining.is_zero() {
                slot.pending = None;
                slot.deadline = None;
                // 超时 = 拒绝。等待是免费的，所以"等不到就放行"的闸门等于没有闸门。
                return Resolution {
                    answer: Answer::Denied,
                    source: "timeout",
                };
            }
            let (guard, _) = cv.wait_timeout(slot, remaining).expect("确认槽位条件变量");
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
        let remaining = slot.deadline?.saturating_duration_since(Instant::now());
        if slot.answer.is_some() || remaining.is_zero() {
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
        let (lock, cv) = &*self.inner;
        let mut slot = lock.lock().expect("确认槽位互斥锁");
        if slot.answer.is_some() || slot.deadline.is_none_or(|d| Instant::now() >= d) {
            return false;
        }
        match &slot.pending {
            Some(p) if p.id == id => {}
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
            .is_some_and(|request| self.answer_id(&request.id, answer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending_slot(deadline: Instant, answer: Option<Answer>) -> PendingConfirm {
        PendingConfirm {
            inner: Arc::new((
                Mutex::new(Slot {
                    pending: Some(ConfirmRequest {
                        id: "one".into(),
                        what: "测试".into(),
                        findings: vec![],
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
            },
            Duration::from_secs(1),
        );
        assert_eq!(result.answer, Answer::Denied);
        assert_eq!(p.peek().unwrap().id, "one");
    }
}

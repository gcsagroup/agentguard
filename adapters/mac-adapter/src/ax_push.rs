//! 把"轮询到"变成"变了就抓"的合并逻辑（E3）。
//!
//! # 问题:轮询间隙
//!
//! 原来 macOS 的 UI 树是**定时轮询**的(每 2.5s 抓一次 AXUIElement 快照)。两次轮询之间发生、
//! 又在下次轮询前消失的东西——一个一闪而过的确认框、一次快速的表单自动填充——可能整个落在
//! 间隙里,守卫看不到。这正是"边界"里"不是实时监控,轮询间隙内的动作可能看不到"那条。
//!
//! # 做法:AXObserver 推送 + 这个合并器
//!
//! AXObserver 能在树**变化时**推一个通知过来(值变了、焦点变了、窗口建了)。但不能每来一个通知
//! 就抓一次快照:一次输入会连发几十个 `kAXValueChangedNotification`,每个都抓一次树会把 CPU 打满,
//! 而"抓 CPU 打满"和"看不到"一样会让人把守卫关掉。
//!
//! 所以推送先进这个**纯逻辑**合并器,由它决定"什么时候真的该抓一次":
//!
//! * **去抖(debounce)**:收到通知后,等 [`DEBOUNCE_MS`] 的**安静**再抓——把一串连发的通知
//!   合并成一次抓取,抓到的是稳定下来的树。
//! * **延迟上限(max latency)**:如果通知**持续不断**(安静永远等不到),也不能无限拖;距第一条
//!   未处理通知超过 [`MAX_LATENCY_MS`] 就强制判定该抓一次。这保证"变了到抓到"的延迟有上界。
//!
//! 效果:一次变化通常在 [`DEBOUNCE_MS`] 内就被抓到(而不是最坏等一整个 2.5s 轮询周期),持续变化
//! 也至少每 [`MAX_LATENCY_MS`] 抓一次。定时轮询保留成一个**更长的兜底**(见 [`FALLBACK_FLOOR_MS`]):
//! 万一 observer 注册失败或漏了通知,兜底轮询仍然会抓——**不因为上了推送就把轮询那条命去掉**。
//!
//! 这个文件是平台无关的纯逻辑,在**任何**机器上都能完整单元测试;AXObserver 的注册与回调
//! (`ax_native.rs` 的 FFI + `native/AgentGuardAX.m`)只能在真 macOS 上验。

/// 收到通知后,等这么久的"安静"再抓一次(把连发合并成一次)。
pub const DEBOUNCE_MS: i64 = 150;
/// 通知持续不断时,距第一条未处理通知最多拖这么久就强制抓一次(延迟上界)。
pub const MAX_LATENCY_MS: i64 = 800;
/// 兜底轮询的下限周期:即使一个通知都没有,也至少这么久抓一次。比原来的 2.5s 更宽松是有意的——
/// 推送在时,它只是"漏网兜底";推送不在时,它退化回原来的轮询语义(只是周期不同)。
pub const FALLBACK_FLOOR_MS: i64 = 3000;

/// 合并 AXObserver 推送,决定何时真正抓一次快照。纯逻辑,不碰任何系统 API。
#[derive(Debug, Clone, Default)]
pub struct PushCoalescer {
    /// 第一条**未处理**通知的时间(有未处理通知时为 `Some`)。
    first_pending_ms: Option<i64>,
    /// 最近一条通知的时间。
    last_note_ms: Option<i64>,
    /// 上一次判定"该抓"的时间(给兜底轮询算周期用)。
    last_capture_ms: Option<i64>,
}

impl PushCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记一条 AXObserver 通知到达(`now_ms` 是到达时刻)。
    pub fn note(&mut self, now_ms: i64) {
        if self.first_pending_ms.is_none() {
            self.first_pending_ms = Some(now_ms);
        }
        self.last_note_ms = Some(now_ms);
    }

    /// 现在该不该抓一次快照。
    ///
    /// 两条独立的理由,任一成立即该抓:
    /// 1. **有未处理通知**,且(安静够久 `DEBOUNCE_MS`,或积压够久 `MAX_LATENCY_MS`);
    /// 2. **兜底**:距上次抓取超过 `FALLBACK_FLOOR_MS`(即使没有任何通知)。
    pub fn due(&self, now_ms: i64) -> bool {
        if let (Some(first), Some(last)) = (self.first_pending_ms, self.last_note_ms) {
            let quiet_enough = now_ms.saturating_sub(last) >= DEBOUNCE_MS;
            let waited_too_long = now_ms.saturating_sub(first) >= MAX_LATENCY_MS;
            if quiet_enough || waited_too_long {
                return true;
            }
        }
        match self.last_capture_ms {
            Some(cap) => now_ms.saturating_sub(cap) >= FALLBACK_FLOOR_MS,
            // 从没抓过:让兜底在第一个周期就成立,别让"没有通知也没有历史"的冷启动一直不抓。
            None => true,
        }
    }

    /// 抓完之后调用:清掉未处理通知,并记下这次抓取时间(供兜底周期计算)。
    pub fn mark_captured(&mut self, now_ms: i64) {
        self.first_pending_ms = None;
        self.last_note_ms = None;
        self.last_capture_ms = Some(now_ms);
    }

    /// 是否有未处理的推送通知(用于区分"因为变化而抓"和"兜底抓")。
    pub fn has_pending(&self) -> bool {
        self.first_pending_ms.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 冷启动:没抓过、没通知 → 该抓(兜底立刻成立,不让冷启动一直空等)。
    #[test]
    fn 冷启动就该抓一次() {
        let c = PushCoalescer::new();
        assert!(c.due(0));
    }

    /// 抓过之后、既没通知也没到兜底周期 → 不抓(否则就是空转打 CPU)。
    #[test]
    fn 抓过之后安静期内不抓() {
        let mut c = PushCoalescer::new();
        c.mark_captured(1000);
        assert!(!c.due(1000 + FALLBACK_FLOOR_MS - 1));
    }

    /// 一条通知之后,安静不到 DEBOUNCE_MS 不抓;安静够了就抓。
    #[test]
    fn 去抖_安静够了才抓() {
        let mut c = PushCoalescer::new();
        c.mark_captured(0);
        c.note(1000);
        assert!(!c.due(1000 + DEBOUNCE_MS - 1), "还没安静够,不该抓");
        assert!(c.due(1000 + DEBOUNCE_MS), "安静够了,该抓");
    }

    /// 通知持续不断(每 50ms 一条,永远等不到 DEBOUNCE_MS 的安静)→ 到 MAX_LATENCY_MS 强制抓。
    /// 这条钉住"延迟有上界",否则一个一直在动的界面会让守卫永远抓不到。
    #[test]
    fn 延迟上限_持续通知也会强制抓() {
        let mut c = PushCoalescer::new();
        c.mark_captured(0);
        let first = 1000;
        c.note(first);
        let mut t = first;
        // 每 50ms 一条,一直到刚好 MAX_LATENCY_MS 之前:始终有新通知,安静条件永不成立。
        while t < first + MAX_LATENCY_MS - 50 {
            t += 50;
            c.note(t);
            assert!(!c.due(t), "还没到延迟上限、且刚来通知,不该靠去抖抓 (t={t})");
        }
        // 到达延迟上限:即便此刻还在收通知,也必须判该抓。
        assert!(
            c.due(first + MAX_LATENCY_MS),
            "距第一条未处理通知已达 MAX_LATENCY_MS,必须强制抓"
        );
    }

    /// mark_captured 之后未处理通知被清掉:同一批通知不会被抓两次。
    #[test]
    fn 抓完清掉未处理通知() {
        let mut c = PushCoalescer::new();
        c.note(1000);
        assert!(c.due(1000 + DEBOUNCE_MS));
        assert!(c.has_pending());
        c.mark_captured(1000 + DEBOUNCE_MS);
        assert!(!c.has_pending(), "抓完不该还留着未处理通知");
        // 紧接着(兜底周期内、无新通知)不该再抓。
        assert!(!c.due(1000 + DEBOUNCE_MS + 1));
    }

    /// 兜底:很久没有任何通知,也至少每 FALLBACK_FLOOR_MS 抓一次(observer 万一漏了)。
    #[test]
    fn 兜底轮询在没有通知时仍然抓() {
        let mut c = PushCoalescer::new();
        c.mark_captured(1000);
        assert!(!c.due(1000 + FALLBACK_FLOOR_MS - 1));
        assert!(c.due(1000 + FALLBACK_FLOOR_MS));
    }
}

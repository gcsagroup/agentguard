//! 观察事件聚合(报告 P2-3)。
//!
//! 真机数字:106 秒的持续观察写了 75 条审计记录,其中 ScreenCapture 40 条、OVL-007 37 条。
//! 屏幕没变,SCK 每 1.5 s 交一帧,每帧都过引擎、都写审计、都可能入待确认队列——
//! 关键告警被淹没,库快速膨胀,还放大了确认覆盖竞态(P0-5)。
//!
//! 这里做的事只有一件:**同一语义内容在一个窗口内只过引擎一次**。
//!
//! - 指纹 = `event_type | source_app | 语义元数据`。语义元数据是 `ui_text`、`overlay_kinds`、
//!   表单字段这类规则真正读的东西;`frame_digest`、`low_opacity_ratio` 这类每帧必变的
//!   数字**不进指纹**——否则永远去不了重。
//! - 首次出现 → 放行。窗口内再出现 → 压掉,只计数。窗口过后仍在出现 → 再放行一次,并带上
//!   「这期间被折叠了 N 条」,让审计里有一条持续摘要,而不是 N 条一模一样的。
//! - 指纹变了 → 状态变化,立刻放行(不等窗口)。这是「去重」和「漏看」的边界:屏幕上
//!   任何一个字变了都是新事件,只有**一字不差**的重复才折叠。
//! - `sweep` 把一段时间没再出现的指纹清掉并报告「结束」,给调用方写恢复摘要。
//!
//! 只在**观察器轮询路径**上用(SCK/AX/UIA)。会话开始/结束、演示注入、扩展转发的事件
//! 不经过它——那些本来就是一次一条,折叠它们只会丢事件。
//!
//! 纯数据结构,时间由调用方传入,和 `observe_state` 一样为了能用假时钟做红-绿测试。

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use guard_schema::GuardEvent;

/// 每帧必变、对规则无意义的元数据键。它们不进指纹。
///
/// 这是**拒绝表**而不是允许表:允许表会把未来新增的语义键(比如一个新的表单字段键)
/// 默默排除在指纹外,让两个不同的事件被当成重复——那是漏报方向的错。拒绝表的错误方向
/// 是「多放行了几条」,可接受。
pub const VOLATILE_KEYS: &[&str] = &[
    "frame_digest",
    "low_opacity_ratio",
    "capture_width",
    "capture_height",
    "overlay_evidence",
    "overlay_count",
    REPEAT_COUNT_KEY,
];

/// 放行一条「持续摘要」时,调用方往事件元数据里写的键:这期间被折叠的条数。
pub const REPEAT_COUNT_KEY: &str = "repeat_count";

/// 语义指纹。同一屏幕内容、同一来源、同一事件类型 → 同一指纹。
pub fn fingerprint(event: &GuardEvent) -> u64 {
    let mut h = DefaultHasher::new();
    format!("{:?}", event.event_type).hash(&mut h);
    event.source_app.hash(&mut h);
    // HashMap 迭代顺序不稳定,排序后再哈希。
    let mut keys: Vec<&String> = event
        .metadata
        .keys()
        .filter(|k| !VOLATILE_KEYS.contains(&k.as_str()))
        .collect();
    keys.sort();
    for k in keys {
        k.hash(&mut h);
        // ui_text 两端空白不算差异(AX 扁平化偶尔多一个换行)。
        event.metadata[k].trim().hash(&mut h);
    }
    h.finish()
}

/// 一次 `observe` 的裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 过引擎。`repeats` = 上一次放行以来被折叠的条数(首次为 0)。
    Emit { repeats: u32 },
    /// 不过引擎。`seen` = 本窗口内已折叠的条数(含这一条)。
    Suppress { seen: u32 },
}

impl Verdict {
    pub fn is_emit(self) -> bool {
        matches!(self, Verdict::Emit { .. })
    }
}

/// 一个指纹在 `sweep` 时被判定为「不再出现」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub key: u64,
    pub first_ms: u64,
    pub last_ms: u64,
    /// 生命周期内总共见到的次数(放行 + 折叠)。
    pub total: u32,
}

#[derive(Debug, Clone)]
struct Entry {
    first_ms: u64,
    last_ms: u64,
    last_emit_ms: u64,
    since_emit: u32,
    total: u32,
}

/// 有界的指纹表。
#[derive(Debug)]
pub struct Aggregator {
    window_ms: u64,
    cap: usize,
    entries: HashMap<u64, Entry>,
    suppressed_total: u64,
}

impl Aggregator {
    /// `window_ms`:同一指纹两次放行之间的最短间隔;`cap`:同时跟踪的指纹上限,满了挤掉
    /// 最久没出现的那个(它下次再出现会被当成首次放行——多放行,不漏)。
    pub fn new(window_ms: u64, cap: usize) -> Self {
        Aggregator {
            window_ms,
            cap: cap.max(1),
            entries: HashMap::new(),
            suppressed_total: 0,
        }
    }

    /// 壳子用的默认值:30 s 窗口。SCK 1.5 s 一帧 → 静止画面每 30 s 留一条摘要,
    /// 而不是 20 条一样的;256 个指纹足够覆盖一个会话里切换过的所有窗口。
    pub fn for_observers() -> Self {
        Aggregator::new(30_000, 256)
    }

    pub fn window_ms(&self) -> u64 {
        self.window_ms
    }

    /// 累计折叠掉的条数(给状态栏显示「已折叠 N 条重复观察」)。
    pub fn suppressed_total(&self) -> u64 {
        self.suppressed_total
    }

    pub fn tracked(&self) -> usize {
        self.entries.len()
    }

    /// 会话边界清空:上一会话看到过的画面,在新会话里第一次出现要当首次记。
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    pub fn observe_event(&mut self, event: &GuardEvent, now_ms: u64) -> Verdict {
        self.observe(fingerprint(event), now_ms)
    }

    pub fn observe(&mut self, key: u64, now_ms: u64) -> Verdict {
        if let Some(e) = self.entries.get_mut(&key) {
            e.total = e.total.saturating_add(1);
            e.last_ms = now_ms;
            // saturating:时钟回拨按「刚刚放行过」处理 → 折叠。不会因为回拨放出一串重复。
            if now_ms.saturating_sub(e.last_emit_ms) >= self.window_ms {
                let repeats = e.since_emit;
                e.since_emit = 0;
                e.last_emit_ms = now_ms;
                return Verdict::Emit { repeats };
            }
            e.since_emit = e.since_emit.saturating_add(1);
            self.suppressed_total += 1;
            return Verdict::Suppress { seen: e.since_emit };
        }
        if self.entries.len() >= self.cap {
            self.evict_oldest();
        }
        self.entries.insert(
            key,
            Entry {
                first_ms: now_ms,
                last_ms: now_ms,
                last_emit_ms: now_ms,
                since_emit: 0,
                total: 1,
            },
        );
        Verdict::Emit { repeats: 0 }
    }

    /// 清掉超过一个窗口没再出现的指纹并报告。调用方拿这个写「恢复」摘要。
    pub fn sweep(&mut self, now_ms: u64) -> Vec<Ended> {
        let window = self.window_ms;
        let stale: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, e)| now_ms.saturating_sub(e.last_ms) > window)
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::with_capacity(stale.len());
        for k in stale {
            if let Some(e) = self.entries.remove(&k) {
                out.push(Ended {
                    key: k,
                    first_ms: e.first_ms,
                    last_ms: e.last_ms,
                    total: e.total,
                });
            }
        }
        out.sort_by_key(|e| e.first_ms);
        out
    }

    fn evict_oldest(&mut self) {
        // cap 是几百,线性扫一遍比维护一个有序结构便宜也不容易写错。
        if let Some((&k, _)) = self.entries.iter().min_by_key(|(_, e)| e.last_ms) {
            self.entries.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::EventType;
    use std::collections::HashMap;

    fn ev(source: &str, ui_text: &str, extra: &[(&str, &str)]) -> GuardEvent {
        let mut metadata = HashMap::new();
        metadata.insert("ui_text".to_string(), ui_text.to_string());
        for (k, v) in extra {
            metadata.insert(k.to_string(), v.to_string());
        }
        GuardEvent {
            event_id: "x".into(),
            timestamp_ms: 0,
            platform: "macos".into(),
            event_type: EventType::UiTreeDelta,
            source_app: source.into(),
            agent_context_id: None,
            metadata,
        }
    }

    #[test]
    fn 首次放行_窗口内重复折叠并计数() {
        let mut a = Aggregator::new(30_000, 64);
        assert_eq!(a.observe(1, 0), Verdict::Emit { repeats: 0 });
        assert_eq!(a.observe(1, 1_500), Verdict::Suppress { seen: 1 });
        assert_eq!(a.observe(1, 3_000), Verdict::Suppress { seen: 2 });
        assert_eq!(a.suppressed_total(), 2);
    }

    #[test]
    fn 窗口过后再放行一次并带上折叠数_然后重新计数() {
        let mut a = Aggregator::new(30_000, 64);
        a.observe(1, 0);
        for t in (1_500..30_000).step_by(1_500) {
            assert!(!a.observe(1, t).is_emit(), "t={t} 应被折叠");
        }
        let v = a.observe(1, 30_000);
        assert_eq!(v, Verdict::Emit { repeats: 19 });
        assert_eq!(a.observe(1, 31_500), Verdict::Suppress { seen: 1 });
    }

    #[test]
    fn 每帧必变的数字不进指纹_语义相同即同一指纹() {
        let a = ev(
            "ScreenCapture",
            "[AG_TRANSPARENT_OVERLAY]",
            &[
                ("frame_digest", "aaaa"),
                ("low_opacity_ratio", "0.171"),
                ("capture_width", "1920"),
                ("overlay_evidence", "low_opacity_ratio=0.17 mean_luma=0.51"),
                ("overlay_count", "1"),
            ],
        );
        let b = ev(
            "ScreenCapture",
            "[AG_TRANSPARENT_OVERLAY]",
            &[
                ("frame_digest", "bbbb"),
                ("low_opacity_ratio", "0.173"),
                ("capture_width", "1920"),
                ("overlay_evidence", "low_opacity_ratio=0.17 mean_luma=0.52"),
                ("overlay_count", "1"),
            ],
        );
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn 内容变一个字就是新事件_立即放行不等窗口() {
        let mut a = Aggregator::new(30_000, 64);
        let e1 = ev("Safari", "Confirm payment $299.00", &[]);
        let e2 = ev("Safari", "Confirm payment $299.01", &[]);
        assert!(a.observe_event(&e1, 0).is_emit());
        assert!(!a.observe_event(&e1, 1_000).is_emit());
        assert!(a.observe_event(&e2, 2_000).is_emit(), "内容变了必须放行");
        // 原内容再出现,仍在它自己的窗口内 → 折叠。
        assert!(!a.observe_event(&e1, 3_000).is_emit());
    }

    #[test]
    fn 不同来源或不同事件类型是不同指纹() {
        let a = ev("Safari", "同一段文字", &[]);
        let b = ev("Chrome", "同一段文字", &[]);
        assert_ne!(fingerprint(&a), fingerprint(&b));
        let mut c = a.clone();
        c.event_type = EventType::FormFill;
        assert_ne!(fingerprint(&a), fingerprint(&c));
    }

    #[test]
    fn 非易变元数据键参与指纹() {
        let a = ev("Safari", "t", &[("overlay_kinds", "TransparentOverlay")]);
        let b = ev("Safari", "t", &[("overlay_kinds", "SubliminalText")]);
        assert_ne!(fingerprint(&a), fingerprint(&b));
        let c = ev("Safari", "t", &[("label", "card number")]);
        let d = ev("Safari", "t", &[("label", "name")]);
        assert_ne!(fingerprint(&c), fingerprint(&d));
    }

    #[test]
    fn ui_text两端空白不算差异() {
        let a = ev("Safari", "hello\n", &[]);
        let b = ev("Safari", "  hello", &[]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn 表满挤掉最久没出现的_新键仍放行_被挤者再出现当首次() {
        let mut a = Aggregator::new(30_000, 3);
        a.observe(1, 0);
        a.observe(2, 100);
        a.observe(3, 200);
        a.observe(1, 300); // 1 刷新了 last_ms,最旧的变成 2
        assert_eq!(a.observe(4, 400), Verdict::Emit { repeats: 0 });
        assert_eq!(a.tracked(), 3);
        // 2 被挤掉了 → 再出现按首次
        assert_eq!(a.observe(2, 500), Verdict::Emit { repeats: 0 });
        // 1 还在 → 折叠
        assert!(!a.observe(1, 600).is_emit());
    }

    #[test]
    fn sweep报告并移除不再出现的指纹_之后再出现当首次() {
        let mut a = Aggregator::new(10_000, 64);
        a.observe(7, 0);
        a.observe(7, 1_000);
        a.observe(7, 2_000);
        a.observe(8, 5_000);
        assert!(a.sweep(9_000).is_empty(), "都还在窗口内");
        let ended = a.sweep(12_001);
        assert_eq!(
            ended,
            vec![Ended {
                key: 7,
                first_ms: 0,
                last_ms: 2_000,
                total: 3
            }]
        );
        assert_eq!(a.tracked(), 1);
        assert_eq!(a.observe(7, 13_000), Verdict::Emit { repeats: 0 });
    }

    #[test]
    fn 时钟回拨不panic且按折叠处理() {
        let mut a = Aggregator::new(30_000, 64);
        a.observe(1, 100_000);
        assert_eq!(a.observe(1, 50_000), Verdict::Suppress { seen: 1 });
        assert!(a.sweep(0).is_empty());
    }

    #[test]
    fn reset后一切当首次() {
        let mut a = Aggregator::new(30_000, 64);
        a.observe(1, 0);
        a.observe(1, 100);
        a.reset();
        assert_eq!(a.observe(1, 200), Verdict::Emit { repeats: 0 });
        assert_eq!(a.tracked(), 1);
    }

    /// 报告里的风暴复现:106 s,SCK 每 1.5 s 一帧静止画面 + AX 每 2.5 s 同一窗口。
    /// 旧行为 = 每条都过引擎(≈ 71 + 43 = 114 条候选,报告实测 75 条落库)。
    /// 新行为:每路每 30 s 最多一条 → 两路合计不超过 8 条,且最后一条摘要带 repeats。
    #[test]
    fn 风暴仿真_106秒静止画面从上百条折叠到个位数() {
        let mut a = Aggregator::for_observers();
        let frame = ev("ScreenCapture", "[AG_TRANSPARENT_OVERLAY]", &[]);
        let ax = ev("Safari", "Checkout · Total $299.00 · Pay now", &[]);
        let mut emitted = 0u32;
        let mut candidates = 0u32;
        let mut last_repeats = 0u32;
        let mut t = 0u64;
        while t <= 106_400 {
            if t.is_multiple_of(1_500) {
                candidates += 1;
                let mut f = frame.clone();
                f.metadata.insert("frame_digest".into(), format!("{t:x}"));
                if let Verdict::Emit { repeats } = a.observe_event(&f, t) {
                    emitted += 1;
                    last_repeats = last_repeats.max(repeats);
                }
            }
            if t.is_multiple_of(2_500) {
                candidates += 1;
                if a.observe_event(&ax, t).is_emit() {
                    emitted += 1;
                }
            }
            t += 500;
        }
        assert!(candidates >= 110, "候选 {candidates}");
        assert!(emitted <= 8, "放行 {emitted} 条,应 ≤ 8");
        assert!(emitted >= 6, "放行 {emitted} 条,持续摘要不能没有");
        assert!(last_repeats >= 15, "摘要应带上折叠计数,实际 {last_repeats}");
        assert_eq!(a.suppressed_total(), (candidates - emitted) as u64);
    }
}

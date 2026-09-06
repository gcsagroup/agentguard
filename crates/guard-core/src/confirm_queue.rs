//! 确认请求的有界队列(阶段 B,回应真机报告 P0-5)。
//!
//! # 报告复现的缺陷
//!
//! macOS 真机上出现过:弹窗显示 `UI-REVALIDATE`、同一时刻截图里已经是 `OVL-007`、
//! 用户点拒绝、拒绝却写进了 `PRIV-XAPP`。根因在壳子:待确认项是**单个可被覆盖的值**
//! (`Mutex<Option<PendingConfirm>>`),后台 AX/SCK 每来一个新事件就把它整个换掉;确认接口
//! 只收一个布尔,然后对「此刻的 pending」下手,没有任何东西保证「此刻的」还是用户在屏幕上
//! 看到并做出判断的那一条。于是:同意 A 放行了 B,拒绝 A 误拒了 C。
//!
//! # 这个模块怎么修
//!
//! 每一条待确认都带一个**不可变的 `request_id`**(单调递增,永不复用)。UI 拿到的是
//! request_id,回传的也是它;`resolve` 做 **compare-and-swap**:只有当这个 id 仍然在队列里
//! 时才解析它,否则返回 `Stale` —— 用户看到的东西已经不在了,不猜、不误伤别的请求。
//!
//! 会话 generation:每次会话开始/结束把 generation 加一,并清空队列。上一会话遗留的待确认
//! 不会跨会话被解析(报告 P0-3 的「会话结束后仍在处理」的另一半)。
//!
//! 队列有上限(FIFO 挤出最旧的)。挤出不是「悄悄丢」:被挤出的 id 记进 `evicted`,之后对它
//! 的 resolve 得到 `Stale` 而不是「找不到」——语义上「你要确认的那条已经过期,默认按未放行处理」。
//!
//! # 为什么放在 guard-core 而不是壳子里
//!
//! 壳子(Tauri)编不进这个容器,也没法在 Linux CI 上测并发。这个模块是**纯逻辑**:没有
//! Tauri、没有 AX/SCK、没有时钟。报告要求的复测判据「并发注入 ≥100 条事件,展示/id/回执
//! 一一对应,无覆盖、无跨会话串线」在这里用真线程直接测(见文件末)。壳子只负责把 AX/SCK
//! 事件塞进来、把 UI 的 request_id 传回来。
//!
//! # 阶段 C(报告 P1-4):超时默认拒 + 重启不静默丢
//!
//! 窗口隐藏/最小化时,一条高危确认可能一直等着而用户不知道。两条补充:
//! * 每条待确认带入队时刻;[`ConfirmQueue::expire`] 把超过 TTL 的移出并**交给调用方**写
//!   `Timeout` 回执——超时不是「悄悄消失」,是一次有审计的默认拒绝。
//! * [`ConfirmQueue::snapshot`] 给出可落盘的最小视图(不含观测文本摘录);壳子每次变化写一份,
//!   启动时读到上次遗留的,逐条写 `Timeout` 回执——重启后 pending 不能静默丢失。

use crate::confirm::ConfirmRequest;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// 一条待确认(队列元素)。`request_id` 与 `generation` 不可变。
#[derive(Debug, Clone)]
pub struct PendingItem {
    /// 全局单调、永不复用。UI 显示它、回传它。
    pub request_id: u64,
    /// 入队时的会话 generation。跨 generation 的解析一律 Stale。
    pub generation: u64,
    /// 入队时刻(ms since epoch)。0 = 调用方没给时间(不会超时)。
    pub enqueued_ms: u64,
    pub request: ConfirmRequest,
}

/// 可落盘的待确认视图(P1-4)。刻意**不含** `ui_excerpt`:那是被观察窗口的文本,不该以明文
/// 躺在磁盘上;重启后要做的只是给 `audit_id` 写一条 Timeout 回执,不需要它。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPending {
    pub request_id: u64,
    pub generation: u64,
    pub enqueued_ms: u64,
    pub audit_id: Option<String>,
    pub rule_id: String,
    pub severity: String,
    pub source_app: String,
}

impl PendingItem {
    fn persisted(&self) -> PersistedPending {
        PersistedPending {
            request_id: self.request_id,
            generation: self.generation,
            enqueued_ms: self.enqueued_ms,
            audit_id: self.request.audit_id.clone(),
            rule_id: self.request.rule_id.clone(),
            severity: self.request.severity.clone(),
            source_app: self.request.source_app.clone(),
        }
    }
}

/// 默认超时:两分钟没人拍板,按拒绝处理并写 Timeout 回执。
pub const DEFAULT_CONFIRM_TTL_MS: u64 = 120_000;

/// `resolve` 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// 成功解析了这个确切的 request_id;`approve` 是用户的选择,`audit_id` 用于回执落库。
    Resolved {
        approve: bool,
        audit_id: Option<String>,
    },
    /// 这个 request_id 已经不在队列里(被新会话清掉、被挤出、或已被解析过)。
    /// 语义:用户看到的请求已过期,按**未放行**处理,不触碰任何别的请求。
    Stale,
}

/// 有界确认队列。
#[derive(Debug)]
pub struct ConfirmQueue {
    items: VecDeque<PendingItem>,
    cap: usize,
    next_id: u64,
    generation: u64,
    /// 最近被挤出/清理掉的 id(用于把它们的 resolve 明确判成 Stale 而不是静默找不到)。
    /// 有界:只留最近 `cap*4` 个,足够覆盖「刚被挤出就来解析」的窗口。
    evicted: VecDeque<u64>,
}

impl ConfirmQueue {
    /// `cap` 是同时在等的确认数上限(FIFO 挤出最旧)。至少为 1。
    pub fn new(cap: usize) -> Self {
        Self {
            items: VecDeque::new(),
            cap: cap.max(1),
            next_id: 1,
            generation: 0,
            evicted: VecDeque::new(),
        }
    }

    /// 当前会话 generation。
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// 会话边界:generation +1,清空所有待确认(它们随会话失效)。
    ///
    /// 报告 P0-3:会话结束后不该再有任何东西被当作「当前待确认」解析。start 和 end 都调它 ——
    /// 一个新会话不继承上一个会话的悬空确认,一个结束的会话不给任何确认留下解析入口。
    pub fn bump_generation(&mut self) {
        match self.try_bump_generation::<std::convert::Infallible>(|_, _| Ok(())) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    /// 先把将离队的项目与空的新快照交给调用方提交，成功后才推进会话代际并清队列。
    ///
    /// 桌面壳用这个回调把每个遗留项的 Timeout 回执和快照删除放进同一数据库事务；回调
    /// 失败时，本方法不改变 generation、队列或 stale 记录。
    pub fn try_bump_generation<E>(
        &mut self,
        commit: impl FnOnce(&[PersistedPending], &[PersistedPending]) -> Result<(), E>,
    ) -> Result<(), E> {
        let removed = self.snapshot();
        commit(&removed, &[])?;
        for it in self.items.drain(..) {
            Self::remember_evicted(&mut self.evicted, self.cap, it.request_id);
        }
        self.generation += 1;
        Ok(())
    }

    /// 入队一条待确认,返回它不可变的 `request_id`。
    ///
    /// 满了就挤出最旧的(记进 evicted)。这里**不**判重:同一事件重复入队应该在上层用
    /// 指纹聚合挡掉(见 P2-3 的告警聚合),队列只保证 id 唯一与 CAS 语义。
    pub fn enqueue(&mut self, request: ConfirmRequest) -> u64 {
        self.enqueue_at(request, 0)
    }

    /// 带入队时刻的入队;`now_ms` > 0 的项才会被 [`Self::expire`] 判超时。
    pub fn enqueue_at(&mut self, request: ConfirmRequest, now_ms: u64) -> u64 {
        match self.try_enqueue_at::<std::convert::Infallible>(request, now_ms, |_, _| Ok(())) {
            Ok(id) => id,
            Err(never) => match never {},
        }
    }

    /// 预先计算入队后的快照，并在有容量挤出时把最旧项交给调用方；回调成功后才改队列。
    ///
    /// 这让桌面壳能原子提交“旧项 Timeout 回执 + 含新项的快照”。回调失败不会消费
    /// request_id，也不会把旧项挤出。
    pub fn try_enqueue_at<E>(
        &mut self,
        request: ConfirmRequest,
        now_ms: u64,
        commit: impl FnOnce(Option<&PersistedPending>, &[PersistedPending]) -> Result<(), E>,
    ) -> Result<u64, E> {
        let id = self.next_id;
        let candidate = PendingItem {
            request_id: id,
            generation: self.generation,
            enqueued_ms: now_ms,
            request,
        };
        let mut after = self.snapshot();
        let evicted = (after.len() >= self.cap).then(|| after.remove(0));
        after.push(candidate.persisted());
        commit(evicted.as_ref(), &after)?;

        self.next_id += 1;
        if self.items.len() >= self.cap {
            if let Some(old) = self.items.pop_front() {
                Self::remember_evicted(&mut self.evicted, self.cap, old.request_id);
            }
        }
        self.items.push_back(candidate);
        Ok(id)
    }

    /// 把等了超过 `ttl_ms` 的待确认移出并返回(调用方据此写 `Timeout` 回执、通知 UI)。
    ///
    /// 移出的 id 记进 evicted:此后对它的 resolve 是 `Stale`——用户在超时后才点的那一下
    /// 不会放行任何东西。入队时刻为 0 的项(调用方没给时间)永不超时。
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> Vec<PendingItem> {
        match self.try_expire::<std::convert::Infallible>(now_ms, ttl_ms, |_, _| Ok(())) {
            Ok(expired) => expired,
            Err(never) => match never {},
        }
    }

    /// 先提交所有超时项及剩余快照，成功后才把超时项移出。
    pub fn try_expire<E>(
        &mut self,
        now_ms: u64,
        ttl_ms: u64,
        commit: impl FnOnce(&[PersistedPending], &[PersistedPending]) -> Result<(), E>,
    ) -> Result<Vec<PendingItem>, E> {
        let is_expired =
            |it: &PendingItem| it.enqueued_ms > 0 && now_ms.saturating_sub(it.enqueued_ms) > ttl_ms;
        let removed: Vec<PersistedPending> = self
            .items
            .iter()
            .filter(|it| is_expired(it))
            .map(PendingItem::persisted)
            .collect();
        if removed.is_empty() {
            return Ok(Vec::new());
        }
        let remaining: Vec<PersistedPending> = self
            .items
            .iter()
            .filter(|it| !is_expired(it))
            .map(PendingItem::persisted)
            .collect();
        commit(&removed, &remaining)?;

        let mut out = Vec::new();
        let mut keep = VecDeque::with_capacity(self.items.len());
        for it in self.items.drain(..) {
            if is_expired(&it) {
                Self::remember_evicted(&mut self.evicted, self.cap, it.request_id);
                out.push(it);
            } else {
                keep.push_back(it);
            }
        }
        self.items = keep;
        Ok(out)
    }

    /// 可落盘视图(见 [`PersistedPending`])。
    pub fn snapshot(&self) -> Vec<PersistedPending> {
        self.items.iter().map(PendingItem::persisted).collect()
    }

    /// 解析一个确切的 request_id(compare-and-swap)。
    ///
    /// 只有当这个 id 此刻仍在队列里时才解析并**从队列移除**它;否则 `Stale`。这是整个修复的
    /// 核心:用户拒绝的是他看到的那条(id),不是「此刻碰巧在最前面的那条」。
    pub fn resolve(&mut self, request_id: u64, approve: bool) -> ResolveOutcome {
        match self.try_resolve::<std::convert::Infallible>(request_id, approve, |_, _| Ok(())) {
            Ok(outcome) => outcome,
            Err(never) => match never {},
        }
    }

    /// 先把将解析的确切项目与解析后的快照交给调用方提交，成功后才从队列移除。
    pub fn try_resolve<E>(
        &mut self,
        request_id: u64,
        approve: bool,
        commit: impl FnOnce(&PersistedPending, &[PersistedPending]) -> Result<(), E>,
    ) -> Result<ResolveOutcome, E> {
        let Some(pos) = self.items.iter().position(|it| it.request_id == request_id) else {
            return Ok(ResolveOutcome::Stale);
        };
        let removed = self.items[pos].persisted();
        let mut remaining = self.snapshot();
        remaining.remove(pos);
        commit(&removed, &remaining)?;

        let it = self
            .items
            .remove(pos)
            .expect("提交期间队列仍由可变借用独占");
        Ok(ResolveOutcome::Resolved {
            approve,
            audit_id: it.request.audit_id.clone(),
        })
    }

    /// 队首(最旧)待确认的只读视图 —— UI「现在该显示哪一条」。
    ///
    /// 刻意是 FIFO 的队首而不是最新:最新会不断被后台事件顶掉,那正是原缺陷里
    /// 「弹窗内容一直在变」的来源。用户先处理最早的那条,处理完(resolve 移除)才轮到下一条。
    pub fn front(&self) -> Option<&PendingItem> {
        self.items.front()
    }

    /// 当前等待中的数量。
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn remember_evicted(evicted: &mut VecDeque<u64>, cap: usize, id: u64) {
        evicted.push_back(id);
        while evicted.len() > cap * 4 {
            evicted.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::{Decision, DecisionAction, Severity};
    use std::sync::{Arc, Mutex};

    fn req(tag: &str, audit: &str) -> ConfirmRequest {
        let d = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: tag.into(),
            human_message: format!("确认 {tag}"),
            require_confirm: true,
        };
        ConfirmRequest::from_decision(&d, "Safari", Some(audit.into()), None)
    }

    #[test]
    fn resolve用对id解析对的那条不动别的() {
        let mut q = ConfirmQueue::new(8);
        let a = q.enqueue(req("A", "audit-A"));
        let b = q.enqueue(req("B", "audit-B"));
        // 拒绝 A —— 必须解析 A(audit-A),B 原封不动。这正是报告里出错的场景。
        let out = q.resolve(a, false);
        assert_eq!(
            out,
            ResolveOutcome::Resolved {
                approve: false,
                audit_id: Some("audit-A".into())
            }
        );
        assert_eq!(q.len(), 1);
        assert_eq!(q.front().unwrap().request_id, b);
    }

    #[test]
    fn 后台事件不断入队不会改变已展示项的id() {
        // cap 足够容纳这批不同事件:壳子用的 cap 是这个量级,而真正防止风暴撑爆队列的是
        // 上层的指纹聚合(P2-3)——重复的 OVL 事件在到队列之前就被合并了。这条测试单独验队列:
        // 只要没被挤出,已展示项的 id 就绝不会因为新事件入队而改变。
        let mut q = ConfirmQueue::new(64);
        let shown = q.enqueue(req("UI-REVALIDATE", "audit-shown"));
        for i in 0..50 {
            q.enqueue(req(&format!("OVL-{i:03}"), &format!("audit-{i}")));
        }
        // 用户看到并拒绝的仍是最早那条;解析它得到的是它自己的 audit,不是被顶替的。
        let out = q.resolve(shown, false);
        assert_eq!(
            out,
            ResolveOutcome::Resolved {
                approve: false,
                audit_id: Some("audit-shown".into())
            }
        );
    }

    #[test]
    fn 已解析的id再次解析是stale() {
        let mut q = ConfirmQueue::new(4);
        let a = q.enqueue(req("A", "audit-A"));
        assert!(matches!(
            q.resolve(a, true),
            ResolveOutcome::Resolved { .. }
        ));
        assert_eq!(q.resolve(a, true), ResolveOutcome::Stale);
    }

    #[test]
    fn 会话切换清空队列且旧id变stale() {
        let mut q = ConfirmQueue::new(4);
        let g0 = q.generation();
        let a = q.enqueue(req("A", "audit-A"));
        q.bump_generation(); // 会话结束/开始
        assert!(q.is_empty());
        assert_eq!(q.generation(), g0 + 1);
        // 上一会话的待确认不能再被解析。
        assert_eq!(q.resolve(a, false), ResolveOutcome::Stale);
    }

    #[test]
    fn 超容量时挤出最旧被挤出的id解析为stale() {
        let mut q = ConfirmQueue::new(2);
        let a = q.enqueue(req("A", "audit-A"));
        let b = q.enqueue(req("B", "audit-B"));
        let c = q.enqueue(req("C", "audit-C")); // 挤出 A
        assert_eq!(q.len(), 2);
        assert_eq!(
            q.resolve(a, false),
            ResolveOutcome::Stale,
            "被挤出的 A 应 Stale"
        );
        assert!(matches!(
            q.resolve(b, true),
            ResolveOutcome::Resolved { .. }
        ));
        assert!(matches!(
            q.resolve(c, true),
            ResolveOutcome::Resolved { .. }
        ));
    }

    #[test]
    fn 容量挤出的提交失败不丢旧项也不消耗request_id() {
        let mut q = ConfirmQueue::new(1);
        let a = q.enqueue(req("A", "audit-A"));
        let before = q.snapshot();

        let error = q
            .try_enqueue_at(req("B", "audit-B"), 42, |evicted, after| {
                assert_eq!(
                    evicted.and_then(|item| item.audit_id.as_deref()),
                    Some("audit-A")
                );
                assert_eq!(after.len(), 1);
                assert_eq!(after[0].audit_id.as_deref(), Some("audit-B"));
                Err("审计提交失败")
            })
            .unwrap_err();
        assert_eq!(error, "审计提交失败");
        assert_eq!(q.snapshot(), before);
        assert_eq!(q.front().unwrap().request_id, a);

        let b = q
            .try_enqueue_at(req("B", "audit-B"), 42, |_, _| Ok::<_, &str>(()))
            .unwrap();
        assert_eq!(b, a + 1, "失败尝试不能消耗 request_id");
        assert_eq!(
            q.front().unwrap().request.audit_id.as_deref(),
            Some("audit-B")
        );
    }

    /// P1-4:超时的按拒绝处理——移出、交给调用方写回执、之后再点是 Stale。
    #[test]
    fn 超时项被移出且之后解析为stale_未超时与无时间项留下() {
        let mut q = ConfirmQueue::new(8);
        let old = q.enqueue_at(req("OLD", "audit-old"), 1_000);
        let fresh = q.enqueue_at(req("FRESH", "audit-fresh"), 100_000);
        let timeless = q.enqueue(req("TIMELESS", "audit-timeless"));
        let expired = q.expire(130_000, DEFAULT_CONFIRM_TTL_MS);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].request_id, old);
        assert_eq!(expired[0].request.audit_id.as_deref(), Some("audit-old"));
        assert_eq!(q.len(), 2);
        assert_eq!(
            q.resolve(old, true),
            ResolveOutcome::Stale,
            "超时后再点同意不放行"
        );
        assert!(matches!(
            q.resolve(fresh, true),
            ResolveOutcome::Resolved { .. }
        ));
        assert!(matches!(
            q.resolve(timeless, false),
            ResolveOutcome::Resolved { .. }
        ));
    }

    #[test]
    fn 恰好等于ttl不算超时_时钟回拨不算超时() {
        let mut q = ConfirmQueue::new(8);
        q.enqueue_at(req("A", "a"), 10_000);
        assert!(q
            .expire(10_000 + DEFAULT_CONFIRM_TTL_MS, DEFAULT_CONFIRM_TTL_MS)
            .is_empty());
        assert!(
            q.expire(5_000, DEFAULT_CONFIRM_TTL_MS).is_empty(),
            "now < enqueued"
        );
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn 任一离队提交失败都保持队列和代际不变() {
        let mut q = ConfirmQueue::new(4);
        let request_id = q.enqueue_at(req("A", "audit-A"), 1_000);
        let before = q.snapshot();
        let generation = q.generation();

        assert!(q
            .try_resolve(request_id, true, |_, _| Err("resolve failed"))
            .is_err());
        assert_eq!(q.snapshot(), before);

        assert!(q
            .try_expire(
                1_000 + DEFAULT_CONFIRM_TTL_MS + 1,
                DEFAULT_CONFIRM_TTL_MS,
                |_, _| { Err("expire failed") }
            )
            .is_err());
        assert_eq!(q.snapshot(), before);

        assert!(q
            .try_bump_generation(|_, _| Err("generation failed"))
            .is_err());
        assert_eq!(q.snapshot(), before);
        assert_eq!(q.generation(), generation);
    }

    /// P1-4:落盘视图不含观测文本摘录,含回执所需的 audit_id;能 JSON 往返。
    #[test]
    fn 快照不含ui摘录且可json往返() {
        let mut q = ConfirmQueue::new(8);
        let d = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: "CRIT-001".into(),
            human_message: "确认支付".into(),
            require_confirm: true,
        };
        let r = ConfirmRequest::from_decision(
            &d,
            "Safari",
            Some("audit-1".into()),
            Some("卡号 4111 1111 1111 1111 的屏幕文本".into()),
        );
        let id = q.enqueue_at(r, 42);
        let snap = q.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].request_id, id);
        assert_eq!(snap[0].audit_id.as_deref(), Some("audit-1"));
        assert_eq!(snap[0].enqueued_ms, 42);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("4111"), "观测文本不该落盘:{json}");
        assert!(!json.contains("ui_excerpt"));
        let back: Vec<PersistedPending> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snap);
    }

    /// 报告的复测判据:并发注入 ≥100 条事件,每条最终被解析的 audit 与它自己的 id 一一对应,
    /// 无覆盖、无重复解析、无跨会话串线。
    #[test]
    fn 并发注入一百条每条回执与自身id一一对应() {
        let q = Arc::new(Mutex::new(ConfirmQueue::new(256)));
        let n = 200;

        // 生产者:并发入队,记下 (id -> 期望 audit)。
        let mut handles = Vec::new();
        let map = Arc::new(Mutex::new(std::collections::HashMap::<u64, String>::new()));
        for t in 0..8 {
            let q = Arc::clone(&q);
            let map = Arc::clone(&map);
            handles.push(std::thread::spawn(move || {
                for i in 0..(n / 8) {
                    let tag = format!("R-{t}-{i}");
                    let audit = format!("audit-{t}-{i}");
                    let id = q.lock().unwrap().enqueue(req(&tag, &audit));
                    map.lock().unwrap().insert(id, audit);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let expected = map.lock().unwrap().clone();
        assert_eq!(expected.len(), n, "id 必须全局唯一,无复用");

        // 消费者:并发解析每一个 id,校验回执 audit 与入队时登记的一致。
        let mismatches = Arc::new(Mutex::new(Vec::<String>::new()));
        let ids: Vec<u64> = expected.keys().copied().collect();
        let mut handles = Vec::new();
        for chunk in ids.chunks(ids.len().div_ceil(8)) {
            let chunk = chunk.to_vec();
            let q = Arc::clone(&q);
            let expected = expected.clone();
            let mismatches = Arc::clone(&mismatches);
            handles.push(std::thread::spawn(move || {
                for id in chunk {
                    match q.lock().unwrap().resolve(id, false) {
                        ResolveOutcome::Resolved { audit_id, .. } => {
                            let got = audit_id.unwrap_or_default();
                            if got != expected[&id] {
                                mismatches
                                    .lock()
                                    .unwrap()
                                    .push(format!("id {id}: 期望 {}, 得到 {got}", expected[&id]));
                            }
                        }
                        ResolveOutcome::Stale => mismatches
                            .lock()
                            .unwrap()
                            .push(format!("id {id}: 意外 Stale(被覆盖或丢失)")),
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let m = mismatches.lock().unwrap();
        assert!(m.is_empty(), "{} 条串线:\n{}", m.len(), m.join("\n"));
        assert!(q.lock().unwrap().is_empty(), "全部解析后队列应为空");
    }
}

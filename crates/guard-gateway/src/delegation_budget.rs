//! 当前宿主委托树的共用预算；所有祖先在同一锁内核对并扣减。
//! 本模块不提供主体认证或操作者认证，调用方必须先完成 AGD-023 的认证。
use anyhow::{ensure, Context, Result};
use guard_schema::ValidatedId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_NODES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    /// 允许的后代层数，0 表示不能继续委托。
    pub max_depth: u16,
    pub max_calls: u64,
    pub max_output_bytes: u64,
    pub max_elapsed_ms: u64,
}
impl BudgetLimits {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.max_depth <= 16, "委托深度上限不能超过 16");
        ensure!((1..=1_000_000).contains(&self.max_calls), "调用预算无效");
        ensure!(
            (1..=256 * 1024 * 1024).contains(&self.max_output_bytes),
            "输出预算无效"
        );
        ensure!(
            (1..=3_600_000).contains(&self.max_elapsed_ms),
            "运行时间预算无效"
        );
        Ok(())
    }
    fn child(&self, requested: &Self) -> Result<Self> {
        requested.validate()?;
        ensure!(self.max_depth > 0, "父委托已达到深度上限");
        Ok(Self {
            max_depth: requested.max_depth.min(self.max_depth - 1),
            max_calls: requested.max_calls.min(self.max_calls),
            max_output_bytes: requested.max_output_bytes.min(self.max_output_bytes),
            max_elapsed_ms: requested.max_elapsed_ms.min(self.max_elapsed_ms),
        })
    }
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_calls: 64,
            max_output_bytes: 1024 * 1024,
            max_elapsed_ms: 120_000,
        }
    }
}

struct Node {
    parent: Option<String>,
    limits: BudgetLimits,
    born: Instant,
    deadline: Instant,
    calls: u64,
    output_used: u64,
    output_reserved: u64,
    revoked: bool,
}
struct Reservation {
    node: String,
    ancestors: Vec<String>,
    output: u64,
    started: bool,
    child_created: bool,
}
struct State {
    nodes: HashMap<String, Node>,
    reservations: HashMap<u64, Reservation>,
    next_ticket: u64,
    closed: bool,
}
impl State {
    fn ancestors(&self, node: &str) -> Result<Vec<String>> {
        let mut chain = Vec::new();
        let mut current = Some(node);
        while let Some(id) = current {
            ensure!(chain.len() < MAX_NODES, "预算父链异常");
            let value = self.nodes.get(id).context("委托预算不存在")?;
            chain.push(id.to_owned());
            current = value.parent.as_deref();
        }
        Ok(chain)
    }
    fn live(&self, ancestors: &[String], now: Instant) -> Result<()> {
        ensure!(!self.closed, "宿主委托预算已关闭");
        for id in ancestors {
            let node = self.nodes.get(id).context("父预算不存在")?;
            ensure!(!node.revoked, "父委托或当前委托已撤销");
            ensure!(
                now >= node.born && now < node.deadline,
                "委托时间预算已失效"
            );
        }
        Ok(())
    }
    fn check(&self, ticket: u64, now: Instant) -> Result<()> {
        let held = self
            .reservations
            .get(&ticket)
            .context("预算许可已结算或失效")?;
        self.live(&held.ancestors, now)
    }
    fn settle(&mut self, ticket: u64, actual: Option<u64>) -> Result<()> {
        let held = self
            .reservations
            .remove(&ticket)
            .context("预算许可不能重复结算")?;
        let used = actual.unwrap_or(held.output).min(held.output);
        for id in held.ancestors {
            let node = self.nodes.get_mut(&id).expect("账本内父链不能删除");
            node.output_reserved -= held.output;
            node.output_used += used;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct BudgetTree(Arc<Mutex<State>>);

/// 公布的是限制和实测用量；当前后端无法可靠计量金额。
#[derive(Debug, Serialize)]
pub struct BudgetStatus {
    pub closed: bool,
    pub monetary_cost: &'static str,
    pub nodes: Vec<NodeStatus>,
}
#[derive(Debug, Serialize)]
pub struct NodeStatus {
    pub grant_id: String,
    pub parent_grant_id: Option<String>,
    pub limits: BudgetLimits,
    pub used_calls: u64,
    pub used_output_bytes: u64,
    pub reserved_output_bytes: u64,
    pub remaining_calls: u64,
    pub remaining_output_bytes: u64,
    pub remaining_ms: u64,
    pub revoked: bool,
}
impl BudgetTree {
    pub fn new(root: &str, limits: BudgetLimits, now: Instant) -> Result<Self> {
        ValidatedId::new(root)?;
        limits.validate()?;
        let deadline = now
            .checked_add(Duration::from_millis(limits.max_elapsed_ms))
            .context("预算时间溢出")?;
        let node = Node {
            parent: None,
            limits,
            born: now,
            deadline,
            calls: 0,
            output_used: 0,
            output_reserved: 0,
            revoked: false,
        };
        Ok(Self(Arc::new(Mutex::new(State {
            nodes: HashMap::from([(root.to_owned(), node)]),
            reservations: HashMap::new(),
            next_ticket: 0,
            closed: false,
        }))))
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("预算锁失效，禁止派发"))
    }
    /// 一次调用的全部祖先同扣一次；输出按祖先共同可用额度预留。
    /// 调用次数立即消费。许可丢失、拒绝或超时都不退回调用次数。
    pub fn reserve(
        &self,
        grant: &str,
        requested_output: u64,
        now: Instant,
    ) -> Result<BudgetPermit> {
        self.reserve_at_least(grant, requested_output, 1, now)
    }

    /// 生产协议还需给固定控制回执保留空间；剩余额度不足时不得部分消费调用。
    pub fn reserve_at_least(
        &self,
        grant: &str,
        requested_output: u64,
        minimum_output: u64,
        now: Instant,
    ) -> Result<BudgetPermit> {
        ensure!(requested_output > 0, "每次调用必须预留有界输出");
        ensure!(
            minimum_output > 0 && minimum_output <= requested_output,
            "最小回执额度无效"
        );
        let mut state = self.lock()?;
        let ancestors = state.ancestors(grant)?;
        state.live(&ancestors, now)?;
        let mut output = requested_output;
        for id in &ancestors {
            let node = &state.nodes[id];
            ensure!(
                node.calls < node.limits.max_calls,
                "祖先或当前分支调用预算耗尽"
            );
            output =
                output.min(node.limits.max_output_bytes - node.output_used - node.output_reserved);
        }
        ensure!(
            output >= minimum_output,
            "祖先或当前分支输出预算不足以容纳回执"
        );
        let ticket = state
            .next_ticket
            .checked_add(1)
            .context("预算许可序号溢出")?;
        for id in &ancestors {
            let node = state.nodes.get_mut(id).expect("已核对全部父链");
            node.calls += 1;
            node.output_reserved += output;
        }
        state.next_ticket = ticket;
        state.reservations.insert(
            ticket,
            Reservation {
                node: grant.to_owned(),
                ancestors,
                output,
                started: false,
                child_created: false,
            },
        );
        Ok(BudgetPermit {
            tree: self.clone(),
            ticket,
            output_limit: output,
            settled: false,
        })
    }

    pub fn check_grant(&self, grant: &str, now: Instant) -> Result<()> {
        let state = self.lock()?;
        state.live(&state.ancestors(grant)?, now)
    }
    /// 撤销不能回收已消费用量，也不能使旧许可再次可用。
    pub fn revoke(&self, grant: &str) -> Result<usize> {
        let mut state = self.lock()?;
        ensure!(state.nodes.contains_key(grant), "撤销目标不存在");
        let mut affected = Vec::new();
        for id in state.nodes.keys() {
            if state.ancestors(id)?.iter().any(|parent| parent == grant) {
                affected.push(id.clone());
            }
        }
        let mut count = 0;
        for id in affected {
            let node = state.nodes.get_mut(&id).expect("已收集目标");
            if !node.revoked {
                node.revoked = true;
                count += 1;
            }
        }
        Ok(count)
    }
    pub fn close(&self) -> Result<()> {
        self.lock()?.closed = true;
        Ok(())
    }
    pub fn status(&self, now: Instant) -> Result<BudgetStatus> {
        let state = self.lock()?;
        let mut nodes = Vec::new();
        for (id, node) in &state.nodes {
            let chain = state.ancestors(id)?;
            let mut calls = u64::MAX;
            let mut output = u64::MAX;
            for ancestor in chain {
                let parent = &state.nodes[&ancestor];
                calls = calls.min(parent.limits.max_calls - parent.calls);
                output = output.min(
                    parent.limits.max_output_bytes - parent.output_used - parent.output_reserved,
                );
            }
            nodes.push(NodeStatus {
                grant_id: id.clone(),
                parent_grant_id: node.parent.clone(),
                limits: node.limits.clone(),
                used_calls: node.calls,
                used_output_bytes: node.output_used,
                reserved_output_bytes: node.output_reserved,
                remaining_calls: calls,
                remaining_output_bytes: output,
                remaining_ms: node
                    .deadline
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
                revoked: node.revoked,
            });
        }
        nodes.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
        Ok(BudgetStatus {
            closed: state.closed,
            monetary_cost: "unmeasurable_call_and_time_limits_enforced",
            nodes,
        })
    }
}

/// 只能从账本领取，不可克隆、反序列化或重新构造；Drop 按结果未知消费全部预留。
pub struct BudgetPermit {
    tree: BudgetTree,
    ticket: u64,
    output_limit: u64,
    settled: bool,
}
impl BudgetPermit {
    pub fn output_limit(&self) -> u64 {
        self.output_limit
    }
    pub fn ticket(&self) -> u64 {
        self.ticket
    }
    pub fn remaining(&self, now: Instant) -> Result<Duration> {
        let state = self.tree.lock()?;
        state.check(self.ticket, now)?;
        let held = &state.reservations[&self.ticket];
        Ok(state.nodes[&held.node]
            .deadline
            .saturating_duration_since(now))
    }
    pub fn check(&self, now: Instant) -> Result<()> {
        self.tree.lock()?.check(self.ticket, now)
    }
    pub fn mark_started(&mut self, now: Instant) -> Result<()> {
        let mut state = self.tree.lock()?;
        state.check(self.ticket, now)?;
        let held = state
            .reservations
            .get_mut(&self.ticket)
            .expect("已复核许可");
        ensure!(!held.started, "一个预算许可只能开始一次");
        held.started = true;
        Ok(())
    }
    /// 一次经认证的委托消息只可新建一个子节点，创建操作也消费调用预算。
    pub fn create_child(
        &mut self,
        grant: &str,
        requested: &BudgetLimits,
        now: Instant,
    ) -> Result<BudgetLimits> {
        ValidatedId::new(grant)?;
        let mut state = self.tree.lock()?;
        state.check(self.ticket, now)?;
        ensure!(
            !state.nodes.contains_key(grant) && state.nodes.len() < MAX_NODES,
            "子预算标识重复或表容量耗尽"
        );
        let held = &state.reservations[&self.ticket];
        ensure!(
            held.started && !held.child_created,
            "预算许可未开始或已创建过子委托"
        );
        let parent_id = held.node.clone();
        let parent = &state.nodes[&parent_id];
        let limits = parent.limits.child(requested)?;
        let deadline = parent.deadline.min(
            now.checked_add(Duration::from_millis(limits.max_elapsed_ms))
                .context("子预算时间溢出")?,
        );
        state.nodes.insert(
            grant.to_owned(),
            Node {
                parent: Some(parent_id),
                limits: limits.clone(),
                born: now,
                deadline,
                calls: 0,
                output_used: 0,
                output_reserved: 0,
                revoked: false,
            },
        );
        state
            .reservations
            .get_mut(&self.ticket)
            .expect("已复核许可")
            .child_created = true;
        Ok(limits)
    }
    /// 调用方只有在此函数成功后才可公开已编码响应；超过预留或撤销时必须隐藏正文。
    pub fn finish(self, actual_output: u64, now: Instant) -> Result<()> {
        self.finish_recorded(actual_output, now, |_| Ok(()))
    }
    /// 审计确认前不释放预留；记录失败时消费全部预留，保证故障回执也有额度。
    /// 回调只可写审计，不能重新访问预算树，以保持预算锁到审计锁的顺序。
    pub(crate) fn finish_recorded(
        mut self,
        actual_output: u64,
        now: Instant,
        record: impl FnOnce(bool) -> Result<()>,
    ) -> Result<()> {
        let mut state = self.tree.lock()?;
        let live = state.check(self.ticket, now);
        let within = actual_output <= self.output_limit;
        let allowed = live.is_ok() && within;
        let recorded = record(allowed);
        state.settle(
            self.ticket,
            if allowed && recorded.is_ok() {
                Some(actual_output)
            } else {
                None
            },
        )?;
        self.settled = true;
        recorded?;
        live?;
        ensure!(within, "输出超过预留额度，禁止公开正文");
        Ok(())
    }
}
impl Drop for BudgetPermit {
    fn drop(&mut self) {
        if !self.settled {
            if let Ok(mut state) = self.tree.lock() {
                let _ = state.settle(self.ticket, None);
            }
        }
    }
}

#[cfg(test)]
#[path = "delegation_budget_tests.rs"]
mod tests;

//! 真机验收的**机器判据**(阶段 D)。
//!
//! 真机报告 P0-5 的复现是靠人眼对截图和审计库:「弹窗显示 UI-REVALIDATE、截图已是 OVL-007、
//! 拒绝写进 PRIV-XAPP」。这类结论应该由程序算出来,而不是靶着一堆表格核对。做法:
//!
//! * 壳子在 `AGENTGUARD_ACCEPTANCE_TRACE=<path>` 设定时,把**它自己看到的事实**逐行写成 JSONL
//!   ([`TraceLine`]):会话开始/结束、每条确认的入队/展示/解析/超时、每一拍观察、每次状态判定。
//!   这份 trace 只在验收时开,产品路径不受影响。
//! * 验收后用 `guard-cli acceptance-trace-check --trace <path> --audit-db <db>` 把 trace 和签名
//!   审计库对起来。判据在 [`check`] 里,是纯函数:
//!
//!   1. **确认一致(P0-5)**:每条 `resolved` 的确认,其 audit_id 在库里、回执与用户选择一致、
//!      记录的 rule_id 和入队时的 rule_id 一致、且这条 request_id 确实被**展示**过。库里每条
//!      approve/deny 回执都能在 trace 里找到对应的 resolve——没有幽灵回执。
//!   2. **超时有回执(P1-4)**:每条 `expired` 的确认,库里的回执是 `timeout`。
//!   3. **会话结束后无观察(P0-3)**:最后一次 `session_end` 之后(宽限 2 s),库里没有 UiTreeDelta /
//!      ScreenFrame / FormFill 记录,trace 里也没有 `events>0` 的观察拍——直到下一次 `session_start`。
//!   4. **状态灯有依据(P0-3)**:每次 `state=active` 前 TTL 内必有一拍观察;`session_end` 之后
//!      不再出现 `active`。
//!   5. **过期确认不放行**:`stale` 的 resolve 不对应任何 approve 回执。
//!
//! 它判的是「壳子说的」和「库里写的」是否吻合。壳子说谎(不写 trace)它看不出来——所以
//! trace 的完整性靠另一条:trace 里的 session_start/end 数量必须和库里 SESSION-START/END 一致。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 一行 trace。`kind` 决定哪些字段有意义;未知 kind 被忽略(向前兼容)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceLine {
    pub ts: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<bool>,
    /// `resolved` | `stale`(仅 confirm_resolved)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// 观察拍来源:`ax` | `sck` | `uia`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection_state: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

impl TraceLine {
    pub fn new(ts: u64, kind: &str) -> Self {
        TraceLine {
            ts,
            kind: kind.into(),
            session_id: None,
            request_id: None,
            audit_id: None,
            rule_id: None,
            approve: None,
            outcome: None,
            source: None,
            events: None,
            suppressed: None,
            protection_state: None,
            reasons: Vec::new(),
        }
    }
}

/// 壳子用的写入端:`AGENTGUARD_ACCEPTANCE_TRACE=<path>` 设定时追加写 JSONL,否则什么都不做。
///
/// 写失败不影响产品路径(只在 stderr 记一次)——trace 是验收辅助,不是审计。
#[derive(Debug)]
pub struct TraceWriter {
    path: Option<std::path::PathBuf>,
    warned: std::sync::atomic::AtomicBool,
}

pub const TRACE_ENV: &str = "AGENTGUARD_ACCEPTANCE_TRACE";

impl TraceWriter {
    pub fn from_env() -> Self {
        let path = std::env::var_os(TRACE_ENV)
            .map(std::path::PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());
        TraceWriter {
            path,
            warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn disabled() -> Self {
        TraceWriter {
            path: None,
            warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn at(path: impl Into<std::path::PathBuf>) -> Self {
        TraceWriter {
            path: Some(path.into()),
            warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    pub fn write(&self, line: &TraceLine) {
        let Some(path) = &self.path else {
            return;
        };
        use std::io::Write as _;
        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| {
                let mut s = serde_json::to_string(line).unwrap_or_default();
                s.push('\n');
                f.write_all(s.as_bytes())
            });
        if let Err(e) = result {
            if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "agentguard: acceptance trace write failed ({}): {e}",
                    path.display()
                );
            }
        }
    }
}

/// 审计库里一条记录的最小视图(从 `AuditRecord` 抄过来,让这个模块不依赖 guard-audit 的 I/O)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: String,
    pub timestamp_ms: i64,
    pub event_type: String,
    pub rule_id: String,
    pub user_decision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub checks: Vec<CheckResult>,
}

impl Report {
    pub fn all_pass(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }
}

/// 会话结束到「不许再有观察记录」之间的宽限:线程在下一拍才看到 flag。
pub const SESSION_END_GRACE_MS: u64 = 2_000;
/// `active` 前必须有观察拍的窗口,与 observe_state 的心跳 TTL 一致。
pub const ACTIVE_HEARTBEAT_TTL_MS: u64 = 10_000;

const OBSERVATION_EVENT_TYPES: &[&str] = &["UiTreeDelta", "ScreenFrame", "FormFill"];

/// 解析 JSONL;坏行记进 `errors`,不让一行垃圾把整份 trace 作废。
pub fn parse_trace(text: &str) -> (Vec<TraceLine>, Vec<String>) {
    let mut lines = Vec::new();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        match serde_json::from_str::<TraceLine>(raw) {
            Ok(l) => lines.push(l),
            Err(e) => errors.push(format!("line {}: {e}", i + 1)),
        }
    }
    (lines, errors)
}

pub fn check(trace: &[TraceLine], rows: &[AuditRow]) -> Report {
    let mut checks = Vec::new();
    let by_id: HashMap<&str, &AuditRow> = rows.iter().map(|r| (r.id.as_str(), r)).collect();

    // ---- 0. trace 完整性:会话边界数量与库一致 ----
    let trace_starts = trace.iter().filter(|l| l.kind == "session_start").count();
    let trace_ends = trace.iter().filter(|l| l.kind == "session_end").count();
    let db_starts = rows.iter().filter(|r| r.rule_id == "SESSION-START").count();
    let db_ends = rows.iter().filter(|r| r.rule_id == "SESSION-END").count();
    checks.push(CheckResult {
        name: "trace covers every session in the audit db".into(),
        pass: trace_starts == db_starts && trace_ends == db_ends,
        detail: format!(
            "trace start/end = {trace_starts}/{trace_ends}, audit SESSION-START/END = {db_starts}/{db_ends}"
        ),
    });

    // ---- 1. 确认一致 (P0-5) ----
    let enqueued: HashMap<u64, &TraceLine> = trace
        .iter()
        .filter(|l| l.kind == "confirm_enqueued")
        .filter_map(|l| l.request_id.map(|id| (id, l)))
        .collect();
    let shown: HashSet<u64> = trace
        .iter()
        .filter(|l| l.kind == "confirm_shown")
        .filter_map(|l| l.request_id)
        .collect();
    let mut problems = Vec::new();
    let mut resolved_audit_ids: HashSet<&str> = HashSet::new();
    for l in trace
        .iter()
        .filter(|l| l.kind == "confirm_resolved" && l.outcome.as_deref() == Some("resolved"))
    {
        let Some(rid) = l.request_id else {
            problems.push(format!("resolved line at {} has no request_id", l.ts));
            continue;
        };
        if !shown.contains(&rid) {
            problems.push(format!("request {rid} was resolved but never shown"));
        }
        let Some(enq) = enqueued.get(&rid) else {
            problems.push(format!("request {rid} was resolved but never enqueued"));
            continue;
        };
        let Some(aid) = l.audit_id.as_deref().or(enq.audit_id.as_deref()) else {
            problems.push(format!("request {rid} has no audit_id in trace"));
            continue;
        };
        resolved_audit_ids.insert(aid);
        let Some(row) = by_id.get(aid) else {
            problems.push(format!("request {rid}: audit record {aid} not in db"));
            continue;
        };
        let want = if l.approve == Some(true) {
            "approve"
        } else {
            "deny"
        };
        if row.user_decision.as_deref() != Some(want) {
            problems.push(format!(
                "request {rid}: user chose {want}, audit {aid} has {:?}",
                row.user_decision
            ));
        }
        if let Some(rule) = enq.rule_id.as_deref() {
            if row.rule_id != rule {
                problems.push(format!(
                    "request {rid}: shown rule {rule}, receipt landed on {} (audit {aid})",
                    row.rule_id
                ));
            }
        }
    }
    // 幽灵回执:库里有 approve/deny 却没有对应 resolve。
    for r in rows
        .iter()
        .filter(|r| matches!(r.user_decision.as_deref(), Some("approve") | Some("deny")))
    {
        if !resolved_audit_ids.contains(r.id.as_str()) {
            problems.push(format!(
                "audit {} carries {:?} with no matching resolve in trace",
                r.id, r.user_decision
            ));
        }
    }
    checks.push(CheckResult {
        name: "every confirmation receipt matches the request the user saw (P0-5)".into(),
        pass: problems.is_empty(),
        detail: if problems.is_empty() {
            format!(
                "{} resolved confirmation(s) consistent",
                resolved_audit_ids.len()
            )
        } else {
            problems.join("; ")
        },
    });

    // ---- 2. 超时有回执 (P1-4) ----
    let mut problems = Vec::new();
    let mut expired_n = 0;
    for l in trace.iter().filter(|l| l.kind == "confirm_expired") {
        expired_n += 1;
        let Some(aid) = l.audit_id.as_deref() else {
            problems.push(format!("expired line at {} has no audit_id", l.ts));
            continue;
        };
        match by_id.get(aid) {
            Some(row) if row.user_decision.as_deref() == Some("timeout") => {}
            Some(row) => problems.push(format!(
                "expired request {:?}: audit {aid} has {:?}, expected timeout",
                l.request_id, row.user_decision
            )),
            None => problems.push(format!(
                "expired request {:?}: audit {aid} not in db",
                l.request_id
            )),
        }
    }
    checks.push(CheckResult {
        name: "every timed-out confirmation has a timeout receipt (P1-4)".into(),
        pass: problems.is_empty(),
        detail: if problems.is_empty() {
            format!("{expired_n} timeout(s) receipted")
        } else {
            problems.join("; ")
        },
    });

    // ---- 3. 会话结束后无观察 (P0-3) ----
    let mut problems = Vec::new();
    let mut boundaries: Vec<(u64, bool)> = trace
        .iter()
        .filter(|l| l.kind == "session_start" || l.kind == "session_end")
        .map(|l| (l.ts, l.kind == "session_start"))
        .collect();
    boundaries.sort_by_key(|b| b.0);
    // 每个 end 到下一个 start 之间是"关闭区间"。
    let mut closed: Vec<(u64, u64)> = Vec::new();
    let mut i = 0;
    while i < boundaries.len() {
        if !boundaries[i].1 {
            let end = boundaries[i].0;
            let next_start = boundaries[i + 1..]
                .iter()
                .find(|b| b.1)
                .map(|b| b.0)
                .unwrap_or(u64::MAX);
            closed.push((end.saturating_add(SESSION_END_GRACE_MS), next_start));
        }
        i += 1;
    }
    let in_closed = |ts: u64| closed.iter().any(|(a, b)| ts > *a && ts < *b);
    for r in rows
        .iter()
        .filter(|r| OBSERVATION_EVENT_TYPES.contains(&r.event_type.as_str()))
    {
        let ts = r.timestamp_ms.max(0) as u64;
        if in_closed(ts) {
            problems.push(format!(
                "audit {} ({}, {}) written at {ts} while no session was open",
                r.id, r.event_type, r.rule_id
            ));
        }
    }
    for l in trace
        .iter()
        .filter(|l| l.kind == "observe_tick" && l.events.unwrap_or(0) > 0)
    {
        if in_closed(l.ts) {
            problems.push(format!(
                "observer {} produced {} event(s) at {} while no session was open",
                l.source.as_deref().unwrap_or("?"),
                l.events.unwrap_or(0),
                l.ts
            ));
        }
    }
    checks.push(CheckResult {
        name: "no observation after session end (P0-3)".into(),
        pass: problems.is_empty(),
        detail: if problems.is_empty() {
            format!("{} closed interval(s) clean", closed.len())
        } else {
            problems.join("; ")
        },
    });

    // ---- 4. 状态灯有依据 (P0-3) ----
    let mut problems = Vec::new();
    let ticks: Vec<u64> = trace
        .iter()
        .filter(|l| l.kind == "observe_tick")
        .map(|l| l.ts)
        .collect();
    let mut active_n = 0;
    for l in trace
        .iter()
        .filter(|l| l.kind == "state" && l.protection_state.as_deref() == Some("active"))
    {
        active_n += 1;
        if in_closed(l.ts) {
            problems.push(format!(
                "state=active at {} while no session was open",
                l.ts
            ));
        }
        let backed = ticks
            .iter()
            .any(|t| *t <= l.ts && l.ts - *t <= ACTIVE_HEARTBEAT_TTL_MS);
        if !backed {
            problems.push(format!(
                "state=active at {} without an observation tick in the previous {}s",
                l.ts,
                ACTIVE_HEARTBEAT_TTL_MS / 1000
            ));
        }
    }
    checks.push(CheckResult {
        name: "'protecting' was only shown while something was observing (P0-3)".into(),
        pass: problems.is_empty(),
        detail: if problems.is_empty() {
            format!("{active_n} active sample(s) backed by observation")
        } else {
            problems.join("; ")
        },
    });

    // ---- 5. 过期确认不放行 ----
    let stale_approves: Vec<String> = trace
        .iter()
        .filter(|l| {
            l.kind == "confirm_resolved"
                && l.outcome.as_deref() == Some("stale")
                && l.approve == Some(true)
        })
        .filter_map(|l| {
            let aid = l.audit_id.as_deref()?;
            let row = by_id.get(aid)?;
            (row.user_decision.as_deref() == Some("approve")).then(|| {
                format!(
                    "stale approve on request {:?} produced approve receipt {aid}",
                    l.request_id
                )
            })
        })
        .collect();
    checks.push(CheckResult {
        name: "a stale 'allow' never produced an approve receipt".into(),
        pass: stale_approves.is_empty(),
        detail: if stale_approves.is_empty() {
            "ok".into()
        } else {
            stale_approves.join("; ")
        },
    });

    Report { checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, ts: i64, et: &str, rule: &str, ud: Option<&str>) -> AuditRow {
        AuditRow {
            id: id.into(),
            timestamp_ms: ts,
            event_type: et.into(),
            rule_id: rule.into(),
            user_decision: ud.map(str::to_string),
        }
    }

    fn l(ts: u64, kind: &str) -> TraceLine {
        TraceLine::new(ts, kind)
    }

    /// 一份干净的验收:开会话 → 观察 → 一条确认展示并拒绝 → 一条超时 → 结束。全绿。
    fn clean() -> (Vec<TraceLine>, Vec<AuditRow>) {
        let t = vec![
            TraceLine {
                session_id: Some("s1".into()),
                ..l(1_000, "session_start")
            },
            TraceLine {
                source: Some("ax".into()),
                events: Some(1),
                suppressed: Some(0),
                ..l(2_000, "observe_tick")
            },
            TraceLine {
                protection_state: Some("active".into()),
                ..l(2_500, "state")
            },
            TraceLine {
                request_id: Some(7),
                audit_id: Some("a-7".into()),
                rule_id: Some("CRIT-001".into()),
                ..l(3_000, "confirm_enqueued")
            },
            TraceLine {
                request_id: Some(7),
                ..l(3_100, "confirm_shown")
            },
            TraceLine {
                request_id: Some(7),
                audit_id: Some("a-7".into()),
                approve: Some(false),
                outcome: Some("resolved".into()),
                ..l(4_000, "confirm_resolved")
            },
            TraceLine {
                request_id: Some(8),
                audit_id: Some("a-8".into()),
                rule_id: Some("OVL-007".into()),
                ..l(5_000, "confirm_enqueued")
            },
            TraceLine {
                request_id: Some(8),
                audit_id: Some("a-8".into()),
                ..l(130_000, "confirm_expired")
            },
            TraceLine {
                session_id: Some("s1".into()),
                ..l(131_000, "session_end")
            },
            TraceLine {
                protection_state: Some("stopped".into()),
                ..l(131_100, "state")
            },
        ];
        let rows = vec![
            row("s", 1_000, "AgentSessionStart", "SESSION-START", None),
            row("a-7", 3_000, "UiTreeDelta", "CRIT-001", Some("deny")),
            row("a-8", 5_000, "UiTreeDelta", "OVL-007", Some("timeout")),
            row("e", 131_000, "AgentSessionEnd", "SESSION-END", None),
        ];
        (t, rows)
    }

    #[test]
    fn 干净的验收全绿() {
        let (t, rows) = clean();
        let r = check(&t, &rows);
        assert!(r.all_pass(), "{:#?}", r.checks);
        assert_eq!(r.checks.len(), 6);
    }

    /// 报告 P0-5 的原形:用户拒绝的是 UI-REVALIDATE(request 7),回执却落在 PRIV-XAPP 的记录上。
    #[test]
    fn 回执落到别的规则上被抓出() {
        let (t, mut rows) = clean();
        rows[1] = row("a-7", 3_000, "UiTreeDelta", "PRIV-XAPP", Some("deny"));
        let r = check(&t, &rows);
        let c = &r.checks[1];
        assert!(!c.pass);
        assert!(c.detail.contains("shown rule CRIT-001"), "{}", c.detail);
        assert!(c.detail.contains("PRIV-XAPP"));
    }

    #[test]
    fn 用户拒绝但库里写成同意被抓出() {
        let (t, mut rows) = clean();
        rows[1] = row("a-7", 3_000, "UiTreeDelta", "CRIT-001", Some("approve"));
        let r = check(&t, &rows);
        assert!(!r.checks[1].pass);
        assert!(r.checks[1].detail.contains("user chose deny"));
    }

    #[test]
    fn 解析了从没展示过的请求被抓出() {
        let (mut t, rows) = clean();
        t.retain(|x| x.kind != "confirm_shown");
        let r = check(&t, &rows);
        assert!(!r.checks[1].pass);
        assert!(r.checks[1].detail.contains("never shown"));
    }

    #[test]
    fn 幽灵回执被抓出() {
        let (t, mut rows) = clean();
        rows.push(row(
            "ghost",
            3_500,
            "UiTreeDelta",
            "PRIV-FM",
            Some("approve"),
        ));
        let r = check(&t, &rows);
        assert!(!r.checks[1].pass);
        assert!(r.checks[1].detail.contains("ghost"));
    }

    #[test]
    fn 超时没写回执被抓出() {
        let (t, mut rows) = clean();
        rows[2] = row("a-8", 5_000, "UiTreeDelta", "OVL-007", None);
        let r = check(&t, &rows);
        assert!(!r.checks[2].pass);
        assert!(r.checks[2].detail.contains("expected timeout"));
    }

    /// 报告第 3 条:End 之后还在采。宽限 2 s 内的那一拍不算,2 s 后的算。
    #[test]
    fn 会话结束后的观察记录被抓出_宽限内不算() {
        let (t, mut rows) = clean();
        rows.push(row("late-ok", 132_500, "ScreenFrame", "OVL-007", None)); // 131_000 + 1.5s
        assert!(check(&t, &rows).checks[3].pass);
        rows.push(row("late", 140_000, "ScreenFrame", "OVL-007", None));
        let r = check(&t, &rows);
        assert!(!r.checks[3].pass);
        assert!(r.checks[3].detail.contains("late"));
        assert!(!r.checks[3].detail.contains("late-ok"));
    }

    #[test]
    fn 会话结束后观察器仍产出事件被抓出() {
        let (mut t, rows) = clean();
        t.push(TraceLine {
            source: Some("sck".into()),
            events: Some(2),
            ..l(140_000, "observe_tick")
        });
        let r = check(&t, &rows);
        assert!(!r.checks[3].pass);
        assert!(r.checks[3].detail.contains("observer sck"));
    }

    #[test]
    fn 下一个会话开始后观察又合法() {
        let (mut t, mut rows) = clean();
        t.push(TraceLine {
            session_id: Some("s2".into()),
            ..l(200_000, "session_start")
        });
        t.push(TraceLine {
            source: Some("ax".into()),
            events: Some(1),
            ..l(201_000, "observe_tick")
        });
        rows.push(row(
            "s2",
            200_000,
            "AgentSessionStart",
            "SESSION-START",
            None,
        ));
        rows.push(row("obs2", 201_000, "UiTreeDelta", "PRIV-FM", None));
        let r = check(&t, &rows);
        assert!(r.checks[3].pass, "{}", r.checks[3].detail);
    }

    /// 报告原症状:界面「守护中」,而没有任何观察在跑。
    #[test]
    fn 没有观察拍支撑的active被抓出_会话结束后的active被抓出() {
        let (mut t, rows) = clean();
        t.push(TraceLine {
            protection_state: Some("active".into()),
            ..l(60_000, "state") // 上一拍在 2_000,差 58 s
        });
        let r = check(&t, &rows);
        assert!(!r.checks[4].pass);
        assert!(r.checks[4].detail.contains("without an observation tick"));
        let (mut t, rows) = clean();
        t.push(TraceLine {
            protection_state: Some("active".into()),
            ..l(140_000, "state")
        });
        let r = check(&t, &rows);
        assert!(!r.checks[4].pass);
        assert!(r.checks[4].detail.contains("no session was open"));
    }

    #[test]
    fn stale的同意产生了approve回执被抓出() {
        let (mut t, mut rows) = clean();
        t.push(TraceLine {
            request_id: Some(7),
            audit_id: Some("a-7".into()),
            approve: Some(true),
            outcome: Some("stale".into()),
            ..l(4_500, "confirm_resolved")
        });
        // stale 本不该动库;这里模拟一个坏实现把它写成 approve 了。
        rows[1] = row("a-7", 3_000, "UiTreeDelta", "CRIT-001", Some("approve"));
        let r = check(&t, &rows);
        assert!(!r.checks[5].pass);
    }

    #[test]
    fn trace会话数与库不一致被抓出() {
        let (t, mut rows) = clean();
        rows.push(row(
            "s-extra",
            500_000,
            "AgentSessionStart",
            "SESSION-START",
            None,
        ));
        let r = check(&t, &rows);
        assert!(!r.checks[0].pass);
    }

    #[test]
    fn 解析容忍坏行并报告() {
        let text = "{\"ts\":1,\"kind\":\"session_start\"}\nnot json\n\n{\"ts\":2,\"kind\":\"future_kind\",\"extra\":1}\n";
        let (lines, errors) = parse_trace(text);
        assert_eq!(lines.len(), 2);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("line 2"));
    }

    #[test]
    fn 写入端追加jsonl_未设路径时静默() {
        let dir = std::env::temp_dir().join(format!("ag-trace-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("trace.jsonl");
        let _ = std::fs::remove_file(&path);
        let w = TraceWriter::at(&path);
        assert!(w.enabled());
        w.write(&l(1, "session_start"));
        w.write(&TraceLine {
            request_id: Some(2),
            ..l(2, "confirm_shown")
        });
        let text = std::fs::read_to_string(&path).unwrap();
        let (lines, errs) = parse_trace(&text);
        assert!(errs.is_empty());
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].request_id, Some(2));
        let off = TraceWriter::disabled();
        assert!(!off.enabled());
        off.write(&l(3, "noop")); // 不 panic、不写
        assert_eq!(
            parse_trace(&std::fs::read_to_string(&path).unwrap())
                .0
                .len(),
            2
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trace行json往返() {
        let line = TraceLine {
            request_id: Some(3),
            audit_id: Some("x".into()),
            approve: Some(true),
            outcome: Some("resolved".into()),
            ..l(9, "confirm_resolved")
        };
        let s = serde_json::to_string(&line).unwrap();
        assert!(!s.contains("source"), "None 字段不该出现:{s}");
        let back: TraceLine = serde_json::from_str(&s).unwrap();
        assert_eq!(back, line);
    }
}

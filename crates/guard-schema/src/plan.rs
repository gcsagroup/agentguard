//! Declared task plans for trajectory alignment (Aura §4.3.2).
//!
//! Aura defines a trajectory `T = {(I_user, A₁…Aₜ)}` and requires every candidate
//! action be justified against **both** the original instruction and the steps
//! already executed, with a self-consistency drift pass and re-anchoring.
//!
//! What we had was a string comparison: `TASK-DRIFT` fired when an event's
//! `task_profile` label differed from the session's. That has no trajectory state,
//! no per-action justification, and — the part that matters — **a drifting sequence
//! that keeps the same label is completely invisible**. An agent told to book a
//! hotel could confirm three payments, disclose a passport to an unrelated host and
//! persist the user's card, all labelled `book_hotel`, and nothing would fire.
//!
//! # What this is, and what it is not
//!
//! Aura's justification step is a model call: it asks whether an action *makes
//! sense* given the instruction. We cannot do that deterministically offline, and
//! pretending otherwise would be the overclaim this project keeps having to correct.
//!
//! What is here instead is **structural conformance to a plan declared in policy**:
//! which step kinds a task may take, how many times, in what order, and which step
//! ends it. That catches the label-preserving drift the string comparison misses,
//! and it does so without a model — but it is a weaker claim than the paper's, and
//! `eval/coverage/surfaces.yaml` says so.
//!
//! # Why the plan lives in policy and not in the event
//!
//! The agent may only *name* a task (`task_profile: book_hotel`). What that task is
//! permitted to do comes from [`TaskPlanLibrary`], which the operator ships. An
//! earlier iteration let an event assert its own sink clearance, and that read as a
//! security control while being an instruction the attacker wrote. A plan the agent
//! supplied would be exactly the same mistake: it would authorise whatever the
//! agent was about to do.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::policy::PolicyError;

/// A structural kind of action, derived by the engine from the event itself.
///
/// **No adapter has to emit this.** Requiring a new `step_kind` field on events would
/// mean the mechanism did nothing until every adapter shipped an update — which is how
/// the app attestor spent an iteration as dead code while being documented as
/// implemented. Every variant below is recoverable from what the adapters already
/// send.
///
/// Two sources, and the split matters. Most kinds come from the event type and its
/// metadata. Critical actions (payment, transfer) come from a `step_kind:`
/// **declaration on the rule** in `p0_rules.yaml`, checked across every rule that
/// matches the text. Keying them on the *winning* rule id was defeated by one appended
/// marker: rule precedence is longest-matched-pattern, so attacker-authored screen text
/// could move the win elsewhere and the payment fell through to [`Self::Observe`] —
/// uncounted, with the trajectory then reporting perfect conformance over two payments
/// in a one-payment task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// Reading the screen. Never drift on its own: observation is not an action, and
    /// counting it would make every plan a list of everything the agent might see.
    Observe,
    /// Moving to another app (deeplink / focus change).
    AppSwitch,
    /// Disclosing LOW-tier profile data into a form.
    DiscloseLow,
    /// Disclosing HIGH-tier profile data into a form.
    DiscloseHigh,
    /// Asking for access to a profile key.
    RequestPermission,
    /// A payment / purchase confirmation.
    ConfirmPayment,
    /// A funds transfer.
    TransferFunds,
    /// Data leaving the device.
    NetworkEgress,
    /// Writing to the agent's own memory store.
    PersistMemory,
    /// Reading back a saved preference.
    RecallMemory,
    /// Running a shell command.
    RunShell,
}

impl StepKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::AppSwitch => "app_switch",
            Self::DiscloseLow => "disclose_low",
            Self::DiscloseHigh => "disclose_high",
            Self::RequestPermission => "request_permission",
            Self::ConfirmPayment => "confirm_payment",
            Self::TransferFunds => "transfer_funds",
            Self::NetworkEgress => "network_egress",
            Self::PersistMemory => "persist_memory",
            Self::RecallMemory => "recall_memory",
            Self::RunShell => "run_shell",
        }
    }

    /// Steps that are pure observation and so are never checked against a plan.
    pub fn is_observation(self) -> bool {
        matches!(self, Self::Observe)
    }
}

/// What one task profile is permitted to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlan {
    /// The `task_profile` an `agent_session_start` names to select this plan.
    pub task_profile: String,
    /// Human description, for the message a violation produces.
    #[serde(default)]
    pub goal: String,
    /// Step kinds this task may take. Anything else is out of plan.
    ///
    /// [`StepKind::Observe`] is always permitted and need not be listed.
    #[serde(default)]
    pub allow: Vec<StepKind>,
    /// Maximum occurrences per step kind. A kind absent from this map is unbounded
    /// (subject to `allow`); a kind mapped to `0` is forbidden outright, which is
    /// worth spelling out separately from omitting it so a plan can *document* that
    /// a task must never egress.
    #[serde(default)]
    pub max: BTreeMap<StepKind, u32>,
    /// Steps that must not occur before every earlier entry has occurred.
    ///
    /// This is the check the label comparison could not make: `[disclose_low,
    /// confirm_payment]` means a payment confirmation before any disclosure is out
    /// of order — the same two step kinds, the same task label, wrong sequence.
    #[serde(default)]
    pub order: Vec<StepKind>,
    /// The step that completes the task. Plan steps *after* it are drift: the task
    /// is done, so anything further was not asked for.
    #[serde(default)]
    pub terminal: Option<StepKind>,
    /// The **resource** ceiling for this task (Aura §4.4 `S_max`). See [`TaskScope`].
    ///
    /// `allow`/`max`/`order` constrain what *kinds* of step may happen; this constrains what those
    /// steps may touch. Absent means unconstrained, which is what every plan written before this
    /// field existed says.
    #[serde(default)]
    pub scope: TaskScope,
}

/// What a host declares when it opens a session: the task, and optionally a narrower scope.
///
/// One type, with one place that knows the metadata key names, because the alternative is four
/// adapters each spelling `task_data_keys` from memory. Every field is optional: a host that knows
/// only the task profile sends only that, and the plan's ceiling then *is* the grant.
///
/// This exists because the mechanism was, at first, reachable only from the eval harness. Every
/// adapter's `start_session` sent `metadata: HashMap::new()`, so no shipped event stream ever named
/// a task profile — the plan library was loaded by four hosts and selected by none of them. That is
/// the same shape as the app attestor spending an iteration as dead code, and the honest fix is a
/// channel rather than a sentence in the docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDeclaration {
    /// The `task_profile` that selects a plan. Without it there is no ceiling.
    pub profile: Option<String>,
    /// A request to narrow the plan's app ceiling. Never widens it — see [`TaskScope::narrow`].
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default)]
    pub data_keys: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl TaskDeclaration {
    pub fn for_profile(profile: impl Into<String>) -> Self {
        Self {
            profile: Some(profile.into()),
            ..Default::default()
        }
    }

    /// The metadata an `agent_session_start` event must carry to declare this.
    ///
    /// Comma-separated, because that is what the engine already parses for `task_apps`. Empty lists
    /// are omitted rather than sent as `""`: the engine distinguishes "not declared" from "declared
    /// as nothing" throughout, and a blank value would blur them.
    pub fn to_metadata(&self) -> std::collections::HashMap<String, String> {
        let mut out = std::collections::HashMap::new();
        if let Some(p) = self
            .profile
            .as_ref()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
        {
            out.insert("task_profile".to_string(), p.to_string());
        }
        for (key, list) in [
            ("task_apps", &self.apps),
            ("task_data_keys", &self.data_keys),
            ("task_hosts", &self.hosts),
        ] {
            let joined = list
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            if !joined.is_empty() {
                out.insert(key.to_string(), joined);
            }
        }
        out
    }
}

/// The resource ceiling for one task profile — Aura §4.4's `S_max` (AgentScan "God Mode").
///
/// # What this adds to `allow` / `max` / `order`
///
/// Trajectory alignment (iteration 14) constrains *what kinds of step* a task may take, and it
/// does that well. It says nothing about **which resources** those steps may touch, and a probe
/// of the shipped engine showed exactly what that costs:
///
/// ```text
/// task_profile=navigation_jump, then a UI delta from "OnlineBank"   → Allow
/// task_profile=book_hotel, then form_fill medical_record_id         → Allow
/// task_profile=book_hotel, then form_fill social_security_number    → Allow
/// ```
///
/// A navigation task walked into a banking app and the guard said nothing, because "app switch" is
/// a permitted *kind*. A hotel booking filled a medical record id, because `disclose_high` is a
/// permitted *kind* and nothing enumerated which HIGH keys a hotel booking needs. That is the
/// over-provisioning Aura calls God Mode: the session inherits everything the user can do.
///
/// # Where the ceiling comes from, and why not from the agent
///
/// From the **plan**, which `policies/task-plans.yaml` already says is deliberately not something
/// the agent supplies: *"a plan the agent wrote would authorise whatever the agent was about to
/// do"*. The session may then *narrow* within it — `task_apps` on `agent_session_start` is a
/// request, and the effective grant is the **intersection**. Narrowing is safe in a way widening
/// never is: an agent that constrains itself has only constrained itself, while an agent that
/// picks its own ceiling has no ceiling. Today it picks its own: a session declaring
/// `task_apps: "AMap,OnlineBank,Crypto Wallet"` was granted all three.
///
/// # Absent is not empty
///
/// Every dimension is `Option<Vec<String>>`, and the distinction carries weight:
///
/// * **absent** — this plan does not constrain that dimension, so the check does not run. A plan
///   written before this field existed keeps behaving exactly as it did.
/// * **empty** — an explicit statement that the task touches *none* of that resource. `hosts: []`
///   means "this task never egresses", the same way `max: {network_egress: 0}` documents a
///   prohibition rather than omitting it.
///
/// Collapsing those two would force a choice between breaking every existing plan and making an
/// explicit prohibition unwritable. It is the same distinction `AndroidEvent.log_readers` draws
/// between "not surveyed" and "surveyed and clean", for the same reason.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TaskScope {
    /// Apps that may act in this task. Matched with the same relation as `task_apps`.
    #[serde(default)]
    pub apps: Option<Vec<String>>,
    /// Profile keys this task may disclose. Matched **exactly** (trimmed, case-folded): a profile
    /// key is an identifier, and the lesson from `AgentCard::may_declare` is that a loose match on
    /// an identifier is exploitable rather than convenient.
    #[serde(default)]
    pub data_keys: Option<Vec<String>>,
    /// Hosts this task may send to. An entry matches that host exactly, or any subdomain of it —
    /// see [`host_in_scope`].
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    /// 这个任务可以读、可以写的路径天花板。
    ///
    /// 和上面三个维度共用 `narrow()`，所以三条性质是免费拿到的：没声明就等于请求被忽略（不是
    /// 被批准）；grant 永远是天花板与请求的交集而不是并集；越界请求会被记录成
    /// `SCOPE-OVER-REQUEST`。
    ///
    /// 为什么和路径放在同一份声明里，而不是另开一个沙箱策略文件：引擎推理的东西和内核将来要
    /// 执行的东西必须是同一句话。两份必须保持一致的策略文件，就是它们开始不一致的方式。
    /// 详见 `docs/interception-design.md` §5。
    #[serde(default)]
    pub paths: Option<TaskPaths>,
}

/// 路径天花板的读写两半。
///
/// 读和写分开，因为它们的默认值方向不同：一个任务通常需要读比写多得多的地方，而把两者合成
/// 一个列表就意味着"能读的都能写"。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPaths {
    #[serde(default)]
    pub read: Option<Vec<String>>,
    #[serde(default)]
    pub write: Option<Vec<String>>,
}

/// Whether `observed` is `entry` or a subdomain of it.
///
/// The dot boundary is the whole point: a bare `ends_with("stripe.com")` also accepts
/// `stripe.com.evil.example`, which is the classic suffix-match forgery and would turn a host
/// allow-list into a host allow-anything. Compared case-insensitively, with a trailing dot and a
/// `:port` stripped, because a URL host arrives in whatever form the adapter found it.
pub fn host_in_scope(observed: &str, entry: &str) -> bool {
    let norm = |s: &str| -> String {
        let s = s.trim().trim_end_matches('.').to_lowercase();
        // Strip credentials and port; an IPv6 literal keeps its brackets.
        let s = s.rsplit('@').next().unwrap_or(&s).to_string();
        match s.rfind(':') {
            Some(i) if !s.ends_with(']') && !s[i + 1..].contains(']') => s[..i].to_string(),
            _ => s,
        }
    };
    let (o, e) = (norm(observed), norm(entry));
    if o.is_empty() || e.is_empty() {
        return false;
    }
    o == e || o.ends_with(&format!(".{e}"))
}

/// The host component of a URL, without a scheme parser.
///
/// Deliberately small: everything before the first `/`, `\\`, `?` or `#` after the scheme, with any
/// `user:pass@` prefix removed. A URL this cannot parse yields `None`, and a `None` host is
/// **out** of any declared host scope rather than in it — a destination the guard cannot name is
/// not a destination it can approve.
///
/// The backslash is not a nicety. WHATWG URL treats `\\` as an authority terminator for special
/// schemes exactly like `/`, so a browser fetching `https://evil.example\\.stripe.com/x` goes to
/// **evil.example** — while a parser splitting only on `/` reads the host as
/// `evil.example\\.stripe.com`, which `host_in_scope` then accepts as a subdomain of `stripe.com`.
/// The guard approved a destination it had misidentified, in the granting direction.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest
        .split(['/', '\\', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

impl TaskScope {
    /// Reject a scope that cannot mean what it says.
    ///
    /// The library already refuses an `order` clause naming a step the plan disallows, on the
    /// grounds that it "reads as protection while doing nothing". A scope has three ways to do the
    /// same thing, and one of them inverts:
    ///
    /// * a **blank entry** — `apps: [""]` reads as the tightest possible grant and is the loosest,
    ///   because `apps_match` treats an empty string as matching everything. A scope whose meaning
    ///   is the opposite of its appearance is the worst kind of policy line.
    /// * a **single-label host** — `hosts: ["com"]` grants every `.com`, and it is one deleted
    ///   character away from `booking.com`. There is no public-suffix list here, so the rule is
    ///   blunt: a host entry needs a dot.
    /// * a **scheme or path in a host entry** — `hosts: ["https://stripe.com/pay"]` never matches,
    ///   because the observed side is a bare host. Silent non-matching reads as coverage.
    pub fn validate(&self, profile: &str) -> Result<(), PolicyError> {
        let path_read = self.paths.as_ref().and_then(|p| p.read.clone());
        let path_write = self.paths.as_ref().and_then(|p| p.write.clone());
        for (dim, items) in [
            ("apps", &self.apps),
            ("data_keys", &self.data_keys),
            ("hosts", &self.hosts),
            ("paths.read", &path_read),
            ("paths.write", &path_write),
        ] {
            let Some(items) = items else { continue };
            for entry in items {
                if entry.trim().is_empty() {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{profile}': scope.{dim} contains a blank entry. A blank reads as \
                         the tightest grant and is the loosest — `apps_match` treats an empty \
                         string as matching every app. Remove it, or write the entry you meant."
                    )));
                }
            }
        }
        // 路径条目的三种"看起来是保护、实际不是"的写法。理由和 hosts 那三条同源：一条
        // 永远匹配不上的授权，读起来像覆盖。
        for (dim, items) in [("paths.read", &path_read), ("paths.write", &path_write)] {
            let Some(items) = items else { continue };
            for entry in items {
                let t = entry.trim();
                // 一、相对路径。它会随进程的工作目录改变含义——同一份策略文件从不同位置启动
                // 授权的是不同目录。一份会变的策略比没有策略更糟，因为它看起来是确定的。
                if !(t.starts_with('/')
                    || t.starts_with('~')
                    || t.starts_with('\\')
                    || (t.len() >= 2
                        && t.as_bytes()[0].is_ascii_alphabetic()
                        && t.as_bytes()[1] == b':'))
                {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{profile}': scope.{dim} 里的 '{entry}' 是相对路径。授权会按\
                         进程启动时的工作目录归约，于是同一份策略在不同位置授权不同的目录。\
                         写绝对路径或者 '~/' 开头的路径。"
                    )));
                }
                // 二、通配符。一个通配符可以展开到授权之外，所以它证明不了任何包含关系；
                // 归约阶段会把它丢弃，那时这条授权就静默失效了。
                if t.contains('*') || t.contains('?') || t.contains('[') {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{profile}': scope.{dim} 里的 '{entry}' 含通配符。授权按前缀\
                         包含判断，通配符无法归约成一个前缀，这条授权会被丢弃而不是生效。\
                         写它所在的目录。"
                    )));
                }
                // 三、未归约的 `..`。写 `~/ws/../..` 的人几乎不可能是有意授权 `~` 的父目录。
                if t.split(['/', '\\']).any(|c| c == "..") {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{profile}': scope.{dim} 里的 '{entry}' 含 '..'。归约之后它\
                         指向的目录和字面看到的不是一个，写归约后的路径。"
                    )));
                }
            }
        }
        if let Some(hosts) = &self.hosts {
            for h in hosts {
                let t = h.trim().trim_end_matches('.');
                if t.contains("://") || t.contains('/') {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{profile}': scope.hosts entry '{h}' looks like a URL. Entries \
                         are compared against a bare host, so this can never match — write \
                         'stripe.com', not 'https://stripe.com/pay'."
                    )));
                }
                // An IPv6 literal or an IPv4 address is a host; a single label is a suffix.
                if !t.starts_with('[') && !t.contains('.') {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{profile}': scope.hosts entry '{h}' is a single label, which \
                         grants every host under it — 'com' grants every .com, and is one deleted \
                         character from 'booking.com'. There is no public-suffix list here, so a \
                         host entry must contain a dot."
                    )));
                }
            }
        }
        Ok(())
    }

    /// Whether this scope constrains anything at all.
    pub fn is_unconstrained(&self) -> bool {
        self.apps.is_none() && self.data_keys.is_none() && self.hosts.is_none()
    }

    /// The effective grant for one dimension: the ceiling narrowed by the session's request.
    ///
    /// Returns the intersection, plus the requested entries that were **outside** the ceiling so
    /// the caller can report an over-request. An over-request is not an error that stops the
    /// session — it is a signal, and dropping the entry is the enforcement.
    ///
    /// # The grant is built from the *ceiling's* entries, never the request's
    ///
    /// This is the correction that makes the word "intersection" true. The first version pushed the
    /// matching **request** string into the grant, and with `apps_match` — a bidirectional
    /// substring relation — as the comparator, that let a request *widen* the ceiling:
    ///
    /// ```text
    /// ceiling ["AMap", "Maps", ...]   request "a"
    ///   → "a" substring-matches "AMap", so "a" is granted verbatim
    ///   → "a" then matches every source app containing an "a": OnlineBank, Crypto Wallet, Signal
    /// ceiling ["Booking", "Stripe"]   request "NotBooking-Evil"
    ///   → substring-matches "Booking", granted verbatim, and then satisfied the *exact* HIGH-tier
    ///     sink-clearance check — the forgery iteration 13 closed, reopened one layer up
    /// ```
    ///
    /// Granting the ceiling's own entry makes the grant a subset of the ceiling *by construction*,
    /// whatever relation the comparator uses and whatever the request contains. A request may
    /// select from the ceiling; it cannot contribute a string to it.
    ///
    /// With no ceiling the request is **ignored** rather than installed. Letting an unconstrained
    /// dimension take its constraint from the request read as "a session may always narrow itself",
    /// and it handed any process that can post an event a way to pin a session into a grant the
    /// operator never wrote — every later event a `require_confirm` block, and under
    /// `--confirm deny` a paused engine. Narrowing is only meaningful inside a ceiling.
    pub fn narrow<'a>(
        ceiling: Option<&'a [String]>,
        requested: Option<&'a [String]>,
        matches: impl Fn(&str, &str) -> bool,
    ) -> (Option<Vec<String>>, Vec<String>) {
        let Some(cap) = ceiling else {
            return (None, Vec::new());
        };
        let Some(req) = requested else {
            return (Some(dedupe(cap.to_vec())), Vec::new());
        };
        let granted: Vec<String> = cap
            .iter()
            .filter(|c| req.iter().any(|r| matches(r, c)))
            .cloned()
            .collect();
        let refused: Vec<String> = req
            .iter()
            .filter(|r| !cap.iter().any(|c| matches(r, c)))
            .cloned()
            .collect();
        (Some(dedupe(granted)), dedupe(refused))
    }
}

/// Case-folded de-duplication, order preserved.
///
/// A grant is written into the signed `SESSION-START` row and truncated for readability there, so a
/// duplicate is not cosmetic: repeating one entry seven times pushed the others past the truncation
/// and let the agent choose what the audit record named. Ceiling-derived grants make that
/// unreachable, and de-duplicating makes it unreachable twice.
fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::with_capacity(items.len());
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let key = item.trim().to_lowercase();
        if key.is_empty() || seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(item);
    }
    out
}

impl TaskPlan {
    pub fn permits(&self, kind: StepKind) -> bool {
        kind.is_observation() || self.allow.contains(&kind)
    }

    pub fn limit(&self, kind: StepKind) -> Option<u32> {
        self.max.get(&kind).copied()
    }
}

/// The operator's plan library.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskPlanLibrary {
    #[serde(default)]
    pub plans: Vec<TaskPlan>,
    /// How to treat a session whose `task_profile` has no plan.
    ///
    /// Default `false`: an unplanned task is *reported* and then runs unconstrained.
    /// Failing closed here would block every task profile an operator has not yet
    /// written a plan for, which in practice means the library never gets adopted.
    /// The report is what tells them which plans are missing.
    ///
    /// With `true`, a session naming an unknown profile has no permitted steps —
    /// use it once the library covers the deployment.
    #[serde(default)]
    pub require_plan: bool,
}

impl TaskPlanLibrary {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        let lib: Self = serde_yaml::from_str(yaml)?;
        lib.validate()?;
        Ok(lib)
    }

    pub fn plan_for(&self, task_profile: &str) -> Option<&TaskPlan> {
        let want = task_profile.trim();
        self.plans.iter().find(|p| p.task_profile == want)
    }

    /// Reject a library that cannot mean what it says.
    ///
    /// A plan whose `order` or `terminal` names a step it does not `allow` is not a
    /// stricter plan — it is a plan with an unreachable clause, and the clause reads
    /// as protection while doing nothing. Same for a `max` of a disallowed kind
    /// above zero.
    fn validate(&self) -> Result<(), PolicyError> {
        let mut seen = std::collections::HashSet::new();
        for p in &self.plans {
            p.scope.validate(&p.task_profile)?;
            // A host grant on a task that may never egress is a clause that can never be reached —
            // the same defect as an `order` naming a disallowed step, on the resource axis. It is
            // worth catching because it is *silently* unreachable in the safe direction, so nothing
            // ever fails and the list reads as policy. Two shipped plans had it, and only a corpus
            // scenario that actually egressed surfaced it.
            if let Some(hosts) = &p.scope.hosts {
                let egress_forbidden = !p.permits(StepKind::NetworkEgress)
                    || p.limit(StepKind::NetworkEgress) == Some(0);
                if !hosts.is_empty() && egress_forbidden {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{}': scope.hosts grants {} host(s) while the plan forbids \
                         `network_egress` (absent from `allow`, or `max: 0`). The grant can never be \
                         reached, so it reads as policy and is none — either allow bounded egress, or \
                         write `hosts: []` to say the task never egresses.",
                        p.task_profile,
                        hosts.len()
                    )));
                }
            }
            if !seen.insert(p.task_profile.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "task plan library: duplicate task_profile '{}'",
                    p.task_profile
                )));
            }
            for k in &p.order {
                if !p.permits(*k) {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{}': order names '{}', which the plan does not allow — the clause could never be satisfied",
                        p.task_profile,
                        k.label()
                    )));
                }
            }
            if let Some(t) = p.terminal {
                if !p.permits(t) {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{}': terminal step '{}' is not allowed by the plan",
                        p.task_profile,
                        t.label()
                    )));
                }
            }
            for (k, n) in &p.max {
                if *n > 0 && !p.permits(*k) {
                    return Err(PolicyError::Invalid(format!(
                        "task plan '{}': max allows {n} '{}' but the plan does not permit it; write 0, or add it to allow",
                        p.task_profile,
                        k.label()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lib(yaml: &str) -> Result<TaskPlanLibrary, PolicyError> {
        TaskPlanLibrary::from_yaml_str(yaml)
    }

    #[test]
    fn observation_is_always_permitted() {
        let l = lib("plans:\n  - task_profile: t\n    allow: [confirm_payment]\n").unwrap();
        let p = l.plan_for("t").unwrap();
        assert!(p.permits(StepKind::Observe), "never has to be listed");
        assert!(p.permits(StepKind::ConfirmPayment));
        assert!(!p.permits(StepKind::NetworkEgress));
    }

    /// A clause that names a step the plan forbids is unreachable, and an
    /// unreachable clause reads as protection while providing none.
    #[test]
    fn unreachable_clauses_are_rejected() {
        let err = lib(
            "plans:\n  - task_profile: t\n    allow: [confirm_payment]\n    order: [disclose_low, confirm_payment]\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("could never be satisfied"), "{err}");

        let err = lib(
            "plans:\n  - task_profile: t\n    allow: [observe]\n    terminal: confirm_payment\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("terminal step"), "{err}");

        let err = lib("plans:\n  - task_profile: t\n    allow: [observe]\n    max:\n      network_egress: 3\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not permit it"), "{err}");

        // `max: 0` on a disallowed kind is fine — it documents the prohibition.
        assert!(lib("plans:\n  - task_profile: t\n    allow: [observe]\n    max:\n      network_egress: 0\n").is_ok());
    }

    #[test]
    fn duplicate_profiles_are_rejected() {
        let err = lib("plans:\n  - task_profile: t\n  - task_profile: t\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn the_shipped_library_is_valid_and_covers_the_corpus_profiles() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/task-plans.yaml");
        let raw = std::fs::read_to_string(&path).unwrap();
        let l = TaskPlanLibrary::from_yaml_str(&raw).unwrap();
        assert!(l.plans.len() >= 3, "plans: {}", l.plans.len());
        assert!(
            !l.require_plan,
            "the shipped library must not fail closed: it does not cover every profile the corpus uses, and blocking unplanned tasks would make it unadoptable"
        );
        // Every step kind a plan *counts* must be derivable from the shipped rules,
        // or the budget silently never fills.
        //
        // Payments are the case that bit: a plan with `max: {confirm_payment: 1}` is
        // enforceable only because `p0_rules.yaml` annotates CRIT-001 with
        // `step_kind: confirm_payment`. Drop the annotation and the plan reads as a
        // constraint while counting nothing — which is exactly what happened when the
        // step kind was keyed on the rule id instead.
        let rules_raw = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/p0_rules.yaml"),
        )
        .unwrap();
        let rules = crate::rules::RuleSet::from_yaml_str(&rules_raw).unwrap();
        let declared: std::collections::HashSet<StepKind> =
            rules.rules.iter().filter_map(|r| r.step_kind).collect();
        for p in &l.plans {
            for (k, n) in &p.max {
                if *n > 0 && matches!(k, StepKind::ConfirmPayment | StepKind::TransferFunds) {
                    assert!(
                        declared.contains(k),
                        "plan '{}' budgets {n} '{}' but no rule in p0_rules.yaml declares that step_kind, so the budget can never fill",
                        p.task_profile,
                        k.label()
                    );
                }
            }
        }

        // Each plan must actually constrain something, or it is decoration.
        for p in &l.plans {
            assert!(
                !p.order.is_empty() || !p.max.is_empty() || p.terminal.is_some(),
                "plan '{}' allows a step list and nothing else — it cannot detect label-preserving drift, which is the whole point",
                p.task_profile
            );
        }
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    /// The suffix-match forgery a bare `ends_with` would accept.
    #[test]
    fn host_scope_respects_the_dot_boundary() {
        assert!(host_in_scope("stripe.com", "stripe.com"));
        assert!(host_in_scope("checkout.stripe.com", "stripe.com"));
        assert!(host_in_scope("a.b.stripe.com", "stripe.com"));
        assert!(
            host_in_scope("CHECKOUT.Stripe.COM", "stripe.com"),
            "case-folded"
        );
        assert!(host_in_scope("stripe.com.", "stripe.com"), "trailing dot");
        assert!(
            host_in_scope("checkout.stripe.com:8443", "stripe.com"),
            "port stripped"
        );
        // The forgeries.
        assert!(!host_in_scope("stripe.com.evil.example", "stripe.com"));
        assert!(!host_in_scope("notstripe.com", "stripe.com"));
        assert!(!host_in_scope("evilstripe.com", "stripe.com"));
        assert!(!host_in_scope("stripe.com.br", "stripe.com"));
        assert!(!host_in_scope("stripe.co", "stripe.com"));
        // And the reverse direction is not a match: a parent is not in a child's scope.
        assert!(!host_in_scope("stripe.com", "checkout.stripe.com"));
        assert!(!host_in_scope("", "stripe.com"));
        assert!(!host_in_scope("stripe.com", ""));
    }

    #[test]
    fn url_host_extraction() {
        for (url, want) in [
            (
                "https://checkout.stripe.com/pay?x=1",
                Some("checkout.stripe.com"),
            ),
            ("http://example.com", Some("example.com")),
            ("https://user:pass@example.com/x", Some("example.com")),
            ("https://example.com:8443/x", Some("example.com:8443")),
            ("example.com/path", Some("example.com")),
            ("https://example.com#frag", Some("example.com")),
            ("https://", None),
            ("", None),
            ("/relative/path", None),
        ] {
            assert_eq!(url_host(url).as_deref(), want, "{url}");
        }
        // A host the extractor cannot name must be *out* of scope, never in it.
        assert!(!host_in_scope(
            &url_host("https://").unwrap_or_default(),
            "example.com"
        ));
    }

    /// Narrowing is an intersection, never a union — and the grant is built from the **ceiling's**
    /// entries, so a request cannot contribute a string to it.
    #[test]
    fn narrowing_only_ever_removes() {
        let m = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
        let cap = vec!["Booking".to_string(), "Stripe".to_string()];
        let req = vec!["Booking".to_string(), "Crypto Wallet".to_string()];
        let (granted, refused) = TaskScope::narrow(Some(&cap), Some(&req), m);
        assert_eq!(granted.unwrap(), vec!["Booking".to_string()]);
        assert_eq!(refused, vec!["Crypto Wallet".to_string()]);

        // **No ceiling: the request is ignored, not installed.** Installing it let any process that
        // can post an event pin a session into a grant the operator never wrote, which under
        // `--confirm deny` pauses the engine — a denial of service dressed as self-restraint.
        let (granted, refused) = TaskScope::narrow(None, Some(&req), m);
        assert_eq!(granted, None, "an absent ceiling stays absent");
        assert!(refused.is_empty());

        // No request: the ceiling *is* the grant. Least privilege by default — the task's declared
        // needs rather than everything the user can do.
        let (granted, refused) = TaskScope::narrow(Some(&cap), None, m);
        assert_eq!(granted.unwrap(), cap);
        assert!(refused.is_empty());

        // Neither: unconstrained, and that must stay distinguishable from "constrained to nothing".
        let (granted, refused) = TaskScope::narrow(None, None, m);
        assert_eq!(granted, None);
        assert!(refused.is_empty());

        // An explicitly empty ceiling grants nothing, whatever is requested.
        let (granted, refused) = TaskScope::narrow(Some(&[]), Some(&req), m);
        assert_eq!(granted.unwrap(), Vec::<String>::new());
        assert_eq!(refused.len(), 2);
    }

    /// **A request cannot widen the ceiling, whatever the comparator does.** With a substring
    /// comparator — which is what the app dimension used — a one-character request selected a
    /// ceiling entry and, in the first version, was granted *verbatim*: `"a"` then matched every app
    /// containing an "a". The grant now carries the ceiling's entry instead.
    #[test]
    fn a_request_cannot_contribute_a_string_to_the_grant() {
        let substring = |a: &str, b: &str| {
            let (a, b) = (a.to_lowercase(), b.to_lowercase());
            a == b || a.contains(&b) || b.contains(&a)
        };
        let cap = vec!["AMap".to_string(), "Maps".to_string()];
        let (granted, refused) = TaskScope::narrow(Some(&cap), Some(&["a".to_string()]), substring);
        let granted = granted.unwrap();
        assert!(
            granted.iter().all(|g| cap.contains(g)),
            "grant must be a subset of the ceiling, got {granted:?}"
        );
        assert!(!granted.contains(&"a".to_string()), "{granted:?}");
        assert!(
            refused.is_empty(),
            "\"a\" did select ceiling entries: {refused:?}"
        );
        // And the `NotBooking-Evil` case: it selects `Booking`, and `Booking` is what is granted.
        let cap = vec!["Booking".to_string()];
        let (granted, _) = TaskScope::narrow(
            Some(&cap),
            Some(&["NotBooking-Evil".to_string()]),
            substring,
        );
        assert_eq!(granted.unwrap(), vec!["Booking".to_string()]);
    }

    /// A duplicate entry is not cosmetic: the grant is truncated for the audit row, so repeating one
    /// entry could push the others out of the record the operator reads.
    #[test]
    fn the_grant_is_deduplicated() {
        let m = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
        let cap = vec!["Booking".to_string(), "Stripe".to_string()];
        let req = vec!["Booking".to_string(); 7];
        let (granted, _) = TaskScope::narrow(Some(&cap), Some(&req), m);
        assert_eq!(granted.unwrap(), vec!["Booking".to_string()]);
        // Case variants collapse too.
        let cap = vec![
            "Booking".to_string(),
            "BOOKING".to_string(),
            "booking".to_string(),
        ];
        let (granted, _) = TaskScope::narrow(Some(&cap), None, m);
        assert_eq!(granted.unwrap().len(), 1);
    }

    /// A scope that cannot mean what it says must not load.
    #[test]
    fn an_unmeanable_scope_is_a_load_error() {
        let cases = [
            // A blank entry reads as the tightest grant and is the loosest.
            ("apps: [\"\"]", "blank entry"),
            ("data_keys: [\"  \"]", "blank entry"),
            ("hosts: [\"\"]", "blank entry"),
            // A single label grants everything under it.
            ("hosts: [\"com\"]", "single label"),
            ("hosts: [\"uk\"]", "single label"),
            // A URL never matches a bare host.
            ("hosts: [\"https://stripe.com/pay\"]", "looks like a URL"),
            ("hosts: [\"stripe.com/pay\"]", "looks like a URL"),
        ];
        for (line, expect) in cases {
            let yaml = format!(
                "require_plan: false\nplans:\n  - task_profile: t\n    allow: [app_switch]\n    scope:\n      {line}\n"
            );
            let err =
                TaskPlanLibrary::from_yaml_str(&yaml).expect_err(&format!("{line} must not load"));
            assert!(err.to_string().contains(expect), "{line}: {err}");
        }
        // And the shapes that must still load. A host grant needs `network_egress` in `allow`, or
        // it is a clause that can never be reached — which is the next assertion.
        for line in [
            "hosts: [\"stripe.com\"]",
            "hosts: [\"[::1]\"]",
            "hosts: [\"127.0.0.1\"]",
        ] {
            let yaml = format!(
                "require_plan: false\nplans:\n  - task_profile: t\n    allow: [app_switch, network_egress]\n    scope:\n      {line}\n"
            );
            TaskPlanLibrary::from_yaml_str(&yaml).unwrap_or_else(|e| panic!("{line}: {e}"));
        }
        for line in [
            "hosts: []",
            "apps: [\"AMap\", \"高德地图\"]",
            "data_keys: [\"name\"]",
        ] {
            let yaml = format!(
                "require_plan: false\nplans:\n  - task_profile: t\n    allow: [app_switch]\n    scope:\n      {line}\n"
            );
            TaskPlanLibrary::from_yaml_str(&yaml).unwrap_or_else(|e| panic!("{line}: {e}"));
        }
    }

    /// A host grant on a task that may never egress is a clause that can never be reached — silently
    /// unreachable in the *safe* direction, so nothing ever fails and the list reads as policy. Two
    /// shipped plans had exactly that, and only a corpus scenario that actually egressed found it.
    #[test]
    fn a_host_grant_on_a_task_that_cannot_egress_is_a_load_error() {
        for (allow, max) in [
            ("[app_switch]", ""),
            (
                "[app_switch, network_egress]",
                "    max:\n      network_egress: 0\n",
            ),
        ] {
            let yaml = format!(
                "require_plan: false\nplans:\n  - task_profile: t\n    allow: {allow}\n{max}    scope:\n      hosts: [\"stripe.com\"]\n"
            );
            let err = TaskPlanLibrary::from_yaml_str(&yaml).expect_err("must not load");
            assert!(err.to_string().contains("can never be reached"), "{err}");
        }
        // `hosts: []` is the way to say "never egresses", and it is always loadable.
        TaskPlanLibrary::from_yaml_str(
            "require_plan: false\nplans:\n  - task_profile: t\n    allow: [app_switch]\n    scope:\n      hosts: []\n",
        )
        .unwrap();
    }

    /// The backslash authority terminator, and the host it hides.
    #[test]
    fn url_host_terminates_the_authority_on_a_backslash() {
        assert_eq!(
            url_host("https://evil.example\\.stripe.com/upload").as_deref(),
            Some("evil.example"),
            "WHATWG URL ends the authority at a backslash for special schemes"
        );
        assert!(!host_in_scope(
            &url_host("https://evil.example\\.stripe.com/upload").unwrap(),
            "stripe.com"
        ));
        // Mixed separators, and a backslash before a query.
        assert_eq!(
            url_host("https://a.example\\b/c").as_deref(),
            Some("a.example")
        );
        assert_eq!(
            url_host("https://a.example\\?x=1").as_deref(),
            Some("a.example")
        );
    }

    /// Absent and empty must survive a YAML round trip as different values, or an explicit
    /// prohibition becomes unwritable.
    #[test]
    fn absent_and_empty_are_different_in_yaml() {
        let absent: TaskScope = serde_yaml::from_str("{}").unwrap();
        assert!(absent.is_unconstrained());
        assert_eq!(absent.hosts, None);
        let empty: TaskScope = serde_yaml::from_str("hosts: []").unwrap();
        assert!(!empty.is_unconstrained());
        assert_eq!(empty.hosts, Some(vec![]));
        // And per dimension: a plan may scope apps while leaving data keys alone.
        let partial: TaskScope = serde_yaml::from_str("apps: [\"AMap\"]").unwrap();
        assert_eq!(partial.apps.as_deref(), Some(&["AMap".to_string()][..]));
        assert_eq!(partial.data_keys, None);
    }

    /// A plan written before `scope:` existed must parse and constrain nothing.
    #[test]
    fn a_plan_without_a_scope_is_unconstrained() {
        let lib = TaskPlanLibrary::from_yaml_str(
            "require_plan: false\nplans:\n  - task_profile: order_food\n    allow: [disclose_low]\n",
        )
        .unwrap();
        assert!(lib.plans[0].scope.is_unconstrained());
    }
}

#[cfg(test)]
mod 路径天花板 {
    use super::*;

    fn scope_with_paths(read: Option<Vec<&str>>, write: Option<Vec<&str>>) -> TaskScope {
        TaskScope {
            paths: Some(TaskPaths {
                read: read.map(|v| v.into_iter().map(String::from).collect()),
                write: write.map(|v| v.into_iter().map(String::from).collect()),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn 绝对路径和波浪号开头都合法() {
        assert!(
            scope_with_paths(Some(vec!["/srv/data"]), Some(vec!["~/proj/out"]))
                .validate("t")
                .is_ok()
        );
        // Windows 盘符也算绝对。
        assert!(scope_with_paths(None, Some(vec!["C:\\work\\out"]))
            .validate("t")
            .is_ok());
    }

    #[test]
    fn 相对路径被拒绝() {
        // 它会随进程的工作目录改变含义。同一份策略从桌面壳子和从 CLI 启动授权不同的目录。
        let err = scope_with_paths(None, Some(vec!["build/out"]))
            .validate("t")
            .unwrap_err()
            .to_string();
        assert!(err.contains("相对路径"), "{err}");
    }

    #[test]
    fn 通配符被拒绝而不是静默失效() {
        // 归约阶段会丢弃含通配符的授权，那时这条策略就静默不生效了——校验必须提前说出来。
        let err = scope_with_paths(None, Some(vec!["~/proj/*"]))
            .validate("t")
            .unwrap_err()
            .to_string();
        assert!(err.contains("通配符"), "{err}");
    }

    #[test]
    fn 未归约的双点被拒绝() {
        let err = scope_with_paths(None, Some(vec!["~/proj/../.."]))
            .validate("t")
            .unwrap_err()
            .to_string();
        assert!(err.contains(".."), "{err}");
    }

    #[test]
    fn 空条目被拒绝() {
        // 和 apps/hosts 同一条理由：空串读起来像最紧的授权，实际是最松的。
        let err = scope_with_paths(None, Some(vec![""]))
            .validate("t")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blank"), "{err}");
    }

    #[test]
    fn 没有_paths_的作用域仍然合法() {
        // 反面用例：路径是可选的，加了这一维不能让所有既有策略失效。
        assert!(TaskScope::default().validate("t").is_ok());
    }

    #[test]
    fn 路径天花板走的是同一个_narrow() {
        // 这是"复用而不是另建一套"的验收点：交集、没天花板就忽略请求、越界被记录，
        // 三条性质来自既有实现，不是这里重写的。
        let ceiling = vec!["/srv/data".to_string(), "/srv/logs".to_string()];
        let requested = vec!["/srv/data".to_string(), "/etc".to_string()];
        let (granted, refused) = TaskScope::narrow(Some(&ceiling), Some(&requested), |r, c| r == c);
        assert_eq!(granted.as_deref(), Some(&["/srv/data".to_string()][..]));
        assert_eq!(refused, vec!["/etc".to_string()]);

        // 没有天花板：请求被忽略，不是被批准。
        let (granted, refused) = TaskScope::narrow(None, Some(&requested), |r, c| r == c);
        assert!(granted.is_none(), "没有天花板时不能产生任何授权");
        assert!(refused.is_empty());
    }
}

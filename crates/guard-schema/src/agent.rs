//! Agent identity cards and session attestation (Aura pillar i, §4.1/§4.4.6).
//!
//! Aura pillar (i) wants an agent **registry**, identity cards, and mutual
//! attestation; §4.4.6 wants each action cryptographically attributed to its
//! entity — agent, user, or third-party app.
//!
//! Three of those four were absent. Iteration 7 added per-record Ed25519 audit
//! signing, but with a **device** key: it attributes an action to the machine, not
//! to the agent that took it. Iteration 13 verified *third-party app* identity by
//! signing-certificate pinning, which is the app side of an interaction. Nothing
//! attested *which agent* was acting, so two agents on one device were
//! indistinguishable to the guard, and `agent_context_id` — the only agent-shaped
//! field on an event — was a string the agent chose.
//!
//! # The whole mechanism in one sentence
//!
//! An agent proves it holds the private key for a registered `agent_id` by signing
//! its session-start payload; everything in that session is then attributable to
//! that agent, and the registry says what that agent is allowed to declare.
//!
//! # Where this stops
//!
//! **Only the session start is signed.** Signing every event would put an Ed25519
//! operation on the accessibility hot path, and no adapter can do it today. So an
//! attacker who can inject events into an already-attested session inherits its
//! attribution — the same shape of boundary as the app attestor's ("the digest is
//! only as good as the adapter that produced it"), and stated in
//! `docs/agent-identity.md` rather than left for a reader to discover.
//!
//! The signed payload binds the session id, the agent id and the declared task, so a
//! captured attestation cannot be replayed for a different session or a different
//! task — which is the part that is worth having without per-event signatures. The
//! session id it binds is the one the *transport* carries, not one the agent supplies
//! in metadata; the first cut had that the other way round, so the signature bound an
//! id nothing ever compared against the session the events were tagged with.
//!
//! Two further limits belong here because they are easy to read past. The consumed-nonce
//! set lives in memory, per process, in a bounded window — so an `api-serve` restart
//! forgets it and the native-messaging host never had it. And an event carrying no
//! session id of its own is attributed to whatever this engine attested, which matters
//! because `api-serve` shares one `Engine` across callers. Both are in
//! `docs/agent-identity.md` under "What this is not".

use serde::{Deserialize, Serialize};

use crate::policy::PolicyError;

/// One registered agent: an identity card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Stable id the agent claims in `agent_id`.
    pub agent_id: String,
    #[serde(default)]
    pub display_name: String,
    /// Ed25519 public key, 64 lowercase hex chars.
    ///
    /// A card with no key can never be verified. That is reported as a registry gap
    /// rather than treated as "this agent needs no proof" — the mistake the app
    /// registry made with an empty `signers` list.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Task profiles this agent may declare. Empty means "any".
    ///
    /// Ties the two halves together: an agent attested as a shopping assistant
    /// declaring `crypto_transfer` is refused on its *card*, before its trajectory
    /// plan is even consulted.
    #[serde(default)]
    pub task_profiles: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

impl AgentCard {
    /// Whether this card permits the declared task profile.
    ///
    /// **Exact match**, deliberately, because `TaskPlanLibrary::plan_for` is an exact
    /// match too and the two must agree on what "the same task" means. This used to
    /// be `eq_ignore_ascii_case`, and the mismatch was exploitable rather than
    /// cosmetic: declaring `ORDER_FOOD` stayed on a card listing `order_food` — so the
    /// capability check passed — while finding *no plan*, which left the session
    /// `unplanned` and shed trajectory alignment entirely. The identical flow was
    /// `PLAN-OUT-OF-SCOPE` under `order_food` and `ALLOW` under `ORDER_FOOD`.
    ///
    /// A looser check on one side of a pair of gates is not a lenience, it is a hole:
    /// the value passes the gate that names it and misses the gate that indexes it.
    pub fn may_declare(&self, task_profile: &str) -> bool {
        self.task_profiles.is_empty()
            || self
                .task_profiles
                .iter()
                .any(|p| p.as_str() == task_profile.trim())
    }
}

/// The operator's agent registry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentRegistry {
    #[serde(default)]
    pub agents: Vec<AgentCard>,
    /// Whether a session must present a verified attestation before it is allowed to
    /// act.
    ///
    /// **Off by default**, and for the same reason as the app registry's
    /// `require_attestation`: no adapter signs a session today, so switching this on
    /// globally would refuse every session every shipped adapter opens. With it off,
    /// identity is still resolved and a *forged* attestation is still refused — what
    /// changes is whether an unsigned session is allowed to proceed.
    #[serde(default)]
    pub require_attestation: bool,
}

impl AgentRegistry {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        let reg: Self = serde_yaml::from_str(yaml)?;
        reg.validate()?;
        Ok(reg)
    }

    /// Look a card up by claimed id.
    ///
    /// The *query* is trimmed because it arrives from event metadata; the stored ids
    /// are required to be trimmed already ([`AgentRegistry::validate`]), so this is a
    /// whitespace normalisation on untrusted input and not a fuzzy match. Case,
    /// substrings and interior whitespace are all significant.
    pub fn card(&self, agent_id: &str) -> Option<&AgentCard> {
        let want = agent_id.trim();
        self.agents.iter().find(|a| a.agent_id == want)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let mut seen = std::collections::HashSet::new();
        for a in &self.agents {
            if a.agent_id.trim().is_empty() {
                return Err(PolicyError::Invalid(
                    "agent registry: an entry has an empty agent_id".into(),
                ));
            }
            // Ids are stored canonically so that `card()`'s trim is a normalisation of
            // untrusted input rather than a second, looser matching rule.
            if a.agent_id != a.agent_id.trim() {
                return Err(PolicyError::Invalid(format!(
                    "agent registry: agent_id '{}' has surrounding whitespace",
                    a.agent_id
                )));
            }
            // An id carrying a control character would be able to forge a field
            // boundary in the two places ids are concatenated with a delimiter: the
            // audit record's canonical content, and the replay-nonce key. Rejected
            // at the registry, which is the one place the value is operator-authored,
            // rather than escaped at each use site.
            if a.agent_id.chars().any(|c| c.is_control()) {
                return Err(PolicyError::Invalid(format!(
                    "agent registry: agent_id '{}' contains a control character",
                    a.agent_id.escape_debug()
                )));
            }
            if !seen.insert(a.agent_id.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "agent registry: duplicate agent_id '{}'",
                    a.agent_id
                )));
            }
            if let Some(k) = &a.public_key {
                if !is_ed25519_hex(k) {
                    return Err(PolicyError::Invalid(format!(
                        "agent registry: '{}' public_key is not 64 lowercase hex chars",
                        a.agent_id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// An Ed25519 public key as 64 **lowercase** hex characters.
///
/// Lowercase is enforced, not merely documented: `agent-keygen` emits lowercase, so a
/// registry is either in canonical form or it is rejected, and two cards cannot pin
/// what is textually the same key in two spellings.
pub fn is_ed25519_hex(k: &str) -> bool {
    let k = k.trim();
    k.len() == 64
        && k.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The bytes an agent signs to open a session.
///
/// Domain-separated and **length-prefixed** (4-byte big-endian per field), binding
/// everything that must not be substitutable:
///
/// * `agent_id` — a signature cannot be re-presented as another agent's.
/// * `session_id` — a captured attestation cannot open a second session.
/// * `task_profile` — nor be replayed for a different task, which is what makes the
///   card's `task_profiles` list meaningful rather than advisory.
/// * `nonce` — a fresh value per session, so an attestation seen once cannot be
///   used again even for the same session id.
///
/// Leaving any of these out is not a small simplification: without `session_id` one
/// captured signature attests every future session, and without `task_profile` an
/// agent restricted to shopping can sign once and then declare a transfer.
///
/// # Why lengths and not a delimiter
///
/// v1 of this function separated the fields with `0x1f` and claimed in its own test
/// that concatenation could therefore not be ambiguous. It could: `0x1f` is a legal
/// byte inside a Rust `String`, so an agent id of `a␟b` with session `c` produced
/// exactly the bytes of the id `a` with session `b␟c`. The test only tried `"ab"+"c"`
/// against `"a"+"bc"`, which a delimiter does separate — it tested the easy case and
/// read as proof of the hard one.
///
/// A length prefix is unambiguous for *every* input rather than for every input
/// without the delimiter in it, so the property no longer depends on validating what
/// callers pass. (Ids are separately required to be control-character free by
/// [`AgentRegistry::validate`]; that is defence in depth, not the reason this holds.)
pub fn session_attestation_message(
    agent_id: &str,
    session_id: &str,
    task_profile: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(b"AGENTGUARD-AGENT-SESSION-v2");
    for f in [agent_id, session_id, task_profile, nonce] {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f.as_bytes());
    }
    out
}

/// Whether a session id actually names a session.
///
/// The signature binds `session_id`, so an id that names nothing binds nothing: the
/// same bytes verify for every session carrying that same non-id. The first cut only
/// refused the empty string, which no attacker sends — `trim()` strips Unicode
/// whitespace and nothing else, so `"\u{200b}"`, `"\u{ad}"`, `"\0"`, `"\u{1f}"` and
/// `"-"` all sailed through and produced a `Verified`, attributing session whose
/// `agent_session_id` rendered blank in the audit log.
///
/// The rule is therefore positive rather than a denylist of invisible characters: an id
/// must contain **at least one alphanumeric character** (Unicode-aware, so non-Latin
/// ids are fine) and **no control characters**. Every id a real host generates — a
/// UUID, a counter, a slug — passes; nothing that renders as blank does.
pub fn is_anchored_session_id(session_id: &str) -> bool {
    let s = session_id.trim();
    !s.is_empty() && !s.chars().any(char::is_control) && s.chars().any(char::is_alphanumeric)
}

/// Ed25519 公钥，其私钥半边是公开的。
///
/// 这些是仓库自带的夹具密钥（`policies/agent-registry.yaml`、评测语料、单元测试
/// 里都用它们），种子是单字节重复，任何人都能在一行里重算出私钥。
///
/// **为什么要在代码里硬编码这张表。** 原先这件事只写在 YAML 的注释里：
/// "真实部署请替换"。注释不是执行。一个运维照抄了示例注册表、又把
/// `require_attestation` 打开，结果是任何人都能为 `claude-desktop` 伪造出一个
/// **能通过验签**的 attestation —— 比不做身份校验更糟，因为它会给出
/// `Verified` 这个肯定结论。这正是本项目反复踩到的第一种缺陷形状：
/// 攻击者可自行断言的输入被用在"授予"方向上。
///
/// 现在这张表让判决层能在验签**之后**把这种密钥降级为"无法验证"
/// （[`AgentIdentity::PubliclyKnownKey`]），而不是 `Verified`。
///
/// 第二个字段是出处，直接印在解释文本里，运维不需要翻代码就知道为什么被拒。
pub const PUBLICLY_KNOWN_AGENT_KEYS: &[(&str, &str)] = &[
    (
        "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5",
        "仓库夹具密钥，种子为 0xa1 重复 32 次",
    ),
    (
        "55154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207",
        "仓库夹具密钥，种子为 0xb2 重复 32 次",
    ),
];

/// 若 `public_key_hex` 是一个私钥公开的已知密钥，返回它的出处。
///
/// 大小写与首尾空白都做归一化，因为注册表里的十六进制是人手写的；
/// 一个大写的夹具密钥仍然是同一个夹具密钥。
pub fn publicly_known_agent_key(public_key_hex: &str) -> Option<&'static str> {
    let want = public_key_hex.trim().to_ascii_lowercase();
    PUBLICLY_KNOWN_AGENT_KEYS
        .iter()
        .find(|(k, _)| *k == want)
        .map(|(_, why)| *why)
}

/// How an agent's claimed identity resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdentity {
    /// Registered, and the session attestation verified against its card's key.
    Verified { agent_id: String, name: String },
    /// Registered, and the attestation did **not** verify. Someone is claiming this
    /// agent's identity without its key.
    BadSignature { agent_id: String, name: String },
    /// Registered, but no attestation was presented at all. Not an attack, and not a
    /// verification either.
    Unattested { agent_id: String, name: String },
    /// Registered with no public key on record, so verification is impossible by
    /// construction. A registry gap, reported as one.
    NoKeyOnRecord { agent_id: String, name: String },
    /// 注册表为这个 agent 钉的是一个**私钥已公开**的密钥（见
    /// [`PUBLICLY_KNOWN_AGENT_KEYS`]）。签名本身是有效的，但它证明不了任何事：
    /// 任何人都能产生同一个签名。
    ///
    /// 因此这里**不是** `Verified`，也**不是** `is_impersonation` —— 证据既不支持
    /// 也不反对这个身份声明，它只是不构成证据。语义上等同于
    /// `NoKeyOnRecord`：`require_attestation: false` 时会话照走，
    /// `require_attestation: true` 时被拒。差别只在于它有自己的判决码，
    /// 让运维看得见"你钉了一把假钥匙"。
    PubliclyKnownKey {
        agent_id: String,
        name: String,
        /// 该密钥的出处，直接来自 [`PUBLICLY_KNOWN_AGENT_KEYS`]。
        provenance: String,
    },
    /// This agent id has already opened a session with this nonce. A replayed
    /// attestation.
    ReplayedNonce { agent_id: String, nonce: String },
    /// An attestation was presented for a session with **no id**.
    ///
    /// The signature would then bind no session at all: the same bytes verify for every
    /// unnamed session, which is exactly what including `session_id` in the payload
    /// exists to prevent. A host that cannot name its session cannot attest one.
    UnanchoredSession { agent_id: String, name: String },
    /// Verified, but the card does not permit the task this session declares.
    TaskNotPermitted {
        agent_id: String,
        name: String,
        task_profile: String,
    },
    /// Not in the registry.
    Unregistered { agent_id: String },
    /// No `agent_id` claimed at all.
    Anonymous,
}

impl AgentCard {
    /// 这张卡钉的公钥是不是一把私钥公开的已知密钥；返回出处。
    pub fn publicly_known_key(&self) -> Option<&'static str> {
        self.public_key
            .as_deref()
            .and_then(publicly_known_agent_key)
    }
}

impl AgentRegistry {
    /// 所有钉了"假钥匙"的卡：`(agent_id, 出处)`。
    ///
    /// 加载时**不**报错：仓库自带的示例注册表就是这样，评测语料要能加载它。
    /// 真正的拦是在判决层（[`AgentIdentity::PubliclyKnownKey`]），那里失败是关闭的；
    /// 这个方法是给 `agentguard preflight` 用的，让运维在上线**之前**就看到。
    pub fn publicly_known_key_cards(&self) -> Vec<(&str, &'static str)> {
        self.agents
            .iter()
            .filter_map(|c| c.publicly_known_key().map(|why| (c.agent_id.as_str(), why)))
            .collect()
    }
}

impl AgentIdentity {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The evidence positively contradicts the claim.
    pub fn is_impersonation(&self) -> bool {
        matches!(
            self,
            Self::BadSignature { .. }
                | Self::ReplayedNonce { .. }
                | Self::TaskNotPermitted { .. }
                | Self::UnanchoredSession { .. }
        )
    }

    pub fn agent_id(&self) -> Option<&str> {
        match self {
            Self::Verified { agent_id, .. }
            | Self::BadSignature { agent_id, .. }
            | Self::Unattested { agent_id, .. }
            | Self::NoKeyOnRecord { agent_id, .. }
            | Self::PubliclyKnownKey { agent_id, .. }
            | Self::ReplayedNonce { agent_id, .. }
            | Self::UnanchoredSession { agent_id, .. }
            | Self::TaskNotPermitted { agent_id, .. }
            | Self::Unregistered { agent_id } => Some(agent_id),
            Self::Anonymous => None,
        }
    }

    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "AGENT-VERIFIED",
            Self::BadSignature { .. } => "AGENT-BAD-SIGNATURE",
            Self::Unattested { .. } | Self::NoKeyOnRecord { .. } => "AGENT-UNATTESTED",
            Self::PubliclyKnownKey { .. } => "AGENT-KEY-PUBLICLY-KNOWN",
            Self::ReplayedNonce { .. } => "AGENT-REPLAY",
            Self::UnanchoredSession { .. } => "AGENT-SESSION-UNANCHORED",
            Self::TaskNotPermitted { .. } => "AGENT-TASK-NOT-PERMITTED",
            Self::Unregistered { .. } => "AGENT-UNREGISTERED",
            Self::Anonymous => "AGENT-ANONYMOUS",
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::Verified { agent_id, name } => {
                format!("session attributed to {name} ('{agent_id}') by signature")
            }
            Self::BadSignature { agent_id, name } => format!(
                "session claims to be {name} ('{agent_id}') but the attestation does not verify against that agent's registered key"
            ),
            Self::Unattested { agent_id, name } => format!(
                "'{agent_id}' ({name}) presented no session attestation; this session is not attributable to any agent"
            ),
            Self::NoKeyOnRecord { agent_id, name } => format!(
                "'{agent_id}' ({name}) has no public key on record, so its identity cannot be verified"
            ),
            Self::PubliclyKnownKey {
                agent_id,
                name,
                provenance,
            } => format!(
                "'{agent_id}' ({name}) 的 attestation 验签通过了，但注册表为它钉的公钥私钥半边是公开的（{provenance}），任何人都能产生同一个签名；这个会话不归属于任何 agent。请用 `agentguard agent-keygen` 换一对新密钥。"
            ),
            Self::ReplayedNonce { agent_id, nonce } => format!(
                "'{agent_id}' presented an attestation nonce already used in this process ({nonce}); a captured attestation is being replayed"
            ),
            Self::UnanchoredSession { agent_id, name } => format!(
                "{name} ('{agent_id}') presented an attestation for a session with no id; the signature would bind no session, so it would verify for every unnamed one"
            ),
            Self::TaskNotPermitted {
                agent_id,
                name,
                task_profile,
            } => format!(
                "{name} ('{agent_id}') is verified but its identity card does not permit the task '{task_profile}'"
            ),
            Self::Unregistered { agent_id } => {
                format!("'{agent_id}' is not a registered agent")
            }
            Self::Anonymous => {
                "session claims no agent_id; nothing can be attributed to it".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn reg(yaml: &str) -> Result<AgentRegistry, PolicyError> {
        AgentRegistry::from_yaml_str(yaml)
    }

    #[test]
    fn cards_resolve_by_exact_id() {
        let r = reg(&format!(
            "agents:\n  - agent_id: claude-desktop\n    public_key: \"{KEY}\"\n"
        ))
        .unwrap();
        assert!(r.card("claude-desktop").is_some());
        assert!(
            r.card("claude-desktop-evil").is_none(),
            "no substring match"
        );
        assert!(r.card("Claude-Desktop").is_none(), "ids are exact");
    }

    #[test]
    fn a_card_with_no_key_is_a_registry_gap_not_a_free_pass() {
        let r = reg("agents:\n  - agent_id: legacy-bot\n").unwrap();
        assert!(r.card("legacy-bot").unwrap().public_key.is_none());
    }

    #[test]
    fn malformed_registries_are_rejected() {
        for (yaml, want) in [
            ("agents:\n  - agent_id: \"\"\n", "empty agent_id"),
            ("agents:\n  - agent_id: a\n  - agent_id: a\n", "duplicate"),
            (
                "agents:\n  - agent_id: a\n    public_key: \"abc\"\n",
                "64 lowercase hex",
            ),
            // Uppercase is a second spelling of the same key, so two cards could pin
            // one key twice and only one of them match what `agent-keygen` prints.
            (
                &format!(
                    "agents:\n  - agent_id: a\n    public_key: \"{}\"\n",
                    KEY.replace('1', "A")
                ),
                "64 lowercase hex",
            ),
            ("agents:\n  - agent_id: \" a \"\n", "surrounding whitespace"),
            // A control character in an id would forge a field boundary wherever ids
            // are concatenated: the audit canonical content, the replay-nonce key.
            (
                "agents:\n  - agent_id: \"a\\u001fb\"\n",
                "control character",
            ),
        ] {
            let err = reg(yaml).unwrap_err().to_string();
            assert!(err.contains(want), "{yaml} → {err}");
        }
    }

    #[test]
    fn a_card_may_restrict_which_tasks_it_declares() {
        let r = reg(&format!(
            "agents:\n  - agent_id: shopper\n    public_key: \"{KEY}\"\n    task_profiles: [order_food, book_hotel]\n  - agent_id: anything\n    public_key: \"{KEY}\"\n"
        ))
        .unwrap();
        let shopper = r.card("shopper").unwrap();
        assert!(shopper.may_declare("order_food"));
        assert!(shopper.may_declare(" order_food "), "metadata is trimmed");
        // Exact, because `TaskPlanLibrary::plan_for` is exact. When this was
        // case-insensitive, `ORDER_FOOD` passed the card *and* matched no plan, so
        // the session ran unplanned: the capability check said yes and trajectory
        // alignment switched itself off.
        assert!(!shopper.may_declare("ORDER_FOOD"), "case is significant");
        assert!(!shopper.may_declare("crypto_transfer"));
        // An empty list means "any", so a card does not have to enumerate.
        assert!(r.card("anything").unwrap().may_declare("crypto_transfer"));
    }

    /// Every field in the payload is there to stop a specific substitution.
    #[test]
    fn the_attestation_payload_binds_agent_session_task_and_nonce() {
        let base = session_attestation_message("a", "s", "t", "n");
        for other in [
            session_attestation_message("b", "s", "t", "n"),
            session_attestation_message("a", "s2", "t", "n"),
            session_attestation_message("a", "s", "t2", "n"),
            session_attestation_message("a", "s", "t", "n2"),
        ] {
            assert_ne!(base, other);
        }
        assert!(base.starts_with(b"AGENTGUARD-AGENT-SESSION-v2"));
        assert_ne!(
            session_attestation_message("ab", "c", "t", "n"),
            session_attestation_message("a", "bc", "t", "n")
        );
    }

    /// The framing must be unambiguous for *every* input, not only for inputs that
    /// happen to avoid the delimiter.
    ///
    /// v1 separated fields with `0x1f` and asserted non-ambiguity using `"ab"+"c"` vs
    /// `"a"+"bc"` — a pair a delimiter does separate. The case that mattered is the
    /// one where a field *contains* the delimiter, and there v1 genuinely collided.
    #[test]
    fn a_field_containing_the_separator_cannot_forge_a_boundary() {
        let sep = "\u{1f}";
        assert_ne!(
            session_attestation_message(&format!("a{sep}b"), "c", "t", "n"),
            session_attestation_message("a", &format!("b{sep}c"), "t", "n"),
        );
        // The same shape, one field over.
        assert_ne!(
            session_attestation_message("a", &format!("s{sep}order_food"), "", "n"),
            session_attestation_message("a", "s", &format!("{sep}order_food"), "n"),
        );
    }

    /// An id that renders as blank names nothing, and a signature over it binds
    /// nothing. Refusing only `""` was refusing the one value no attacker sends.
    #[test]
    fn a_session_id_must_actually_name_a_session() {
        for ok in [
            "s",
            "sess-eval-1",
            "benign_agent_verified_session_001",
            "8f14e45f-cea1",
            " padded ",
            "会话1",
        ] {
            assert!(is_anchored_session_id(ok), "{ok:?} must be accepted");
        }
        for bad in [
            "",
            " ",
            "\t\n",
            "\u{200b}", // zero-width space
            "\u{ad}",   // soft hyphen
            "\0",
            "\u{1f}", // the old field separator
            "-",
            "---",
            "\u{200b}\u{200b}",
        ] {
            assert!(!is_anchored_session_id(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn only_verified_counts_as_verified() {
        let cases = [
            AgentIdentity::BadSignature {
                agent_id: "a".into(),
                name: "A".into(),
            },
            AgentIdentity::Unattested {
                agent_id: "a".into(),
                name: "A".into(),
            },
            AgentIdentity::NoKeyOnRecord {
                agent_id: "a".into(),
                name: "A".into(),
            },
            AgentIdentity::ReplayedNonce {
                agent_id: "a".into(),
                nonce: "n".into(),
            },
            AgentIdentity::Unregistered {
                agent_id: "a".into(),
            },
            AgentIdentity::Anonymous,
        ];
        for c in cases {
            assert!(!c.is_verified(), "{c:?}");
            assert!(!c.explain().is_empty());
        }
        assert!(AgentIdentity::Verified {
            agent_id: "a".into(),
            name: "A".into()
        }
        .is_verified());
    }

    /// A forged, replayed or out-of-scope attestation is evidence against the claim;
    /// a missing one is not.
    #[test]
    fn impersonation_is_evidence_not_absence() {
        assert!(AgentIdentity::BadSignature {
            agent_id: "a".into(),
            name: "A".into()
        }
        .is_impersonation());
        assert!(AgentIdentity::ReplayedNonce {
            agent_id: "a".into(),
            nonce: "n".into()
        }
        .is_impersonation());
        assert!(!AgentIdentity::Unattested {
            agent_id: "a".into(),
            name: "A".into()
        }
        .is_impersonation());
        assert!(!AgentIdentity::Unregistered {
            agent_id: "a".into()
        }
        .is_impersonation());
    }

    #[test]
    fn the_shipped_registry_is_valid_and_says_its_keys_are_fixtures() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/agent-registry.yaml");
        let raw = std::fs::read_to_string(&path).unwrap();
        let r = AgentRegistry::from_yaml_str(&raw).unwrap();
        assert!(r.agents.len() >= 2);
        // `require_attestation` is deliberately *not* asserted here. It is an operator
        // setting, and a test pinning the shipped default turns hardening a deployment
        // into a `cargo test` failure — the test would be enforcing a policy choice it
        // has no business enforcing. What must hold either way is that forged and
        // replayed attestations are refused, which
        // `guard_core` proves at both settings
        // (`a_forged_attestation_is_refused_whether_or_not_attestation_is_required`).
        assert!(
            raw.contains("FIXTURE KEYS"),
            "the registry must say plainly that its keys are fixtures"
        );
        // At least one card must restrict its task profiles, or the capability check
        // is untested by the shipped policy.
        assert!(
            r.agents.iter().any(|a| !a.task_profiles.is_empty()),
            "no card exercises task_profiles"
        );
    }

    /// 发布注册表里钉的每一把公钥,都必须在 `PUBLICLY_KNOWN_AGENT_KEYS` 里。
    ///
    /// 方向是刻意反着的。这不是在要求"发布的密钥必须是假的",而是在守一个不变量:
    /// **本仓库自带的示例注册表用的全是夹具密钥**,所以每一把都必须被判决层认出来
    /// 并降级为"无法验证"。
    ///
    /// 没有这条测试,以后有人往示例注册表里加一张新卡、配一把新的夹具密钥,
    /// 却忘了同步那张表 —— 那把钥匙就会变成一把**能通过验签**的钥匙,
    /// 而它的私钥就在同一次提交里。测试仍然全绿,因为现有测试查的是那两把老钥匙。
    ///
    /// 真实部署会把这个文件替换成自己的密钥;这条测试只对仓库里提交的这一份生效。
    #[test]
    fn 发布注册表钉的密钥必须全部可被识别为夹具密钥() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/agent-registry.yaml");
        let r = AgentRegistry::from_yaml_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let pinned: Vec<&AgentCard> = r.agents.iter().filter(|a| a.public_key.is_some()).collect();
        assert!(!pinned.is_empty(), "示例注册表至少要有一张钉了密钥的卡");
        for card in &pinned {
            assert!(
                card.publicly_known_key().is_some(),
                "'{}' 钉的公钥不在 PUBLICLY_KNOWN_AGENT_KEYS 里:\n\
                 如果这是一把新的夹具密钥,把它加进那张表;\n\
                 如果这是一把真密钥,它不该被提交到本仓库。",
                card.agent_id
            );
        }
        assert_eq!(
            r.publicly_known_key_cards().len(),
            pinned.len(),
            "publicly_known_key_cards() 少报了"
        );
    }

    /// 评测注册表钉的密钥必须**全部不在**那张表里 —— 边界的另一半。
    ///
    /// 上一条守的是"发布模板里的密钥都拦得住"。这一条守的是"评测语料还走得到
    /// `Verified` 之后的检查"。两条缺任何一条,机制都会静默退化:
    ///
    ///   - 少了上一条:新加的夹具密钥变成一把真能验签的钥匙,而私钥在同一次提交里。
    ///   - 少了这一条:哪天有人把评测密钥也加进那张表(看起来更"安全"),
    ///     `AGENT-REPLAY` 和 `AGENT-TASK-NOT-PERMITTED` 就再也跑不到了 ——
    ///     它们都在 `Verified` 的下游。语料仍然全绿,因为那些场景会改判成
    ///     `AGENT-KEY-PUBLICLY-KNOWN`,而它同样是"拦住了"。
    ///
    /// 换句话说:把安全检查加得更严,可能把另一个安全检查的**覆盖**删掉。
    #[test]
    fn 评测注册表的密钥必须不在公开密钥表里() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../eval/fixtures/agent-registry.yaml");
        let r = AgentRegistry::from_yaml_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let pinned: Vec<&AgentCard> = r.agents.iter().filter(|a| a.public_key.is_some()).collect();
        assert!(pinned.len() >= 2, "评测注册表至少要有两张钉了密钥的卡");
        for card in &pinned {
            assert!(
                card.publicly_known_key().is_none(),
                "'{}' 钉的密钥在 PUBLICLY_KNOWN_AGENT_KEYS 里,\n\
                 它的会话会被判成 AGENT-KEY-PUBLICLY-KNOWN,\n\
                 于是 AGENT-REPLAY / AGENT-TASK-NOT-PERMITTED 失去覆盖。",
                card.agent_id
            );
        }
        assert!(r.publicly_known_key_cards().is_empty());
    }

    /// Every task a shipped card may declare must have a plan.
    ///
    /// An empty `task_profiles` means "any", and "any" includes profiles the plan
    /// library has never heard of — which with `require_plan: false` leaves the session
    /// `unplanned`, i.e. a card that restricts nothing also switches trajectory
    /// alignment off for whatever it declares. So a card holding a key must enumerate,
    /// and everything it enumerates must be plannable. A card with *no* key is exempt:
    /// it can never be verified, so it can never declare anything.
    #[test]
    fn every_task_a_shipped_card_may_declare_has_a_plan() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let registry = AgentRegistry::from_yaml_str(
            &std::fs::read_to_string(root.join("policies/agent-registry.yaml")).unwrap(),
        )
        .unwrap();
        let plans = crate::TaskPlanLibrary::from_yaml_str(
            &std::fs::read_to_string(root.join("policies/task-plans.yaml")).unwrap(),
        )
        .unwrap();
        for card in registry.agents.iter().filter(|a| a.public_key.is_some()) {
            assert!(
                !card.task_profiles.is_empty(),
                "'{}' holds a key and restricts nothing, so it may declare a task with no plan",
                card.agent_id
            );
            for profile in &card.task_profiles {
                assert!(
                    plans.plan_for(profile).is_some(),
                    "'{}' may declare '{profile}', which has no plan — the session would run unplanned",
                    card.agent_id
                );
            }
        }
    }
}

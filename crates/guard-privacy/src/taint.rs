//! Information-flow labels for agent data (Aura §4.3.1).
//!
//! The previous implementation was a flat list of `(profile_key, app)` marks: a
//! HIGH-tier key re-entered in a second app raised a `PRIV-XAPP` **alert**. That
//! is a leak detector, not a flow control. Four things Aura requires were absent:
//!
//! 1. **A lattice.** Aura §4.3.1's own schema is `M = ⟨Content, Tag_origin⟩`
//!    with `Tag_origin ∈ {TAG_VERIFIED, TAG_TAINTED}` — an **integrity** tag, and
//!    nothing else. The confidentiality axis here ([`Confidentiality`]) is *our
//!    addition*, not an Aura requirement: one integrity bit cannot express "this
//!    value is the user's passport number", and that fact forbids different flows
//!    than "this text came from a web page" does. Both axes are needed, but only
//!    one of them is the paper's.
//! 2. **Dependency inheritance.** A value derived from a labelled value inherits
//!    its label. Without it, `summary = f(passport, itinerary)` launders the
//!    passport: the derived string is untracked and flows anywhere.
//! 3. **Memory as ⟨Content, Tag_origin⟩.** Saving a value and reading it back
//!    must not lose its label, or memory becomes a laundering channel: write the
//!    tainted value, read it as clean.
//! 4. **No-Write-Down, enforced.** Aura's No-Write-Down is the *integrity* rule:
//!    "if the agent attempts to retrieve a `TAG_TAINTED` variable to populate a
//!    parameter of a Critical Node, the system intercepts". That is
//!    [`FlowVerdict::NoWriteDown`] / `FLOW-NWD` here. The confidentiality rule —
//!    a HIGH value into a lower-clearance sink — is [`FlowVerdict::Confidentiality`]
//!    / `FLOW-CONF`, and is our own, so it is named separately rather than
//!    borrowing the paper's term. An earlier revision had these two the wrong way
//!    round, which would have led a reader checking the code against §4.3.1 to
//!    conclude the wrong rule was implemented.
//!
//! # The one invariant everything rests on
//!
//! **A label only ever moves up the lattice, except through [`TaintLattice::declassify`].**
//! [`TaintLattice::introduce`] and [`TaintLattice::derive`] *join* with any
//! existing label for that id rather than replacing it. Without that invariant the
//! carefully-guarded `declassify` is irrelevant, because two cheaper paths move a
//! label down: re-deriving an existing id from a public parent, and re-filling the
//! form that seeded it. Both were live holes — one event each was enough to walk a
//! passport number to a public network sink with no user-visible signal.
//!
//! This module is the lattice and the flow check. It deliberately does not decide
//! policy severity — [`crate::PrivacySession`] maps a [`FlowVerdict`] onto the
//! contract's enforcement mode, so a deployment can run No-Write-Down in
//! block-until-approved or alert-only mode without the lattice changing meaning.
//!
//! # Threat model boundary
//!
//! Labels only track values AgentGuard is *told* about. An agent that reads the
//! user's passport number off the screen and retypes it from its own context
//! window, never emitting a `data_derive` event, is invisible here — the same
//! boundary documented in `docs/scope-and-non-goals.md`. This is flow control
//! over declared flows, not a sandbox.

use std::collections::HashMap;

use guard_schema::DataTier;
use serde::{Deserialize, Serialize};

/// Aura's integrity tag: can this value be trusted to drive an action?
///
/// Ordered `Tainted < Verified`: a join takes the **minimum**, so anything
/// touching untrusted content becomes untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    /// Derived from untrusted screen / DOM / network content. May not authorise a
    /// critical action: this is the injected-instruction path.
    Tainted,
    /// Traceable to the user's own instruction or a trusted local source.
    Verified,
}

/// Confidentiality level of the *content*.
///
/// Ordered `Public < Low < High`: a join takes the **maximum**, so a derived
/// value is at least as sensitive as anything it was built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    Public,
    Low,
    High,
}

impl Confidentiality {
    pub fn from_tier(tier: DataTier) -> Self {
        match tier {
            DataTier::Low => Self::Low,
            DataTier::High => Self::High,
        }
    }
}

/// A lattice point: `⟨integrity, confidentiality⟩`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub integrity: Integrity,
    pub confidentiality: Confidentiality,
}

impl Label {
    pub const fn new(integrity: Integrity, confidentiality: Confidentiality) -> Self {
        Self {
            integrity,
            confidentiality,
        }
    }

    /// The user's own instruction: trusted, not secret.
    pub const fn user_instruction() -> Self {
        Self::new(Integrity::Verified, Confidentiality::Public)
    }

    /// Content read off the screen or the network: untrusted, not (yet) secret.
    pub const fn untrusted_content() -> Self {
        Self::new(Integrity::Tainted, Confidentiality::Public)
    }

    /// Least upper bound: worst integrity, highest confidentiality.
    ///
    /// This is what makes inheritance transitive without walking the graph — a
    /// derived value's label already contains its parents' joins.
    pub fn join(self, other: Self) -> Self {
        Self {
            integrity: self.integrity.min(other.integrity),
            confidentiality: self.confidentiality.max(other.confidentiality),
        }
    }

    /// `self ⊑ other`: no more secret and no less trusted than `other`.
    pub fn flows_to(self, other: Self) -> bool {
        self.confidentiality <= other.confidentiality && self.integrity >= other.integrity
    }
}

/// Where a value entered the system. Kept alongside the label because the label
/// alone cannot explain *why* a flow was blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The user typed or dictated it.
    UserInstruction,
    /// Read from the user's profile store under `key`.
    Profile { key: String },
    /// Observed in an app's UI / DOM / captured frame.
    Screen { app: String },
    /// Received over the network from `host`.
    Network { host: String },
    /// Computed by the agent from other values.
    Derived,
    /// Read back out of the agent's memory store.
    Memory { key: String },
}

/// A tracked value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedValue {
    pub id: String,
    pub label: Label,
    pub origin: Origin,
    /// Ids this value was derived from, for explaining a verdict.
    pub parents: Vec<String>,
    /// Set when a human lowered the label. Retained forever: a declassification
    /// is the one place the lattice is bypassed, so it has to stay auditable.
    pub declassified: Option<Declassification>,
}

/// A human decision to lower a label (Aura HITL declassification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Declassification {
    pub from: Label,
    pub to: Label,
    /// Who approved. Never defaulted — an unattributed declassification is
    /// indistinguishable from the agent declassifying its own data.
    pub approved_by: String,
    pub reason: String,
}

/// A place a value can flow to, with the clearance that place has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sink {
    /// Human-readable target: an app name, a hostname, a shell tool.
    pub name: String,
    pub kind: SinkKind,
    /// Highest confidentiality this sink may receive.
    pub clearance: Confidentiality,
    /// Minimum integrity a value needs to drive this sink. `Verified` for
    /// anything with a side effect the user would care about.
    pub required_integrity: Integrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// A field in an application.
    AppField,
    /// Egress to a network host.
    Network,
    /// The system clipboard — readable by every app on the device.
    Clipboard,
    /// A shell command argument.
    ShellArg,
    /// A critical action: payment, transfer, delete.
    CriticalAction,
    /// The agent's own memory store.
    Memory,
}

impl Sink {
    /// Build the sink for a declared flow: the single place clearance and required
    /// integrity are decided.
    ///
    /// This lives here, rather than in the engine, so the unit tests exercise the
    /// same defaults the engine ships. An earlier revision had three convenience
    /// constructors that only the tests ever called, while the engine built `Sink`
    /// literals with *different* parameters — so the tests passed on cases that
    /// never occurred and the case that did occur (`app_field` defaulting to `Low`)
    /// had no test at all. That is where a real hole was found.
    ///
    /// `requested_clearance` is whatever the event asked for. It may only **lower**
    /// the ceiling, never raise it: clearance is an authorisation, and taking an
    /// authorisation from the channel it authorises let a network flow declare
    /// itself cleared for HIGH-tier data.
    pub fn for_declared_flow(
        name: impl Into<String>,
        kind: SinkKind,
        declared_in_task: bool,
        requested_clearance: Option<Confidentiality>,
    ) -> Self {
        let ceiling = match kind {
            // The clipboard is readable by every app on the device and the network
            // leaves the device entirely, so neither is ever cleared implicitly.
            SinkKind::Clipboard | SinkKind::Network => Confidentiality::Public,
            // An app the session declared it needs is cleared for HIGH-tier data.
            _ if declared_in_task => Confidentiality::High,
            // Any other local sink is cleared for LOW but not HIGH. Defaulting
            // these to Public instead blocked a guest name going into a form —
            // over-blocking that gets the whole feature switched off.
            _ => Confidentiality::Low,
        };
        Self {
            name: name.into(),
            kind,
            clearance: requested_clearance
                .map(|c| c.min(ceiling))
                .unwrap_or(ceiling),
            // Anything with a side effect the user would care about must be
            // traceable to the user's own instruction (Aura's Critical Node).
            required_integrity: match kind {
                SinkKind::CriticalAction | SinkKind::ShellArg => Integrity::Verified,
                _ => Integrity::Tainted,
            },
        }
    }

    fn label(&self) -> Label {
        Label::new(self.required_integrity, self.clearance)
    }
}

/// Why a flow was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowVerdict {
    Allow,
    /// Aura §4.3.1 No-Write-Down: a `TAG_TAINTED` value is populating a parameter
    /// of a Critical Node. The prompt-injection-to-action path, and the paper's
    /// actual rule of this name.
    NoWriteDown {
        sink: String,
    },
    /// Confidentiality violation: the value is more secret than the sink's
    /// clearance. **Our own rule**, not Aura's — §4.3.1 has no confidentiality
    /// axis — so it carries its own name and rule id rather than borrowing one.
    Confidentiality {
        value_level: Confidentiality,
        sink_clearance: Confidentiality,
    },
    /// The value id is not tracked, so no claim can be made about it. Reported
    /// rather than silently allowed: "unknown" is not "safe".
    Unknown {
        value_id: String,
    },
}

impl FlowVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::Allow => "FLOW-OK",
            Self::NoWriteDown { .. } => "FLOW-NWD",
            Self::Confidentiality { .. } => "FLOW-CONF",
            Self::Unknown { .. } => "FLOW-UNKNOWN",
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::Allow => "flow permitted by the lattice".into(),
            Self::NoWriteDown { sink } => format!(
                "No-Write-Down: untrusted (TAG_TAINTED) content is populating '{sink}', which requires verified provenance"
            ),
            Self::Confidentiality {
                value_level,
                sink_clearance,
            } => format!(
                "{value_level:?}-confidentiality value into a {sink_clearance:?}-clearance sink"
            ),
            Self::Unknown { value_id } => {
                format!("value '{value_id}' has no provenance label; flow cannot be justified")
            }
        }
    }
}

/// The label store: tracked values, plus the agent's memory as
/// ⟨Content, Tag_origin⟩ so a save/load round trip cannot launder a label.
#[derive(Debug, Default, Clone)]
pub struct TaintLattice {
    values: HashMap<String, TaintedValue>,
    /// `memory key → value id`. Storing the *id* rather than the content is what
    /// makes the label survive the round trip.
    memory: HashMap<String, String>,
    declassifications: Vec<(String, Declassification)>,
}

impl TaintLattice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a value that entered from outside.
    ///
    /// If the id already exists its label is **joined**, never replaced, and its
    /// origin and declassification record are kept. Replacing was a laundering
    /// path: taint `profile:name` via a derive, re-fill the form that seeds it,
    /// and the label was back to `Verified` — the same flow blocked one event
    /// earlier then sailed through. It also silently revoked an approved
    /// declassification when a second form asked for the same field.
    pub fn introduce(&mut self, id: impl Into<String>, label: Label, origin: Origin) -> Label {
        let id = id.into();
        match self.values.get_mut(&id) {
            Some(existing) => {
                existing.label = existing.label.join(label);
                existing.label
            }
            None => {
                self.values.insert(
                    id.clone(),
                    TaintedValue {
                        id,
                        label,
                        origin,
                        parents: Vec::new(),
                        declassified: None,
                    },
                );
                label
            }
        }
    }

    /// Register a value the agent computed from others (Aura dependency
    /// inheritance). The result is the join of every parent, so a value built
    /// from the passport number is itself HIGH, and one built from web text is
    /// itself tainted.
    ///
    /// An **unknown parent is treated as the bottom of the lattice**
    /// (tainted, high): a derivation whose inputs cannot be accounted for must
    /// not come out cleaner than one whose inputs can. Silently ignoring unknown
    /// parents would make laundering trivial — derive from an unregistered id.
    pub fn derive(&mut self, id: impl Into<String>, parents: &[&str]) -> Label {
        let id = id.into();
        let mut label = Label::new(Integrity::Verified, Confidentiality::Public);
        let mut unknown = false;
        for p in parents {
            match self.values.get(*p) {
                Some(v) => label = label.join(v.label),
                None => unknown = true,
            }
        }
        if unknown || parents.is_empty() {
            label = label.join(Label::new(Integrity::Tainted, Confidentiality::High));
        }
        // Re-deriving an existing id may only *raise* its label. This was the
        // single worst hole in the first cut: `data_derive` with
        // `value_id: profile:passport_number, parents: <some public value>`
        // overwrote the passport's HIGH label with Public, and the next flow to an
        // arbitrary network host was allowed — no block, no alert, no audit record,
        // and it wiped the `declassified` field on the way past. `declassify` is
        // the only downward move; this is the invariant that makes that true.
        let parent_ids: Vec<String> = parents.iter().map(|p| p.to_string()).collect();
        match self.values.get_mut(&id) {
            Some(existing) => {
                existing.label = existing.label.join(label);
                // Set membership, not `Vec::contains`.
                //
                // Re-deriving an id with N parents cost O(N²) here, and two identical
                // `data_derive` events are enough to reach it: `decide_data_derive` splits
                // `metadata["parents"]` on `,` with no cap, and the local API reads the body
                // with `read_to_end` and no size limit. 256k parents (a 1.9 MB body) held
                // the engine's single mutex for **61 seconds** on the second event — and the
                // verdict is `FLOW-DERIVE`/`LogOnly`, so the event is not even suspicious.
                // Every real event queues behind it; a guard that is not judging is off.
                let seen: std::collections::HashSet<&str> =
                    existing.parents.iter().map(|s| s.as_str()).collect();
                let fresh: Vec<String> = parent_ids
                    .iter()
                    .filter(|p| !seen.contains(p.as_str()))
                    .cloned()
                    .collect();
                drop(seen);
                existing.parents.extend(fresh);
                existing.label
            }
            None => {
                self.values.insert(
                    id.clone(),
                    TaintedValue {
                        id,
                        label,
                        origin: Origin::Derived,
                        parents: parent_ids,
                        declassified: None,
                    },
                );
                label
            }
        }
    }

    pub fn label_of(&self, id: &str) -> Option<Label> {
        self.values.get(id).map(|v| v.label)
    }

    pub fn get(&self, id: &str) -> Option<&TaintedValue> {
        self.values.get(id)
    }

    pub fn tracked(&self) -> usize {
        self.values.len()
    }

    /// Save a labelled value into the agent's memory under `key`.
    pub fn memory_save(&mut self, key: impl Into<String>, value_id: impl Into<String>) {
        self.memory.insert(key.into(), value_id.into());
    }

    /// Read a memory key back out as a *new* value id that inherits the saved
    /// label. Returns `None` when the key holds nothing tracked.
    ///
    /// The laundering path this closes: save a HIGH/tainted value, then read it
    /// back as a fresh unlabelled string and send it anywhere.
    pub fn memory_load(&mut self, key: &str, new_id: impl Into<String>) -> Option<Label> {
        let stored = self.memory.get(key)?.clone();
        let label = self.label_of(&stored)?;
        let new_id = new_id.into();
        Some(self.introduce(
            new_id,
            label,
            Origin::Memory {
                key: key.to_string(),
            },
        ))
    }

    /// Would this value be allowed into this sink?
    pub fn check_flow(&self, value_id: &str, sink: &Sink) -> FlowVerdict {
        let Some(v) = self.values.get(value_id) else {
            return FlowVerdict::Unknown {
                value_id: value_id.to_string(),
            };
        };
        // Integrity first: an injected instruction reaching a payment button is
        // the more urgent failure, and reporting it as a confidentiality problem
        // would send the user the wrong message.
        if v.label.integrity < sink.required_integrity {
            return FlowVerdict::NoWriteDown {
                sink: sink.name.clone(),
            };
        }
        if v.label.confidentiality > sink.clearance {
            return FlowVerdict::Confidentiality {
                value_level: v.label.confidentiality,
                sink_clearance: sink.clearance,
            };
        }
        debug_assert!(v.label.flows_to(sink.label()));
        FlowVerdict::Allow
    }

    /// Whether a declassification would be accepted, without performing it.
    ///
    /// Lets a caller refuse a malformed request *before* prompting a human. Asking
    /// someone to approve "declassify v_x to High", which is not a downgrade at
    /// all, teaches them to click yes on anything.
    pub fn check_declassifiable(&self, value_id: &str, to: Label) -> Result<(), DeclassifyError> {
        let v = self
            .values
            .get(value_id)
            .ok_or_else(|| DeclassifyError::UnknownValue(value_id.to_string()))?;
        Self::validate_downgrade(v.label, to)
    }

    /// A declassification must strictly move down the lattice: lower
    /// confidentiality, or raise integrity (endorsement), and never the reverse.
    /// A no-op is refused too — it would leave a misleading audit record.
    fn validate_downgrade(from: Label, to: Label) -> Result<(), DeclassifyError> {
        let lowers_confidentiality = to.confidentiality < from.confidentiality;
        let raises_integrity = to.integrity > from.integrity;
        if !(lowers_confidentiality || raises_integrity)
            || to.confidentiality > from.confidentiality
            || to.integrity < from.integrity
        {
            return Err(DeclassifyError::NotADowngrade { from, to });
        }
        Ok(())
    }

    /// Lower a value's label with explicit human approval (Aura HITL
    /// declassification). The only downward move in the lattice.
    ///
    /// Errors when: the value is unknown, `approved` is false, `approved_by` is
    /// empty, or the requested label is not actually *lower* — a "declassify"
    /// that raises confidentiality or drops integrity is a mislabelled write and
    /// must not be laundered through this path.
    pub fn declassify(
        &mut self,
        value_id: &str,
        to: Label,
        approved: bool,
        approved_by: &str,
        reason: &str,
    ) -> Result<Label, DeclassifyError> {
        let v = self
            .values
            .get_mut(value_id)
            .ok_or_else(|| DeclassifyError::UnknownValue(value_id.to_string()))?;
        if !approved {
            return Err(DeclassifyError::NotApproved);
        }
        if approved_by.trim().is_empty() {
            return Err(DeclassifyError::NoApprover);
        }
        let from = v.label;
        Self::validate_downgrade(from, to)?;
        let record = Declassification {
            from,
            to,
            approved_by: approved_by.to_string(),
            reason: reason.to_string(),
        };
        v.label = to;
        v.declassified = Some(record.clone());
        self.declassifications.push((value_id.to_string(), record));
        Ok(to)
    }

    /// Every declassification in this session, for the audit trail.
    pub fn declassifications(&self) -> &[(String, Declassification)] {
        &self.declassifications
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclassifyError {
    UnknownValue(String),
    /// No human said yes. An agent cannot declassify its own data.
    NotApproved,
    NoApprover,
    NotADowngrade {
        from: Label,
        to: Label,
    },
}

impl std::fmt::Display for DeclassifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownValue(id) => write!(f, "cannot declassify unknown value '{id}'"),
            Self::NotApproved => write!(
                f,
                "declassification requires explicit human approval; the agent may not declassify its own data"
            ),
            Self::NoApprover => write!(f, "declassification has no approver attributed"),
            Self::NotADowngrade { from, to } => write!(
                f,
                "{to:?} is not a downgrade of {from:?}; declassification only lowers confidentiality or raises integrity"
            ),
        }
    }
}

impl std::error::Error for DeclassifyError {}

#[cfg(test)]
mod tests {
    use super::*;

    const HIGH_VERIFIED: Label = Label::new(Integrity::Verified, Confidentiality::High);

    fn passport(l: &mut TaintLattice) -> &'static str {
        l.introduce(
            "v_passport",
            HIGH_VERIFIED,
            Origin::Profile {
                key: "passport_number".into(),
            },
        );
        "v_passport"
    }

    #[test]
    fn join_is_worst_integrity_and_highest_confidentiality() {
        let a = Label::new(Integrity::Verified, Confidentiality::High);
        let b = Label::new(Integrity::Tainted, Confidentiality::Low);
        let j = a.join(b);
        assert_eq!(j.integrity, Integrity::Tainted);
        assert_eq!(j.confidentiality, Confidentiality::High);
        assert_eq!(j, b.join(a), "join must be commutative");
        assert_eq!(j.join(j), j, "and idempotent");
    }

    /// Aura dependency inheritance: the whole point is that `f(secret, public)`
    /// is not public.
    #[test]
    fn derived_value_inherits_both_components() {
        let mut l = TaintLattice::new();
        passport(&mut l);
        l.introduce(
            "v_web",
            Label::untrusted_content(),
            Origin::Screen {
                app: "Chrome".into(),
            },
        );
        let d = l.derive("v_summary", &["v_passport", "v_web"]);
        assert_eq!(
            d.confidentiality,
            Confidentiality::High,
            "secret in, secret out"
        );
        assert_eq!(
            d.integrity,
            Integrity::Tainted,
            "untrusted in, untrusted out"
        );

        // Transitivity: a value derived from the derived value keeps both.
        let d2 = l.derive("v_email_body", &["v_summary"]);
        assert_eq!(d2, d);
    }

    /// A derivation whose inputs are not accounted for must not come out cleaner
    /// than one whose inputs are, or laundering is one unregistered id away.
    #[test]
    fn unknown_or_absent_parents_sink_to_the_bottom() {
        let mut l = TaintLattice::new();
        let d = l.derive("v_mystery", &["v_never_registered"]);
        assert_eq!(d.integrity, Integrity::Tainted);
        assert_eq!(d.confidentiality, Confidentiality::High);

        let e = l.derive("v_from_nothing", &[]);
        assert_eq!(e.integrity, Integrity::Tainted);
        assert_eq!(e.confidentiality, Confidentiality::High);
    }

    #[test]
    fn no_write_down_blocks_secret_into_public_sink() {
        let mut l = TaintLattice::new();
        passport(&mut l);
        let out = Sink::for_declared_flow("evil.example", SinkKind::Network, false, None);
        let v = l.check_flow("v_passport", &out);
        assert!(matches!(
            v,
            FlowVerdict::Confidentiality {
                value_level: Confidentiality::High,
                sink_clearance: Confidentiality::Public
            }
        ));
        assert_eq!(v.rule_id(), "FLOW-CONF");
        // The user's own app is cleared for it.
        assert!(l
            .check_flow(
                "v_passport",
                &Sink::for_declared_flow("Booking.app", SinkKind::AppField, true, None)
            )
            .is_allowed());
    }

    /// The injection-to-action path: untrusted content must not drive a payment.
    #[test]
    fn tainted_content_cannot_drive_a_critical_action() {
        let mut l = TaintLattice::new();
        l.introduce(
            "v_page_text",
            Label::untrusted_content(),
            Origin::Screen {
                app: "Chrome".into(),
            },
        );
        let verdict = l.check_flow(
            "v_page_text",
            &Sink::for_declared_flow("transfer_funds", SinkKind::CriticalAction, true, None),
        );
        assert_eq!(
            verdict.rule_id(),
            "FLOW-NWD",
            "Aura's own No-Write-Down rule"
        );
        // Whereas the user's own instruction may.
        l.introduce("v_user", Label::user_instruction(), Origin::UserInstruction);
        assert!(l
            .check_flow(
                "v_user",
                &Sink::for_declared_flow("transfer_funds", SinkKind::CriticalAction, true, None)
            )
            .is_allowed());
    }

    /// Integrity is reported ahead of confidentiality when both fail, because
    /// "an injected instruction is driving your payment" is the message the user
    /// needs, not "this data is too sensitive for this sink".
    #[test]
    fn integrity_failure_is_reported_before_confidentiality() {
        let mut l = TaintLattice::new();
        l.introduce(
            "v_both",
            Label::new(Integrity::Tainted, Confidentiality::High),
            Origin::Screen {
                app: "Chrome".into(),
            },
        );
        let sink = Sink {
            name: "pay".into(),
            kind: SinkKind::CriticalAction,
            clearance: Confidentiality::Low,
            required_integrity: Integrity::Verified,
        };
        assert_eq!(l.check_flow("v_both", &sink).rule_id(), "FLOW-NWD");
    }

    /// Memory laundering: write it tainted, read it back clean.
    #[test]
    fn memory_round_trip_preserves_the_label() {
        let mut l = TaintLattice::new();
        l.introduce(
            "v_scraped",
            Label::new(Integrity::Tainted, Confidentiality::High),
            Origin::Screen {
                app: "Chrome".into(),
            },
        );
        l.memory_save("note.itinerary", "v_scraped");
        let reloaded = l
            .memory_load("note.itinerary", "v_reloaded")
            .expect("tracked");
        assert_eq!(reloaded.integrity, Integrity::Tainted);
        assert_eq!(reloaded.confidentiality, Confidentiality::High);
        assert_eq!(
            l.check_flow(
                "v_reloaded",
                &Sink::for_declared_flow("pastebin.example", SinkKind::Network, false, None)
            )
            .rule_id(),
            "FLOW-CONF",
            "a memory round trip must not launder the label"
        );
        assert_eq!(
            l.get("v_reloaded").unwrap().origin,
            Origin::Memory {
                key: "note.itinerary".into()
            }
        );
    }

    #[test]
    fn untracked_value_is_unknown_not_allowed() {
        let l = TaintLattice::new();
        let v = l.check_flow(
            "v_nope",
            &Sink::for_declared_flow("x", SinkKind::Network, false, None),
        );
        assert_eq!(v.rule_id(), "FLOW-UNKNOWN");
        assert!(!v.is_allowed(), "unknown provenance is not permission");
    }

    #[test]
    fn declassification_needs_an_attributed_human_approval() {
        let mut l = TaintLattice::new();
        passport(&mut l);
        let public = Label::new(Integrity::Verified, Confidentiality::Public);

        assert_eq!(
            l.declassify("v_passport", public, false, "ming", "share with airline"),
            Err(DeclassifyError::NotApproved),
            "the agent may not declassify its own data"
        );
        assert_eq!(
            l.declassify("v_passport", public, true, "   ", "share with airline"),
            Err(DeclassifyError::NoApprover)
        );
        assert!(matches!(
            l.declassify("v_unknown", public, true, "ming", "x"),
            Err(DeclassifyError::UnknownValue(_))
        ));
        // Still HIGH after every refusal.
        assert_eq!(
            l.label_of("v_passport").unwrap().confidentiality,
            Confidentiality::High
        );

        let now = l
            .declassify("v_passport", public, true, "ming", "share with airline")
            .unwrap();
        assert_eq!(now, public);
        assert!(l
            .check_flow(
                "v_passport",
                &Sink::for_declared_flow("airline.example", SinkKind::Network, false, None)
            )
            .is_allowed());
        let (id, rec) = &l.declassifications()[0];
        assert_eq!(id, "v_passport");
        assert_eq!(rec.approved_by, "ming");
        assert_eq!(rec.from.confidentiality, Confidentiality::High);
        assert!(l.get("v_passport").unwrap().declassified.is_some());
    }

    /// "Declassify" must not be a general relabel: raising confidentiality or
    /// dropping integrity through this path would let it launder a bad write.
    #[test]
    fn declassification_only_moves_down_the_lattice() {
        let mut l = TaintLattice::new();
        l.introduce(
            "v_low",
            Label::new(Integrity::Verified, Confidentiality::Low),
            Origin::UserInstruction,
        );
        assert!(matches!(
            l.declassify(
                "v_low",
                Label::new(Integrity::Verified, Confidentiality::High),
                true,
                "ming",
                "oops"
            ),
            Err(DeclassifyError::NotADowngrade { .. })
        ));
        assert!(
            matches!(
                l.declassify(
                    "v_low",
                    Label::new(Integrity::Tainted, Confidentiality::Low),
                    true,
                    "ming",
                    "oops"
                ),
                Err(DeclassifyError::NotADowngrade { .. })
            ),
            "dropping integrity is not a declassification"
        );
        // A no-op is also refused: it would leave a misleading audit record.
        assert!(matches!(
            l.declassify(
                "v_low",
                Label::new(Integrity::Verified, Confidentiality::Low),
                true,
                "ming",
                "noop"
            ),
            Err(DeclassifyError::NotADowngrade { .. })
        ));
        // Raising integrity *is* a valid declassification (endorsement).
        l.introduce("v_t", Label::untrusted_content(), Origin::UserInstruction);
        assert!(l
            .declassify(
                "v_t",
                Label::new(Integrity::Verified, Confidentiality::Public),
                true,
                "ming",
                "user confirmed this text is their own instruction"
            )
            .is_ok());
    }

    #[test]
    fn flows_to_matches_check_flow() {
        let cases = [
            (Confidentiality::High, Confidentiality::Public, false),
            (Confidentiality::Low, Confidentiality::High, true),
            (Confidentiality::Public, Confidentiality::Public, true),
        ];
        for (v, s, want) in cases {
            let label = Label::new(Integrity::Verified, v);
            let sink = Label::new(Integrity::Verified, s);
            assert_eq!(label.flows_to(sink), want, "{v:?} -> {s:?}");
        }
    }
}

//! Field observation model replacing MyPhoneBench form_drafts SQLite reads.

use guard_schema::DataTier;
use serde::{Deserialize, Serialize};

/// Privacy probe layout types from MyPhoneBench methodology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    /// Bait chain: optional HIGH after required LOW → over-permissioning.
    OverPermissioning,
    /// Marketing / VIP widget re-asking known PII → trap resistance.
    TrapResistance,
    /// Optional personal field between required fields → form minimization.
    FormMinimization,
}

/// Necessity class for graduated over-permissioning penalties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldNecessity {
    Required,
    Plausible,
    Unnecessary,
    Forbidden,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedField {
    pub field_id: String,
    pub label: String,
    pub profile_key: String,
    pub required: bool,
    pub tier: DataTier,
    pub probe_type: Option<ProbeType>,
    pub value_filled: bool,
    pub necessity: FieldNecessity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub item_key: String,
    pub tier: DataTier,
    /// Whether access was granted (or only attempted).
    pub granted: bool,
    pub necessity: FieldNecessity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFillEvent {
    pub field: ObservedField,
    /// True when the widget is a privacy trap (non-essential re-collection).
    pub is_trap: bool,
}

/// User-controlled memory save (MyPhoneBench iMy `save_profile` analogue).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySaveEvent {
    pub key: String,
    /// True when the save was permitted by contract / confirmed by the user.
    pub approved: bool,
}

/// Later-session use of a saved preference (MyPhoneBench paired-task axis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUseEvent {
    pub key: String,
    /// Whether the used key matches what the later task actually needed
    /// (ground truth from paired evaluation), when known.
    pub correct: bool,
}

/// Taint marker: HIGH-tier data observed in `app` (Aura cross-app pivoting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintMark {
    pub profile_key: String,
    pub app: String,
}

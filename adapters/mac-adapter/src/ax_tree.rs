//! macOS names for the shared UI-tree model.
//!
//! The model and every conversion now live in [`guard_vision::uitree`], shared with the
//! Windows UIA walker so that one tree shape and one field-classification vocabulary serve
//! both. What remains here is the macOS vocabulary — the historical `Ax*` type names that
//! callers already use, and the `"macos"` platform stamp — so that sharing the
//! implementation did not require renaming anything at the call sites.

use guard_privacy::AppFormSchema;
use guard_schema::GuardEvent;
use guard_vision::uitree;

/// A node in the frontmost app's accessibility tree.
pub type AxNode = uitree::UiNode;
/// A snapshot of the frontmost app's accessibility tree.
pub type AxSnapshot = uitree::UiSnapshot;

pub use uitree::flatten_text;

/// This platform's stamp on every event derived from an AX tree.
pub const PLATFORM: &str = "macos";

/// Build a `UiTreeDelta` event from an AX snapshot, including overlay markers.
pub fn snapshot_to_event(
    snapshot: &AxSnapshot,
    event_id: impl Into<String>,
    timestamp_ms: i64,
    agent_context_id: Option<String>,
) -> GuardEvent {
    uitree::snapshot_to_event(snapshot, PLATFORM, event_id, timestamp_ms, agent_context_id)
}

/// Like [`snapshot_to_event`], optionally applying the A2 edge-zone heuristics.
pub fn snapshot_to_event_with_viewport(
    snapshot: &AxSnapshot,
    event_id: impl Into<String>,
    timestamp_ms: i64,
    agent_context_id: Option<String>,
    viewport: Option<&guard_overlay::Viewport>,
) -> GuardEvent {
    uitree::snapshot_to_event_with_viewport(
        snapshot,
        PLATFORM,
        event_id,
        timestamp_ms,
        agent_context_id,
        viewport,
    )
}

/// Emit FormFill events for editable AX nodes, classified via form schemas / heuristics.
pub fn form_fills_from_snapshot(
    snapshot: &AxSnapshot,
    event_id_prefix: &str,
    timestamp_ms: i64,
    agent_context_id: Option<String>,
    schemas: &[AppFormSchema],
) -> Vec<GuardEvent> {
    uitree::form_fills_from_snapshot(
        snapshot,
        PLATFORM,
        event_id_prefix,
        timestamp_ms,
        agent_context_id,
        schemas,
    )
}

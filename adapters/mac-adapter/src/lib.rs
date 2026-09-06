//! macOS adapter — simulation reuses WinAdapter observation model for Phase 1;
//! native AX / ScreenCaptureKit attach points live behind `cfg(target_os = "macos")`.

mod ax_gate;
mod ax_native;
mod ax_push;
mod ax_tree;
mod native;
mod observer_lifecycle;
mod sck_native;
pub mod screencapture;

// The pixel analysis is shared, not owned. These re-exports keep every historical path
// (`mac_adapter::framehash::...`, `mac_adapter::digest_rgba`) resolving to the one
// implementation in `guard-vision`, so moving it broke no caller.
pub use guard_vision::{framehash, stego, subliminal, viewtree};

pub use ax_gate::{AxNativeCallFailure, AxNativeGate};
pub use ax_native::{
    ax_probe, live_ax_snapshot, start_ax_observer, stop_ax_observer, take_ax_notifications,
};
pub use ax_push::{PushCoalescer, DEBOUNCE_MS, FALLBACK_FLOOR_MS, MAX_LATENCY_MS};
pub use ax_tree::{
    flatten_text, form_fills_from_snapshot, snapshot_to_event, snapshot_to_event_with_viewport,
    AxNode, AxSnapshot,
};
pub use framehash::{compare as compare_frame_digests, digest_rgba, DigestDelta, FrameDigest};
pub use native::{mac_capabilities, permissions, AxCapture, MacAdapter, MacCapabilities};
pub use observer_lifecycle::{ObserverGeneration, ObserverLifecycle, ObserverWorker, StopOutcome};
pub use sck_native::{
    drain_sck_frames, drain_sck_frames_generation, sck_probe, sck_start, sck_start_generation,
    sck_stop, sck_stop_generation,
};
pub use screencapture::{
    analyze_frame, demo_transparent_overlay_frame, markers_as_ui_text, screencapturekit_available,
    simulate_frame_from_regions, start_capture_session, start_capture_session_generation,
    stop_capture_session, stop_capture_session_generation, CaptureFrameMeta, CaptureSessionInfo,
    FrameAnalysis, FrameConsistency, FrameStats,
};
pub use stego::{chroma_lsb_flip_rate, lsb_flip_rate};
pub use subliminal::{band_ratios, subliminal_ratio, subliminal_ratio_wide};
pub use viewtree::{
    compare as compare_viewtree, cross_validate as cross_validate_viewtree, ViewtreeComparison,
};
pub use win_adapter::{PlatformAdapter, SimObservation};

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::EventType;

    #[test]
    fn sim_bridge_on_mac() {
        let mut adapter = MacAdapter::new();
        adapter.start_session("m1", "Claude");
        adapter.ingest(SimObservation::UiText {
            app: "Safari".into(),
            text: "确认支付".into(),
        });
        let events = adapter.drain().unwrap();
        assert!(matches!(events[0].event_type, EventType::AgentSessionStart));
        assert_eq!(events[1].platform, "macos");
    }

    #[test]
    fn capture_frame_pairs_with_recent_ax_snapshot() {
        // AgentScan Viewtree Interference, end to end through the adapter: the
        // AX tree describes a checkout, the frame renders a transfer.
        let json = r#"{
            "source_app": "Safari",
            "root": {
                "role": "AXWebArea",
                "title": "Checkout",
                "value": "Order total 99.00 Shipping address Confirm payment",
                "children": []
            }
        }"#;
        let snap = AxSnapshot::from_sim_json(json).unwrap();
        let mut adapter = MacAdapter::new();
        adapter.start_session("m3", "Safari");
        adapter.ingest_ax_snapshot(snap);
        let ax_timestamp = adapter
            .drain()
            .unwrap()
            .into_iter()
            .filter(|event| matches!(event.event_type, EventType::UiTreeDelta))
            .map(|event| event.timestamp_ms)
            .max()
            .expect("AX snapshot event");
        let mut stats = simulate_frame_from_regions(640, 360, ax_timestamp, vec![]);
        stats.ocr_text =
            Some("Transfer 5000 to account 8891 | Recipient Unknown Wallet | Approve now".into());
        adapter.ingest_capture_frame(stats, "Safari");
        let events = adapter.drain().unwrap();
        let last = events.last().unwrap();
        let ui_text = last.metadata.get("ui_text").unwrap();
        assert!(
            ui_text.contains("[AG_VIEWTREE_SCREEN_ONLY]"),
            "expected viewtree marker, got {ui_text}"
        );
    }

    #[test]
    fn new_session_does_not_pair_with_previous_session_ax_snapshot() {
        let json = r#"{
            "source_app": "Safari",
            "root": {
                "role": "AXWebArea",
                "title": "Checkout",
                "value": "Order total 99.00 Shipping address Confirm payment",
                "children": []
            }
        }"#;
        let mut adapter = MacAdapter::new();
        adapter.start_session("old", "Safari");
        adapter.ingest_ax_snapshot(AxSnapshot::from_sim_json(json).unwrap());
        adapter.drain().unwrap();

        adapter.start_session("new", "Safari");
        let mut stats = simulate_frame_from_regions(640, 360, 0, vec![]);
        stats.ocr_text = Some("Transfer 5000 to Unknown Wallet".into());
        adapter.ingest_capture_frame(stats, "Safari");
        let events = adapter.drain().unwrap();
        let capture = events.last().unwrap();
        assert_eq!(capture.agent_context_id.as_deref(), Some("new"));
        assert!(
            !capture
                .metadata
                .get("ui_text")
                .is_some_and(|text| text.contains("[AG_VIEWTREE_")),
            "新会话第一帧不得与上一会话 AX 快照交叉核对"
        );
    }

    #[test]
    fn ax_snapshot_ingest() {
        let json = r#"{
            "source_app": "Safari",
            "root": {
                "role": "AXWebArea",
                "title": "Checkout",
                "value": "",
                "children": []
            }
        }"#;
        let snap = AxSnapshot::from_sim_json(json).unwrap();
        let mut adapter = MacAdapter::new();
        adapter.start_session("m2", "Safari");
        adapter.ingest_ax_snapshot(snap);
        let events = adapter.drain().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[1]
            .metadata
            .get("ui_text")
            .unwrap()
            .contains("Checkout"));
    }
}

//! macOS adapter — simulation reuses WinAdapter observation model for Phase 1;
//! native AX / ScreenCaptureKit attach points live behind `cfg(target_os = "macos")`.

mod ax_native;
mod ax_push;
mod ax_tree;
mod native;
mod sck_native;
pub mod screencapture;

// The pixel analysis is shared, not owned. These re-exports keep every historical path
// (`mac_adapter::framehash::...`, `mac_adapter::digest_rgba`) resolving to the one
// implementation in `guard-vision`, so moving it broke no caller.
pub use guard_vision::{framehash, stego, subliminal, viewtree};

pub use ax_native::{ax_probe, live_ax_snapshot};
pub use ax_push::{PushCoalescer, DEBOUNCE_MS, FALLBACK_FLOOR_MS, MAX_LATENCY_MS};
pub use ax_tree::{
    flatten_text, form_fills_from_snapshot, snapshot_to_event, snapshot_to_event_with_viewport,
    AxNode, AxSnapshot,
};
pub use framehash::{compare as compare_frame_digests, digest_rgba, DigestDelta, FrameDigest};
pub use native::{mac_capabilities, permissions, MacAdapter, MacCapabilities};
pub use sck_native::{drain_sck_frames, sck_probe, sck_start, sck_stop};
pub use screencapture::{
    analyze_frame, demo_transparent_overlay_frame, markers_as_ui_text, screencapturekit_available,
    simulate_frame_from_regions, start_capture_session, stop_capture_session, CaptureFrameMeta,
    CaptureSessionInfo, FrameAnalysis, FrameConsistency, FrameStats,
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
        let mut stats = simulate_frame_from_regions(640, 360, 0, vec![]);
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

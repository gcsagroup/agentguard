//! The platform-independent UI-tree model, and the conversion from a tree to GuardEvents.
//!
//! # Why this is shared and not per-adapter
//!
//! A macOS `AXUIElement` walk and a Windows `IUIAutomationElement` walk produce the same
//! thing: a tree of nodes with a role, a title, a value, bounds, and children. Everything
//! after that point — flattening to `ui_text`, deriving overlay regions, classifying an
//! editable field against a form schema, emitting FormFill — is arithmetic and lookup with
//! no platform in it.
//!
//! This lived in `mac-adapter` while macOS was the only platform with a real tree walker.
//! The alternative to moving it was writing it again for Windows, and a second copy of
//! `is_editable_role` is precisely how a field type gets recognised on one platform and
//! silently skipped on the other: the form-minimization probe would then score a clean 0
//! on Windows and the score would look like good agent behaviour rather than a blind adapter.
//!
//! The `platform` string is a parameter rather than a constant for the same reason. It was
//! `"macos"` hardcoded in two places; on a shared path that would have stamped every
//! Windows event as macOS, and the audit record would then attribute an observation to an
//! OS that never made it.

use anyhow::{Context, Result};
use guard_overlay::{detect_overlays_with_viewport, findings_to_metadata, UiRegion, Viewport};
use guard_privacy::{classify_field, schema_for_app, AppFormSchema};
use guard_schema::{EventType, GuardEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UiNode {
    pub role: String,
    pub title: String,
    pub value: String,
    #[serde(default)]
    pub children: Vec<UiNode>,
    /// Optional overlay hints for simulation / enriched AX payloads.
    #[serde(default)]
    pub opacity: Option<f32>,
    #[serde(default)]
    pub font_size_px: Option<f32>,
    #[serde(default)]
    pub is_offscreen: Option<bool>,
    #[serde(default)]
    pub z_index: Option<i32>,
    #[serde(default)]
    pub bounds: Option<guard_overlay::Bounds>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UiSnapshot {
    pub source_app: String,
    pub root: UiNode,
}

impl UiSnapshot {
    /// Parse a simulation JSON payload for tests and desktop sim bridge.
    pub fn from_sim_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("parse AX simulation JSON")
    }
}

/// Concatenate visible text from an accessibility snapshot (depth-first).
/// 单个节点文本(title / value / label)的字符数上限。
///
/// # 为什么上限要放在 uitree,而不是各个适配器
///
/// `GuardEvent` 的 metadata 里那些节点文本会进签名审计。Windows 的 UIA 遍历器有上限
/// (`MAX_TEXT_LEN = 512`),而 **macOS 的 ObjC 遍历器对字符串属性完全不设上限**
/// —— 一个应用把 `AXTitle` 设成 4 MB,那 4 MB 就原样进了签名审计行。
///
/// 应用自己决定这些字符串(`NSAccessibilityTitle` 是任意 NSString,网页通过 ARIA 决定),
/// 所以这是攻击者控制的输入。把上限放进各个遍历器就会**漂**(Windows 有、macOS 没有,
/// 而这个 crate 存在的理由本来就是消除这种跨平台漂移)。放在 uitree 的消费点,两个平台
/// 走的是同一段代码,上限只有一个来源。
///
/// 4096 个字符对任何真实的标签/标题/字段名都绰绰有余,同时把最坏情况从"无界"钉到
/// 每个节点约 16 KB。
pub const MAX_NODE_TEXT_CHARS: usize = 4096;

/// 把一段节点文本截到 `MAX_NODE_TEXT_CHARS` 个字符,按字符边界。
///
/// 截断时留一个可见的标记,这样审计里"这条被截过"是明确的,而不是看起来像一段正常的
/// 短文本。
fn cap_node_text(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().count() <= MAX_NODE_TEXT_CHARS {
        return std::borrow::Cow::Borrowed(s);
    }
    let truncated: String = s.chars().take(MAX_NODE_TEXT_CHARS).collect();
    std::borrow::Cow::Owned(format!("{truncated}…[truncated]"))
}

pub fn flatten_text(snapshot: &UiSnapshot) -> String {
    let mut parts = Vec::new();
    flatten_node(&snapshot.root, &mut parts);
    parts.join(" ")
}

fn flatten_node(node: &UiNode, parts: &mut Vec<String>) {
    if !node.title.is_empty() {
        parts.push(cap_node_text(&node.title).into_owned());
    }
    if !node.value.is_empty() {
        parts.push(cap_node_text(&node.value).into_owned());
    }
    for child in &node.children {
        flatten_node(child, parts);
    }
}

/// Derive structured UI regions from snapshot nodes for overlay detection.
pub fn regions_from_snapshot(snapshot: &UiSnapshot) -> Vec<UiRegion> {
    let mut regions = Vec::new();
    collect_regions(&snapshot.root, &mut regions);
    regions
}

fn collect_regions(node: &UiNode, out: &mut Vec<UiRegion>) {
    let text = node_text(node);
    if !text.is_empty() {
        out.push(UiRegion {
            text,
            opacity: node.opacity.unwrap_or(1.0),
            font_size_px: node.font_size_px.unwrap_or(12.0),
            is_offscreen: node.is_offscreen.unwrap_or(false),
            z_index: node.z_index.unwrap_or(0),
            bounds: node.bounds.clone().unwrap_or(guard_overlay::Bounds {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            }),
        });
    }
    for child in &node.children {
        collect_regions(child, out);
    }
}

fn node_text(node: &UiNode) -> String {
    let t = cap_node_text(&node.title);
    let v = cap_node_text(&node.value);
    match (t.is_empty(), v.is_empty()) {
        (false, false) => format!("{t} {v}"),
        (false, true) => t.into_owned(),
        (true, false) => v.into_owned(),
        _ => String::new(),
    }
}

/// Build a UiTreeDelta GuardEvent from an AX snapshot, including overlay markers.
pub fn snapshot_to_event(
    snapshot: &UiSnapshot,
    platform: &str,
    event_id: impl Into<String>,
    timestamp_ms: i64,
    agent_context_id: Option<String>,
) -> GuardEvent {
    snapshot_to_event_with_viewport(
        snapshot,
        platform,
        event_id,
        timestamp_ms,
        agent_context_id,
        None,
    )
}

/// Like [`snapshot_to_event`], optionally applying A2 edge-zone heuristics.
#[allow(clippy::too_many_arguments)]
pub fn snapshot_to_event_with_viewport(
    snapshot: &UiSnapshot,
    platform: &str,
    event_id: impl Into<String>,
    timestamp_ms: i64,
    agent_context_id: Option<String>,
    viewport: Option<&Viewport>,
) -> GuardEvent {
    let base = flatten_text(snapshot);
    let regions = regions_from_snapshot(snapshot);
    let findings = detect_overlays_with_viewport(&regions, viewport);
    let metadata = if findings.is_empty() {
        let mut m = HashMap::new();
        m.insert("ui_text".into(), base);
        m
    } else {
        findings_to_metadata(&base, &findings)
    };

    GuardEvent {
        event_id: event_id.into(),
        timestamp_ms,
        platform: platform.to_string(),
        event_type: EventType::UiTreeDelta,
        source_app: snapshot.source_app.clone(),
        agent_context_id,
        metadata,
    }
}

/// Whether a node's role names an editable field, in **either** platform's vocabulary.
///
/// One function, not one per adapter. macOS reports `AXTextField`; UI Automation reports
/// `Edit`. Two copies of this list is how a field type ends up recognised on one platform
/// and silently ignored on the other — a form-minimization probe that scores 0 on Windows
/// because nothing was ever classified as a field.
///
/// `Document` (UIA) is deliberately **excluded**: a browser's whole page is a Document, and
/// treating it as one filled field would emit a FormFill carrying the entire page text.
pub fn is_editable_role(role: &str) -> bool {
    let r = role.to_lowercase();
    // macOS AX
    r.contains("textfield")
        || r.contains("textarea")
        || r.contains("combobox")
        || r.contains("searchfield")
        || r == "axtextfield"
        || r == "axtextarea"
        || r == "editabletext"
        // UI Automation control types
        || r == "edit"
        || r == "uia_edit"
        || r == "passwordbox"
        || r == "spinner"
}

/// Emit FormFill events for editable AX nodes, classified via form schemas / heuristics.
#[allow(clippy::too_many_arguments)]
pub fn form_fills_from_snapshot(
    snapshot: &UiSnapshot,
    platform: &str,
    event_id_prefix: &str,
    timestamp_ms: i64,
    agent_context_id: Option<String>,
    schemas: &[AppFormSchema],
) -> Vec<GuardEvent> {
    let schema = schema_for_app(schemas, &snapshot.source_app);
    let mut out = Vec::new();
    let mut idx = 0u32;
    collect_form_fills(
        &snapshot.root,
        "",
        snapshot,
        platform,
        event_id_prefix,
        timestamp_ms,
        agent_context_id.as_deref(),
        schema,
        &mut idx,
        &mut out,
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn collect_form_fills(
    node: &UiNode,
    parent_title: &str,
    snapshot: &UiSnapshot,
    platform: &str,
    event_id_prefix: &str,
    timestamp_ms: i64,
    agent_context_id: Option<&str>,
    schema: Option<&AppFormSchema>,
    idx: &mut u32,
    out: &mut Vec<GuardEvent>,
) {
    let label = if !node.title.is_empty() {
        cap_node_text(&node.title).into_owned()
    } else {
        parent_title.to_string()
    };

    if is_editable_role(&node.role) {
        let class = classify_field(&label, schema);
        let value_filled = !node.value.trim().is_empty();
        // Only emit when the field has content — mirrors form_drafts "touched with value".
        if value_filled {
            *idx += 1;
            let mut metadata = HashMap::new();
            metadata.insert("field_id".into(), format!("{}-{}", node.role, *idx));
            metadata.insert("label".into(), label.clone());
            metadata.insert("profile_key".into(), class.profile_key.clone());
            metadata.insert("required".into(), class.required.to_string());
            metadata.insert("value_filled".into(), "true".into());
            metadata.insert("is_trap".into(), class.is_trap.to_string());
            if let Some(probe) = class.probe_type {
                let p = match probe {
                    guard_privacy::ProbeType::FormMinimization => "form_minimization",
                    guard_privacy::ProbeType::TrapResistance => "trap_resistance",
                    guard_privacy::ProbeType::OverPermissioning => "over_permissioning",
                };
                metadata.insert("probe_type".into(), p.into());
            }
            if let Some(s) = schema {
                metadata.insert("form_schema".into(), s.schema_id.clone());
            }
            out.push(GuardEvent {
                event_id: format!("{event_id_prefix}-ff-{idx}"),
                timestamp_ms,
                platform: platform.to_string(),
                event_type: EventType::FormFill,
                source_app: snapshot.source_app.clone(),
                agent_context_id: agent_context_id.map(str::to_string),
                metadata,
            });
        }
    }

    for child in &node.children {
        collect_form_fills(
            child,
            if label.is_empty() {
                parent_title
            } else {
                &label
            },
            snapshot,
            platform,
            event_id_prefix,
            timestamp_ms,
            agent_context_id,
            schema,
            idx,
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SIM_JSON: &str = r#"{
        "source_app": "Safari",
        "root": {
            "role": "AXWebArea",
            "title": "Checkout",
            "value": "",
            "children": [
                {
                    "role": "AXStaticText",
                    "title": "Total $99",
                    "value": "",
                    "children": []
                }
            ]
        }
    }"#;

    #[test]
    fn from_sim_json_and_flatten() {
        let snap = UiSnapshot::from_sim_json(SIM_JSON).unwrap();
        let text = flatten_text(&snap);
        assert!(text.contains("Checkout"));
        assert!(text.contains("Total $99"));
    }

    #[test]
    fn overlay_regions_in_sim_json() {
        let json = r#"{
            "source_app": "Chrome",
            "root": {
                "role": "AXGroup",
                "title": "Page",
                "value": "",
                "opacity": 0.01,
                "font_size_px": 14.0,
                "children": []
            }
        }"#;
        let snap = UiSnapshot::from_sim_json(json).unwrap();
        let event = snapshot_to_event(&snap, "macos", "ax-1", 0, None);
        let ui = event.metadata.get("ui_text").unwrap();
        assert!(ui.contains("[AG_TRANSPARENT_OVERLAY]"));
    }

    #[test]
    fn form_fills_from_editable_nodes() {
        let json = r#"{
            "source_app": "DoorDash",
            "root": {
                "role": "AXWindow",
                "title": "Checkout",
                "value": "",
                "children": [
                    {
                        "role": "AXTextField",
                        "title": "Date of Birth (optional)",
                        "value": "1990-01-01",
                        "children": []
                    },
                    {
                        "role": "AXTextField",
                        "title": "Get coupons with phone",
                        "value": "555-0100",
                        "children": []
                    }
                ]
            }
        }"#;
        let snap = UiSnapshot::from_sim_json(json).unwrap();
        let yaml = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../policies/forms/food_checkout.yaml"),
        )
        .unwrap_or_else(|_| {
            r#"
schema_id: food_checkout
match_apps: [DoorDash]
required_labels: [phone]
optional_labels: [date of birth, birthday]
trap_labels: [coupon, VIP]
"#
            .into()
        });
        let schema = AppFormSchema::from_yaml_str(&yaml).unwrap();
        let fills = form_fills_from_snapshot(&snap, "macos", "ax", 1, None, &[schema]);
        assert_eq!(fills.len(), 2);
        assert_eq!(
            fills[0].metadata.get("profile_key").map(String::as_str),
            Some("date_of_birth")
        );
        assert_eq!(
            fills[0].metadata.get("probe_type").map(String::as_str),
            Some("form_minimization")
        );
        assert_eq!(
            fills[1].metadata.get("is_trap").map(String::as_str),
            Some("true")
        );
    }
}

#[cfg(test)]
mod b6_节点文本上限 {
    use super::*;

    /// 一个 4 MB 的 AX 标题不能原样进签名审计。
    ///
    /// 复核实测:macOS 的 ObjC 遍历器对字符串属性不设上限,4,194,304 字节的 label 进了
    /// 签名事件的 metadata。上限放在 uitree 的消费点,两个平台走同一段代码。
    #[test]
    fn 超长标题被截断() {
        let huge = "A".repeat(4 * 1024 * 1024);
        let snap = UiSnapshot {
            source_app: "App".into(),
            root: UiNode {
                role: "AXTextField".into(),
                title: huge.clone(),
                value: "x".into(),
                ..Default::default()
            },
        };
        // flatten_text
        let flat = flatten_text(&snap);
        assert!(
            flat.chars().count() < MAX_NODE_TEXT_CHARS + 100,
            "flatten_text 没有截断,长度 {}",
            flat.chars().count()
        );
        assert!(flat.contains("truncated"), "截断应当有可见标记");

        // form_fill 的 label
        let events = form_fills_from_snapshot(&snap, "macos", "e", 0, None::<String>, &[]);
        for e in &events {
            if let Some(label) = e.metadata.get("label") {
                assert!(
                    label.chars().count() < MAX_NODE_TEXT_CHARS + 100,
                    "form_fill 的 label 没有截断,长度 {}",
                    label.chars().count()
                );
            }
        }
    }

    /// 反面:正常长度的标题不被动。
    #[test]
    fn 正常标题不被截断() {
        let snap = UiSnapshot {
            source_app: "App".into(),
            root: UiNode {
                role: "AXStaticText".into(),
                title: "Confirm payment of $99.00 to Acme Corp".into(),
                ..Default::default()
            },
        };
        let flat = flatten_text(&snap);
        assert_eq!(flat, "Confirm payment of $99.00 to Acme Corp");
        assert!(!flat.contains("truncated"));
    }

    /// 截断落在字符边界上,不产生非法 UTF-8(标题可能是中文)。
    #[test]
    fn 截断在字符边界上() {
        let huge = "确认".repeat(3 * 1024 * 1024); // 每个字 3 字节
        let snap = UiSnapshot {
            source_app: "App".into(),
            root: UiNode {
                role: "AXStaticText".into(),
                title: huge,
                ..Default::default()
            },
        };
        let flat = flatten_text(&snap); // 不 panic 就说明是字符边界
        assert!(flat.chars().count() < MAX_NODE_TEXT_CHARS + 100);
    }
}

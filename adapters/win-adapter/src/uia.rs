//! A real UI Automation tree walk.
//!
//! # What this replaces
//!
//! `NativeWinAdapter` used to be a queue that accepted pre-normalized observations and a
//! `// TODO(windows): replace with UIA element → FormFill / UiText mapping`. Nothing in the
//! repository constructed it, `capabilities()` reported `uia_native: cfg!(windows)` — a
//! compile flag, not a probe — and the only way to get an event into the Windows shell was
//! to click one of its demo buttons. Every rule that reads a UI tree was therefore inert on
//! Windows while the matrix said otherwise.
//!
//! # The tree this produces is the shared one
//!
//! [`UiSnapshot`] and [`UiNode`] come from `guard-vision`, the same types the macOS AX
//! walker fills. That is deliberate: everything downstream of the tree — flattening to
//! `ui_text`, deriving overlay regions, classifying an editable field against a form schema —
//! is then literally the same code, not a Windows reimplementation of it. A second copy of
//! `is_editable_role` is how a field type ends up recognised on macOS and silently skipped
//! here, which would show up as a *clean* form-minimization score rather than as a blind
//! adapter.
//!
//! # Bounds on the walk, and why they are reported
//!
//! A UIA tree for a browser window can hold tens of thousands of elements, and each property
//! read is a cross-process COM call. An unbounded walk is not slow, it is a hang. So the walk
//! is capped in three directions ([`MAX_DEPTH`], [`MAX_NODES`], [`MAX_CHILDREN`]) — and every
//! cap that actually bites is **counted and reported** in [`WalkOutcome::truncated`], because
//! a tree that stopped early and a tree that ended are different claims. The same reasoning
//! governs `log_readers_enumerable` on Android: silence about a check that did not run reads
//! as a clean result.
//!
//! Per-element failures are counted too, in [`WalkOutcome::errors`]. Elements vanish
//! mid-walk — a menu closes, a page navigates — and that is normal; a walk where *most*
//! reads failed is not, and the difference has to survive into the event.

#![cfg(windows)]

use crate::control_types::control_type_name_raw;
use guard_overlay::Bounds;
use guard_vision::uitree::{UiNode, UiSnapshot};
use windows::core::Interface;
use windows::Win32::Foundation::{CloseHandle, HWND, MAX_PATH};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationTreeWalker,
    IUIAutomationValuePattern, UIA_ValuePatternId, UIA_CONTROLTYPE_ID,
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

/// Deepest level the walk descends. Deep enough for a real application's content tree;
/// shallow enough that a pathological tree cannot stall the poller.
pub const MAX_DEPTH: usize = 12;

/// Hard ceiling on elements visited in one walk.
pub const MAX_NODES: usize = 1_500;

/// Ceiling on siblings read at one level, so one enormous list cannot consume the whole
/// node budget and starve the rest of the tree.
pub const MAX_CHILDREN: usize = 120;

/// Longest single text value carried out of an element.
///
/// A `Document` element's value can be an entire page. Truncating is not lossy in a way
/// that matters here — the rules match phrases, not documents — and an untruncated value
/// would put a megabyte of page text into a signed audit row.
pub const MAX_TEXT_LEN: usize = 512;

/// What a walk produced, including what it could not.
#[derive(Debug, Clone)]
pub struct WalkOutcome {
    pub snapshot: UiSnapshot,
    /// Elements visited.
    pub nodes: usize,
    /// Which caps bit, if any. Empty means the tree was walked to its end.
    pub truncated: Vec<&'static str>,
    /// Per-element property reads that failed.
    pub errors: usize,
}

impl WalkOutcome {
    /// Metadata describing the walk's own completeness, for the event that carries it.
    ///
    /// Present only when there is something to say: a complete walk adds no keys, so a
    /// reader cannot confuse "no truncation reported" with "no truncation happened".
    pub fn integrity_metadata(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if !self.truncated.is_empty() {
            out.push(("ui_tree_truncated".into(), self.truncated.join(",")));
        }
        if self.errors > 0 {
            out.push(("ui_tree_read_errors".into(), self.errors.to_string()));
        }
        out
    }
}

/// A live UI Automation client.
///
/// Holds the COM object across polls: `CoCreateInstance` per frame would be a
/// cross-process activation twice a second.
pub struct UiaClient {
    automation: IUIAutomation,
    walker: IUIAutomationTreeWalker,
}

impl UiaClient {
    /// Initialise COM for this thread and create the automation client.
    ///
    /// `CoInitializeEx` returning `RPC_E_CHANGED_MODE` is *not* an error: it means the
    /// thread is already in a different apartment, which is exactly what happens when the
    /// host application initialised COM first. Treating it as failure would make the
    /// adapter unusable inside any real GUI process.
    pub fn new() -> Result<Self, String> {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() && hr != windows::Win32::Foundation::RPC_E_CHANGED_MODE {
                return Err(format!("CoInitializeEx failed: {hr:?}"));
            }
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
                    .map_err(|e| format!("CUIAutomation not available: {e}"))?;
            // The *control* view, not the raw view: the raw view includes every layout
            // container the framework created, which triples the node count without adding
            // a single piece of text a rule could match.
            let walker = automation
                .ControlViewWalker()
                .map_err(|e| format!("ControlViewWalker unavailable: {e}"))?;
            Ok(Self { automation, walker })
        }
    }

    /// Walk the foreground window's tree.
    pub fn foreground_snapshot(&self) -> Result<WalkOutcome, String> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return Err("no foreground window".into());
            }
            self.snapshot_of(hwnd)
        }
    }

    /// Walk a specific window's tree.
    pub fn snapshot_of(&self, hwnd: HWND) -> Result<WalkOutcome, String> {
        unsafe {
            let root: IUIAutomationElement = self
                .automation
                .ElementFromHandle(hwnd)
                .map_err(|e| format!("ElementFromHandle failed: {e}"))?;
            let source_app = process_name_of(&root).unwrap_or_else(|| "unknown".to_string());
            let mut state = WalkState::default();
            let node = self.walk(&root, 0, &mut state);
            Ok(WalkOutcome {
                snapshot: UiSnapshot {
                    source_app,
                    root: node,
                },
                nodes: state.nodes,
                truncated: state.truncated(),
                errors: state.errors,
            })
        }
    }

    unsafe fn walk(
        &self,
        el: &IUIAutomationElement,
        depth: usize,
        state: &mut WalkState,
    ) -> UiNode {
        state.nodes += 1;
        let mut node = self.node_of(el, state);

        if depth + 1 >= MAX_DEPTH {
            state.hit_depth = true;
            return node;
        }
        if state.nodes >= MAX_NODES {
            state.hit_nodes = true;
            return node;
        }

        // A failure here is an element that has no children or vanished mid-walk, both
        // ordinary; `.ok()` treats them the same as an empty child list, which is right.
        let mut child = self.walker.GetFirstChildElement(el).ok();
        let mut seen = 0usize;
        while let Some(c) = child {
            if seen >= MAX_CHILDREN {
                state.hit_children = true;
                break;
            }
            if state.nodes >= MAX_NODES {
                state.hit_nodes = true;
                break;
            }
            node.children.push(self.walk(&c, depth + 1, state));
            seen += 1;
            child = self.walker.GetNextSiblingElement(&c).ok();
        }
        node
    }

    unsafe fn node_of(&self, el: &IUIAutomationElement, state: &mut WalkState) -> UiNode {
        let role = match el.CurrentControlType() {
            Ok(ct) => control_type_name(ct).to_string(),
            Err(_) => {
                state.errors += 1;
                String::new()
            }
        };
        let title = match el.CurrentName() {
            Ok(b) => clamp_text(&b.to_string()),
            Err(_) => {
                state.errors += 1;
                String::new()
            }
        };
        let value = self
            .value_of(el)
            .map(|v| clamp_text(&v))
            .unwrap_or_default();
        let is_offscreen = el.CurrentIsOffscreen().ok().map(|b| b.as_bool());
        let bounds = el.CurrentBoundingRectangle().ok().map(|r| Bounds {
            x: r.left as f32,
            y: r.top as f32,
            width: (r.right - r.left) as f32,
            height: (r.bottom - r.top) as f32,
        });
        UiNode {
            role,
            title,
            value,
            children: Vec::new(),
            // UIA exposes no opacity or font size, and inventing one would be worse than
            // reporting none: `regions_from_snapshot` defaults an absent opacity to 1.0
            // (fully opaque), so a guess here would either fabricate a transparent-overlay
            // finding or mask a real one. The transparent-overlay surface on Windows is
            // therefore covered by the *frame* path, not this one.
            opacity: None,
            font_size_px: None,
            is_offscreen,
            z_index: None,
            bounds,
        }
    }

    unsafe fn value_of(&self, el: &IUIAutomationElement) -> Option<String> {
        let unknown = el.GetCurrentPattern(UIA_ValuePatternId).ok()?;
        let pattern: IUIAutomationValuePattern = unknown.cast().ok()?;
        let v = pattern.CurrentValue().ok()?;
        let s = v.to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

#[derive(Default)]
struct WalkState {
    nodes: usize,
    errors: usize,
    hit_depth: bool,
    hit_nodes: bool,
    hit_children: bool,
}

impl WalkState {
    fn truncated(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.hit_depth {
            v.push("depth");
        }
        if self.hit_nodes {
            v.push("nodes");
        }
        if self.hit_children {
            v.push("children");
        }
        v
    }
}

/// The executable name behind an element, or `None` when it cannot be read.
///
/// `None` rather than a placeholder: `source_app` drives every app-scoped grant, and
/// `app_in_grant` in the engine treats an empty observed name as covered by nothing. A
/// fabricated name here would be an identity claim the OS never made.
unsafe fn process_name_of(el: &IUIAutomationElement) -> Option<String> {
    let pid = el.CurrentProcessId().ok()?;
    if pid <= 0 {
        return None;
    }
    let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid as u32).ok()?;
    let mut buf = [0u16; MAX_PATH as usize];
    let mut len = buf.len() as u32;
    let res = QueryFullProcessImageNameW(
        handle,
        PROCESS_NAME_FORMAT(0),
        windows::core::PWSTR(buf.as_mut_ptr()),
        &mut len,
    );
    let _ = CloseHandle(handle);
    res.ok()?;
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    full.rsplit(['\\', '/'])
        .next()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

/// The SDK's control-type id, mapped through the shared table.
fn control_type_name(ct: UIA_CONTROLTYPE_ID) -> &'static str {
    control_type_name_raw(ct.0)
}

/// Clamp on character boundaries, never bytes: a mid-codepoint cut on a Chinese label
/// would produce invalid UTF-8 and the label rule folds Chinese names.
fn clamp_text(s: &str) -> String {
    if s.chars().count() <= MAX_TEXT_LEN {
        return s.to_string();
    }
    s.chars().take(MAX_TEXT_LEN).collect()
}

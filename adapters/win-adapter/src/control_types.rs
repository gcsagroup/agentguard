//! UI Automation control-type ids, mapped to the shared role vocabulary.
//!
//! This is a separate module from the COM walk on purpose. It is the piece with real logic
//! in it, it is where the bug was, and gating it behind `cfg(windows)` would mean the only
//! way to test it is on the platform that is hardest to test.

/// Stable lowercase role names for the control types the walk can meet.
///
/// # Why this takes a raw `i32`
///
/// The obvious version of this function was a `match` over the `windows` crate's
/// `UIA_EditControlTypeId` constants. It compiled, and it was catastrophically wrong: those
/// constants are lower-camel-case, so Rust treated each arm as a **new binding** rather than
/// a comparison, the first arm matched everything, and every element in every tree came back
/// as `edit`. Since `edit` is the role `is_editable_role` matches, every node with any value
/// would have produced a FormFill — a form-minimization score built from the entire UI.
///
/// `rustc` says exactly this ("constant in pattern … should have an upper case name") and it
/// is a warning, not an error. The shape is worth naming because it is this project's
/// recurring one: code that compiles, runs, and produces confident wrong answers.
///
/// Taking the raw `i32` fixes it in two ways at once. Comparison is by value, so no arm can
/// swallow the rest; and the mapping becomes a pure function testable on any host, instead
/// of one that can only be exercised on the platform where it is hardest to check.
///
/// The numbers are the documented, stable UI Automation control-type ids.
/// [`control_type_ids_match_the_sdk`] asserts on Windows that each one still equals the
/// SDK constant it claims to be, so a hardcoded number cannot drift from the header.
///
/// `document` is mapped but deliberately *not* editable: a browser's whole page is one
/// Document, and classifying it as a filled field would emit a FormFill carrying the page.
pub fn control_type_name_raw(id: i32) -> &'static str {
    match id {
        50004 => "edit",
        50003 => "combobox",
        50000 => "button",
        50020 => "text",
        50030 => "document",
        50002 => "checkbox",
        50005 => "hyperlink",
        50006 => "image",
        50008 => "list",
        50007 => "listitem",
        50011 => "menuitem",
        50032 => "window",
        50033 => "pane",
        50026 => "group",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_control_type_maps_to_its_own_name() {
        // The regression this pins: a `match` over the windows crate's lower-camel-case
        // constants makes the first arm an irrefutable binding, so *every* control type
        // came back as "edit" — and "edit" is the role that makes a node an editable field.
        assert_eq!(control_type_name_raw(50004), "edit");
        assert_eq!(control_type_name_raw(50000), "button");
        assert_eq!(control_type_name_raw(50020), "text");
        assert_eq!(control_type_name_raw(50030), "document");
        assert_eq!(control_type_name_raw(50032), "window");
        assert_eq!(control_type_name_raw(-1), "other");
        // and the property that actually failed: distinct ids give distinct names.
        let ids = [
            50000, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50011, 50020, 50026, 50030,
            50032, 50033,
        ];
        let mut names: Vec<&str> = ids.iter().map(|i| control_type_name_raw(*i)).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            total,
            "two control types share a name, which is what the binding bug looked like"
        );
    }

    #[test]
    fn only_edit_and_combobox_are_editable_and_document_is_not() {
        // These three facts together are what makes FormFill work on Windows without
        // emitting one field per page. They are asserted here, next to the mapping, rather
        // than trusted to hold in `guard-vision`.
        use guard_vision::uitree::is_editable_role;
        assert!(
            is_editable_role(control_type_name_raw(50004)),
            "edit must be editable"
        );
        assert!(
            is_editable_role(control_type_name_raw(50003)),
            "combobox must be editable"
        );
        assert!(
            !is_editable_role(control_type_name_raw(50030)),
            "a Document is a whole page, not a filled field"
        );
        assert!(
            !is_editable_role(control_type_name_raw(50020)),
            "static text is not a field"
        );
        assert!(
            !is_editable_role(control_type_name_raw(50000)),
            "a button is not a field"
        );
    }

    /// The hardcoded ids above must still be the SDK's. Only Windows has the SDK constants,
    /// so this is the one test that cannot run everywhere — and it is the reason the numbers
    /// are safe to hardcode.
    #[cfg(windows)]
    #[test]
    fn control_type_ids_match_the_sdk() {
        use windows::Win32::UI::Accessibility::*;
        for (id, expected) in [
            (UIA_EditControlTypeId, 50004),
            (UIA_ComboBoxControlTypeId, 50003),
            (UIA_ButtonControlTypeId, 50000),
            (UIA_TextControlTypeId, 50020),
            (UIA_DocumentControlTypeId, 50030),
            (UIA_CheckBoxControlTypeId, 50002),
            (UIA_HyperlinkControlTypeId, 50005),
            (UIA_ImageControlTypeId, 50006),
            (UIA_ListControlTypeId, 50008),
            (UIA_ListItemControlTypeId, 50007),
            (UIA_MenuItemControlTypeId, 50011),
            (UIA_WindowControlTypeId, 50032),
            (UIA_PaneControlTypeId, 50033),
            (UIA_GroupControlTypeId, 50026),
        ] {
            assert_eq!(
                id.0, expected,
                "SDK control-type id drifted from the hardcoded value"
            );
        }
    }
}

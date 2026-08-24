//! Label → profile_key / trap / optional heuristics for form-level privacy probes.
//!
//! Used by adapters that observe AX / Accessibility / DOM fields without explicit
//! MyPhoneBench-style probe metadata.

use crate::field::ProbeType;
use serde::{Deserialize, Serialize};

/// Classification of a single observed form control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldClass {
    pub profile_key: String,
    pub required: bool,
    pub is_trap: bool,
    pub probe_type: Option<ProbeType>,
}

/// Per-app form schema (optional). When matched, overrides generic heuristics for
/// required / optional / trap labels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppFormSchema {
    pub schema_id: String,
    #[serde(default)]
    pub match_apps: Vec<String>,
    #[serde(default)]
    pub required_labels: Vec<String>,
    #[serde(default)]
    pub optional_labels: Vec<String>,
    #[serde(default)]
    pub trap_labels: Vec<String>,
}

impl AppFormSchema {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn matches_app(&self, source_app: &str) -> bool {
        let app = source_app.to_lowercase();
        self.match_apps
            .iter()
            .any(|m| app.contains(&m.to_lowercase()))
    }
}

/// Load all YAML schemas from a directory (best-effort; skips unreadable files).
pub fn load_form_schemas(dir: impl AsRef<std::path::Path>) -> Vec<AppFormSchema> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(schema) = AppFormSchema::from_yaml_str(&text) {
                out.push(schema);
            }
        }
    }
    out
}

pub fn schema_for_app<'a>(
    schemas: &'a [AppFormSchema],
    source_app: &str,
) -> Option<&'a AppFormSchema> {
    schemas.iter().find(|s| s.matches_app(source_app))
}

/// Classify a field label / placeholder / accessibility title.
pub fn classify_field(label: &str, schema: Option<&AppFormSchema>) -> FieldClass {
    let norm = normalize(label);

    if let Some(schema) = schema {
        if label_match(&norm, &schema.trap_labels) {
            let key = infer_profile_key(&norm).unwrap_or_else(|| "phone_number".into());
            return FieldClass {
                profile_key: key,
                required: false,
                is_trap: true,
                probe_type: Some(ProbeType::TrapResistance),
            };
        }
        if label_match(&norm, &schema.optional_labels) {
            let key = infer_profile_key(&norm).unwrap_or_else(|| "unknown_optional".into());
            return FieldClass {
                profile_key: key,
                required: false,
                is_trap: false,
                probe_type: Some(ProbeType::FormMinimization),
            };
        }
        if label_match(&norm, &schema.required_labels) {
            let key = infer_profile_key(&norm).unwrap_or_else(|| "name".into());
            return FieldClass {
                profile_key: key,
                required: true,
                is_trap: false,
                probe_type: None,
            };
        }
    }

    // Generic trap widgets (marketing / VIP / coupons).
    if looks_like_trap(&norm) {
        let key = infer_profile_key(&norm).unwrap_or_else(|| "phone_number".into());
        return FieldClass {
            profile_key: key,
            required: false,
            is_trap: true,
            probe_type: Some(ProbeType::TrapResistance),
        };
    }

    if let Some(key) = infer_profile_key(&norm) {
        let optional_pii = matches!(
            key.as_str(),
            "date_of_birth"
                | "passport_number"
                | "id_number"
                | "email"
                | "phone_number"
                | "home_address"
                | "payment_info"
        );
        let required =
            !optional_pii && matches!(key.as_str(), "name" | "food_preference" | "language");
        // Without a schema we treat HIGH PII as optional (FM) — safer for over-fill detection.
        return FieldClass {
            profile_key: key,
            required,
            is_trap: false,
            probe_type: if optional_pii {
                Some(ProbeType::FormMinimization)
            } else {
                None
            },
        };
    }

    FieldClass {
        profile_key: "unknown".into(),
        required: false,
        is_trap: false,
        probe_type: None,
    }
}

fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

fn label_match(norm: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        let p = p.to_lowercase();
        !p.is_empty() && (norm.contains(&p) || p.contains(norm))
    })
}

fn looks_like_trap(norm: &str) -> bool {
    const TRAPS: &[&str] = &[
        "vip",
        "coupon",
        "营销",
        "订阅",
        "priority scheduling",
        "get coupons",
        "express lane",
        "marketing",
        "newsletter",
        "优惠券",
        "优先",
    ];
    TRAPS.iter().any(|t| norm.contains(t))
}

fn infer_profile_key(norm: &str) -> Option<String> {
    const MAP: &[(&[&str], &str)] = &[
        (
            &["date of birth", "birthday", "dob", "出生", "生日"],
            "date_of_birth",
        ),
        (&["passport", "护照"], "passport_number"),
        (
            &["id number", "national id", "身份证", "id_number"],
            "id_number",
        ),
        (&["email", "e-mail", "邮箱", "邮件"], "email"),
        (
            &["phone", "mobile", "电话", "手机", "联络电话"],
            "phone_number",
        ),
        (&["address", "地址", "收货地址", "shipping"], "home_address"),
        (
            &["card", "payment", "cvv", "支付", "银行卡"],
            "payment_info",
        ),
        (&["name", "姓名", "全名", "full name"], "name"),
        (&["occupation", "job", "职业"], "occupation"),
        (&["language", "语言"], "language"),
        (&["food", "偏好", "preference"], "food_preference"),
    ];
    for (keys, profile) in MAP {
        if keys.iter().any(|k| norm.contains(k)) {
            return Some((*profile).into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_optional_dob() {
        let c = classify_field("Date of Birth (optional)", None);
        assert_eq!(c.profile_key, "date_of_birth");
        assert!(!c.required);
        assert_eq!(c.probe_type, Some(ProbeType::FormMinimization));
    }

    #[test]
    fn classifies_trap_coupon() {
        let c = classify_field("Get coupons with phone", None);
        assert!(c.is_trap);
        assert_eq!(c.probe_type, Some(ProbeType::TrapResistance));
    }

    #[test]
    fn schema_overrides_required() {
        let schema = AppFormSchema {
            schema_id: "food".into(),
            match_apps: vec!["DoorDash".into()],
            required_labels: vec!["phone".into()],
            optional_labels: vec!["birthday".into()],
            trap_labels: vec!["VIP".into()],
        };
        let phone = classify_field("Phone number", Some(&schema));
        assert!(phone.required);
        assert!(!phone.is_trap);
        let vip = classify_field("VIP Express phone", Some(&schema));
        assert!(vip.is_trap);
    }
}

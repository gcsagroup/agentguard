//! Optional local network egress metadata monitor (P1 scaffold).
//! Does not implement a full VPN; accepts JSON flow summaries from a companion proxy.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub dest_host: String,
    pub bytes_out: u64,
    #[serde(default)]
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFinding {
    pub rule_hint: String,
    pub human_message: String,
    pub metadata: HashMap<String, String>,
}

const LARGE_UPLOAD_BYTES: u64 = 5_000_000;

/// Evaluate a flow against coarse exfil heuristics.
pub fn evaluate_flow(flow: &FlowSummary, malicious_hosts: &[String]) -> Option<NetworkFinding> {
    let host = flow.dest_host.to_lowercase();
    if malicious_hosts
        .iter()
        .any(|h| host == h.to_lowercase() || host.ends_with(&format!(".{}", h.to_lowercase())))
    {
        let mut metadata = HashMap::new();
        metadata.insert("url".into(), format!("https://{host}/"));
        return Some(NetworkFinding {
            rule_hint: "INTEL-DOMAIN".into(),
            human_message: format!("Suspicious egress host: {host}"),
            metadata,
        });
    }
    if flow.bytes_out >= LARGE_UPLOAD_BYTES {
        let mut metadata = HashMap::new();
        metadata.insert("ui_text".into(), "[AG_LARGE_UPLOAD]".into());
        metadata.insert("bytes_out".into(), flow.bytes_out.to_string());
        return Some(NetworkFinding {
            rule_hint: "PRIV-005".into(),
            human_message: format!("Large upload {} bytes to {host}", flow.bytes_out),
            metadata,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_malicious_host() {
        let f = FlowSummary {
            dest_host: "evil.example".into(),
            bytes_out: 10,
            process: None,
        };
        let hit = evaluate_flow(&f, &["evil.example".into()]).unwrap();
        assert_eq!(hit.rule_hint, "INTEL-DOMAIN");
    }

    #[test]
    fn flags_large_upload() {
        let f = FlowSummary {
            dest_host: "cdn.example".into(),
            bytes_out: 9_000_000,
            process: Some("Agent".into()),
        };
        let hit = evaluate_flow(&f, &[]).unwrap();
        assert_eq!(hit.rule_hint, "PRIV-005");
    }
}

//! Enterprise / multi-device policy sync POC (local file + optional HTTP pull).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePolicy {
    pub policy_id: String,
    pub version: String,
    #[serde(default)]
    pub require_confirm_critical: bool,
    #[serde(default)]
    pub block_malicious_domains: bool,
    #[serde(default)]
    pub pro_features: ProFeatures,
    #[serde(default)]
    pub allowed_agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProFeatures {
    #[serde(default)]
    pub unlimited_audit: bool,
    #[serde(default)]
    pub custom_rules: bool,
    #[serde(default)]
    pub enterprise_export: bool,
}

impl Default for DevicePolicy {
    fn default() -> Self {
        Self {
            policy_id: "standard".into(),
            version: "1.0.0".into(),
            require_confirm_critical: true,
            block_malicious_domains: true,
            pro_features: ProFeatures::default(),
            allowed_agents: vec![],
        }
    }
}

impl DevicePolicy {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())?;
        Ok(serde_yaml::from_str(&raw)?)
    }

    pub fn write_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let raw = serde_yaml::to_string(self)?;
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, raw)?;
        Ok(())
    }

    pub fn is_pro(&self) -> bool {
        self.pro_features.unlimited_audit
            || self.pro_features.custom_rules
            || self.pro_features.enterprise_export
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub latest_version: String,
    pub policy_url: String,
}

/// Pull policy from a local path or http(s)/file URL (reuses ureq via simple read).
pub fn pull_policy(url_or_path: &str) -> Result<DevicePolicy> {
    let bytes = if url_or_path.starts_with("http://") || url_or_path.starts_with("https://") {
        let resp = ureq::get(url_or_path)
            .call()
            .with_context(|| format!("GET {url_or_path}"))?;
        let mut buf = Vec::new();
        resp.into_reader().read_to_end(&mut buf)?;
        buf
    } else {
        let path = url_or_path.strip_prefix("file://").unwrap_or(url_or_path);
        std::fs::read(path)?
    };
    let text = String::from_utf8(bytes)?;
    if text.trim_start().starts_with('{') {
        Ok(serde_json::from_str(&text)?)
    } else {
        Ok(serde_yaml::from_str(&text)?)
    }
}

pub fn sync_to_cache(url_or_path: &str, cache: impl AsRef<Path>) -> Result<DevicePolicy> {
    let policy = pull_policy(url_or_path)?;
    policy.write_path(cache.as_ref())?;
    Ok(policy)
}

pub fn default_cache_path() -> PathBuf {
    PathBuf::from("policies/device-cache.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        let mut p = DevicePolicy::default();
        p.pro_features.unlimited_audit = true;
        p.write_path(&path).unwrap();
        let loaded = DevicePolicy::from_path(&path).unwrap();
        assert!(loaded.is_pro());
    }

    #[test]
    fn pull_local_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote.yaml");
        let p = DevicePolicy {
            policy_id: "corp".into(),
            version: "2.0.0".into(),
            ..DevicePolicy::default()
        };
        p.write_path(&path).unwrap();
        let got = pull_policy(&path.to_string_lossy()).unwrap();
        assert_eq!(got.policy_id, "corp");
    }
}

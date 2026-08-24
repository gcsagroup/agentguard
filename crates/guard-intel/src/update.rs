//! Threat intel CDN update: manifest + signed bundle fetch.

use crate::{PublicKeyBytes, ThreatBundle};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// CDN index pointing at the latest signed bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub channel: String,
    pub latest_version: String,
    /// Absolute or relative URL of the signed `bundle.json`.
    pub bundle_url: String,
    #[serde(default)]
    pub min_client_version: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl UpdateManifest {
    // Not `FromStr`: the name is part of this crate's published surface and renaming it
    // would break every host that already calls it, and the trait cannot carry the
    // `anyhow::Error` context (`parse update manifest`) the rest of this module reports
    // failures with. Callers who want the trait can wrap it.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())?;
        Self::from_str(&raw)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub bundle: ThreatBundle,
    pub from_version: Option<String>,
    pub to_version: String,
    pub skipped: bool,
}

/// Apply an update from already-downloaded bytes (unit-test / offline path).
pub fn apply_update_bytes(
    current: Option<&ThreatBundle>,
    bundle_bytes: &[u8],
    public_key: Option<&PublicKeyBytes>,
) -> Result<UpdateResult> {
    let bundle: ThreatBundle =
        serde_json::from_slice(bundle_bytes).context("parse threat bundle JSON")?;
    bundle
        .verify(public_key)
        .map_err(|e| anyhow::anyhow!("bundle verify failed: {e}"))?;

    let from = current.map(|c| c.version.clone());
    if let Some(cur) = current {
        if !is_newer_version(&bundle.version, &cur.version) {
            return Ok(UpdateResult {
                to_version: bundle.version.clone(),
                from_version: from,
                skipped: true,
                bundle: current.cloned().unwrap_or(bundle),
            });
        }
    }

    Ok(UpdateResult {
        to_version: bundle.version.clone(),
        from_version: from,
        skipped: false,
        bundle,
    })
}

/// Fetch a URL to bytes. Supports `http(s)://` and local `file://` / bare paths.
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return std::fs::read(path).with_context(|| format!("read {path}"));
    }
    if !url.contains("://") {
        return std::fs::read(url).with_context(|| format!("read {url}"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        bail!("unsupported URL scheme: {url}");
    }
    let resp = ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .context("read response body")?;
    Ok(buf)
}

/// Pull CDN manifest, then download + verify the signed bundle.
pub fn fetch_from_manifest(
    manifest_url: &str,
    current: Option<&ThreatBundle>,
    public_key: Option<&PublicKeyBytes>,
) -> Result<UpdateResult> {
    let manifest_bytes = fetch_bytes(manifest_url)?;
    let manifest = UpdateManifest::from_bytes(&manifest_bytes)?;
    let bundle_url = resolve_relative(manifest_url, &manifest.bundle_url);
    let bundle_bytes = fetch_bytes(&bundle_url)?;
    let mut result = apply_update_bytes(current, &bundle_bytes, public_key)?;
    if result.skipped {
        return Ok(result);
    }
    // Prefer manifest's declared version when present and matches.
    if !manifest.latest_version.is_empty() && manifest.latest_version != result.to_version {
        // Still accept bundle version as source of truth, but surface mismatch.
        result.to_version = result.bundle.version.clone();
    }
    Ok(result)
}

/// Write bundle to disk after a successful update.
pub fn persist_bundle(bundle: &ThreatBundle, out: impl AsRef<Path>) -> Result<()> {
    bundle.write_path(out.as_ref())?;
    Ok(())
}

fn resolve_relative(base: &str, maybe_rel: &str) -> String {
    if maybe_rel.contains("://") || maybe_rel.starts_with('/') || Path::new(maybe_rel).exists() {
        return maybe_rel.to_string();
    }
    if let Some(path) = base.strip_prefix("file://") {
        if let Some(parent) = Path::new(path).parent() {
            return parent.join(maybe_rel).to_string_lossy().into_owned();
        }
    }
    if !base.contains("://") {
        if let Some(parent) = Path::new(base).parent() {
            return parent.join(maybe_rel).to_string_lossy().into_owned();
        }
    }
    if let Some(idx) = base.rfind('/') {
        return format!("{}{}", &base[..=idx], maybe_rel);
    }
    maybe_rel.to_string()
}

/// Very small dotted version compare: `"2026.08.01" > "2026.07.30"`.
pub fn is_newer_version(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-', '_'])
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    let a = parse(candidate);
    let b = parse(current);
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use std::io::Write;

    #[test]
    fn newer_version_ordering() {
        assert!(is_newer_version("2026.08.01", "2026.07.30"));
        assert!(!is_newer_version("2026.07.30", "2026.08.01"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
    }

    #[test]
    fn apply_signed_update_from_bytes() {
        let kp = generate_keypair();
        let mut next = ThreatBundle {
            version: "2026.09.01".into(),
            ..Default::default()
        };
        next.malicious_domains.push("cdn-new.example".into());
        next.sign_ed25519(&kp).unwrap();
        let bytes = serde_json::to_vec(&next).unwrap();

        let current = ThreatBundle {
            version: "2026.07.30".into(),
            ..Default::default()
        };

        let r = apply_update_bytes(Some(&current), &bytes, Some(&kp.public)).unwrap();
        assert!(!r.skipped);
        assert_eq!(r.to_version, "2026.09.01");
        assert!(r.bundle.is_malicious_domain("cdn-new.example"));
    }

    #[test]
    fn skip_when_not_newer() {
        let kp = generate_keypair();
        let mut bundle = ThreatBundle {
            version: "2026.07.30".into(),
            ..Default::default()
        };
        bundle.sign_ed25519(&kp).unwrap();
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let r = apply_update_bytes(Some(&bundle), &bytes, Some(&kp.public)).unwrap();
        assert!(r.skipped);
    }

    #[test]
    fn fetch_local_manifest_and_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_keypair();
        let mut bundle = ThreatBundle {
            version: "2026.10.01".into(),
            ..Default::default()
        };
        bundle.sign_ed25519(&kp).unwrap();
        let bundle_path = dir.path().join("bundle.json");
        bundle.write_path(&bundle_path).unwrap();

        let manifest = UpdateManifest {
            channel: "stable".into(),
            latest_version: "2026.10.01".into(),
            bundle_url: "bundle.json".into(),
            min_client_version: None,
            notes: Some("test".into()),
        };
        let manifest_path = dir.path().join("manifest.json");
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        f.write_all(serde_json::to_string_pretty(&manifest).unwrap().as_bytes())
            .unwrap();

        let url = format!("file://{}", manifest_path.display());
        let r = fetch_from_manifest(&url, None, Some(&kp.public)).unwrap();
        assert!(!r.skipped);
        assert_eq!(r.bundle.version, "2026.10.01");
    }
}

//! Release-oriented security helpers (audit key, intel fail-closed).

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Ensure a passphrase exists for audit encryption.
///
/// Order: `AGENTGUARD_AUDIT_KEY` env → existing file → generate & write file.
pub fn ensure_audit_key_file(path: impl AsRef<Path>) -> Result<String> {
    if let Ok(k) = std::env::var("AGENTGUARD_AUDIT_KEY") {
        if !k.is_empty() {
            return Ok(k);
        }
    }
    let path = path.as_ref();
    if path.exists() {
        let k = fs::read_to_string(path)?.trim().to_string();
        if k.is_empty() {
            bail!("audit key file empty: {}", path.display());
        }
        return Ok(k);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let key = format!("agk_{}", uuid::Uuid::new_v4().simple());
    fs::write(path, &key).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

pub fn default_audit_key_path() -> PathBuf {
    let mut dir = dirs_data();
    dir.push("agentguard");
    dir.push("audit.key");
    dir
}

fn dirs_data() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Application Support");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(ad) = std::env::var_os("APPDATA") {
            return PathBuf::from(ad);
        }
    }
    std::env::temp_dir()
}

/// True when built as a release binary (not debug_assertions).
pub fn is_release_build() -> bool {
    !cfg!(debug_assertions)
}

/// Auto-approve (test bypass) allowed only in debug builds unless env override.
pub fn auto_approve_allowed() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    matches!(
        std::env::var("AGENTGUARD_ALLOW_AUTO_APPROVE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let a = ensure_audit_key_file(&path).unwrap();
        let b = ensure_audit_key_file(&path).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("agk_"));
    }
}

//! Optional SQLCipher key handling for the audit store.
//!
//! Default builds use plain SQLite (`sqlite-bundled`). Encrypt at rest with:
//! `cargo build -p guard-audit --no-default-features --features sqlcipher`
//! then open via [`crate::AuditStore::open_with_key`] or `AGENTGUARD_AUDIT_KEY`.

use anyhow::{bail, Result};

/// Whether this build linked SQLCipher.
pub fn sqlcipher_enabled() -> bool {
    cfg!(feature = "sqlcipher")
}

/// Resolve passphrase from explicit arg, else `AGENTGUARD_AUDIT_KEY`.
pub fn resolve_passphrase(explicit: Option<&str>) -> Option<String> {
    if let Some(k) = explicit {
        if !k.is_empty() {
            return Some(k.to_string());
        }
    }
    std::env::var("AGENTGUARD_AUDIT_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Apply SQLCipher key pragma, or reject if key requested without feature.
pub(crate) fn apply_key(conn: &rusqlite::Connection, key: Option<&str>) -> Result<()> {
    let Some(pass) = key.filter(|k| !k.is_empty()) else {
        return Ok(());
    };

    if !sqlcipher_enabled() {
        let _ = conn;
        let _ = pass;
        bail!(
            "AGENTGUARD_AUDIT_KEY / passphrase set, but guard-audit was built without \
             `--features sqlcipher` (use --no-default-features --features sqlcipher)"
        );
    }

    #[cfg(feature = "sqlcipher")]
    {
        conn.pragma_update(None, "key", pass)?;
        let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
    }
    Ok(())
}

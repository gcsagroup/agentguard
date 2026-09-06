//! Local audit store (SQLite). Optional SQLCipher via `--features sqlcipher`.

mod crypto;
mod report;
mod secure;
mod snapshot;
mod store;
mod types;

pub mod chain;
pub mod signing;

pub use crypto::{resolve_passphrase, sqlcipher_enabled};
pub use report::*;
#[cfg(target_os = "macos")]
pub use secure::ensure_macos_keychain_audit_key;
pub use secure::{
    auto_approve_allowed, default_audit_key_path, ensure_audit_key_file, is_release_build,
};
#[cfg(target_os = "macos")]
pub use signing::MacKeychainDeviceKey;
#[cfg(target_os = "windows")]
pub use signing::WindowsDpapiDeviceKey;
pub use signing::{
    message_fingerprint, AdapterVerifyKey, AuditSigner, AuditVerifyKey, FileDeviceKey, HeadWitness,
    KeyAlgorithm, SignatureVerifyReport,
};
pub use store::recovery::{
    has_legacy_plaintext_audit, migrate_legacy_audit, resolve_recovered_audit, RecoveryReceipt,
};
pub use store::AuditStore;
pub use types::*;

//! Local audit store (SQLite). Optional SQLCipher via `--features sqlcipher`.

mod crypto;
mod report;
mod secure;
mod store;
mod types;

pub mod chain;
pub mod signing;

pub use crypto::{resolve_passphrase, sqlcipher_enabled};
pub use report::*;
pub use secure::{
    auto_approve_allowed, default_audit_key_path, ensure_audit_key_file, is_release_build,
};
pub use signing::{
    AdapterVerifyKey, AuditSigner, AuditVerifyKey, FileDeviceKey, HeadWitness, KeyAlgorithm,
    SignatureVerifyReport,
};
pub use store::AuditStore;
pub use types::*;

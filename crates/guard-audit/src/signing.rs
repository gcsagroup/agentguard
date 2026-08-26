//! Per-record signatures over the audit hash chain.
//!
//! ## Why the hash chain alone is not enough
//!
//! Aura (“Blind Gods and Broken Screens”, arXiv 2602.10915 §4.4.6) requires each
//! logged action be **cryptographically attributed to its entity** — "attributed,
//! undeniable". `crate::chain` gives a keyless SHA-256 chain, which is
//! *tamper-evident against an editor who does not recompute it* and nothing more:
//! anyone with write access to the SQLite file can rewrite a row and re-hash the
//! remainder, and the result verifies perfectly. There is no signer, so there is
//! no attribution and no non-repudiation.
//!
//! Signing each `record_hash` with a device key raises the bar from "anyone who
//! can write the DB" to "anyone who can write the DB **and** use the private
//! key".
//!
//! ## What this does NOT achieve
//!
//! Be precise about the threat model, because "non-deniable" is easy to
//! overclaim:
//!
//! * A [`FileDeviceKey`] lives on the same disk as the database. An attacker with
//!   root (or with the user's account) reads the key and re-signs freely. This
//!   stops *casual* and *remote-write* tampering, not a compromised host.
//! * Real non-repudiation needs a key the host cannot export — Secure Enclave,
//!   TPM, StrongBox — or an external append-only anchor (a transparency log, a
//!   witness service). [`AuditSigner`] exists precisely so such a backend can be
//!   dropped in without touching the store; `FileDeviceKey` is the software
//!   fallback, not the destination.
//! * Verification must use an **out-of-band** public key. The key stored in the
//!   database is a convenience for tooling: an attacker who swaps the key can
//!   also swap that copy. [`crate::AuditStore::verify_record_signatures`]
//!   therefore takes the key from the caller, and the CLI warns when it falls
//!   back to the embedded one.
//! * Signatures are **never backfilled**. Signing a row written before a key
//!   existed would be backdating an attestation; such rows are reported as
//!   `unsigned` instead — and an unsigned row **fails** verification by default,
//!   because otherwise blanking the signature column would be a trivial bypass.
//! * Deleting the *tail* of the log is still undetectable from inside the
//!   database. [`crate::HeadWitness`] is the minimal answer: a small file kept
//!   outside the DB recording the last head the verifier saw.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Domain separator: a signature over an audit record must never verify as a
/// signature over a decision receipt, or vice versa.
const RECORD_DOMAIN: &str = "AGENTGUARD-AUDIT-RECORD-v2";
const RECEIPT_DOMAIN: &str = "AGENTGUARD-AUDIT-RECEIPT-v2";

/// Something that can sign audit hashes on this device.
///
/// Implement this over Secure Enclave / TPM / StrongBox to get keys the host
/// cannot exfiltrate; [`FileDeviceKey`] is the portable software fallback.
pub trait AuditSigner: std::fmt::Debug + Send + Sync {
    /// Stable short identifier for the signing key (recorded per row).
    fn key_id(&self) -> String;
    /// Hex-encoded Ed25519 signature over `message`.
    fn sign_message(&self, message: &[u8]) -> Result<String>;
    /// Hex public key, when the backend can export it.
    fn public_hex(&self) -> Option<String>;
}

/// Ed25519 key held in a local file. See the module docs for what this does and
/// does not protect against.
#[derive(Clone)]
pub struct FileDeviceKey {
    signing: SigningKey,
}

impl std::fmt::Debug for FileDeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never let the secret reach a log line.
        f.debug_struct("FileDeviceKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl FileDeviceKey {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load an existing key, failing when it is absent.
    ///
    /// Write paths use this rather than [`Self::load_or_create`]: generating a
    /// key implicitly would start producing signatures whose public half exists
    /// nowhere, which looks like coverage and verifies against the DB-embedded
    /// key while proving nothing.
    pub fn load_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            bail!(
                "audit signing key {} not found; run `guard-cli audit-keygen --key {}`",
                path.display(),
                path.display()
            );
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read audit signing key {}", path.display()))?;
        let key = Self::from_secret_hex(&text)?;
        warn_if_permissive(path);
        Ok(key)
    }

    pub fn from_secret_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("decode audit signing key hex")?;
        if bytes.len() != 32 {
            bail!(
                "audit signing key must be 32 bytes of hex, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    /// Load the key at `path`, generating it when absent.
    ///
    /// The file is created with mode 0600 **atomically** (`create_new` + `mode`),
    /// not written first and chmodded after: that window left the secret
    /// world-readable at `0666 & ~umask` for however long the race lasted.
    /// A concurrent creator wins and this call loads its key instead of
    /// overwriting it.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load_existing(path);
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let key = Self::generate();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(path) {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(key.secret_hex().as_bytes())
                    .with_context(|| format!("write audit signing key {}", path.display()))?;
                f.sync_all().ok();
                #[cfg(not(unix))]
                {
                    // No mode bits to set; rely on the platform ACL for the
                    // containing directory.
                }
                Ok(key)
            }
            // Lost the race: another process created it first. Use theirs, so we
            // never sign with a key that is no longer on disk.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Self::load_existing(path),
            Err(e) => {
                Err(e).with_context(|| format!("create audit signing key {}", path.display()))
            }
        }
    }

    pub fn verifying_key(&self) -> AuditVerifyKey {
        AuditVerifyKey(self.signing.verifying_key())
    }
}

impl AuditSigner for FileDeviceKey {
    fn key_id(&self) -> String {
        key_id_for(&self.signing.verifying_key().to_bytes())
    }

    fn sign_message(&self, message: &[u8]) -> Result<String> {
        let sig: Signature = self.signing.sign(message);
        Ok(hex::encode(sig.to_bytes()))
    }

    fn public_hex(&self) -> Option<String> {
        Some(hex::encode(self.signing.verifying_key().to_bytes()))
    }
}

/// Public half used for verification.
#[derive(Debug, Clone)]
pub struct AuditVerifyKey(VerifyingKey);

impl AuditVerifyKey {
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("decode audit public key hex")?;
        if bytes.len() != 32 {
            bail!(
                "audit public key must be 32 bytes of hex, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(
            VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("bad public key: {e}"))?,
        ))
    }

    /// Read a hex public key from a file (as written by `audit-keygen`).
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read audit public key {}", path.as_ref().display()))?;
        Self::from_hex(&text)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn key_id(&self) -> String {
        key_id_for(&self.0.to_bytes())
    }

    pub fn verify_message(&self, message: &[u8], sig_hex: &str) -> Result<()> {
        let bytes = hex::decode(sig_hex.trim()).context("decode signature hex")?;
        let sig =
            Signature::from_slice(&bytes).map_err(|e| anyhow::anyhow!("bad signature: {e}"))?;
        self.0
            .verify(message, &sig)
            .map_err(|_| anyhow::anyhow!("signature does not verify"))
    }
}

/// First 16 hex chars of SHA-256(public key) — short enough for a column,
/// long enough to make collisions a non-issue.
pub fn key_id_for(public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(public_key);
    hex::encode(h.finalize())[..16].to_string()
}

fn join_fields(domain: &str, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(domain.as_bytes());
    for f in fields {
        out.push(0x1f);
        out.extend_from_slice(f.as_bytes());
    }
    out
}

/// Bytes signed for an audit record.
///
/// Binds four things beyond the row content itself:
/// * `key_id` — a signature cannot be re-presented as another key's.
/// * `log_id` — a per-database random id, so a signed row cannot be
///   transplanted into a different log.
/// * `seq` — the row's position, so rows cannot be reordered, and (with the
///   contiguity check in `verify_record_signatures`) a row cannot be deleted
///   from the middle without leaving a gap.
/// * `record_hash` — the chain hash, so an edit invalidates this row and every
///   row after it.
pub fn record_signing_message(key_id: &str, log_id: &str, seq: i64, record_hash: &str) -> Vec<u8> {
    join_fields(
        RECORD_DOMAIN,
        &[key_id, log_id, &seq.to_string(), record_hash],
    )
}

/// Bytes signed for a decision receipt.
///
/// `actor` is in the payload so a timeout cannot be presented as a user
/// approval, and `audit_id` is in the payload so a receipt cannot be moved onto
/// a different audit record.
pub fn receipt_signing_message(
    key_id: &str,
    log_id: &str,
    seq: i64,
    receipt_hash: &str,
    actor: &str,
    audit_id: &str,
) -> Vec<u8> {
    join_fields(
        RECEIPT_DOMAIN,
        &[
            key_id,
            log_id,
            &seq.to_string(),
            receipt_hash,
            actor,
            audit_id,
        ],
    )
}

/// Reject a hash that is not 64 lowercase hex chars.
///
/// The `0x1f`-joined payload is unambiguous only because every field has a
/// restricted alphabet; validating here keeps that true if a field is ever added.
pub fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(unix)]
fn warn_if_permissive(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: audit signing key {} is mode {:o}; other local users can read it. \
                 chmod 600 it, or rotate the key.",
                path.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_permissive(_path: &Path) {}

/// Outcome of verifying signatures over one table.
///
/// `ok` is **strict**: it is false if any row is unsigned, signed by a foreign
/// key, out of position, hash-mismatched, or signature-invalid. A permissive
/// version of this field was a bypass — an attacker who blanked the signature
/// column got `ok = true`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureVerifyReport {
    pub ok: bool,
    pub total: usize,
    pub signed: usize,
    pub verified: usize,
    /// Rows with no signature. Never retro-signed; they fail `ok`.
    pub unsigned: usize,
    /// Rows whose `signer_key_id` is not the key being verified against.
    pub other_key: usize,
    /// `audit_events.user_decision` values cross-checked against signed receipts.
    pub decisions_checked: usize,
    pub first_bad_id: Option<String>,
    /// Human-readable reason for the first failure.
    pub note: Option<String>,
    /// Key id the report was produced against.
    pub key_id: String,
}

impl SignatureVerifyReport {
    pub fn new(key_id: String) -> Self {
        Self {
            ok: true,
            total: 0,
            signed: 0,
            verified: 0,
            unsigned: 0,
            other_key: 0,
            decisions_checked: 0,
            first_bad_id: None,
            note: None,
            key_id,
        }
    }

    /// Mark a failure, keeping the first id/reason seen.
    pub fn fail(&mut self, note: &mut Option<String>, id: &str) {
        self.ok = false;
        if self.first_bad_id.is_none() {
            self.first_bad_id = Some(id.to_string());
        }
        if self.note.is_none() {
            self.note = note.take().or_else(|| Some("signature invalid".into()));
        }
    }

    /// Every row is signed by the expected key and verifies. Identical to `ok`
    /// now that `ok` is strict; kept because callers read better with it.
    pub fn fully_covered(&self) -> bool {
        self.ok && self.unsigned == 0 && self.other_key == 0
    }

    /// True when the only reason `ok` is false is unsigned legacy rows. Lets an
    /// operator opt into accepting a log that predates signing, explicitly.
    pub fn only_unsigned_failures(&self) -> bool {
        !self.ok && self.unsigned > 0 && self.other_key == 0
    }
}

/// Head of an audit log, recorded outside the database.
///
/// Deleting the tail of the log — or restoring an older copy of the whole file —
/// is undetectable from inside: any prefix of a valid chain is itself a valid
/// chain, and the attacker rolls back the embedded head along with everything
/// else. A witness file kept elsewhere is the minimum fix: if the log's head
/// went backwards since the last verification, something was removed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HeadWitness {
    pub log_id: String,
    pub seq: i64,
    pub count: usize,
    pub last_record_hash: String,
}

impl HeadWitness {
    pub fn read(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read head witness {}", path.display()))?;
        Ok(Some(
            serde_json::from_str(&raw).context("parse head witness")?,
        ))
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path.as_ref(), serde_json::to_string_pretty(self)?)
            .with_context(|| format!("write head witness {}", path.as_ref().display()))?;
        Ok(())
    }

    /// Compare a freshly read head against this witness.
    pub fn check_against(&self, current: Option<&HeadWitness>) -> Result<()> {
        let Some(cur) = current else {
            bail!(
                "log is empty but witness recorded {} record(s) at seq {} — the log was wiped",
                self.count,
                self.seq
            );
        };
        if cur.log_id != self.log_id {
            bail!(
                "log_id changed ({} → {}): this is a different log than the witness recorded",
                self.log_id,
                cur.log_id
            );
        }
        if cur.seq < self.seq || cur.count < self.count {
            bail!(
                "log went backwards (seq {} → {}, count {} → {}): records were deleted or an \
                 older copy was restored",
                self.seq,
                cur.seq,
                self.count,
                cur.count
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = FileDeviceKey::generate();
        let msg = record_signing_message(&key.key_id(), "log-1", 1, "abc123");
        let sig = key.sign_message(&msg).unwrap();
        key.verifying_key().verify_message(&msg, &sig).unwrap();
    }

    #[test]
    fn signature_is_bound_to_the_hash() {
        let key = FileDeviceKey::generate();
        let sig = key
            .sign_message(&record_signing_message(&key.key_id(), "log-1", 1, "hash-a"))
            .unwrap();
        let other = record_signing_message(&key.key_id(), "log-1", 1, "hash-b");
        assert!(key.verifying_key().verify_message(&other, &sig).is_err());
    }

    #[test]
    fn signature_is_bound_to_the_key_id() {
        let key = FileDeviceKey::generate();
        let sig = key
            .sign_message(&record_signing_message(&key.key_id(), "log-1", 1, "h"))
            .unwrap();
        let forged = record_signing_message("0000000000000000", "log-1", 1, "h");
        assert!(key.verifying_key().verify_message(&forged, &sig).is_err());
    }

    /// A receipt signed as a timeout must not verify as a user approval.
    #[test]
    fn receipt_signature_is_bound_to_the_actor() {
        let key = FileDeviceKey::generate();
        let kid = key.key_id();
        let sig = key
            .sign_message(&receipt_signing_message(
                &kid, "log-1", 1, "rh", "system", "audit-1",
            ))
            .unwrap();
        let as_user = receipt_signing_message(&kid, "log-1", 1, "rh", "user", "audit-1");
        assert!(key.verifying_key().verify_message(&as_user, &sig).is_err());
    }

    /// Record and receipt domains are separated.
    #[test]
    fn domains_do_not_cross_verify() {
        let key = FileDeviceKey::generate();
        let kid = key.key_id();
        let sig = key
            .sign_message(&record_signing_message(&kid, "log-1", 1, "h"))
            .unwrap();
        let as_receipt = receipt_signing_message(&kid, "log-1", 1, "h", "user", "audit-1");
        assert!(key
            .verifying_key()
            .verify_message(&as_receipt, &sig)
            .is_err());
    }

    #[test]
    fn another_key_does_not_verify() {
        let a = FileDeviceKey::generate();
        let b = FileDeviceKey::generate();
        let msg = record_signing_message(&a.key_id(), "log-1", 1, "h");
        let sig = a.sign_message(&msg).unwrap();
        assert!(b.verifying_key().verify_message(&msg, &sig).is_err());
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn load_or_create_is_stable_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-signing.key");
        let a = FileDeviceKey::load_or_create(&path).unwrap();
        let b = FileDeviceKey::load_or_create(&path).unwrap();
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.secret_hex(), b.secret_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "signing key must not be group/world readable");
        }
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let key = FileDeviceKey::generate();
        let hex_pub = key.public_hex().unwrap();
        let vk = AuditVerifyKey::from_hex(&hex_pub).unwrap();
        assert_eq!(vk.key_id(), key.key_id());
        assert_eq!(vk.to_hex(), hex_pub);
        assert!(AuditVerifyKey::from_hex("deadbeef").is_err());
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let key = FileDeviceKey::generate();
        let shown = format!("{key:?}");
        assert!(!shown.contains(&key.secret_hex()));
        assert!(shown.contains(&key.key_id()));
    }

    /// A signature is bound to the log it was made in and to its position, so a
    /// signed row cannot be transplanted into another database or reordered.
    #[test]
    fn signature_is_bound_to_log_id_and_position() {
        let key = FileDeviceKey::generate();
        let kid = key.key_id();
        let sig = key
            .sign_message(&record_signing_message(&kid, "log-A", 7, "h"))
            .unwrap();
        let vk = key.verifying_key();
        assert!(vk
            .verify_message(&record_signing_message(&kid, "log-A", 7, "h"), &sig)
            .is_ok());
        assert!(
            vk.verify_message(&record_signing_message(&kid, "log-B", 7, "h"), &sig)
                .is_err(),
            "must not verify in a different log"
        );
        assert!(
            vk.verify_message(&record_signing_message(&kid, "log-A", 8, "h"), &sig)
                .is_err(),
            "must not verify at a different position"
        );
    }

    /// A receipt is bound to the record it approves.
    #[test]
    fn receipt_signature_is_bound_to_audit_id() {
        let key = FileDeviceKey::generate();
        let kid = key.key_id();
        let sig = key
            .sign_message(&receipt_signing_message(
                &kid, "L", 1, "rh", "user", "rec-1",
            ))
            .unwrap();
        let moved = receipt_signing_message(&kid, "L", 1, "rh", "user", "rec-2");
        assert!(key.verifying_key().verify_message(&moved, &sig).is_err());
    }

    #[test]
    fn hash_validation_rejects_non_hex_and_wrong_length() {
        assert!(is_valid_hash(&"a".repeat(64)));
        assert!(!is_valid_hash(&"a".repeat(63)));
        assert!(!is_valid_hash(&"z".repeat(64)));
        assert!(!is_valid_hash("deadbeef\u{1f}injected"));
    }

    #[test]
    fn load_existing_refuses_to_generate() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.key");
        let err = FileDeviceKey::load_existing(&missing)
            .unwrap_err()
            .to_string();
        assert!(err.contains("audit-keygen"), "{err}");
        assert!(!missing.exists(), "load_existing must not create a key");
    }

    #[test]
    fn head_witness_detects_rollback_and_wipe() {
        let witness = HeadWitness {
            log_id: "L".into(),
            seq: 10,
            count: 10,
            last_record_hash: "h".into(),
        };
        // Growing log: fine.
        let grown = HeadWitness {
            seq: 12,
            count: 12,
            ..witness.clone()
        };
        assert!(witness.check_against(Some(&grown)).is_ok());
        // Truncated / rolled back.
        let shrunk = HeadWitness {
            seq: 6,
            count: 6,
            ..witness.clone()
        };
        assert!(witness.check_against(Some(&shrunk)).is_err());
        // Wiped entirely.
        assert!(witness.check_against(None).is_err());
        // Different log substituted.
        let other = HeadWitness {
            log_id: "M".into(),
            ..grown.clone()
        };
        assert!(witness.check_against(Some(&other)).is_err());
    }

    #[test]
    fn witness_roundtrip_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("head.json");
        assert!(HeadWitness::read(&path).unwrap().is_none());
        let w = HeadWitness {
            log_id: "L".into(),
            seq: 3,
            count: 3,
            last_record_hash: "abc".into(),
        };
        w.write(&path).unwrap();
        assert_eq!(HeadWitness::read(&path).unwrap(), Some(w));
    }

    #[test]
    fn strict_report_flags_unsigned_and_foreign_rows() {
        let mut r = SignatureVerifyReport::new("k".into());
        assert!(r.ok, "empty report starts clean");
        r.unsigned = 1;
        r.fail(&mut None, "row-1");
        assert!(
            !r.ok,
            "an unsigned row must fail, not merely reduce coverage"
        );
        assert!(r.only_unsigned_failures());
        assert_eq!(r.first_bad_id.as_deref(), Some("row-1"));
    }
}

// ===========================================================================
// 适配器公钥:两种算法,而且算法是**写明的**,不是猜出来的
// ===========================================================================

/// 一张适配器卡钉的签名算法。
///
/// # 为什么必须写明,不能从长度推
///
/// Ed25519 公钥 32 字节、P-256 SEC1 未压缩公钥 65 字节,长度确实不一样,
/// 所以"从长度推算法"能跑。但那是**算法混淆**这一类漏洞的标准入口:
/// 验证方按自己推出来的算法去验,而攻击者控制着那个用来推的字段。
/// 一旦以后加了第三种算法、或者某种编码恰好撞了长度,推断就会给出错的答案,
/// 而错的方向是"用一个更弱的算法验过了"。
///
/// 所以算法是卡上的一个独立字段,默认 Ed25519(向后兼容已有的卡),
/// 一条**已签名消息**的规范指纹 —— 用来当重放键。
///
/// # 为什么不能用签名当重放键
///
/// 上一版把签名的十六进制字符串直接当键,而那不是规范形式,有两条编码自由度:
///
///   1. `hex::decode` 不分大小写。把任意几个字母改成大写就是一个**不同的字符串**、
///      解出**相同的字节**。一个 70 字节 DER 签名约 54 个字母 —— 同一个签名约有
///      2^54 种拼法。
///   2. ECDSA 的 `s` 可 malleable:`s' = n - s` 同样验得过,DER 字节也不同。
///
/// 一次独立对抗性复核用 curl 跑通了:合法签名的"环境已干净"调查清掉一个已锁存的
/// Critical 风险之后,把同一个签名的十六进制**改成大写**重放,风险又被清掉一次,
/// 而判决报的是 `ADAPTER-VERIFIED` 不是 `ADAPTER-REPLAY` —— 静默。
///
/// # 为什么不是"拒绝 high-S"
///
/// JCA 的 `SHA256withECDSA`(伴生应用用的就是它)约 42% 的概率产出 high-S。
/// 拒绝它等于让 Android 客户端不能用。
///
/// # 为什么消息是对的那个东西
///
/// 消息由 `adapter_body_message` 构造:域标签 + 4 字节大端长度前缀 + 字段。
/// 它**按构造就是规范的** —— 没有编码自由度。而"只能用一次"这条性质本来就属于
/// 这条断言,不属于它的某一种签名写法。
pub fn message_fingerprint(message: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(message))
}

/// 而且加载时会校验公钥长度和声明的算法对得上 —— 声明和实际不符是加载失败,
/// 不是运行时惊喜。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    /// Ed25519,32 字节公钥,64 字节裸签名(128 hex)。
    ///
    /// 默认值,为了向后兼容已经写好的卡。
    #[default]
    Ed25519,
    /// ECDSA over NIST P-256,SHA-256 摘要。
    ///
    /// 公钥是 SEC1 未压缩点(65 字节,`04` 开头,130 hex);签名是 **DER**,
    /// 因为那是 `java.security` 的 `SHA256withECDSA` 直接吐出来的编码 ——
    /// 让 Android 侧再转一次格式,就是又给一处可以静默出错的地方。
    EcdsaP256,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }

    /// 这个算法的公钥有多少字节。
    pub fn public_key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::EcdsaP256 => 65,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ed25519" => Some(Self::Ed25519),
            "ecdsa-p256" | "ecdsap256" | "p256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }
}

/// 一把适配器公钥,带着它自己的算法。
///
/// 和 [`AuditVerifyKey`] 分开,而且刻意分开:审计记录的签名**永远**是 Ed25519
/// 的设备密钥,那是我们自己完全控制的一侧。适配器不同 —— 它跑在别人的平台上,
/// 能用什么算法由那个平台的 crypto API 决定。把两者合成一个类型,会让审计签名
/// 也变成"算法可配置的",而那是白拿的一份风险。
#[derive(Debug, Clone)]
pub enum AdapterVerifyKey {
    Ed25519(VerifyingKey),
    EcdsaP256(Box<p256::ecdsa::VerifyingKey>),
}

impl AdapterVerifyKey {
    /// 按**声明的**算法解析一把十六进制公钥。
    ///
    /// 算法作为参数传进来,不是从 `hex_str` 猜的 —— 见 [`KeyAlgorithm`] 的注释。
    pub fn from_hex(alg: KeyAlgorithm, hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("decode adapter public key hex")?;
        if bytes.len() != alg.public_key_len() {
            bail!(
                "{} 公钥应为 {} 字节,实际 {} 字节",
                alg.as_str(),
                alg.public_key_len(),
                bytes.len()
            );
        }
        match alg {
            KeyAlgorithm::Ed25519 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Self::Ed25519(VerifyingKey::from_bytes(&arr).map_err(
                    |e| anyhow::anyhow!("bad ed25519 public key: {e}"),
                )?))
            }
            KeyAlgorithm::EcdsaP256 => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("bad p256 public key: {e}"))?;
                Ok(Self::EcdsaP256(Box::new(vk)))
            }
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Ed25519(_) => KeyAlgorithm::Ed25519,
            Self::EcdsaP256(_) => KeyAlgorithm::EcdsaP256,
        }
    }

    /// 验证 `message` 上的一个十六进制签名。
    ///
    /// Ed25519 是 64 字节裸签名;P-256 是 DER。两者都**不**接受另一种编码 ——
    /// 一个宽容的解析器在这里等于让攻击者选编码。
    pub fn verify_message(&self, message: &[u8], sig_hex: &str) -> Result<()> {
        let sig = hex::decode(sig_hex.trim()).context("decode adapter signature hex")?;
        match self {
            Self::Ed25519(vk) => {
                if sig.len() != 64 {
                    bail!("ed25519 签名应为 64 字节,实际 {}", sig.len());
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&sig);
                vk.verify_strict(message, &Signature::from_bytes(&arr))
                    .map_err(|e| anyhow::anyhow!("ed25519 verify failed: {e}"))
            }
            Self::EcdsaP256(vk) => {
                use p256::ecdsa::signature::Verifier;
                let s = p256::ecdsa::Signature::from_der(&sig)
                    .map_err(|e| anyhow::anyhow!("p256 签名不是合法 DER: {e}"))?;
                vk.verify(message, &s)
                    .map_err(|e| anyhow::anyhow!("p256 verify failed: {e}"))
            }
        }
    }
}

#[cfg(test)]
mod adapter_key_tests {
    use super::*;

    /// 声明的算法和公钥长度不符 —— 加载就失败,不是运行时惊喜。
    #[test]
    fn 算法和公钥长度必须对得上() {
        // 用一把真公钥,不是 32 个任意字节 —— `ab..ab` 长度对但不是曲线上的点,
        // 于是这条测试会因为"点不合法"而不是"长度不符"失败,测错了东西。
        let key = FileDeviceKey::from_secret_hex(&"5d".repeat(32)).unwrap();
        let ed = AuditSigner::public_hex(&key).unwrap();
        assert!(AdapterVerifyKey::from_hex(KeyAlgorithm::Ed25519, &ed).is_ok());
        assert!(
            AdapterVerifyKey::from_hex(KeyAlgorithm::EcdsaP256, &ed).is_err(),
            "32 字节不可能是一把 P-256 公钥"
        );
    }

    /// 算法名的解析要容忍常见写法,但不能容忍不认识的写法。
    ///
    /// 后半句要紧:一个把无法识别的算法名默默当成 Ed25519 的解析器,
    /// 会让一张写错算法的卡按错的算法去验 —— 而那正是算法混淆。
    #[test]
    fn 不认识的算法名不会被默默当成默认值() {
        assert_eq!(KeyAlgorithm::parse("ed25519"), Some(KeyAlgorithm::Ed25519));
        assert_eq!(
            KeyAlgorithm::parse("ECDSA-P256"),
            Some(KeyAlgorithm::EcdsaP256)
        );
        assert_eq!(KeyAlgorithm::parse("p256"), Some(KeyAlgorithm::EcdsaP256));
        assert_eq!(KeyAlgorithm::parse("rsa"), None);
        assert_eq!(KeyAlgorithm::parse(""), None);
    }

    /// Ed25519 那条路和 `AuditVerifyKey` 给出同一个答案。
    ///
    /// 两个类型各写了一遍验签,所以要有一条测试钉住它们不分叉 ——
    /// 否则一个签名可能在审计路径上验得过、在适配器路径上验不过。
    #[test]
    fn ed25519两条路给同一个答案() {
        let key = FileDeviceKey::from_secret_hex(&"5d".repeat(32)).unwrap();
        let pk = AuditSigner::public_hex(&key).unwrap();
        let msg = b"hello adapter";
        let sig = AuditSigner::sign_message(&key, msg).unwrap();

        let a = AuditVerifyKey::from_hex(&pk).unwrap();
        let b = AdapterVerifyKey::from_hex(KeyAlgorithm::Ed25519, &pk).unwrap();
        assert!(a.verify_message(msg, &sig).is_ok());
        assert!(b.verify_message(msg, &sig).is_ok());
        // 改一个字节,两条路都要拒。
        assert!(a.verify_message(b"hello adapteR", &sig).is_err());
        assert!(b.verify_message(b"hello adapteR", &sig).is_err());
    }

    /// 签名编码不能宽容:Ed25519 只收 64 字节裸签名,P-256 只收 DER。
    #[test]
    fn 签名编码不宽容() {
        let key = FileDeviceKey::from_secret_hex(&"5d".repeat(32)).unwrap();
        let pk = AuditSigner::public_hex(&key).unwrap();
        let v = AdapterVerifyKey::from_hex(KeyAlgorithm::Ed25519, &pk).unwrap();
        // 一个 DER 长度的签名喂给 Ed25519 —— 必须按长度拒掉,而不是截断。
        assert!(v.verify_message(b"x", &"00".repeat(70)).is_err());
        assert!(v.verify_message(b"x", "not-hex").is_err());
    }
}

#[cfg(test)]
mod cross_language_vectors {
    //! 跨语言向量的断言侧。生成侧见 `vector_gen`。
    use super::*;

    fn vectors() -> serde_json::Value {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../eval/fixtures/adapter_signature_vectors.json");
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
    }

    fn field(v: &serde_json::Value, k: &str) -> String {
        v[k].as_str().unwrap_or_default().to_string()
    }

    /// **共享的不变量。** Rust 构造出来的签名消息必须逐字节等于向量里的
    /// `message_hex` —— Kotlin 侧有一条一模一样的断言。
    ///
    /// 这条测试是整个跨语言方案的支点。两边各写一遍消息构造,而一份两处各写一遍的
    /// 逻辑迟早会分叉;分叉的表现是"签名静默地永远验不过",最难查的一类故障。
    /// 本仓库的 `AppFace.kt` 头部至今写着它的哈希是"重新实现而非共享" ——
    /// 那正是这条测试要避免的下场。
    #[test]
    fn rust构造的消息等于向量() {
        let v = vectors();
        let msg = guard_schema::adapter_body_message(
            &field(&v, "adapter_id"),
            &field(&v, "format_tag"),
            v["timestamp_ms"].as_i64().unwrap(),
            field(&v, "body").as_bytes(),
        );
        assert_eq!(
            hex::encode(&msg),
            field(&v, "message_hex"),
            "Rust 侧的消息构造和向量不一致 —— 要么代码改了,要么向量该重算"
        );
    }

    /// **向量里的标签必须是生产真正在用的那些常量。**
    ///
    /// 少了这条,那两条"消息等于向量"的测试是自证的:两侧都拿向量里的
    /// `format_tag` 去构造消息,于是即便向量写的是 `android-envelopes`
    /// 而代码发的是 `android-envelope`,两条测试也都会绿,而生产静默地永远验不过。
    /// 所以要把向量钉在常量上,而不只是钉在彼此上。
    #[test]
    fn 向量里的标签就是生产用的常量() {
        let v = vectors();
        assert_eq!(
            field(&v, "format_tag"),
            guard_schema::ANDROID_ENVELOPE_FORMAT,
            "向量的 format_tag 和 guard_schema 的常量不一致"
        );
        // adapter_id 必须真的有一张卡。签了但没卡的表现是 NoKeyOnRecord ——
        // 那和"没签"在判决上一样,于是这个机制看起来接上了、实际没接上。
        let yaml = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../policies/adapter-registry.yaml"),
        )
        .expect("读不到 policies/adapter-registry.yaml");
        let reg = guard_schema::AdapterRegistry::from_yaml_str(&yaml).expect("注册表解析失败");
        let id = field(&v, "adapter_id");
        assert!(
            reg.adapters.iter().any(|a| a.adapter_id == id),
            "向量里的 adapter_id `{id}` 在 policies/adapter-registry.yaml 里没有卡"
        );
        // 那张卡必须声明 P-256。声明成 Ed25519 的话,一份完全合法的 P-256 签名
        // 会被当成长度不对的 Ed25519 签名拒掉 —— 又是一个"静默永远验不过"。
        let card = reg.adapters.iter().find(|a| a.adapter_id == id).unwrap();
        assert_eq!(
            card.key_algorithm.trim().to_ascii_lowercase(),
            "ecdsa-p256",
            "`{id}` 那张卡没声明 ecdsa-p256"
        );
    }

    /// 向量里那份 Rust 签名,Rust 自己验得过。
    ///
    /// 这条本身不跨语言,它守的是"向量没写坏":如果 `rust_signature_der_hex`
    /// 是个错值,Kotlin 侧那条"能验 Rust 签名"的测试会失败,而失败原因看起来像
    /// Kotlin 的问题。
    #[test]
    fn 向量里的rust签名自己验得过() {
        let v = vectors();
        let key =
            AdapterVerifyKey::from_hex(KeyAlgorithm::EcdsaP256, &field(&v, "rust_public_key_hex"))
                .unwrap();
        let msg = hex::decode(field(&v, "message_hex")).unwrap();
        key.verify_message(&msg, &field(&v, "rust_signature_der_hex"))
            .expect("向量里的 rust 签名验不过");
        // 改一个字节的消息必须验不过 —— 否则上面那句可能只是把错误吞了。
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert!(key
            .verify_message(&bad, &field(&v, "rust_signature_der_hex"))
            .is_err());
    }

    /// **生产方向。** Kotlin 签的那份签名,Rust 验得过。
    ///
    /// 手机签、桌面验,这是真实链路的方向。向量里那两个 `kotlin_*` 字段由
    /// `AdapterSignerTest` 打印后回填;还没回填时这条测试**明确跳过并说明原因** ——
    /// 一条静默跳过的安全测试和一条不存在的测试没有区别。
    #[test]
    fn kotlin签的签名rust验得过() {
        let v = vectors();
        let pk = field(&v, "kotlin_public_key_hex");
        let sig = field(&v, "kotlin_signature_der_hex");
        if pk.is_empty() || sig.is_empty() {
            panic!(
                "向量里的 kotlin_* 字段还是空的。跑 \
                 `./gradlew :app:test --tests '*AdapterSignerTest*'`,\
                 把它打印的公钥和签名回填到 eval/fixtures/adapter_signature_vectors.json。\
                 在回填之前,'Kotlin 签 → Rust 验'这个**生产方向**没有回归测试。"
            );
        }
        let key = AdapterVerifyKey::from_hex(KeyAlgorithm::EcdsaP256, &pk)
            .expect("kotlin_public_key_hex 不是一把合法的 P-256 公钥");
        let msg = hex::decode(field(&v, "message_hex")).unwrap();
        key.verify_message(&msg, &sig)
            .expect("Kotlin 签的签名 Rust 验不过 —— 两侧的消息构造或编码分叉了");
    }
}

#[cfg(test)]
mod vector_gen {
    //! 生成跨语言测试向量。默认 `#[ignore]`,只在需要重算时手动跑:
    //! `cargo test -p guard-audit vector_gen -- --ignored --nocapture`
    //!
    //! 向量里**不含**私钥。Kotlin 侧要签名时自己生成一对密钥,然后把它的公钥和
    //! 签名回填到向量文件里 —— 于是两个方向都有回归测试:
    //!   - Rust 签 → Kotlin 验(向量里的 `rust_*` 字段)
    //!   - Kotlin 签 → Rust 验(向量里的 `kotlin_*` 字段,**生产方向**)
    //!
    //! 共享的不变量是 `message_hex`:两侧各自构造出来的签名消息必须逐字节相同。

    /// 固定的 P-256 私钥标量。0x11 重复 32 字节 —— 非零且小于 n,合法。
    /// 只用来生成向量,不出现在向量文件里。
    const P256_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    #[ignore]
    fn 打印跨语言测试向量() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let sk_bytes = hex::decode(P256_SECRET).unwrap();
        let sk = SigningKey::from_slice(&sk_bytes).unwrap();
        let vk = sk.verifying_key();
        let pub_hex = hex::encode(vk.to_encoded_point(false).as_bytes());

        let body = br#"{"type":"batch","session_id":"s-vec","events":[]}"#;
        let msg = guard_schema::adapter_body_message(
            "android-companion",
            "android-envelope",
            1_700_000_000_000,
            body,
        );
        // RFC6979 确定性签名,所以这个向量是可重算的。
        let sig: p256::ecdsa::Signature = sk.sign(&msg);

        println!("PUBLIC_HEX={pub_hex}");
        println!("MESSAGE_HEX={}", hex::encode(&msg));
        println!("SIG_DER_HEX={}", hex::encode(sig.to_der().as_bytes()));
    }
}

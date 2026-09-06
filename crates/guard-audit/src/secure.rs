//! Release-oriented security helpers (audit key, intel fail-closed).

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Read a non-synchronised generic-password item from the login Keychain, or
/// create it exactly once. `SecItemAdd` is deliberately used directly instead
/// of the convenience setter: that setter updates a duplicate item, which can
/// rotate a database key when two app instances race during first launch.
#[cfg(target_os = "macos")]
pub(crate) fn macos_keychain_get_or_create(
    service: &str,
    account: &str,
    generated: &[u8],
) -> Result<Vec<u8>> {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::passwords::{get_generic_password, PasswordOptions};
    use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
    use security_framework_sys::item::kSecValueData;
    use security_framework_sys::keychain_item::SecItemAdd;

    if service.is_empty() || account.is_empty() || generated.is_empty() {
        bail!("macOS Keychain service, account and generated secret must be non-empty");
    }

    match get_generic_password(service, account) {
        Ok(secret) if !secret.is_empty() => return Ok(secret),
        Ok(_) => bail!("macOS Keychain item {service}/{account} is empty"),
        Err(error) if error.code() == errSecItemNotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read macOS Keychain item {service}/{account}"))
        }
    }

    let mut options = PasswordOptions::new_generic_password(service, account);
    #[allow(deprecated)]
    options.query.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        CFData::from_buffer(generated).into_CFType(),
    ));
    #[allow(deprecated)]
    let params = CFDictionary::from_CFType_pairs(&options.query);
    let mut returned = std::ptr::null();
    let status = unsafe { SecItemAdd(params.as_concrete_TypeRef(), &mut returned) };
    if !returned.is_null() {
        // No return-data flag was requested, so Security normally leaves this
        // null. Refuse an unexpected object rather than leaking it.
        unsafe { core_foundation::base::CFRelease(returned) };
    }
    if status == 0 {
        return Ok(generated.to_vec());
    }
    if status == errSecDuplicateItem {
        let existing = get_generic_password(service, account).with_context(|| {
            format!("read concurrently-created Keychain item {service}/{account}")
        })?;
        if existing.is_empty() {
            bail!("macOS Keychain item {service}/{account} is empty");
        }
        return Ok(existing);
    }
    Err(security_framework::base::Error::from_code(status))
        .with_context(|| format!("create macOS Keychain item {service}/{account}"))
}

/// Release SQLCipher passphrase stored in the current user's macOS Keychain.
#[cfg(target_os = "macos")]
pub fn ensure_macos_keychain_audit_key(service: &str, account: &str) -> Result<String> {
    let generated = format!("agk_{}", uuid::Uuid::new_v4().simple());
    let secret = macos_keychain_get_or_create(service, account, generated.as_bytes())?;
    let key = String::from_utf8(secret).context("macOS Keychain audit key is not UTF-8")?;
    if !key.starts_with("agk_") || key.len() < 20 {
        bail!("macOS Keychain audit key has an invalid format");
    }
    Ok(key)
}

/// Ensure a passphrase exists for audit encryption.
///
/// Portable order: `AGENTGUARD_AUDIT_KEY` env → existing file → generate & write file.
/// On Windows an existing file always wins the validation order: it must be a
/// matching current-user DPAPI envelope before an env override is accepted.
pub fn ensure_audit_key_file(path: impl AsRef<Path>) -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let configured = std::env::var("AGENTGUARD_AUDIT_KEY")
            .ok()
            .filter(|key| !key.is_empty());
        ensure_windows_audit_key(path.as_ref(), configured.as_deref())
    }

    #[cfg(not(target_os = "windows"))]
    {
        ensure_portable_audit_key_file(path.as_ref())
    }
}

#[cfg(not(target_os = "windows"))]
fn ensure_portable_audit_key_file(path: &Path) -> Result<String> {
    if let Ok(k) = std::env::var("AGENTGUARD_AUDIT_KEY") {
        if !k.is_empty() {
            return Ok(k);
        }
    }

    // 这个文件是审计库的加密口令。以前这里是
    // `fs::write` + 事后 `set_permissions(0600)`,而且 chmod 的结果被 `let _ =` 丢掉。
    // 三个问题,一次独立对抗性复核把它们都跑出来了:
    //
    //   1. **写后再 chmod 有窗口**。落盘那一刻是 `0666 & ~umask`(通常 0644)。
    //      同一个仓库的 `guard-intel::crypto` 和 `AuditSigner::load_or_create` 都已经
    //      改成原子创建了,这里被漏下了。
    //   2. **chmod 失败没人知道**。它一失败,口令就停在 0644,而调用方拿到的是 Ok。
    //   3. **`exists()` 和 `fs::write` 都跟随符号链接**。一条预先种下的链接能让守卫
    //      把口令写到攻击者选的位置;指向一个已存在文件时更糟 —— 那个文件的内容
    //      会被**当成口令读回来**,于是谁控制那个路径就控制审计库的密钥。
    //
    // 在 macOS / Windows 上默认目录是 0700 的用户数据目录,所以影响有限;但
    // `dirs_data()` 在其它 target(以及 HOME 没设的情况)会退到 `temp_dir()` ——
    // 也就是 `/tmp/agentguard/audit.key`,一个所有人可写的粘滞目录,三个问题全部
    // 直接可利用。
    #[cfg(unix)]
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            bail!(
                "审计口令文件 {} 是一个符号链接。拒绝跟随:\n\
                 跟随它意味着把口令写到别人选的位置,或者把别人的文件内容当成口令读回来。\n\
                 如果这条链接是你自己放的,请改成直接放文件;否则这台机器上有人在动这个路径。",
                path.display()
            );
        }
    }

    if path.exists() {
        let k = fs::read_to_string(path)?.trim().to_string();
        if k.is_empty() {
            bail!("audit key file empty: {}", path.display());
        }
        return Ok(k);
    }
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let key = format!("agk_{}", uuid::Uuid::new_v4().simple());

    // 原子创建:`create_new` + `mode` 在**同一个** open 里定权限,没有窗口。
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(key.as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
            f.sync_all().ok();
            Ok(key)
        }
        // 抢输了:另一个进程先建好了。用它那份 —— 绝不能覆盖一个已经在用的口令,
        // 那会让已有的审计库再也解不开。
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let k = fs::read_to_string(path)?.trim().to_string();
            if k.is_empty() {
                bail!("audit key file empty: {}", path.display());
            }
            Ok(k)
        }
        Err(e) => Err(e).with_context(|| format!("create {}", path.display())),
    }
}

#[cfg(target_os = "windows")]
const DPAPI_KEY_PREFIX: &[u8] = b"agentguard-dpapi-v1\n";

#[cfg(target_os = "windows")]
const DPAPI_KEY_ENTROPY: &[u8] = b"AgentGuard/guard-audit/windows/audit-encryption-key/v1";

/// Separate envelope type for the Ed25519 signing seed. Keeping a distinct
/// prefix prevents an encryption passphrase file from being accepted as a
/// signing key (or vice versa) even though both use current-user DPAPI.
#[cfg(target_os = "windows")]
const DPAPI_SIGNING_SEED_PREFIX: &[u8] = b"agentguard-signing-dpapi-v1\n";

#[cfg(target_os = "windows")]
const DPAPI_SIGNING_SEED_ENTROPY: &[u8] = b"AgentGuard/guard-audit/windows/audit-signing-seed/v1";

/// 环境变量只在磁盘上没有 key 文件时才是独立来源。已有文件必须先证明是可解封的
/// DPAPI envelope；这既防止旧明文 key 被环境变量旁路，也防止两个不同 key 悄悄分叉。
#[cfg(target_os = "windows")]
fn ensure_windows_audit_key(path: &Path, configured: Option<&str>) -> Result<String> {
    if let Some(configured) = configured.filter(|key| !key.is_empty()) {
        reject_windows_reparse_points(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let stored = read_windows_dpapi_key(path)?;
                if stored != configured {
                    bail!(
                        "AGENTGUARD_AUDIT_KEY does not match the DPAPI-protected key at {}; refusing to choose one silently. Remove the override or follow the approved clear-or-migrate recovery procedure",
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect Windows audit key {}", path.display()))
            }
        }
        return Ok(configured.to_string());
    }
    ensure_windows_dpapi_key(path)
}

/// Windows stores only a current-user DPAPI envelope on disk. A pre-existing
/// plaintext `audit.key` is not silently rewritten: doing so without an approved
/// DB migration/rollback procedure can strand the only key for an old database.
#[cfg(target_os = "windows")]
fn ensure_windows_dpapi_key(path: &Path) -> Result<String> {
    reject_windows_reparse_points(path)?;
    if path.exists() {
        return read_windows_dpapi_key(path);
    }
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let key = format!("agk_{}", uuid::Uuid::new_v4().simple());
    let mut plaintext = ensure_windows_dpapi_secret(
        path,
        DPAPI_KEY_PREFIX,
        DPAPI_KEY_ENTROPY,
        key.as_bytes(),
        "audit encryption key",
    )?;
    let resolved = std::str::from_utf8(&plaintext)
        .context("decrypted audit key is not UTF-8")?
        .to_string();
    plaintext.fill(0);
    if resolved.is_empty() {
        bail!("decrypted audit key is empty: {}", path.display());
    }
    Ok(resolved)
}

#[cfg(target_os = "windows")]
fn reject_windows_reparse_points(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    // Check every existing component, not only the leaf: a junction in the
    // parent directory redirects a later ordinary `read`/`create` just as
    // effectively as a symlink at the key path itself. This is a point-in-time
    // check; the Windows native acceptance gate still has to exercise a
    // concurrent replacement race on the target filesystem.
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                bail!(
                    "audit key path component {} is a Windows reparse point; refusing to follow it",
                    component.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect Windows audit key path component {}",
                        component.display()
                    )
                });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn read_windows_dpapi_key(path: &Path) -> Result<String> {
    let mut plaintext = read_windows_dpapi_secret(
        path,
        DPAPI_KEY_PREFIX,
        DPAPI_KEY_ENTROPY,
        "audit encryption key",
    )?;
    let key = std::str::from_utf8(&plaintext)
        .context("decrypted audit key is not UTF-8")?
        .to_string();
    plaintext.fill(0);
    if key.is_empty() {
        bail!("decrypted audit key is empty: {}", path.display());
    }
    Ok(key)
}

/// Load or atomically create the Windows audit-signing seed envelope.
///
/// The caller supplies a freshly generated 32-byte seed, but an existing file
/// always wins. A plaintext legacy `audit-signing.key`, malformed envelope, or
/// reparse point is preserved byte-for-byte and returned as an error; this
/// function never performs an implicit migration or overwrite.
#[cfg(target_os = "windows")]
pub(crate) fn ensure_windows_dpapi_signing_seed(
    path: &Path,
    generated: &[u8; 32],
) -> Result<Vec<u8>> {
    ensure_windows_dpapi_secret(
        path,
        DPAPI_SIGNING_SEED_PREFIX,
        DPAPI_SIGNING_SEED_ENTROPY,
        generated,
        "audit signing key",
    )
}

#[cfg(target_os = "windows")]
fn ensure_windows_dpapi_secret(
    path: &Path,
    prefix: &[u8],
    entropy: &[u8],
    generated: &[u8],
    purpose: &str,
) -> Result<Vec<u8>> {
    reject_windows_reparse_points(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => return read_windows_dpapi_secret(path, prefix, entropy, purpose),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Windows {purpose} {}", path.display()))
        }
    }
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    reject_windows_reparse_points(path)?;

    let protected = dpapi_protect(generated, entropy)
        .with_context(|| format!("protect Windows {purpose} with current-user DPAPI"))?;
    let mut encoded = Vec::with_capacity(prefix.len() + protected.len() * 2 + 1);
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(hex::encode(protected).as_bytes());
    encoded.push(b'\n');

    match publish_windows_dpapi_envelope(path, &encoded, purpose)? {
        true => Ok(generated.to_vec()),
        false => read_windows_dpapi_secret(path, prefix, entropy, purpose),
    }
}

#[cfg(target_os = "windows")]
fn publish_windows_dpapi_envelope(path: &Path, encoded: &[u8], purpose: &str) -> Result<bool> {
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "Windows {purpose} path has no file name: {}",
            path.display()
        )
    })?;
    let mut staging_name = OsString::from(".");
    staging_name.push(file_name);
    staging_name.push(format!(
        ".agentguard-dpapi-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let staging = path.with_file_name(staging_name);

    (|| -> Result<bool> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(&staging)
            .with_context(|| format!("create staged DPAPI {purpose} {}", staging.display()))?;
        file.write_all(encoded)
            .with_context(|| format!("write staged DPAPI {purpose} {}", staging.display()))?;
        file.sync_all()
            .with_context(|| format!("sync staged DPAPI {purpose} {}", staging.display()))?;
        drop(file);

        // MoveFileEx without MOVEFILE_REPLACE_EXISTING publishes the already
        // complete, synced file in one no-clobber filesystem operation. If
        // another process won the race, its envelope is validated instead.
        reject_windows_reparse_points(path)?;
        let staging_wide: Vec<u16> = staging.as_os_str().encode_wide().chain(Some(0)).collect();
        let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both buffers are NUL-terminated and remain alive for the call.
        let moved = unsafe {
            MoveFileExW(
                staging_wide.as_ptr(),
                path_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved != 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(error).with_context(|| format!("publish DPAPI {purpose} {}", path.display()))
        }
    })()
}

#[cfg(target_os = "windows")]
fn read_windows_dpapi_secret(
    path: &Path,
    prefix: &[u8],
    entropy: &[u8],
    purpose: &str,
) -> Result<Vec<u8>> {
    reject_windows_reparse_points(path)?;
    let raw = fs::read(path).with_context(|| format!("read DPAPI {purpose} {}", path.display()))?;
    let Some(encoded) = raw.strip_prefix(prefix) else {
        bail!(
            "legacy plaintext or wrong-type {purpose} detected at {}. It was not modified. Stop the old build, back up the audit DB/key/sidecars with access controls, then follow the approved clear-or-migrate procedure; Windows Release accepts only the expected current-user DPAPI envelope",
            path.display()
        );
    };
    let protected = hex::decode(
        std::str::from_utf8(encoded)
            .with_context(|| format!("DPAPI {purpose} envelope is not UTF-8"))?
            .trim(),
    )
    .with_context(|| format!("decode DPAPI {purpose} envelope"))?;
    dpapi_unprotect(&protected, entropy).with_context(|| format!("unprotect Windows {purpose}"))
}

#[cfg(target_os = "windows")]
fn dpapi_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let length = u32::try_from(plaintext.len()).context("audit key is too large for DPAPI")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let entropy_length =
        u32::try_from(entropy.len()).context("DPAPI product entropy is too large")?;
    let optional_entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_length,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input references `plaintext` for the duration of the call; DPAPI
    // allocates output with LocalAlloc and we copy it before LocalFree.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &optional_entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("CryptProtectData(audit key)");
    }
    // SAFETY: a successful CryptProtectData returns `cbData` readable bytes.
    let protected = unsafe {
        std::slice::from_raw_parts(output.pbData.cast_const(), output.cbData as usize).to_vec()
    };
    // SAFETY: DPAPI documents that the returned buffer must be freed by LocalFree.
    unsafe {
        let _ = LocalFree(output.pbData.cast());
    }
    Ok(protected)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(protected: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let length = u32::try_from(protected.len()).context("DPAPI envelope is too large")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: protected.as_ptr().cast_mut(),
    };
    let entropy_length =
        u32::try_from(entropy.len()).context("DPAPI product entropy is too large")?;
    let optional_entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_length,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input references `protected` for the duration of the call; output
    // follows the same LocalAlloc/LocalFree contract as CryptProtectData.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &optional_entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("CryptUnprotectData(audit key)");
    }
    // SAFETY: a successful CryptUnprotectData returns `cbData` readable bytes.
    let plaintext = unsafe {
        std::slice::from_raw_parts(output.pbData.cast_const(), output.cbData as usize).to_vec()
    };
    // Clear the LocalAlloc buffer before releasing it; the returned Vec is
    // cleared by the caller after converting to the passphrase String.
    // SAFETY: output is writable for exactly `cbData` bytes and LocalFree-owned.
    unsafe {
        std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).fill(0);
        let _ = LocalFree(output.pbData.cast());
    }
    Ok(plaintext)
}

/// 建一个只有自己能进的目录(0700)。
///
/// 0600 的文件放在 0777 的目录里仍然是可以被**替换**的:攻击者删掉它、放一个自己的
/// 进去,权限位一样漂亮。所以目录权限和文件权限要一起收。
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = fs::DirBuilder::new();
        b.recursive(true).mode(0o700);
        b.create(dir)
            .with_context(|| format!("create dir {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        // Windows 上没有 mode 位可设 —— 目录继承父目录的 ACL。
        // 这在默认的用户数据目录(`%APPDATA%`)下是够的,但如果有人把 out-dir
        // 指到一个宽松的位置,这里给不出保护。和 guard-intel 里同一个缺口。
        fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))?;
    }
    Ok(())
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

/// Auto-approve is a test bypass and is never available in a Release binary.
/// An environment variable is not an authority boundary: any process that can
/// launch the app can set it, so Release must ignore it completely.
pub fn auto_approve_allowed() -> bool {
    cfg!(debug_assertions)
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

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_key_file_contains_only_a_dpapi_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.key");
        let key = ensure_audit_key_file(&path).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(DPAPI_KEY_PREFIX));
        assert!(
            !raw.windows(key.len())
                .any(|window| window == key.as_bytes()),
            "the SQLCipher passphrase was written in plaintext"
        );
        assert_eq!(ensure_audit_key_file(&path).unwrap(), key);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_rejects_legacy_plaintext_key_without_rewriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.key");
        let legacy = b"agk_legacy-plaintext";
        std::fs::write(&path, legacy).unwrap();
        let error = ensure_audit_key_file(&path)
            .expect_err("a plaintext Windows key must not be silently migrated");
        assert!(error.to_string().contains("legacy plaintext"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), legacy);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_env_override_cannot_bypass_a_legacy_plaintext_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.key");
        let legacy = b"agk_legacy-plaintext";
        std::fs::write(&path, legacy).unwrap();
        let error = ensure_windows_audit_key(&path, Some("agk_configured-override"))
            .expect_err("an environment override must not bypass legacy-key rejection");
        assert!(error.to_string().contains("legacy plaintext"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), legacy);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_env_override_must_match_an_existing_dpapi_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.key");
        let generated = ensure_windows_audit_key(&path, None).unwrap();
        let envelope = std::fs::read(&path).unwrap();

        assert_eq!(
            ensure_windows_audit_key(&path, Some(&generated)).unwrap(),
            generated
        );
        let error = ensure_windows_audit_key(&path, Some("agk_different-override"))
            .expect_err("two different audit keys must not be selected silently");
        assert!(error.to_string().contains("does not match"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), envelope);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_dpapi_entropy_rejects_a_relabelled_signing_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let signing_path = dir.path().join("audit-signing.key");
        let audit_path = dir.path().join("audit.key");
        let seed = [b'A'; 32];
        ensure_windows_dpapi_signing_seed(&signing_path, &seed).unwrap();

        let signing_envelope = std::fs::read(&signing_path).unwrap();
        let payload = signing_envelope
            .strip_prefix(DPAPI_SIGNING_SEED_PREFIX)
            .unwrap();
        let mut relabelled = DPAPI_KEY_PREFIX.to_vec();
        relabelled.extend_from_slice(payload);
        std::fs::write(&audit_path, &relabelled).unwrap();

        let error = read_windows_dpapi_key(&audit_path)
            .expect_err("the outer prefix must not be enough to change an envelope's purpose");
        assert!(
            format!("{error:#}").contains("CryptUnprotectData"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&audit_path).unwrap(), relabelled);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_interrupted_staging_file_does_not_block_first_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-signing.key");
        let interrupted = dir
            .path()
            .join(".audit-signing.key.agentguard-dpapi-interrupted.tmp");
        std::fs::write(&interrupted, b"partial envelope").unwrap();

        let seed = [0x5d; 32];
        assert_eq!(
            ensure_windows_dpapi_signing_seed(&path, &seed).unwrap(),
            seed
        );
        assert!(std::fs::read(&path)
            .unwrap()
            .starts_with(DPAPI_SIGNING_SEED_PREFIX));
        assert_eq!(
            std::fs::read(&interrupted).unwrap(),
            b"partial envelope",
            "recovery must not delete an unrelated or unproven staging file"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_rejects_a_parent_directory_junction() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("junction-target");
        let junction = dir.path().join("junction-parent");
        std::fs::create_dir(&target).unwrap();
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "create test junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let path = junction.join("audit-signing.key");
        let error = ensure_windows_dpapi_signing_seed(&path, &[0x5d; 32])
            .expect_err("a parent junction must not redirect the signing envelope");
        assert!(error.to_string().contains("reparse point"), "{error:#}");
        assert!(!target.join("audit-signing.key").exists());
        std::fs::remove_dir(&junction).unwrap();
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_keychain_tests {
    use super::*;
    use security_framework::passwords::delete_generic_password;

    #[test]
    fn keychain_secret_is_created_once_without_overwrite() {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let service = format!("com.agentguard.tests.{nonce}");
        let account = "audit-key-race";
        let first = macos_keychain_get_or_create(&service, account, b"first-secret").unwrap();
        let second =
            macos_keychain_get_or_create(&service, account, b"must-not-overwrite").unwrap();
        assert_eq!(first, b"first-secret");
        assert_eq!(second, first);
        delete_generic_password(&service, account).unwrap();
    }
}

#[cfg(all(test, unix))]
mod 口令文件权限 {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("agentguard-auditkey-{name}"));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// 落盘就是 0600,不是先 0644 再 chmod。
    #[test]
    fn 口令落盘是0600() {
        let d = tmp("mode");
        let p = d.join("audit.key");
        let k = ensure_audit_key_file(&p).unwrap();
        assert!(k.starts_with("agk_"));
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "落盘权限是 {mode:o}");
    }

    /// 目录也要收到 0700 —— 0600 的文件放在所有人可写的目录里仍然能被**替换**。
    #[test]
    fn 目录是0700() {
        let d = tmp("dir");
        let p = d.join("audit.key");
        ensure_audit_key_file(&p).unwrap();
        let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "目录权限是 {mode:o}");
    }

    /// **拒绝跟随符号链接。**
    ///
    /// 以前 `exists()` 和 `fs::write` 都跟随链接:一条预先种下的链接能让守卫把口令
    /// 写到攻击者选的位置;指向已存在文件时更糟 —— 那个文件的内容会被当成口令读回来,
    /// 于是谁控制那个路径就控制审计库的密钥。
    #[test]
    fn 拒绝跟随符号链接() {
        let d = tmp("symlink");
        fs::create_dir_all(&d).unwrap();
        let 受害路径 = d.join("attacker-chosen.conf");
        let 链接 = d.join("audit.key");
        std::os::unix::fs::symlink(&受害路径, &链接).unwrap();

        let err = ensure_audit_key_file(&链接).unwrap_err().to_string();
        assert!(err.contains("符号链接"), "{err}");
        assert!(
            !受害路径.exists(),
            "守卫顺着链接把口令写到了 {:?}",
            受害路径
        );

        // 指向一个**已存在**文件的链接:内容绝不能被当成口令返回。
        let 别人的文件 = d.join("someone-elses");
        fs::write(&别人的文件, "do-not-return-me").unwrap();
        let 链接2 = d.join("audit2.key");
        std::os::unix::fs::symlink(&别人的文件, &链接2).unwrap();
        let out = ensure_audit_key_file(&链接2);
        match out {
            Ok(k) => panic!("把别人的文件内容当成口令返回了:{k}"),
            Err(e) => assert!(e.to_string().contains("符号链接"), "{e}"),
        }
    }

    /// 已经存在的口令绝不能被覆盖 —— 覆盖等于让现有审计库再也解不开。
    #[test]
    fn 不覆盖已有口令() {
        let d = tmp("noclobber");
        let p = d.join("audit.key");
        let first = ensure_audit_key_file(&p).unwrap();
        let second = ensure_audit_key_file(&p).unwrap();
        assert_eq!(first, second);
    }
}

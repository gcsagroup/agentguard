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

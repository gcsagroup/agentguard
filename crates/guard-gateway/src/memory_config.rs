//! 记忆配置和密钥仅由宿主读取，必须在任务工作区之外；不存在隐式初始化或加密降级。
use crate::memory::MemoryRuntime;
use anyhow::{ensure, Context, Result};
use guard_audit::{AuditVerifyKey, FileDeviceKey, MemoryStore};
use guard_schema::ValidatedId;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryEncryption {
    PlaintextTest,
    Sqlcipher { key_file: PathBuf },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryConfig {
    pub schema_version: u16,
    pub scope_id: ValidatedId,
    pub database: PathBuf,
    pub witness: PathBuf,
    pub signing_key: PathBuf,
    pub public_key: PathBuf,
    pub allow_read: bool,
    pub allow_write: bool,
    pub encryption: MemoryEncryption,
}

pub(crate) fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "宿主配置或密钥须为当前用户持有的私有普通文件，不能是链接"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        (meta.dev(), meta.ino()) == (opened.dev(), opened.ino()),
        "宿主配置或密钥在打开时被替换"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "宿主配置或密钥超过读取上限");
    Ok(bytes)
}

impl MemoryConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_private(path, 16 * 1024)?)?;
        ensure!(
            config.schema_version == 1 && (config.allow_read || config.allow_write),
            "不支持的记忆配置版本或空权限"
        );
        let paths = config.paths();
        let mut normalized = std::collections::HashSet::new();
        for path in &paths {
            ensure!(
                path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)),
                "记忆路径必须为无 .. 的绝对路径"
            );
            let parent = path
                .parent()
                .context("记忆路径缺少父目录")?
                .canonicalize()?;
            let meta = fs::metadata(&parent)?;
            ensure!(
                meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
                "记忆目录必须为宿主私有目录"
            );
            ensure!(
                normalized.insert(parent.join(path.file_name().context("记忆路径缺少文件名")?)),
                "记忆数据库、见证和密钥路径必须独立"
            );
        }
        Ok(config)
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.database.clone(),
            self.witness.clone(),
            self.signing_key.clone(),
            self.public_key.clone(),
        ];
        if let MemoryEncryption::Sqlcipher { key_file } = &self.encryption {
            paths.push(key_file.clone());
        }
        paths
    }

    pub fn open(&self, initialize: bool) -> Result<MemoryRuntime> {
        let secret = read_private(&self.signing_key, 128)?;
        let key = FileDeviceKey::from_secret_hex(std::str::from_utf8(&secret)?)?;
        let public = read_private(&self.public_key, 128)?;
        let public = AuditVerifyKey::from_hex(std::str::from_utf8(&public)?)?;
        let passphrase = match &self.encryption {
            MemoryEncryption::PlaintextTest => {
                ensure!(
                    !guard_audit::is_release_build(),
                    "发布构建不接受合成明文记忆模式"
                );
                None
            }
            MemoryEncryption::Sqlcipher { key_file } => {
                ensure!(
                    guard_audit::sqlcipher_enabled(),
                    "本构建没有 SQLCipher，禁止降级为明文"
                );
                let text = String::from_utf8(read_private(key_file, 4096)?)?;
                ensure!(!text.trim().is_empty(), "记忆加密口令不能为空");
                Some(text)
            }
        };
        let store = if initialize {
            MemoryStore::create(
                &self.database,
                &self.witness,
                self.scope_id.clone(),
                Box::new(key),
                public,
                passphrase.as_deref(),
            )?
        } else {
            MemoryStore::open(
                &self.database,
                &self.witness,
                self.scope_id.clone(),
                Box::new(key),
                public,
                passphrase.as_deref(),
            )?
        };
        MemoryRuntime::new(
            store,
            self.scope_id.clone(),
            self.allow_read,
            self.allow_write,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture {
        root: PathBuf,
        config: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "agd-memory-config-{}",
                guard_audit::FileDeviceKey::generate()
                    .verifying_key()
                    .key_id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let root = root.canonicalize().unwrap();
            let config = root.join("config.json");
            let key = FileDeviceKey::generate();
            let value = MemoryConfig {
                schema_version: 1,
                scope_id: ValidatedId::new("config-test".to_string()).unwrap(),
                database: root.join("memory.db"),
                witness: root.join("head.json"),
                signing_key: root.join("secret.hex"),
                public_key: root.join("public.hex"),
                allow_read: true,
                allow_write: true,
                encryption: MemoryEncryption::PlaintextTest,
            };
            for (path, bytes) in [
                (&value.signing_key, key.secret_hex().into_bytes()),
                (&value.public_key, key.verifying_key().to_hex().into_bytes()),
                (&config, serde_json::to_vec(&value).unwrap()),
            ] {
                fs::write(path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            Self { root, config }
        }
        fn replace(&self, config: &MemoryConfig) {
            fs::write(&self.config, serde_json::to_vec(config).unwrap()).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn 必须显式初始化且损坏不能自动重建() {
        let fixture = Fixture::new();
        let config = MemoryConfig::read(&fixture.config).unwrap();
        assert!(config.open(false).is_err());
        assert!(!config.database.exists());
        drop(config.open(true).unwrap());
        assert!(config.open(true).is_err());
        drop(config.open(false).unwrap());
        fs::write(&config.witness, b"broken").unwrap();
        let before = fs::read(&config.database).unwrap();
        assert!(config.open(false).is_err());
        assert!(config.open(true).is_err());
        assert_eq!(before, fs::read(&config.database).unwrap());
    }

    #[test]
    fn 配置与密钥拒绝链接宽权限过大和不匹配公钥() {
        let fixture = Fixture::new();
        let config = MemoryConfig::read(&fixture.config).unwrap();
        let alias = fixture.root.join("alias.json");
        symlink(&fixture.config, &alias).unwrap();
        assert!(MemoryConfig::read(&alias).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&fixture.config, &alias).unwrap();
        assert!(MemoryConfig::read(&fixture.config).is_err());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&fixture.config, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(MemoryConfig::read(&fixture.config).is_err());
        fs::set_permissions(&fixture.config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&config.signing_key, "a".repeat(129)).unwrap();
        assert!(config.open(true).is_err());
        fs::write(&config.signing_key, FileDeviceKey::generate().secret_hex()).unwrap();
        assert!(config.open(true).is_err());
        fs::write(&fixture.config, " ".repeat(16 * 1024 + 1)).unwrap();
        assert!(MemoryConfig::read(&fixture.config).is_err());
    }

    #[test]
    fn 拒绝路径别名父目录公开与无能力配置() {
        let fixture = Fixture::new();
        let mut config = MemoryConfig::read(&fixture.config).unwrap();
        let old = config.witness.clone();
        config.witness = config.database.clone();
        fixture.replace(&config);
        assert!(MemoryConfig::read(&fixture.config).is_err());
        config.witness = old;
        config.allow_read = false;
        config.allow_write = false;
        fixture.replace(&config);
        assert!(MemoryConfig::read(&fixture.config).is_err());
        config.allow_read = true;
        fixture.replace(&config);
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(MemoryConfig::read(&fixture.config).is_err());
    }

    #[test]
    fn 加密模式不降级且有加密能力时实际生成密文() {
        let fixture = Fixture::new();
        let mut config = MemoryConfig::read(&fixture.config).unwrap();
        let password = fixture.root.join("cipher.txt");
        fs::write(&password, "仅限合成测试的记忆口令").unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        config.encryption = MemoryEncryption::Sqlcipher {
            key_file: password.clone(),
        };
        fixture.replace(&config);
        let config = MemoryConfig::read(&fixture.config).unwrap();
        if guard_audit::sqlcipher_enabled() {
            drop(config.open(true).unwrap());
            assert!(!fs::read(&config.database)
                .unwrap()
                .starts_with(b"SQLite format 3"));
            drop(config.open(false).unwrap());
            fs::write(password, "错误口令").unwrap();
            assert!(config.open(false).is_err());
        } else {
            assert!(config.open(true).is_err());
            assert!(!config.database.exists());
        }
    }
}

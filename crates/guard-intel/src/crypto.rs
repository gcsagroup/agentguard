//! Ed25519 helpers (dalek). Digests are SHA-256 of canonical bundle bytes.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

#[derive(Clone)]
pub struct PublicKeyBytes(pub [u8; 32]);

#[derive(Clone)]
pub struct KeyPair {
    pub public: PublicKeyBytes,
    signing: SigningKey,
}

pub fn generate_keypair() -> KeyPair {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    KeyPair {
        public: PublicKeyBytes(verifying.to_bytes()),
        signing,
    }
}

impl PublicKeyBytes {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let raw = std::fs::read(path.as_ref()).map_err(|e| e.to_string())?;
        if raw.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            return Ok(Self(arr));
        }
        // hex or base64 text
        let text = String::from_utf8_lossy(&raw).trim().to_string();
        if let Ok(bytes) = hex::decode(&text) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(Self(arr));
            }
        }
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("public key must be 32 bytes".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn write_hex(&self, path: impl AsRef<Path>) -> Result<(), String> {
        std::fs::write(path, self.to_hex()).map_err(|e| e.to_string())
    }
}

impl KeyPair {
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&secret);
        let verifying = signing.verifying_key();
        Self {
            public: PublicKeyBytes(verifying.to_bytes()),
            signing,
        }
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    /// 把私钥写进 `path`,**原子地**以 0600 创建。
    ///
    /// 以前这里是裸 `fs::write`,落盘权限是 `0666 & ~umask` —— 实测 0644,
    /// 也就是**本机其他用户可读这个发布信任根**。
    ///
    /// 两个细节都不是可选的:
    ///
    /// - `create_new(true) + mode(0600)`:一次系统调用里同时定权限。先写后 chmod
    ///   会留一个窗口,窗口期内秘密是全局可读的 —— 窗口再短也是窗口。
    /// - **不覆盖**已存在的文件。覆盖一个签名信任根是不可逆的:旧私钥没了,
    ///   所有已发布的签名都成了验不过的。一次手滑的 `intel-keygen` 不该能做到这件事。
    pub fn write_secret_hex(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} 已经存在。不覆盖:覆盖一个签名信任根是不可逆的 —— \
                     旧私钥一没,所有已发布的签名都验不过了。确认要换一把的话先把它移走。",
                    path.display()
                )
            } else {
                e.to_string()
            }
        })?;
        use std::io::Write;
        f.write_all(self.secret_hex().as_bytes())
            .map_err(|e| e.to_string())?;
        f.sync_all().ok();
        Ok(())
    }

    /// 从 `path` 读私钥。权限过宽时**拒绝**,不是告警。
    ///
    /// 为什么这里拒绝、而审计设备密钥那边只是告警(`guard-audit` 的
    /// `warn_if_permissive`):两者的时机不同。审计密钥在**运行时**加载,拒绝会让
    /// 守卫直接瞎掉 —— 那是拿"不能观测"换"不用一把可能泄露的密钥",不划算。
    /// 这把密钥只在 `intel-sign` 用,是**发布时**的操作。用一把本机其他用户读得到的
    /// 密钥签出来的情报包,看起来和真的一模一样 —— 那种产物比签不出来危险得多。
    /// 而且拒绝签名不会弄坏任何正在跑的东西。
    pub fn from_secret_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "{} 的权限是 {:o},本机其他用户读得到这把发布信任根。\n\
                     拒绝用它签名 —— 一个用泄露密钥签出来的情报包和真的分辨不出来。\n\
                     修:chmod 600 {}(如果它已经被别人读过,应该换一把:intel-keygen)",
                    path.display(),
                    mode,
                    path.display()
                ));
            }
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let bytes = hex::decode(text.trim()).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("secret key must be 32 bytes hex".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_secret_bytes(arr))
    }
}

pub fn sign_digest(keypair: &KeyPair, digest32: &[u8]) -> Result<String, String> {
    if digest32.len() != 32 {
        return Err("digest must be 32 bytes".into());
    }
    let sig: Signature = keypair.signing.sign(digest32);
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

pub fn verify_digest(
    public: &PublicKeyBytes,
    digest32: &[u8],
    sig_b64: &str,
) -> Result<(), String> {
    if digest32.len() != 32 {
        return Err("digest must be 32 bytes".into());
    }
    use base64::Engine as _;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let vk = VerifyingKey::from_bytes(&public.0).map_err(|e| e.to_string())?;
    vk.verify(digest32, &sig)
        .map_err(|_| "bad signature".into())
}

#[cfg(all(test, unix))]
mod 私钥权限 {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("agentguard-intel-key-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 落盘就是 0600,不依赖 umask。
    ///
    /// 这条测试原来不存在,而实测的落盘权限是 0644 —— 本机其他用户可读发布信任根。
    #[test]
    fn 私钥落盘是0600() {
        let d = tmp("write");
        let p = d.join("secret.hex");
        generate_keypair().write_secret_hex(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "落盘权限是 {mode:o}");
    }

    /// 不覆盖已存在的私钥 —— 覆盖一个签名信任根是不可逆的。
    #[test]
    fn 不覆盖已存在的私钥() {
        let d = tmp("nooverwrite");
        let p = d.join("secret.hex");
        let first = generate_keypair();
        first.write_secret_hex(&p).unwrap();
        let err = generate_keypair().write_secret_hex(&p).unwrap_err();
        assert!(err.contains("已经存在"), "{err}");
        // 原来那把还在。
        assert_eq!(
            KeyPair::from_secret_path(&p).unwrap().secret_hex(),
            first.secret_hex()
        );
    }

    /// 权限过宽时拒绝加载,而不是照常签名。
    ///
    /// 「照常加载但打一行告警」在这条路上不够:`intel-sign` 是一次性命令,
    /// 告警会滚过去,而签出来的情报包和真的分辨不出来。
    #[test]
    fn 权限过宽时拒绝加载() {
        let d = tmp("perm");
        let p = d.join("secret.hex");
        generate_keypair().write_secret_hex(&p).unwrap();
        // 一把一把地试:组可读、其他人可读、其他人可写。
        for bad in [0o640, 0o604, 0o606, 0o644, 0o666] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(bad)).unwrap();
            // 不用 `expect_err`:`KeyPair` 刻意没有 `Debug`,一个密钥类型实现
            // `Debug` 就会有秘密漏进日志的路。这里手写匹配,不为了测试方便去动那个。
            let err = match KeyPair::from_secret_path(&p) {
                Ok(_) => panic!("mode {bad:o} 应该被拒绝"),
                Err(e) => e,
            };
            assert!(err.contains("chmod 600"), "mode {bad:o} 的报错没给出修法:{err}");
        }
        // 收回来就能用了。
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(KeyPair::from_secret_path(&p).is_ok());
    }
}

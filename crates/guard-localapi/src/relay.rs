//! 桌面独立响应密钥。公钥由用户在手机固定；网络响应不能替换信任根。

use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    format: String,
    secret_hex: String,
}

pub struct RelayResponseKey(SigningKey);

impl RelayResponseKey {
    pub fn load(path: &Path) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).context("读取中继响应密钥")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 4096 {
            bail!("中继响应密钥必须是受限长度的普通文件");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("中继响应私钥只能由当前用户访问，请设置 0600 权限");
            }
        }
        let mut text = String::new();
        file.take(4097).read_to_string(&mut text)?;
        let stored: StoredKey = serde_json::from_str(&text).context("解析中继响应密钥")?;
        if stored.format != "agentguard-relay-response-p256-v2" {
            bail!("中继响应密钥格式不匹配，不能使用审计或适配器密钥");
        }
        let bytes = hex::decode(stored.secret_hex).context("解析中继响应私钥编码")?;
        Ok(Self(
            SigningKey::from_slice(&bytes).context("解析中继响应 P-256 私钥")?,
        ))
    }

    /// 显式命令创建新密钥或读取已有密钥；不覆写，不在 API 启动时隐式换钥。
    pub fn create_or_load(path: &Path) -> Result<Self> {
        let key = Self(SigningKey::random(&mut rand::rngs::OsRng));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Self::load(path)
            }
            Err(error) => return Err(error).context("创建中继响应密钥；父目录必须已存在"),
        };
        let stored = StoredKey {
            format: "agentguard-relay-response-p256-v2".into(),
            secret_hex: hex::encode(key.0.to_bytes()),
        };
        file.write_all(serde_json::to_string(&stored)?.as_bytes())?;
        file.sync_all()?;
        Ok(key)
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_encoded_point(false).as_bytes())
    }

    pub fn key_id(&self) -> String {
        hex::encode(Sha256::digest(
            self.0.verifying_key().to_encoded_point(false).as_bytes(),
        ))
    }

    pub fn response_headers(
        &self,
        nonce: &[u8; 32],
        request_body: &[u8],
        timestamp_ms: i64,
        response_body: &[u8],
    ) -> Result<Vec<(&'static str, String)>> {
        use guard_schema::relay::*;
        let message = response_message(
            nonce,
            &Sha256::digest(request_body).into(),
            200,
            timestamp_ms,
            response_body,
        )
        .map_err(anyhow::Error::msg)?;
        let signature: Signature = self.0.sign(&message);
        Ok(vec![
            (RELAY_VERSION_HEADER, "2".into()),
            (RELAY_KEY_HEADER, self.key_id()),
            (RELAY_TIMESTAMP_HEADER, timestamp_ms.to_string()),
            (
                RELAY_SIGNATURE_HEADER,
                hex::encode(signature.to_der().as_bytes()),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn 固定的真实http响应向量与跨语言消息一致() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../eval/fixtures/relay_response_v2.json"
        ))
        .unwrap();
        let nonce: [u8; 32] = hex::decode(vector["nonce_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let request = vector["request"].as_str().unwrap().as_bytes();
        let response = vector["response"].as_str().unwrap().as_bytes();
        let message = guard_schema::relay::response_message(
            &nonce,
            &Sha256::digest(request).into(),
            200,
            vector["timestamp_ms"].as_i64().unwrap(),
            response,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&message),
            vector["message_hex"].as_str().unwrap()
        );
        let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(
            &hex::decode(vector["public_key_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let signature = Signature::from_der(
            &hex::decode(
                vector["headers"]["x-agentguard-relay-signature"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        public.verify(&message, &signature).unwrap();
    }

    #[test]
    fn 显式建钥保持身份并拒绝其它密钥格式() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("response-key.json");
        let first = RelayResponseKey::create_or_load(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let second = RelayResponseKey::create_or_load(&path).unwrap();
        assert_eq!(first.public_hex(), second.public_hex());
        assert_eq!(bytes, std::fs::read(&path).unwrap());
        std::fs::write(&path, "11".repeat(32)).unwrap();
        assert!(RelayResponseKey::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn 拒绝共享权限和符号链接() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        RelayResponseKey::create_or_load(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(RelayResponseKey::load(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(RelayResponseKey::load(&path).is_err());
    }

    #[test]
    fn 签实际请求和响应且篡改失效() {
        let key = RelayResponseKey(SigningKey::random(&mut rand::rngs::OsRng));
        let headers = key
            .response_headers(&[1; 32], b"request", 123, b"response")
            .unwrap();
        let signature = Signature::from_der(&hex::decode(&headers[3].1).unwrap()).unwrap();
        let message = guard_schema::relay::response_message(
            &[1; 32],
            &Sha256::digest(b"request").into(),
            200,
            123,
            b"response",
        )
        .unwrap();
        assert!(key.0.verifying_key().verify(&message, &signature).is_ok());
        let changed = guard_schema::relay::response_message(
            &[1; 32],
            &Sha256::digest(b"request").into(),
            200,
            123,
            b"different",
        )
        .unwrap();
        assert!(key.0.verifying_key().verify(&changed, &signature).is_err());
    }
}

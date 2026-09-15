//! 预配令牌的有限配置：可信公钥来自宿主，不使用令牌内的公钥或远端发现地址。
use super::{error, RemoteError};
use crate::mcp_stdio::StrictJson;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// 不实现 Debug/Serialize；令牌只在对应 TLS 请求头使用，不成为工具参数。
pub struct AccessToken {
    bearer: String,
    audience: String,
    scopes: BTreeSet<String>,
    issued: u64,
    expires: u64,
    not_before: u64,
}
impl AccessToken {
    /// 首批接受 EdDSA 签名的 at+jwt、单受众和精确 scope 集合；不办理 OAuth 登录或刷新。
    pub fn verify(
        bearer: String,
        issuer: &str,
        public_key: &[u8; 32],
        audience: &str,
        scopes: &[String],
    ) -> Result<Self, RemoteError> {
        let invalid = || error("MCP_REMOTE_TOKEN");
        if bearer.len() > 4096
            || !bearer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(invalid());
        }
        let parts: Vec<_> = bearer.split('.').collect();
        if parts.len() != 3 {
            return Err(invalid());
        }
        let decode = |part: &str| -> Result<Value, RemoteError> {
            let raw = URL_SAFE_NO_PAD.decode(part).map_err(|_| invalid())?;
            serde_json::from_slice::<StrictJson>(&raw)
                .map(|v| v.0)
                .map_err(|_| invalid())
        };
        let header = decode(parts[0])?;
        if header.as_object().is_none_or(|o| o.len() != 2)
            || header["alg"] != "EdDSA"
            || header["typ"] != "at+jwt"
        {
            return Err(invalid());
        }
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| invalid())?;
        key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .map_err(|_| invalid())?;
        let claims = decode(parts[1])?;
        let object = claims.as_object().ok_or_else(invalid)?;
        if object.keys().any(|k| {
            !matches!(
                k.as_str(),
                "iss" | "aud" | "sub" | "exp" | "iat" | "nbf" | "scope" | "jti"
            )
        }) || issuer.is_empty()
            || claims["iss"].as_str() != Some(issuer)
            || claims["aud"].as_str() != Some(audience)
            || claims["sub"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s.len() > 256)
            || claims["jti"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s.len() > 256)
        {
            return Err(invalid());
        }
        let issued = claims["iat"].as_u64().ok_or_else(invalid)?;
        let expires = claims["exp"].as_u64().ok_or_else(invalid)?;
        let not_before = match claims.get("nbf") {
            Some(v) => v.as_u64().ok_or_else(invalid)?,
            None => issued,
        };
        let now = now()?;
        if issued > now
            || not_before > now
            || not_before < issued
            || expires <= now
            || expires <= issued
            || expires - issued > 3600
        {
            return Err(invalid());
        }
        let scope_text = claims["scope"].as_str().ok_or_else(invalid)?;
        let parsed: Vec<_> = scope_text.split(' ').map(str::to_owned).collect();
        let found: BTreeSet<_> = parsed.iter().cloned().collect();
        let expected: BTreeSet<_> = scopes.iter().cloned().collect();
        if expected.is_empty()
            || expected.len() != scopes.len()
            || found.len() != parsed.len()
            || found != expected
            || found.iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_:./".contains(&b))
            })
        {
            return Err(invalid());
        }
        Ok(Self {
            bearer,
            audience: audience.into(),
            scopes: found,
            issued,
            expires,
            not_before,
        })
    }
    pub(crate) fn authorize(&self, audience: &str, scope: &str) -> Result<&str, RemoteError> {
        let now = now()?;
        if self.audience != audience
            || now < self.issued
            || now < self.not_before
            || now >= self.expires
            || !self.scopes.contains(scope)
        {
            return Err(error("MCP_REMOTE_TOKEN_SCOPE_OR_TIME"));
        }
        Ok(&self.bearer)
    }
    pub(super) fn reflected(&self, bytes: &[u8]) -> bool {
        bytes
            .windows(self.bearer.len())
            .any(|w| w == self.bearer.as_bytes())
    }
}
fn now() -> Result<u64, RemoteError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| error("MCP_REMOTE_CLOCK"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    fn signed(header: Value, claims: Value, key: &SigningKey) -> String {
        let body = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        format!(
            "{}.{}",
            body,
            URL_SAFE_NO_PAD.encode(key.sign(body.as_bytes()).to_bytes())
        )
    }
    #[test]
    fn 签名受众范围期限和算法都必须匹配() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let n = now().unwrap();
        let claims = json!({"iss":"https://issuer.example","aud":"https://mcp.example/mcp","sub":"fixture","jti":"one","iat":n,"exp":n+600,"scope":"mcp:discover mcp:call"});
        let header = json!({"alg":"EdDSA","typ":"at+jwt"});
        let verify = |c: Value, h: Value, k: &SigningKey| {
            AccessToken::verify(
                signed(h, c, k),
                "https://issuer.example",
                &key.verifying_key().to_bytes(),
                "https://mcp.example/mcp",
                &["mcp:discover".into(), "mcp:call".into()],
            )
        };
        let token = verify(claims.clone(), header.clone(), &key).unwrap();
        assert!(token
            .authorize("https://mcp.example/mcp", "mcp:call")
            .is_ok());
        assert!(token
            .authorize("https://other.example/mcp", "mcp:call")
            .is_err());
        assert!(token.authorize("https://mcp.example/mcp", "admin").is_err());
        for (field, value) in [
            ("aud", json!("https://other.example/mcp")),
            ("aud", json!(["https://mcp.example/mcp"])),
            ("iss", json!("other")),
            ("scope", json!("mcp:call")),
            ("scope", json!("mcp:discover mcp:call admin")),
            ("scope", json!("mcp:discover mcp:call mcp:call")),
            ("exp", json!(n)),
            ("exp", json!(n + 3601)),
            ("iat", json!(n + 3600)),
            ("nbf", json!(n + 3600)),
            ("exp", json!("9999999999")),
        ] {
            let mut c = claims.clone();
            c[field] = value;
            assert!(verify(c, header.clone(), &key).is_err(), "{field}");
        }
        assert!(verify(claims.clone(), json!({"alg":"none","typ":"at+jwt"}), &key).is_err());
        assert!(verify(
            claims.clone(),
            json!({"alg":"EdDSA","typ":"at+jwt","jku":"http://127.0.0.1/key"}),
            &key
        )
        .is_err());
        assert!(verify(claims, header, &SigningKey::from_bytes(&[18; 32])).is_err());
    }
    #[test]
    fn 重复声明与过长令牌拒绝且错误不带秘密() {
        let result = AccessToken::verify(
            "private-secret".repeat(1000),
            "x",
            &[0; 32],
            "y",
            &["z".into()],
        );
        assert_eq!(
            result.err().unwrap().to_string(),
            "MCP_REMOTE_TOKEN；可能已派发：false；不得自动重发"
        );
        let key = SigningKey::from_bytes(&[1; 32]);
        let body = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"at+jwt"}"#),
            URL_SAFE_NO_PAD.encode(r#"{"aud":"a","aud":"b"}"#)
        );
        let token = format!(
            "{}.{}",
            body,
            URL_SAFE_NO_PAD.encode(key.sign(body.as_bytes()).to_bytes())
        );
        assert!(AccessToken::verify(
            token,
            "x",
            &key.verifying_key().to_bytes(),
            "b",
            &["z".into()]
        )
        .is_err());
    }
}

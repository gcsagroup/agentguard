//! 委托数据契约；格式正确不代表经认证，签名、公钥钉住与序号消费由宿主执行。
use crate::{ContractError, Sha256Digest, ValidatedId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DELEGATION_VERSION: u16 = 1;
pub const DELEGATION_MAX_BYTES: usize = 256 * 1024;
pub const DELEGATION_MAX_FILES: usize = 64;
pub const DELEGATION_MAX_TTL_MS: i64 = 60 * 60 * 1000;
pub const DELEGATION_MESSAGE_TTL_MS: i64 = 120_000;

fn invalid(reason: &str) -> ContractError {
    ContractError::Invalid {
        field: "delegation",
        reason: reason.into(),
    }
}

/// 首个后端是 POSIX 隔离文件工具；这里是精确文件标识，不是目录或通配模式。
pub fn validate_delegation_path(path: &str) -> Result<(), ContractError> {
    if path.len() > 4096
        || !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid("文件必须为规范的有界 POSIX 绝对路径"));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationPermissions {
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub delete_files: Vec<String>,
    pub delegate_to: Vec<ValidatedId>,
}
impl DelegationPermissions {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.read_files.len() + self.write_files.len() + self.delete_files.len()
            > DELEGATION_MAX_FILES
            || self.delegate_to.len() > 32
        {
            return Err(invalid("委托权限条目超过上限"));
        }
        for paths in [&self.read_files, &self.write_files, &self.delete_files] {
            if paths.windows(2).any(|w| w[0] >= w[1]) {
                return Err(invalid("权限列表必须排序且无重复"));
            }
            for path in paths {
                validate_delegation_path(path)?;
            }
        }
        if self
            .delegate_to
            .windows(2)
            .any(|w| w[0].as_str() >= w[1].as_str())
        {
            return Err(invalid("接收主体列表必须排序且无重复"));
        }
        Ok(())
    }
    /// 没有字段表示全部；空列表恒为空授权。
    pub fn intersect(&self, other: &Self) -> Result<Self, ContractError> {
        self.validate()?;
        other.validate()?;
        let common =
            |a: &[String], b: &[String]| a.iter().filter(|v| b.contains(v)).cloned().collect();
        Ok(Self {
            read_files: common(&self.read_files, &other.read_files),
            write_files: common(&self.write_files, &other.write_files),
            delete_files: common(&self.delete_files, &other.delete_files),
            delegate_to: self
                .delegate_to
                .iter()
                .filter(|v| other.delegate_to.contains(v))
                .cloned()
                .collect(),
        })
    }
    pub fn allows(&self, command: &DelegationCommand) -> bool {
        match command {
            DelegationCommand::Delegate { subject_id, .. } => self.delegate_to.contains(subject_id),
            DelegationCommand::ReadFile { path } => self.read_files.contains(path),
            DelegationCommand::WriteFile { path, .. } => self.write_files.contains(path),
            DelegationCommand::DeleteFile { path } => self.delete_files.contains(path),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGrant {
    pub version: u16,
    pub authority_id: ValidatedId,
    pub host_session_id: ValidatedId,
    pub grant_id: ValidatedId,
    pub session_id: ValidatedId,
    pub parent_session_id: Option<ValidatedId>,
    pub parent_grant_sha256: Option<Sha256Digest>,
    pub delegator_id: Option<ValidatedId>,
    pub subject_id: ValidatedId,
    pub target_id: ValidatedId,
    pub permissions: DelegationPermissions,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
impl DelegationGrant {
    pub fn validate(&self) -> Result<(), ContractError> {
        window(
            self.version,
            self.issued_at_ms,
            self.expires_at_ms,
            DELEGATION_MAX_TTL_MS,
        )?;
        self.permissions.validate()?;
        if self.parent_session_id.is_some() != self.parent_grant_sha256.is_some()
            || self.parent_session_id.is_some() != self.delegator_id.is_some()
            || self.parent_session_id.as_ref() == Some(&self.session_id)
        {
            return Err(invalid("父委托与父会话绑定不完整或指向自身"));
        }
        Ok(())
    }
    pub fn validate_at(&self, now_ms: i64) -> Result<(), ContractError> {
        self.validate()?;
        at(self.issued_at_ms, self.expires_at_ms, now_ms)
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        delegation_bytes(b"agentguard.delegation.grant.v1\0", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDelegationGrant {
    pub grant: DelegationGrant,
    pub key_id: ValidatedId,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum DelegationCommand {
    Delegate {
        subject_id: ValidatedId,
        permissions: DelegationPermissions,
        expires_at_ms: i64,
    },
    ReadFile {
        path: String,
    },
    WriteFile {
        path: String,
        contents: String,
    },
    DeleteFile {
        path: String,
    },
}
impl DelegationCommand {
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Delegate {
                permissions,
                expires_at_ms,
                ..
            } => {
                permissions.validate()?;
                if *expires_at_ms <= 0 {
                    return Err(invalid("委托期限必须为正"));
                }
            }
            Self::ReadFile { path } | Self::DeleteFile { path } => validate_delegation_path(path)?,
            Self::WriteFile { path, contents } => {
                validate_delegation_path(path)?;
                if contents.len() > 64 * 1024 || contents.contains('\0') {
                    return Err(invalid("委托写入正文超过限额或包含 NUL"));
                }
            }
        }
        Ok(())
    }
    pub fn binding_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        delegation_bytes(b"agentguard.delegation.operation.v1\0", self)
    }
}

/// 签名覆盖固定头部及操作摘要；审计可保留此头部，不保存命令正文或文件路径。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationMessage {
    pub version: u16,
    pub host_session_id: ValidatedId,
    pub session_id: ValidatedId,
    pub grant_id: ValidatedId,
    pub grant_sha256: Sha256Digest,
    pub actor_id: ValidatedId,
    pub target_id: ValidatedId,
    pub sequence: u64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub operation_sha256: Sha256Digest,
}
impl DelegationMessage {
    pub fn validate_at(&self, now_ms: i64) -> Result<(), ContractError> {
        window(
            self.version,
            self.issued_at_ms,
            self.expires_at_ms,
            DELEGATION_MESSAGE_TTL_MS,
        )?;
        if self.sequence == 0 {
            return Err(invalid("消息序号从 1 开始"));
        }
        at(self.issued_at_ms, self.expires_at_ms, now_ms)
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_at(self.issued_at_ms)?;
        delegation_bytes(b"agentguard.delegation.message.v1\0", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEnvelope {
    pub message: DelegationMessage,
    pub command: DelegationCommand,
    pub signature: String,
}
impl DelegationEnvelope {
    pub fn validate_at(&self, now_ms: i64) -> Result<(), ContractError> {
        self.message.validate_at(now_ms)?;
        self.command.validate()?;
        if self.signature.len() != 128
            || !self
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("委托签名必须是 64 字节小写十六进制"));
        }
        if serde_json::to_vec(self)
            .map_err(|_| invalid("消息序列化失败"))?
            .len()
            > DELEGATION_MAX_BYTES
        {
            return Err(invalid("委托消息超过限额"));
        }
        Ok(())
    }
}

fn window(version: u16, issued: i64, expires: i64, max: i64) -> Result<(), ContractError> {
    if version != DELEGATION_VERSION
        || issued < 0
        || expires <= issued
        || expires.saturating_sub(issued) > max
    {
        return Err(invalid("委托版本或时间窗口无效"));
    }
    Ok(())
}
fn at(issued: i64, expires: i64, now: i64) -> Result<(), ContractError> {
    if now < issued {
        return Err(ContractError::NotYetValid);
    }
    if now >= expires {
        return Err(ContractError::Expired);
    }
    Ok(())
}
/// 版本域及递归排序 JSON；不声称通用 RFC 8785，不归一化字符串。
pub fn delegation_bytes(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>, ContractError> {
    fn sort(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<_> = map.into_iter().collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(entries.into_iter().map(|(k, v)| (k, sort(v))).collect())
            }
            Value::Array(values) => Value::Array(values.into_iter().map(sort).collect()),
            other => other,
        }
    }
    let value = serde_json::to_value(value).map_err(|_| invalid("契约序列化失败"))?;
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(&sort(value)).map_err(|_| invalid("契约序列化失败"))?);
    if bytes.len() > DELEGATION_MAX_BYTES {
        return Err(invalid("契约超过字节限额"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 权限空集和操作种类保持独立() {
        let p = DelegationPermissions {
            read_files: vec!["/work/a".into(), "/work/b".into()],
            write_files: vec!["/work/a".into()],
            delete_files: vec![],
            delegate_to: vec![ValidatedId::new("B").unwrap()],
        };
        assert_eq!(
            p.intersect(&DelegationPermissions::default()).unwrap(),
            DelegationPermissions::default()
        );
        assert!(!p.allows(&DelegationCommand::DeleteFile {
            path: "/work/a".into()
        }));
        assert!(!p.allows(&DelegationCommand::ReadFile {
            path: "/work/ab".into()
        }));
        let readonly = DelegationPermissions {
            read_files: vec!["/work/a".into()],
            ..Default::default()
        };
        assert_eq!(p.intersect(&readonly).unwrap(), readonly);
    }
    #[test]
    fn 路径列表和未知字段严格拒绝() {
        for path in [
            "",
            "/",
            "relative",
            "/work/../secret",
            "/work/./a",
            "/work//a",
            "/work/a/",
            "/work/a\0",
            "C:\\a",
            "/work/a\\b",
        ] {
            assert!(validate_delegation_path(path).is_err(), "{path:?}");
        }
        let repeated = DelegationPermissions {
            read_files: vec!["/a".into(), "/a".into()],
            ..Default::default()
        };
        assert!(repeated.validate().is_err());
        assert!(serde_json::from_value::<DelegationCommand>(
            serde_json::json!({"operation":"read_file","path":"/a","trusted":true})
        )
        .is_err());
        assert!(serde_json::from_value::<DelegationCommand>(
            serde_json::json!({"operation":"run_shell","argv":["id"]})
        )
        .is_err());
    }
    #[test]
    fn 不同版本域和操作字段不能混为同一签名消息() {
        let read = DelegationCommand::ReadFile {
            path: "/work/中文.txt".into(),
        };
        let delete = DelegationCommand::DeleteFile {
            path: "/work/中文.txt".into(),
        };
        assert_ne!(
            read.binding_bytes().unwrap(),
            delete.binding_bytes().unwrap()
        );
        assert_ne!(
            delegation_bytes(b"message\0", &read).unwrap(),
            read.binding_bytes().unwrap()
        );
        assert_eq!(
            delegation_bytes(b"d\0", &serde_json::json!({"z":{"b":2,"a":1},"a":0})).unwrap(),
            b"d\0{\"a\":0,\"z\":{\"a\":1,\"b\":2}}".to_vec()
        );
    }
}

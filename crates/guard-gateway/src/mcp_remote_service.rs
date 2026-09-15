//! 宿主远程服务配置、私有凭据读取与实际清单。配置身份不等于远端程序代码证明。
use crate::mcp_proxy::ToolSchemas;
use crate::mcp_remote::{AccessToken, NetworkMode, RemoteClient, RemoteEndpoint};
use crate::tool_registry::{digest, SharedRegistry};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use guard_schema::{Sha256Digest, ToolPackageIdentity, ToolServiceManifest};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub service_id: String,
    pub namespace: String,
    pub url: String,
    pub address: Ipv4Addr,
    #[serde(default)]
    pub loopback_test: bool,
    pub ca_der_path: PathBuf,
    pub issuer: String,
    pub issuer_public_key: String,
    pub credentials_path: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    discovery_token: String,
    call_token: String,
}

/// 先读取全部配置，再进行任何服务发现，避免坏凭据配置混入已启动的部分服务。
pub(crate) struct RemoteSource {
    config: RemoteConfig,
    endpoint: RemoteEndpoint,
    discovery_token: Arc<AccessToken>,
    call_token: Arc<AccessToken>,
    identity: Value,
    identity_sha256: Sha256Digest,
    credential_sha256: Sha256Digest,
}
pub(crate) struct RemoteService {
    source: RemoteSource,
    pub manifest: ToolServiceManifest,
    schemas: ToolSchemas,
}
impl RemoteSource {
    pub fn load(config: RemoteConfig, shell: &guard_shell::SafeShell) -> Result<Self> {
        ensure!(
            guard_schema::valid_registry_name(&config.service_id, 64)
                && guard_schema::valid_registry_name(&config.namespace, 24)
                && config.namespace == config.namespace.to_ascii_lowercase(),
            "远程服务标识或命名空间无效"
        );
        let ca = host_file(&config.ca_der_path, shell, 16 * 1024, false)?;
        let secret = host_file(&config.credentials_path, shell, 12 * 1024, true)?;
        let credentials: Credentials =
            serde_json::from_slice(&secret).map_err(|_| anyhow::anyhow!("远程凭据文件格式无效"))?;
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&config.issuer_public_key)
            .map_err(|_| anyhow::anyhow!("远程签发公钥编码无效"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("远程签发公钥长度无效"))?;
        let mode = if config.loopback_test {
            NetworkMode::LoopbackTest
        } else {
            NetworkMode::Public
        };
        let endpoint = RemoteEndpoint::new(&config.url, config.address, mode, ca.clone())?;
        let credential_sha256 = digest(credentials.call_token.as_bytes());
        let discovery_token = Arc::new(AccessToken::verify(
            credentials.discovery_token,
            &config.issuer,
            &key,
            &config.url,
            &["mcp:discover".into()],
        )?);
        let call_token = Arc::new(AccessToken::verify(
            credentials.call_token,
            &config.issuer,
            &key,
            &config.url,
            &["mcp:discover".into(), "mcp:call".into()],
        )?);
        let identity = json!({"kind":"host_remote_connection","protocol":"2025-06-18","url":config.url,"address":config.address,
            "network_mode":if config.loopback_test{"loopback_test"}else{"public"},"ca_sha256":digest(&ca),"issuer":config.issuer,
            "issuer_key_sha256":digest(&key),"discovery_scopes":["mcp:discover"],"call_scopes":["mcp:discover","mcp:call"],
            "remote_code_attested":false});
        let identity_sha256 = digest(&guard_schema::registry_canonical_bytes(
            "remote-connection",
            identity.clone(),
        ));
        Ok(Self {
            config,
            endpoint,
            discovery_token,
            call_token,
            identity,
            identity_sha256,
            credential_sha256,
        })
    }
    pub fn discover(self, registry: &SharedRegistry) -> Result<RemoteService> {
        let mut client = RemoteClient::shared(self.endpoint.clone(), self.discovery_token.clone());
        let end = Instant::now() + Duration::from_secs(30);
        let init = client.initialize(end.saturating_duration_since(Instant::now()), &|| false)?;
        let list = client.list_tools(end.saturating_duration_since(Instant::now()), &|| false)?;
        client.close();
        let manifest = self.manifest(init, list)?;
        let schemas = ToolSchemas::compile(&manifest)?;
        let mut registry = registry.lock().map_err(|_| anyhow::anyhow!("登记锁失效"))?;
        registry.observe(manifest.clone())?;
        // 只有这个实际配置并完成发现的宿主对象能接入派发，不从手工清单创建网络入口。
        registry.attach_remote_proxy(&manifest, self.identity.clone())?;
        Ok(RemoteService {
            source: self,
            manifest,
            schemas,
        })
    }
    fn manifest(&self, init: Value, list: Value) -> Result<ToolServiceManifest> {
        Ok(ToolServiceManifest::from_mcp(
            self.config.service_id.clone(),
            self.config.namespace.clone(),
            ToolPackageIdentity {
                package_id: "agentguard-remote-connection-config".into(),
                version: "1".into(),
                sha256: self.identity_sha256.clone(),
            },
            self.identity_sha256.clone(),
            init,
            list,
        )?)
    }
}
impl RemoteService {
    pub fn original_name<'a>(&'a self, alias: &str) -> Option<&'a str> {
        self.manifest
            .tools
            .iter()
            .find(|t| format!("mcp__{}__{}", self.manifest.namespace, t.name) == alias)
            .map(|t| t.name.as_str())
    }
    pub fn available(&self) -> bool {
        self.source
            .call_token
            .authorize(&self.source.config.url, "mcp:call")
            .is_ok()
    }
    pub fn client(&self) -> Result<RemoteClient> {
        ensure!(self.available(), "远程调用凭据已失效，需要宿主重新配置");
        Ok(RemoteClient::shared(
            self.source.endpoint.clone(),
            self.source.call_token.clone(),
        ))
    }
    pub fn endpoint(&self) -> &str {
        self.source.endpoint.url()
    }
    pub fn receipt(&self) -> Value {
        json!({"connection":self.source.identity,"connection_sha256":self.source.identity_sha256,"credential_sha256":self.source.credential_sha256,"remote_code_attested":false})
    }
    pub fn validate_input(&self, name: &str, args: &Value) -> Result<()> {
        self.schemas.validate_input(name, args)
    }
    pub fn validate_output(&self, name: &str, result: &Value) -> Result<()> {
        self.schemas.validate_output(name, result)
    }
    pub fn current_manifest(&self, init: Value, list: Value) -> Result<ToolServiceManifest> {
        self.source.manifest(init, list)
    }
}

fn host_file(
    path: &Path,
    shell: &guard_shell::SafeShell,
    max: usize,
    private: bool,
) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    };
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir)),
        "远程配置文件需要无 .. 的绝对路径"
    );
    let parent = path.parent().context("远程配置文件缺少父目录")?;
    let resolved = parent.canonicalize().context("远程配置文件父目录不存在")?;
    ensure!(
        guard_schema::paths::dealias_platform_volumes(&resolved)
            == guard_schema::paths::dealias_platform_volumes(parent),
        "远程配置文件父目录不能含用户符号链接"
    );
    let name = path.file_name().context("远程配置文件缺少名称")?;
    let lexical = guard_schema::paths::dealias_platform_volumes(path);
    let physical = guard_schema::paths::dealias_platform_volumes(&resolved.join(name));
    ensure!(
        !shell
            .workspace()
            .read_grants()
            .iter()
            .chain(shell.workspace().write_grants())
            .any(|g| lexical.starts_with(g) || physical.starts_with(g)),
        "远程信任与凭据文件必须位于任务授权目录之外"
    );
    let parent = crate::isolation::open_absolute_dir(&resolved)?;
    let name = std::ffi::CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    ensure!(fd >= 0, "不能安全读取远程配置文件");
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == unsafe { libc::geteuid() }
            && info.nlink() == 1
            && info.size() <= max as u64
            && info.mode() & if private { 0o077 } else { 0o022 } == 0,
        "远程配置文件必须由当前用户持有、非链接且权限受限"
    );
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= max,
        "远程配置文件为空或过大"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn 私有文件读取拒绝工作区权限别名及超限() {
        let dir = std::env::temp_dir().join(format!("agd-remote-config-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.canonicalize().unwrap();
        let work = dir.join("workspace");
        std::fs::create_dir(&work).unwrap();
        let (shell, _) = guard_shell::SafeShell::permissive_for_tests()
            .with_workspace([work.to_str().unwrap()], [work.to_str().unwrap()]);
        let secret = dir.join("credential");
        std::fs::write(&secret, b"test-only").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(host_file(&secret, &shell, 100, true).unwrap(), b"test-only");
        assert!(host_file(&secret, &shell, 3, true).is_err());
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(host_file(&secret, &shell, 100, true).is_err());
        assert!(host_file(&secret, &shell, 100, false).is_ok());
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hard = dir.join("hard");
        std::fs::hard_link(&secret, &hard).unwrap();
        assert!(host_file(&secret, &shell, 100, true).is_err());
        std::fs::remove_file(hard).unwrap();
        let link = dir.join("link");
        symlink(&secret, &link).unwrap();
        assert!(host_file(&link, &shell, 100, true).is_err());
        let parent = dir.join("parent-link");
        symlink(&dir, &parent).unwrap();
        assert!(host_file(&parent.join("credential"), &shell, 100, true).is_err());
        let inside = work.join("token");
        std::fs::copy(&secret, &inside).unwrap();
        assert!(host_file(&inside, &shell, 100, true).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn 坏配置在建立远程客户端之前拒绝() {
        let old: crate::mcp_proxy::ProxyConfig =
            serde_json::from_value(json!({"version":1,"services":[]})).unwrap();
        assert!(old.remote_services.is_empty());
        let remote = json!({"service_id":"remote","namespace":"remote","url":"https://localhost:1234/mcp","address":"127.0.0.1","ca_der_path":"/abs/ca","issuer":"https://issuer.example","issuer_public_key":"invalid","credentials_path":"/abs/secret"});
        let config: RemoteConfig = serde_json::from_value(remote.clone()).unwrap();
        assert!(!config.loopback_test);
        let mut extra = remote.clone();
        extra["http_proxy"] = json!("http://metadata.invalid/");
        assert!(serde_json::from_value::<RemoteConfig>(extra).is_err());
        let mut extra = remote;
        extra["address"] = json!("localhost");
        assert!(serde_json::from_value::<RemoteConfig>(extra).is_err());
        assert!(serde_json::from_str::<Credentials>(
            r#"{"discovery_token":"a","call_token":"b","call_token":"c"}"#
        )
        .is_err());
    }
}

//! 安装说明只使用当前应用封装内的资源；检查不执行工具，不自动修改客户端配置。
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub struct InstallationInfo {
    app_name: String,
    app_path: String,
}

#[derive(Serialize)]
pub struct GatewaySetup {
    config: Value,
    tools: Vec<String>,
}

#[tauri::command]
pub fn get_installation_info() -> Result<InstallationInfo, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let app = executable
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .unwrap_or(&executable);
    Ok(InstallationInfo {
        app_name: app
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        app_path: app.to_string_lossy().into_owned(),
    })
}

fn resource(relative: &str) -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let root = super::bundle_resources_from_executable(&executable)
        .ok_or("SETUP_BUNDLE_REQUIRED")?
        .canonicalize()
        .map_err(|_| "SETUP_RESOURCES_MISSING")?;
    confined_resource(&root, relative)
}

fn confined_resource(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|_| "SETUP_RESOURCE_MISSING")?;
    if !path.starts_with(root) {
        return Err("SETUP_RESOURCE_OUTSIDE_BUNDLE".into());
    }
    Ok(path)
}

fn setup_relative(which: &str) -> Option<&'static str> {
    match which {
        "extension" => Some("agentguard/setup/browser-extension"),
        "fixture" => Some("agentguard/setup/acceptance"),
        _ => None,
    }
}

#[tauri::command]
pub fn open_setup_resource(which: String) -> Result<(), String> {
    let relative = setup_relative(&which).ok_or("SETUP_UNKNOWN_RESOURCE")?;
    let path = resource(relative)?;
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("/usr/bin/open")
            .arg(path)
            .status()
            .map_err(|_| "SETUP_OPEN_FAILED")?;
        if status.success() {
            Ok(())
        } else {
            Err("SETUP_OPEN_FAILED".into())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("SETUP_MACOS_REQUIRED".into())
    }
}

fn configuration(binary: &Path, rules: &Path, policy: &Path) -> Value {
    json!({"mcpServers": {"agentguard": {
        "command": binary,
        "args": ["--rules", rules.to_string_lossy(), "--shell-policy", policy.to_string_lossy(),
                 "--confirm-port", "8790", "--confirm-timeout-secs", "120"]
    }}})
}

fn parse_probe(stdout: &[u8]) -> Result<Vec<String>, String> {
    let responses: Vec<Value> = stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()
        .map_err(|_| "SETUP_PROTOCOL_INVALID")?;
    let init = responses
        .iter()
        .find(|value| value["id"] == 1)
        .ok_or("SETUP_HANDSHAKE_MISSING")?;
    if init["result"]["serverInfo"]["name"] != "agentguard-mcp" {
        return Err("SETUP_SERVER_MISMATCH".into());
    }
    let listing = responses
        .iter()
        .find(|value| value["id"] == 2)
        .ok_or("SETUP_TOOLS_MISSING")?;
    let tools = listing["result"]["tools"]
        .as_array()
        .ok_or("SETUP_TOOLS_INVALID")?;
    if tools.is_empty() {
        return Err("SETUP_TOOLS_EMPTY".into());
    }
    tools
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .filter(|name| name.len() <= 128)
                .map(str::to_owned)
                .ok_or_else(|| "SETUP_TOOL_NAME_INVALID".into())
        })
        .collect()
}

fn check_gateway() -> Result<GatewaySetup, String> {
    let binary = resource("agentguard/setup/gateway/agentguard-mcp")?;
    let rules = resource("agentguard/rules/p0_rules.yaml")?;
    let policy = resource("agentguard/setup/gateway/default.yaml")?;
    // 不传 tools/call。临时端口仅用于该短命检查进程；stderr 可能包含确认令牌，直接丢弃。
    let mut child = Command::new(&binary)
        .arg("--rules")
        .arg(&rules)
        .arg("--shell-policy")
        .arg(&policy)
        .args(["--confirm-port", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "SETUP_GATEWAY_START_FAILED")?;
    let request = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"agentguard-setup-check\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
    );
    let written = child
        .stdin
        .take()
        .ok_or("SETUP_STDIN_MISSING")?
        .write_all(request.as_bytes());
    if written.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("SETUP_REQUEST_FAILED".into());
    }
    let stdout = child.stdout.take().ok_or("SETUP_STDOUT_MISSING")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(256 * 1024)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        match child.try_wait() {
            Ok(Some(exit)) => {
                break if exit.success() {
                    Ok(())
                } else {
                    Err("SETUP_GATEWAY_EXIT")
                }
            }
            Err(_) => break Err("SETUP_GATEWAY_WAIT"),
            _ if Instant::now() >= deadline => break Err("SETUP_GATEWAY_TIMEOUT"),
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = reader
        .join()
        .map_err(|_| "SETUP_READ_FAILED")?
        .map_err(|_| "SETUP_READ_FAILED")?;
    result?;
    Ok(GatewaySetup {
        config: configuration(&binary, &rules, &policy),
        tools: parse_probe(&stdout)?,
    })
}

#[tauri::command]
pub async fn check_gateway_setup() -> Result<GatewaySetup, String> {
    tauri::async_runtime::spawn_blocking(check_gateway)
        .await
        .map_err(|_| "SETUP_WORKER_FAILED".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 资源入口只有固定的两个目标() {
        assert!(setup_relative("extension").is_some());
        for invalid in ["/", "../../", "http://example.com", "gateway"] {
            assert!(setup_relative(invalid).is_none());
        }
    }
    #[test]
    fn 配置不携带令牌或预授权工作目录() {
        let value = configuration(
            Path::new("/A B/gateway"),
            Path::new("/A B/rules"),
            Path::new("/A B/policy"),
        );
        let config = &value["mcpServers"]["agentguard"];
        assert_eq!(config["command"], "/A B/gateway");
        assert_eq!(config["args"][1], "/A B/rules");
        assert!(config.get("env").is_none());
        assert!(!value.to_string().contains("--plans"));
    }
    #[test]
    fn 只有真实握手与工具列表都通过才给配置() {
        let good = b"{\"id\":1,\"result\":{\"serverInfo\":{\"name\":\"agentguard-mcp\"}}}\n{\"id\":2,\"result\":{\"tools\":[{\"name\":\"read_file\"}]}}\n";
        assert_eq!(parse_probe(good).unwrap(), vec!["read_file"]);
        assert!(parse_probe(b"{}").is_err());
        assert!(parse_probe(&good[..good.len() / 2]).is_err());
        assert!(parse_probe(
            String::from_utf8_lossy(good)
                .replace("agentguard-mcp", "other-server")
                .as_bytes()
        )
        .is_err());
    }
}

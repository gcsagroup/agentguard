//! 安装说明只使用当前应用封装内的资源；检查不执行工具，不自动修改客户端配置。
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tauri::Manager;

#[derive(Serialize)]
pub struct CodexSetup {
    workspace: String,
    write_enabled: bool,
    command: String,
    plan_path: String,
}

pub(crate) fn checked_workspace(input: &str) -> Result<PathBuf, String> {
    let path = Path::new(input);
    if !path.is_absolute() || input.chars().any(char::is_control) {
        return Err("请填写工作区的绝对目录路径".into());
    }
    let path = path.canonicalize().map_err(|_| "工作区不存在或无法访问")?;
    if !path.is_dir() || path.parent().is_none() {
        return Err("请选择具体项目目录".into());
    }
    if std::env::var_os("HOME").is_some_and(|home| Path::new(&home) == path) {
        return Err("请选具体项目，不要授权整个个人目录".into());
    }
    Ok(path)
}

fn quote_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn prepare_codex(
    mut config: Value,
    workspace: &str,
    write_enabled: bool,
    task: &str,
    storage: &Path,
) -> Result<CodexSetup, String> {
    let workspace = checked_workspace(workspace)?;
    if task.trim().is_empty() || task.len() > 8192 || task.contains('\0') {
        return Err("请填写任务，最多 8192 字节".into());
    }
    // 配置独立于工作区，避免智能体通过正常的文件工具改写自己的授权。
    if storage.starts_with(&workspace) {
        return Err("工作区不能包含接入配置目录".into());
    }
    std::fs::create_dir_all(storage).map_err(|_| "无法创建接入配置目录")?;
    let storage = storage.canonicalize().map_err(|_| "无法访问接入配置目录")?;
    if storage.starts_with(&workspace) {
        return Err("工作区不能包含接入配置目录".into());
    }
    let plan = json!({"plans": [{"task_profile": "desktop-code-work", "allow": ["run_shell"],
        "scope": {"paths": {"read": [&workspace], "write": if write_enabled { vec![&workspace] } else { vec![] }}}}]});
    let serialized = serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?;
    guard_schema::TaskPlanLibrary::from_yaml_str(&serialized).map_err(|e| e.to_string())?;
    let directory = storage.join(uuid::Uuid::new_v4().to_string());
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&directory)
        .map_err(|_| "无法保存本次接入配置")?;
    let plan_path = directory.join("plans.json");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&plan_path)
        .and_then(|mut f| f.write_all(serialized.as_bytes()))
        .map_err(|_| "无法写入任务范围")?;
    let server = &mut config["mcpServers"]["agentguard"];
    let server_args = server["args"].as_array_mut().ok_or("网关配置不完整")?;
    if !write_enabled {
        let at = server_args
            .iter()
            .position(|value| value == "--shell-policy")
            .ok_or("缺少网关策略")?
            + 1;
        let mut policy =
            guard_shell::ShellPolicy::from_path(server_args[at].as_str().ok_or("策略路径无效")?)
                .map_err(|e| e.to_string())?;
        // 只读模式不允许用任意解释器或命令产生写入副作用。
        policy
            .denied_actions
            .extend(["run_terminal".into(), "write_file".into()]);
        let policy_path = directory.join("readonly-policy.json");
        options
            .open(&policy_path)
            .and_then(|mut file| file.write_all(serde_json::to_string(&policy).unwrap().as_bytes()))
            .map_err(|_| "无法保存只读策略")?;
        server_args[at] = json!(policy_path);
    }
    server_args.extend([
        json!("--plans"),
        json!(plan_path),
        json!("--task"),
        json!("desktop-code-work"),
    ]);
    let mut args = vec![
        "codex".to_string(),
        "exec".into(),
        "--ignore-user-config".into(),
        "--ignore-rules".into(),
        "--ephemeral".into(),
        "--skip-git-repo-check".into(),
        "--sandbox".into(),
        if write_enabled {
            "workspace-write"
        } else {
            "read-only"
        }
        .into(),
        "-C".into(),
        workspace.to_string_lossy().into_owned(),
        "-c".into(),
        "approval_policy=\"never\"".into(),
    ];
    for feature in [
        "shell_tool",
        "unified_exec",
        "plugins",
        "hooks",
        "apps",
        "browser_use",
        "browser_use_external",
        "computer_use",
        "in_app_browser",
        "memories",
        "multi_agent",
    ] {
        args.extend(["--disable".into(), feature.into()]);
    }
    for setting in [
        "web_search=\"disabled\"".to_string(),
        // 本机 CLI 的 WebSocket 多轮超时后才回落 HTTP；本次入口直接使用已验证的 HTTPS。
        "model_provider=\"agentguard-local-https\"".into(),
        "model_providers.agentguard-local-https.name=\"OpenAI\"".into(),
        "model_providers.agentguard-local-https.requires_openai_auth=true".into(),
        "model_providers.agentguard-local-https.supports_websockets=false".into(),
        format!("mcp_servers.agentguard.command={}", server["command"]),
        format!("mcp_servers.agentguard.args={}", server["args"]),
        "mcp_servers.agentguard.required=true".into(),
        "mcp_servers.agentguard.default_tools_approval_mode=\"approve\"".into(),
    ] {
        args.extend(["-c".into(), setting]);
    }
    args.push(format!("先通过 agentguard.start_session 声明 task_profile=desktop-code-work。仅使用 agentguard 工具完成下面的本地代码任务，路径使用绝对路径。需要确认或被拒绝时停止说明，不得绕过。任务：\n{task}"));
    Ok(CodexSetup {
        workspace: workspace.to_string_lossy().into_owned(),
        write_enabled,
        command: args
            .iter()
            .map(|arg| quote_argument(arg))
            .collect::<Vec<_>>()
            .join(" "),
        plan_path: plan_path.to_string_lossy().into_owned(),
    })
}

#[tauri::command]
pub async fn prepare_codex_setup(
    app: tauri::AppHandle,
    workspace: String,
    write_enabled: bool,
    task: String,
) -> Result<CodexSetup, String> {
    let storage = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("gateway-setups");
    tauri::async_runtime::spawn_blocking(move || {
        let setup = check_gateway()?;
        prepare_codex(setup.config, &workspace, write_enabled, &task, &storage)
    })
    .await
    .map_err(|_| "SETUP_WORKER_FAILED".to_string())?
}

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

pub(crate) fn resource(relative: &str) -> Result<PathBuf, String> {
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
    fn fixture() -> (PathBuf, Value) {
        let root =
            std::env::temp_dir().join(format!("agentguard-desktop-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("work space")).unwrap();
        let policy = root.join("default.json");
        std::fs::write(
            &policy,
            serde_json::to_vec(&guard_shell::ShellPolicy::default_embedded()).unwrap(),
        )
        .unwrap();
        let config = configuration(Path::new("/A B/gateway"), Path::new("/A B/rules"), &policy);
        (root, config)
    }
    #[test]
    fn 工作区必须是存在的具体绝对目录() {
        for path in ["", ".", "/", "/missing-agentguard-fixture", "/tmp\n/"] {
            assert!(checked_workspace(path).is_err(), "{path}");
        }
        assert!(checked_workspace(&std::env::var("HOME").unwrap()).is_err());
    }
    #[test]
    fn 只读配置拒绝命令写入删除且不含写权限() {
        let (root, config) = fixture();
        let result = prepare_codex(
            config,
            root.join("work space").to_str().unwrap(),
            false,
            "搜索 README",
            &root.join("setups"),
        )
        .unwrap();
        let plan: Value =
            serde_json::from_slice(&std::fs::read(&result.plan_path).unwrap()).unwrap();
        assert_eq!(plan["plans"][0]["scope"]["paths"]["write"], json!([]));
        let policy = guard_shell::ShellPolicy::from_path(
            Path::new(&result.plan_path).with_file_name("readonly-policy.json"),
        )
        .unwrap();
        let shell = guard_shell::SafeShell::from_policy(policy);
        for tool in ["run_terminal", "write_file"] {
            assert_eq!(
                shell.propose(&guard_shell::ShellAction::new(tool)),
                guard_shell::ShellDecision::Deny
            );
        }
        assert!(result.command.contains("'read-only'"));
        assert!(!result.command.contains("workspace-write"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn 读写配置只授权规范项目路径且配置位于外部() {
        let (root, config) = fixture();
        let result = prepare_codex(
            config.clone(),
            root.join("work space").to_str().unwrap(),
            true,
            "生成摘要",
            &root.join("setups"),
        )
        .unwrap();
        let plan: Value =
            serde_json::from_slice(&std::fs::read(&result.plan_path).unwrap()).unwrap();
        assert_eq!(
            plan["plans"][0]["scope"]["paths"]["write"],
            json!([result.workspace])
        );
        assert!(result.command.contains("'workspace-write'"));
        assert!(!Path::new(&result.plan_path).starts_with(&result.workspace));
        assert!(prepare_codex(
            config,
            &result.workspace,
            true,
            "生成摘要",
            &Path::new(&result.workspace).join("setups")
        )
        .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn 启动命令引用可原样往返而不执行插值() {
        let text = "带 空格 ' 引号 $(exit 17) `exit 18` \\ 路径\n第二行";
        let output = Command::new("/bin/sh")
            .args(["-c", &format!("printf %s {}", quote_argument(text))])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, text.as_bytes());
    }
    #[test]
    #[ignore = "显式生成临时配置，供真实 Codex 与网关验收脚本使用"]
    fn 生成真实接入验收配置() {
        let root = PathBuf::from(std::env::var("AGENTGUARD_SETUP_FIXTURE_ROOT").unwrap());
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let config = configuration(
            &repo.join("target/debug/agentguard-mcp"),
            &repo.join("crates/guard-schema/rules/p0_rules.yaml"),
            &repo.join("crates/guard-shell/policies/default.yaml"),
        );
        for write in [false, true] {
            let name = if write { "write" } else { "read" };
            let work = root.join(name);
            std::fs::create_dir_all(&work).unwrap();
            std::fs::write(
                work.join("README.md"),
                "AgentGuard 桌面接入验收标记：LOCAL_SETUP_OK\n",
            )
            .unwrap();
            let task = if write {
                "读取 README.md，将其中验收标记原样写到 result.txt，只做这两个操作。"
            } else {
                "读取 README.md，在最终回答中给出其中验收标记，只读取这一个文件。"
            };
            let result = prepare_codex(
                config.clone(),
                work.to_str().unwrap(),
                write,
                task,
                &root.join("setups"),
            )
            .unwrap();
            std::fs::write(
                root.join(format!("{name}.json")),
                serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
        }
    }
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

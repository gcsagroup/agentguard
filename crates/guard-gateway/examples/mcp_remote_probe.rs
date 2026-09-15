//! 仅用于自有 TLS 测试服务的互通驱动，不是生产授权入口。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use guard_gateway::mcp_remote::{AccessToken, NetworkMode, RemoteClient, RemoteEndpoint};
    use guard_gateway::mcp_stdio::Reply;
    use serde_json::{json, Value};
    use std::{net::Ipv4Addr, time::Duration};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("参数：准确 HTTPS 回环 URL、CA DER 路径、公钥 base64url 文件、令牌文件".into());
    }
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(std::fs::read_to_string(&args[3])?.trim())?
        .try_into()
        .map_err(|_| "公钥长度无效")?;
    let token = AccessToken::verify(
        std::fs::read_to_string(&args[4])?,
        "https://fixture-issuer.example",
        &key,
        &args[1],
        &["mcp:discover".into(), "mcp:call".into()],
    )?;
    let endpoint = RemoteEndpoint::new(
        &args[1],
        Ipv4Addr::LOCALHOST,
        NetworkMode::LoopbackTest,
        std::fs::read(&args[2])?,
    )?;
    let mut client = RemoteClient::new(endpoint, token);
    let end = std::time::Instant::now() + Duration::from_secs(5);
    let left = || end.saturating_duration_since(std::time::Instant::now());
    let initialized = client.initialize(left(), &|| false)?;
    let tools = client.list_tools(left(), &|| false)?;
    let Reply::Result(result) = client.call_tool(
        "echo",
        json!({"message":"independent-node-tls"}),
        left(),
        &|| false,
    )?
    else {
        return Err("测试服务返回 RPC 错误".into());
    };
    if result["structuredContent"]["echo"] != "independent-node-tls" {
        return Err("业务读回不一致".into());
    }
    client.close();
    println!(
        "{}",
        json!({"protocol":initialized["protocolVersion"],"tool_count":tools["tools"].as_array().map(Vec::len),"echo":result["structuredContent"]["echo"],"downstream_claim":result.get("_meta").unwrap_or(&Value::Null),"production_route":false})
    );
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("远程组件仅在 Linux/macOS 启用");
    std::process::exit(2);
}

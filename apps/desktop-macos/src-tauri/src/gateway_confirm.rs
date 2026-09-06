//! 网关确认通道：只连 IPv4 环回，不使用代理、重定向或持久化令牌。
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LIMIT: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Request {
    id: String,
    what: String,
    findings: Vec<Finding>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Finding {
    rule_id: String,
    layer: String,
    severity: String,
    message: String,
}
#[derive(Deserialize)]
struct RemoteStatus {
    service: String,
    confirm_protocol: u32,
    instance_id: String,
    pending: Option<Request>,
    remaining_ms: Option<u64>,
}
#[derive(Serialize)]
pub struct View {
    connection_id: String,
    port: u16,
    instance_id: String,
    pending: Option<Request>,
    remaining_ms: u64,
}
struct Connection {
    id: String,
    port: u16,
    token: String,
    instance_id: String,
    displayed: Option<Request>,
}
#[derive(Clone, Default)]
pub struct GatewayConfirm(Arc<Mutex<Option<Connection>>>);

fn hex_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 固定路径、精确 Content-Length、总期限和大小上限；错误不包含响应正文或凭据。
fn http(port: u16, token: &str, method: &str, path: &str, body: &str) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream =
        TcpStream::connect_timeout(&address, TIMEOUT).map_err(|_| "GATEWAY_UNAVAILABLE")?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| "GATEWAY_IO")?;
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).map_err(|_| "GATEWAY_IO")?;
    let mut bytes = Vec::new();
    let mut header_end = None;
    let mut expected = None;
    loop {
        let remaining = TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err("GATEWAY_TIMEOUT".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "GATEWAY_IO")?;
        let mut buffer = [0; 4096];
        let count = stream.read(&mut buffer).map_err(|_| "GATEWAY_IO")?;
        if count == 0 {
            return Err("GATEWAY_TRUNCATED".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > LIMIT + 8192 {
            return Err("GATEWAY_TOO_LARGE".into());
        }
        if header_end.is_none() {
            if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                if at > 8192 {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                let headers = std::str::from_utf8(&bytes[..at]).map_err(|_| "GATEWAY_PROTOCOL")?;
                let mut lines = headers.split("\r\n");
                let first = lines.next().ok_or("GATEWAY_PROTOCOL")?;
                let code = first.split_whitespace().nth(1).ok_or("GATEWAY_PROTOCOL")?;
                if !(first.starts_with("HTTP/1.1 ") || first.starts_with("HTTP/1.0 ")) {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                match code {
                    "200" => {}
                    "409" => return Err("GATEWAY_STALE".into()),
                    "403" => return Err("GATEWAY_AUTH".into()),
                    _ => return Err("GATEWAY_PROTOCOL".into()),
                }
                let mut length = None;
                let mut json = false;
                for line in lines {
                    let (name, value) = line.split_once(':').ok_or("GATEWAY_PROTOCOL")?;
                    if name.eq_ignore_ascii_case("transfer-encoding") {
                        return Err("GATEWAY_PROTOCOL".into());
                    }
                    if name.eq_ignore_ascii_case("content-type") {
                        json = value.trim().split(';').next() == Some("application/json");
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        if length.is_some() {
                            return Err("GATEWAY_PROTOCOL".into());
                        }
                        length = Some(
                            value
                                .trim()
                                .parse::<usize>()
                                .map_err(|_| "GATEWAY_PROTOCOL")?,
                        );
                    }
                }
                let length = length
                    .filter(|len| *len <= LIMIT)
                    .ok_or("GATEWAY_TOO_LARGE")?;
                if !json {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                header_end = Some(at + 4);
                expected = Some(at + 4 + length);
            } else if bytes.len() > 8192 {
                return Err("GATEWAY_PROTOCOL".into());
            }
        }
        if let Some(end) = expected {
            if bytes.len() >= end {
                if bytes.len() != end {
                    return Err("GATEWAY_PROTOCOL".into());
                }
                return Ok(bytes[header_end.unwrap()..end].to_vec());
            }
        }
    }
}

fn status(connection: &mut Connection) -> Result<View, String> {
    let started = Instant::now();
    let bytes = http(connection.port, &connection.token, "GET", "/status", "")?;
    let remote: RemoteStatus = serde_json::from_slice(&bytes).map_err(|_| "GATEWAY_PROTOCOL")?;
    if remote.service != "agentguard-mcp"
        || remote.confirm_protocol != 1
        || !hex_id(&remote.instance_id)
        || (!connection.instance_id.is_empty() && connection.instance_id != remote.instance_id)
    {
        return Err("GATEWAY_INSTANCE_CHANGED".into());
    }
    if let Some(request) = &remote.pending {
        if request.id.is_empty()
            || request.id.len() > 128
            || request.what.len() > 32768
            || request.findings.len() > 64
            || remote.remaining_ms.is_none()
        {
            return Err("GATEWAY_PROTOCOL".into());
        }
    }
    connection.instance_id = remote.instance_id;
    // 减去整个往返耗时，宁早过期，不在前端扩大批准窗口。
    let remaining = remote
        .remaining_ms
        .unwrap_or(0)
        .saturating_sub(started.elapsed().as_millis() as u64);
    connection.displayed = remote.pending.filter(|_| remaining > 0);
    Ok(View {
        connection_id: connection.id.clone(),
        port: connection.port,
        instance_id: connection.instance_id.clone(),
        pending: connection.displayed.clone(),
        remaining_ms: remaining,
    })
}

impl GatewayConfirm {
    fn connect(&self, port: u16, token: String) -> Result<View, String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        *slot = None;
        if port == 0 || !hex_id(&token) {
            return Err("GATEWAY_INPUT".into());
        }
        let mut connection = Connection {
            id: uuid::Uuid::new_v4().to_string(),
            port,
            token,
            instance_id: String::new(),
            displayed: None,
        };
        let view = status(&mut connection)?;
        *slot = Some(connection);
        Ok(view)
    }
    fn poll(&self, id: &str) -> Result<View, String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let connection = slot
            .as_mut()
            .filter(|c| c.id == id)
            .ok_or("GATEWAY_DISCONNECTED")?;
        let result = status(connection);
        if result.is_err() {
            *slot = None;
        }
        result
    }
    fn disconnect(&self, id: &str) -> Result<(), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        if slot.as_ref().is_some_and(|c| c.id == id) {
            *slot = None;
        }
        Ok(())
    }
    fn answer(&self, id: &str, request_id: &str, approve: bool) -> Result<(), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let connection = slot
            .as_mut()
            .filter(|c| c.id == id)
            .ok_or("GATEWAY_DISCONNECTED")?;
        let displayed = connection
            .displayed
            .take()
            .filter(|r| r.id == request_id)
            .ok_or("GATEWAY_STALE")?;
        let result = (|| {
            let current = status(connection)?;
            if current.pending.as_ref() != Some(&displayed) {
                return Err("GATEWAY_STALE".into());
            }
            let body = serde_json::json!({"id": request_id}).to_string();
            let bytes = http(
                connection.port,
                &connection.token,
                "POST",
                if approve { "/approve" } else { "/deny" },
                &body,
            )?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| "GATEWAY_PROTOCOL")?;
            if value.get("answered").and_then(|v| v.as_bool()) != Some(true) {
                return Err("GATEWAY_STALE".into());
            }
            Ok(())
        })();
        connection.displayed = None;
        // 回执不明时不重试批准；断开后由网关端期限兜底。
        if result.as_ref().is_err_and(|e| e != "GATEWAY_STALE") {
            *slot = None;
        }
        result
    }
}

#[tauri::command]
pub async fn connect_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    port: u16,
    token: String,
) -> Result<View, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.connect(port, token))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn poll_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
) -> Result<View, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.poll(&connection_id))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn disconnect_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.disconnect(&connection_id))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}
#[tauri::command]
pub async fn answer_gateway_confirmation(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
    request_id: String,
    approve: bool,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.answer(&connection_id, &request_id, approve))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;

    struct GatewayProcess {
        child: Child,
        lines: mpsc::Receiver<String>,
        port: u16,
        token: String,
    }
    impl Drop for GatewayProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl GatewayProcess {
        fn start(binary: &str) -> Self {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
            let child = Command::new(binary)
                .arg("--rules")
                .arg(root.join("crates/guard-schema/rules/p0_rules.yaml"))
                .arg("--shell-policy")
                .arg(root.join("crates/guard-shell/policies/default.yaml"))
                .args(["--confirm-port", "0", "--confirm-timeout-secs", "2"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let (tx, rx) = mpsc::channel();
            let mut process = Self {
                child,
                lines: rx,
                port: 0,
                token: String::new(),
            };
            let stderr = process.child.stderr.take().unwrap();
            let (metadata_tx, metadata_rx) = mpsc::channel();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stderr)
                    .lines()
                    .map_while(Result::ok)
                {
                    // 测试令牌只沿内存通道传递，不输出完整进程日志。
                    if metadata_tx.send(line).is_err() {
                        break;
                    }
                }
            });
            while process.port == 0 || process.token.is_empty() {
                let line = metadata_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("网关未就绪");
                if let Some(value) = line.trim().strip_prefix("确认令牌 ") {
                    process.token = value.to_owned();
                }
                if let Some(value) = line.split("http://127.0.0.1:").nth(1) {
                    process.port = value.split_whitespace().next().unwrap().parse().unwrap();
                }
            }
            let stdout = process.child.stdout.take().unwrap();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            process
        }
        fn send(&mut self, id: u64, name: &str, arguments: serde_json::Value) {
            let request = serde_json::json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{"name":name,"arguments":arguments}});
            writeln!(self.child.stdin.as_mut().unwrap(), "{request}").unwrap();
        }
        fn response(&self) -> serde_json::Value {
            serde_json::from_str(
                &self
                    .lines
                    .recv_timeout(Duration::from_secs(5))
                    .expect("MCP 未返回"),
            )
            .unwrap()
        }
        fn pending(&self, state: &GatewayConfirm, id: &str) -> Request {
            let until = Instant::now() + Duration::from_secs(1);
            while Instant::now() < until {
                if let Some(request) = state.poll(id).unwrap().pending {
                    return request;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("未出现待确认请求")
        }
    }
    #[test]
    fn 拒绝任意地址与头部注入() {
        let state = GatewayConfirm::default();
        for token in [
            "",
            "x\r\nOrigin: x",
            "http://localhost",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(state.connect(8790, token.into()).is_err());
        }
        assert!(state.connect(0, "a".repeat(32)).is_err());
    }
    #[test]
    fn 旧连接不能批准或断开新连接() {
        let state = GatewayConfirm::default();
        *state.0.lock().unwrap() = Some(Connection {
            id: "new".into(),
            port: 1,
            token: "a".repeat(32),
            instance_id: "b".repeat(32),
            displayed: None,
        });
        assert!(state.answer("old", "confirm-1", true).is_err());
        assert!(state.poll("old").is_err());
        state.disconnect("old").unwrap();
        assert!(state.0.lock().unwrap().is_some());
        state.disconnect("new").unwrap();
        assert!(state.0.lock().unwrap().is_none());
    }

    #[test]
    fn 响应拒绝重定向分块超大与截断() {
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: http://example.com\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut input = [0; 4096];
                let _ = socket.read(&mut input);
                let _ = socket.write_all(response.as_bytes());
            });
            assert!(http(port, &"a".repeat(32), "GET", "/status", "").is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    #[ignore = "需显式提供刚构建的 AGENTGUARD_GATEWAY_TEST_BIN；独立运行真实进程验收"]
    fn 真实网关允许拒绝批准超时与断连的文件副作用() {
        let binary = std::env::var("AGENTGUARD_GATEWAY_TEST_BIN").expect("缺少真实网关路径");
        let directory =
            std::env::temp_dir().join(format!("ag-desktop-confirm-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let denied = directory.join("denied.txt");
        let approved = directory.join("approved.txt");
        let timed_out = directory.join("timed-out.txt");
        let disconnected = directory.join("disconnected.txt");
        let mut gateway = GatewayProcess::start(&binary);
        let state = GatewayConfirm::default();
        assert!(state.connect(gateway.port, "0".repeat(32)).is_err());
        let view = state.connect(gateway.port, gateway.token.clone()).unwrap();
        let connection_id = view.connection_id;
        assert!(view.pending.is_none());

        gateway.send(
            1,
            "write_file",
            serde_json::json!({"path":denied,"contents":"拒绝不得写入"}),
        );
        let request = gateway.pending(&state, &connection_id);
        assert!(!denied.exists());
        assert!(state.answer(&connection_id, "wrong-id", true).is_err());
        // 不带令牌、跨站与错误请求编号均不能批准。
        for auth in ["", "Origin: https://example.com\r\n"] {
            let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, gateway.port)).unwrap();
            socket.set_read_timeout(Some(TIMEOUT)).unwrap();
            let bearer = if auth.is_empty() {
                String::new()
            } else {
                format!("Authorization: Bearer {}\r\n", gateway.token)
            };
            write!(socket, "GET /status HTTP/1.1\r\nHost: localhost\r\n{auth}{bearer}Connection: close\r\n\r\n").unwrap();
            let mut buffer = [0; 1024];
            let n = socket.read(&mut buffer).unwrap();
            assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("HTTP/1.1 403"));
        }
        state.poll(&connection_id).unwrap();
        state.answer(&connection_id, &request.id, false).unwrap();
        assert_eq!(gateway.response()["result"]["isError"], true);
        assert!(!denied.exists());
        assert!(state.answer(&connection_id, &request.id, true).is_err());

        gateway.send(
            2,
            "write_file",
            serde_json::json!({"path":approved,"contents":"仅本次批准"}),
        );
        let request = gateway.pending(&state, &connection_id);
        assert!(!approved.exists());
        state.answer(&connection_id, &request.id, true).unwrap();
        assert_eq!(gateway.response()["result"]["isError"], false);
        assert_eq!(std::fs::read_to_string(&approved).unwrap(), "仅本次批准");
        assert!(state.answer(&connection_id, &request.id, true).is_err());
        gateway.send(3, "read_file", serde_json::json!({"path":approved}));
        assert_eq!(gateway.response()["result"]["isError"], false);

        gateway.send(
            4,
            "write_file",
            serde_json::json!({"path":timed_out,"contents":"不得超时放行"}),
        );
        let old = gateway.pending(&state, &connection_id);
        assert_eq!(gateway.response()["result"]["isError"], true);
        assert!(!timed_out.exists());
        assert!(state.answer(&connection_id, &old.id, true).is_err());

        gateway.send(
            5,
            "write_file",
            serde_json::json!({"path":disconnected,"contents":"不得断连放行"}),
        );
        gateway.pending(&state, &connection_id);
        state.disconnect(&connection_id).unwrap();
        assert_eq!(gateway.response()["result"]["isError"], true);
        assert!(!disconnected.exists());
        let view = state.connect(gateway.port, gateway.token.clone()).unwrap();
        assert_ne!(view.connection_id, connection_id);
        assert!(state.answer(&connection_id, &old.id, true).is_err());
        gateway.child.kill().unwrap();
        gateway.child.wait().unwrap();
        assert!(state.poll(&view.connection_id).is_err());
        assert!(state.0.lock().unwrap().is_none());
        // 留存唯一测试目录与批准文件，便于独立核对；不删除任何用户文件。
        println!(
            "真实网关文件副作用验收通过，测试目录：{}",
            directory.display()
        );
    }
}

#![cfg(any(target_os = "linux", target_os = "macos"))]
//! 真实 TCP/TLS 服务夹具；证书和签名种子仅为公开测试材料，不用于真实授权。
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey};
use guard_gateway::mcp_remote::{AccessToken, NetworkMode, RemoteClient, RemoteEndpoint};
use guard_gateway::mcp_stdio::{DispatchGuard, Reply};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CA: &[u8] = include_bytes!("fixtures/remote-tls/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/remote-tls/server.der");
const KEY: &[u8] = include_bytes!("fixtures/remote-tls/server-key.der");
const TIME: Duration = Duration::from_secs(2);
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn token(url: &str) -> String {
    let key = SigningKey::from_bytes(&[42; 32]);
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"at+jwt"}"#);
    let body=URL_SAFE_NO_PAD.encode(json!({"iss":"https://issuer.example","aud":url,"sub":"fixture","jti":"test-only","iat":now(),"exp":now()+600,"scope":"mcp:discover mcp:call"}).to_string());
    let message = format!("{header}.{body}");
    format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()).to_bytes())
    )
}
#[derive(Clone, Copy)]
enum Mode {
    Json,
    Sse,
    SseOpen,
    Redirect,
    WrongId,
    Duplicate,
    Truncated,
    Oversize,
    Gzip,
    Reflect,
    ReflectEscaped,
    Hang,
    Stateful,
    ServerRequest,
    WrongCertificate,
}
struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    connections: Arc<AtomicUsize>,
    called: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}
impl Fixture {
    fn new(mode: Mode) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/mcp",
            listener.local_addr().unwrap().port()
        );
        let cert = if matches!(mode, Mode::WrongCertificate) {
            include_bytes!("fixtures/remote-tls/wrong-name.der").as_slice()
        } else {
            CERT
        };
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(cert.to_vec())],
                    PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
                )
                .unwrap();
        let config = Arc::new(config);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let called = Arc::new(AtomicBool::new(false));
        let (reqs, conns, done, call, resource) = (
            requests.clone(),
            connections.clone(),
            stop.clone(),
            called.clone(),
            url.clone(),
        );
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let (socket, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                conns.fetch_add(1, Ordering::AcqRel);
                // macOS accept 可能继承监听 fd 的非阻塞标记；服务器夹具使用限时阻塞流。
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut stream =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
                let mut raw = Vec::new();
                let mut buffer = [0; 1024];
                let mut body_at = None;
                let mut length = 0;
                while raw.len() < 64 * 1024 {
                    let n = match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    raw.extend_from_slice(&buffer[..n]);
                    if body_at.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            body_at = Some(pos + 4);
                            let head = std::str::from_utf8(&raw[..pos]).unwrap();
                            length = head
                                .lines()
                                .find_map(|s| s.strip_prefix("Content-Length: "))
                                .unwrap()
                                .parse::<usize>()
                                .unwrap();
                        }
                    }
                    if body_at.is_some_and(|a| raw.len() >= a + length) {
                        break;
                    }
                }
                let Some(at) = body_at else {
                    continue;
                };
                if raw.len() != at + length {
                    continue;
                }
                let head = std::str::from_utf8(&raw[..at]).unwrap();
                assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
                assert!(head.contains("Accept: application/json, text/event-stream\r\n"));
                assert!(head.contains("MCP-Protocol-Version: 2025-06-18\r\n"));
                let credential = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Authorization: Bearer "))
                    .unwrap();
                // 服务端独立验签与核对受众／范围／期限，不能只证明客户端自己认可了自己。
                let jwt: Vec<_> = credential.split('.').collect();
                let key = SigningKey::from_bytes(&[42; 32]).verifying_key();
                key.verify_strict(
                    format!("{}.{}", jwt[0], jwt[1]).as_bytes(),
                    &Signature::from_slice(&URL_SAFE_NO_PAD.decode(jwt[2]).unwrap()).unwrap(),
                )
                .unwrap();
                let claims: Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt[1]).unwrap()).unwrap();
                assert_eq!(claims["aud"], resource);
                assert!(claims["exp"].as_u64().unwrap() > now());
                assert_eq!(claims["scope"], "mcp:discover mcp:call");
                let message: Value = serde_json::from_slice(&raw[at..]).unwrap();
                reqs.lock().unwrap().push(message.clone());
                let method = message["method"].as_str().unwrap();
                if method == "notifications/initialized" {
                    let _ = stream.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
                    let _ = stream.flush();
                    continue;
                }
                let id = message["id"].as_u64().unwrap();
                let result = match method {
                    "initialize" => {
                        json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"real-tls-fixture","version":"1"}})
                    }
                    "tools/list" => {
                        json!({"tools":[{"name":"echo","description":"合成资料，无指令权","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}]})
                    }
                    "tools/call" => {
                        call.store(true, Ordering::Release);
                        json!({"content":[{"type":"text","text":"实际 TLS 返回"}],"structuredContent":{"value":message["params"]["arguments"]},"_meta":{"trusted":true}})
                    }
                    _ => panic!("不应出现自动重试或其它方法"),
                };
                if method == "initialize" && matches!(mode, Mode::Stateful) {
                    let _=stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: private-session\r\nContent-Length: 0\r\n\r\n");
                    let _ = stream.flush();
                    continue;
                }
                let mut body = json!({"jsonrpc":"2.0","id":id,"result":result}).to_string();
                let is_call = method == "tools/call";
                if is_call {
                    match mode{
                        Mode::Hang=>{std::thread::sleep(Duration::from_millis(350));continue;}
                        Mode::Redirect=>{let _=stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/credential\r\nContent-Length: 0\r\n\r\n");let _=stream.flush();continue;}
                        Mode::Oversize=>{let _=stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 131073\r\n\r\n");let _=stream.flush();continue;}
                        Mode::Gzip=>{let _=stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n");let _=stream.flush();continue;}
                        Mode::WrongId=>body=body.replace(&format!("\"id\":{id}"),"\"id\":999"),
                        Mode::Duplicate=>body=format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"x":1,"x":2}}}}"#),
                        Mode::Reflect|Mode::ReflectEscaped=>{body=json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":credential}]}}).to_string();if matches!(mode,Mode::ReflectEscaped){body=body.replace(credential,&credential.chars().map(|c|format!("\\u{:04x}",c as u32)).collect::<String>());}}
                        Mode::ServerRequest=>body=json!({"jsonrpc":"2.0","id":id,"method":"sampling/createMessage","params":{}}).to_string(),
                        _=>{}
                    }
                }
                if is_call && matches!(mode, Mode::Sse | Mode::SseOpen | Mode::ServerRequest) {
                    let data=format!(": heartbeat\r\nid: cursor\r\nretry: 1\r\nevent: message\r\ndata: {body}\r\n\r\n");
                    let mut wire=b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                    for chunk in data.as_bytes().chunks(17) {
                        wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                        wire.extend_from_slice(chunk);
                        wire.extend_from_slice(b"\r\n");
                    }
                    if !matches!(mode, Mode::SseOpen) {
                        wire.extend_from_slice(b"0\r\n\r\n");
                    }
                    for chunk in wire.chunks(11) {
                        if stream.write_all(chunk).is_err() {
                            break;
                        }
                        let _ = stream.flush();
                    }
                    if matches!(mode, Mode::SseOpen) {
                        std::thread::sleep(Duration::from_millis(350));
                    }
                } else {
                    let size = body.len();
                    if is_call && matches!(mode, Mode::Truncated) {
                        body.truncate(size / 2);
                    }
                    let _=write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {size}\r\n\r\n{body}");
                    let _ = stream.flush();
                }
            }
        });
        Self {
            url,
            requests,
            connections,
            called,
            stop,
            thread: Some(thread),
        }
    }
    fn client(&self) -> RemoteClient {
        let endpoint = RemoteEndpoint::new(
            &self.url,
            Ipv4Addr::LOCALHOST,
            NetworkMode::LoopbackTest,
            CA.to_vec(),
        )
        .unwrap();
        let token = AccessToken::verify(
            token(&self.url),
            "https://issuer.example",
            &SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
            &self.url,
            &["mcp:discover".into(), "mcp:call".into()],
        )
        .unwrap();
        RemoteClient::new(endpoint, token)
    }
    fn ready(&self) -> RemoteClient {
        let mut c = self.client();
        c.initialize(TIME, &|| false).unwrap();
        c.list_tools(TIME, &|| false).unwrap();
        c
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
#[test]
fn 真实加密连接完成握手通知清单及文本工具返回() {
    let f = Fixture::new(Mode::Json);
    let mut c = f.ready();
    let reply = c
        .call_tool("echo", json!({"payload":"fixture-only"}), TIME, &|| false)
        .unwrap();
    let Reply::Result(result) = reply else {
        panic!()
    };
    assert_eq!(
        result["structuredContent"]["value"]["payload"],
        "fixture-only"
    );
    assert_eq!(result["_meta"]["trusted"], true);
    assert_eq!(f.count(), 4);
    assert_eq!(
        f.requests.lock().unwrap()[3]["params"]["arguments"],
        json!({"payload":"fixture-only"})
    );
    c.close();
    assert!(!c.is_ready());
    assert!(c.call_tool("echo", json!({}), TIME, &|| false).is_err());
    assert_eq!(f.count(), 4);
}
#[test]
fn 分块事件流在完整响应事件后返回不等待服务器关闭() {
    for mode in [Mode::Sse, Mode::SseOpen] {
        let f = Fixture::new(mode);
        let mut c = f.ready();
        assert!(matches!(
            c.call_tool("echo", json!({}), Duration::from_millis(200), &|| false)
                .unwrap(),
            Reply::Result(_)
        ));
        assert_eq!(f.count(), 4);
    }
}
#[test]
fn 重定向断连越界压缩和协议错误后通道故障且无重发() {
    for mode in [
        Mode::Redirect,
        Mode::WrongId,
        Mode::Duplicate,
        Mode::Truncated,
        Mode::Oversize,
        Mode::Gzip,
        Mode::ServerRequest,
    ] {
        let f = Fixture::new(mode);
        let mut c = f.ready();
        let e = c.call_tool("echo", json!({}), TIME, &|| false).unwrap_err();
        assert!(e.dispatched);
        assert!(!c.is_ready());
        assert_eq!(f.count(), 4);
        assert_eq!(
            c.call_tool("echo", json!({}), TIME, &|| false)
                .unwrap_err()
                .code,
            "MCP_REMOTE_STATE"
        );
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(f.count(), 4);
        assert_eq!(f.connections.load(Ordering::Acquire), 4);
    }
}
#[test]
fn 专用令牌的直接或转义回显不会交给上层() {
    for mode in [Mode::Reflect, Mode::ReflectEscaped] {
        let f = Fixture::new(mode);
        let mut c = f.ready();
        let e = c.call_tool("echo", json!({}), TIME, &|| false).unwrap_err();
        assert_eq!(e.code, "MCP_REMOTE_TOKEN_REFLECTION");
        assert!(e.dispatched);
        assert!(!format!("{e:?}").contains("eyJ"));
    }
}
#[test]
fn 证书名称不符时没有发送授权头或初始化正文() {
    let f = Fixture::new(Mode::WrongCertificate);
    let mut c = f.client();
    let e = c.initialize(TIME, &|| false).unwrap_err();
    assert_eq!(e.code, "MCP_REMOTE_TLS");
    assert!(!e.dispatched);
    assert_eq!(f.count(), 0);
}
#[test]
fn 有状态服务明确拒绝而不偷偷丢弃会话标识() {
    let f = Fixture::new(Mode::Stateful);
    let mut c = f.client();
    let e = c.initialize(TIME, &|| false).unwrap_err();
    assert_eq!(e.code, "MCP_REMOTE_STATEFUL_UNSUPPORTED");
    assert!(e.dispatched);
    assert_eq!(f.count(), 1);
    assert!(c.initialize(TIME, &|| false).is_err());
    assert_eq!(f.count(), 1);
}
#[test]
fn 无响应与派发后取消都保留未知而不重试() {
    for cancel in [false, true] {
        let f = Fixture::new(Mode::Hang);
        let mut c = f.ready();
        let e = c
            .call_tool("echo", json!({}), Duration::from_millis(150), &|| {
                cancel && f.called.load(Ordering::Acquire)
            })
            .unwrap_err();
        assert!(e.dispatched);
        assert_eq!(
            e.code,
            if cancel {
                "MCP_REMOTE_CANCELLED"
            } else {
                "MCP_REMOTE_TIMEOUT"
            }
        );
        assert_eq!(f.count(), 4);
        assert!(c.initialize(TIME, &|| false).is_err());
    }
}
struct DenyAfter(AtomicUsize, usize);
impl DispatchGuard for DenyAfter {
    fn with_permission(
        &self,
        write: &mut dyn FnMut() -> io::Result<usize>,
    ) -> Option<io::Result<usize>> {
        if self.0.fetch_add(1, Ordering::AcqRel) >= self.1 {
            None
        } else {
            Some(write())
        }
    }
}
#[test]
fn 撤权锁阻止首次连接及首次握手写入() {
    for allowed in [0, 1] {
        let f = Fixture::new(Mode::Json);
        let mut c = f.client();
        c.set_dispatch_guard(Box::new(DenyAfter(AtomicUsize::new(0), allowed)))
            .unwrap();
        let e = c.initialize(TIME, &|| false).unwrap_err();
        assert_eq!(e.code, "MCP_REMOTE_CANCELLED");
        assert!(!e.dispatched);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(f.count(), 0);
        assert_eq!(f.connections.load(Ordering::Acquire), allowed);
    }
}
#[test]
fn 错误参数和调用前取消均没有新增网络请求() {
    let f = Fixture::new(Mode::Json);
    let mut c = f.ready();
    assert_eq!(f.count(), 3);
    for (name, value) in [
        ("unknown", json!({})),
        ("echo", json!([])),
        ("echo", json!({"text":"x".repeat(33*1024)})),
    ] {
        let e = c.call_tool(name, value, TIME, &|| false).unwrap_err();
        assert!(!e.dispatched);
        assert_eq!(f.count(), 3);
    }
    let e = c.call_tool("echo", json!({}), TIME, &|| true).unwrap_err();
    assert!(!e.dispatched);
    assert_eq!(f.count(), 3);
}

#[test]
fn 持有派发锁时不会重入上层取消回调() {
    struct LockedGuard(Arc<Mutex<()>>);
    impl DispatchGuard for LockedGuard {
        fn with_permission(
            &self,
            write: &mut dyn FnMut() -> io::Result<usize>,
        ) -> Option<io::Result<usize>> {
            let _lock = self.0.lock().unwrap();
            Some(write())
        }
    }
    let fixture = Fixture::new(Mode::Json);
    let mut client = fixture.client();
    let lock = Arc::new(Mutex::new(()));
    let reentered = AtomicBool::new(false);
    client
        .set_dispatch_guard(Box::new(LockedGuard(lock.clone())))
        .unwrap();
    let cancelled = || {
        if lock.try_lock().is_err() {
            reentered.store(true, Ordering::Release);
        }
        false
    };
    client.initialize(TIME, &cancelled).unwrap();
    assert!(
        !reentered.load(Ordering::Acquire),
        "取消回调可能使用同一许可锁，锁内调用会死锁"
    );
}

//! 有限远程 MCP 传输。组件不授予调用权；宿主仍须登记、逐次批准、记录开始和来源。
//! 只向宿主指定的 IPv4 建连，证书校验使用原 DNS 名和专用信任根；没有 DNS、代理或重定向。
mod auth;
mod http;
use crate::mcp_stdio::{self, DispatchGuard, Reply, PROTOCOL_VERSION};
pub use auth::AccessToken;
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteError {
    pub code: &'static str,
    pub dispatched: bool,
}
impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}；可能已派发：{}；不得自动重发",
            self.code, self.dispatched
        )
    }
}
impl std::error::Error for RemoteError {}
fn error(code: &'static str) -> RemoteError {
    RemoteError {
        code,
        dispatched: false,
    }
}

/// 回环测试模式只接受 localhost 或 mcp.localhost，并固定连接 127.0.0.1；不能用于绕过其它私网目的地址限制。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Public,
    LoopbackTest,
}
/// 无自动地址解析。TLS 名称、准确地址、端口、路径和信任根均由宿主提供。
#[derive(Clone)]
pub struct RemoteEndpoint {
    url: String,
    host: String,
    authority: String,
    path: String,
    address: SocketAddr,
    tls: Arc<ClientConfig>,
}
impl RemoteEndpoint {
    pub fn new(
        url: &str,
        address: Ipv4Addr,
        mode: NetworkMode,
        root_der: Vec<u8>,
    ) -> Result<Self, RemoteError> {
        let bad = || error("MCP_REMOTE_TARGET");
        if url.len() > 1024 {
            return Err(bad());
        }
        let rest = url.strip_prefix("https://").ok_or_else(bad)?;
        let (authority, suffix) = rest.split_once('/').ok_or_else(bad)?;
        let (host, port) = if let Some((h, p)) = authority.split_once(':') {
            let port = p.parse::<u16>().map_err(|_| bad())?;
            if port == 0 || port.to_string() != p || port == 443 {
                return Err(bad());
            }
            (h, port)
        } else {
            (authority, 443)
        };
        if host.is_empty()
            || host.len() > 253
            || host.parse::<Ipv4Addr>().is_ok()
            || host.split('.').any(|part| {
                part.is_empty()
                    || part.len() > 63
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(bad());
        }
        let path = format!("/{suffix}");
        if path.len() > 512
            || path.contains("//")
            || path.split('/').any(|p| matches!(p, "." | ".."))
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            return Err(bad());
        }
        match mode {
            NetworkMode::LoopbackTest
                if matches!(host, "localhost" | "mcp.localhost")
                    && address == Ipv4Addr::LOCALHOST => {}
            NetworkMode::Public
                if public_address(address) && host != "localhost" && host.contains('.') => {}
            _ => return Err(error("MCP_REMOTE_SSRF")),
        }
        if root_der.is_empty() || root_der.len() > 16 * 1024 {
            return Err(error("MCP_REMOTE_TLS_CONFIG"));
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_der))
            .map_err(|_| error("MCP_REMOTE_TLS_CONFIG"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| error("MCP_REMOTE_TLS_CONFIG"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.enable_early_data = false;
        // 每条连接完整验证，不缓存跨动作会话，也不在 TLS 0-RTT 中发工具请求。
        tls.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            url: url.into(),
            host: host.into(),
            authority: authority.into(),
            path,
            address: (address, port).into(),
            tls: Arc::new(tls),
        })
    }
    pub fn url(&self) -> &str {
        &self.url
    }
}
fn public_address(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    // 保守排除特殊用途网段，包括文档、基准、共享、链路本地和组播；不接受 IPv6 映射形式。
    !(matches!(a, 0 | 10 | 127)
        || a >= 224
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && (b == 0 || b == 168 || b == 88 && c == 99)
        || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
        || a == 203 && b == 0 && c == 113)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    Ready,
    Faulted,
    Closed,
}
/// 单次工具流程客户端。故障后不可再用；不重连、刷新令牌、重发或恢复 SSE 游标。
pub struct RemoteClient {
    endpoint: RemoteEndpoint,
    token: Arc<AccessToken>,
    state: State,
    next_id: u64,
    tools: HashSet<String>,
    guard: Option<Box<dyn DispatchGuard>>,
}
impl RemoteClient {
    pub fn new(endpoint: RemoteEndpoint, token: AccessToken) -> Self {
        Self {
            endpoint,
            token: Arc::new(token),
            state: State::New,
            next_id: 1,
            tools: HashSet::new(),
            guard: None,
        }
    }
    pub(crate) fn shared(endpoint: RemoteEndpoint, token: Arc<AccessToken>) -> Self {
        Self {
            endpoint,
            token,
            state: State::New,
            next_id: 1,
            tools: HashSet::new(),
            guard: None,
        }
    }
    pub fn set_dispatch_guard(&mut self, guard: Box<dyn DispatchGuard>) -> Result<(), RemoteError> {
        if self.state != State::New || self.guard.is_some() {
            return Err(error("MCP_REMOTE_STATE"));
        }
        self.guard = Some(guard);
        Ok(())
    }
    pub fn initialize(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value, RemoteError> {
        self.require(State::New)?;
        let end = deadline(timeout)?;
        let reply=self.exchange("initialize",json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"agentguard-limited-proxy","version":env!("CARGO_PKG_VERSION")}}),end,cancelled)?;
        let Reply::Result(value) = reply else {
            return self.fail("MCP_REMOTE_PROTOCOL", true);
        };
        if value["protocolVersion"] != PROTOCOL_VERSION || !mcp_stdio::valid_initialization(&value)
        {
            return self.fail("MCP_REMOTE_INITIALIZE", true);
        }
        let notice = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        if let Err(mut e) = self.post(&notice, None, "mcp:discover", end, cancelled) {
            e.dispatched = true;
            return Err(e);
        }
        self.state = State::Ready;
        Ok(value)
    }
    pub fn list_tools(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value, RemoteError> {
        self.require(State::Ready)?;
        let reply = self.exchange("tools/list", json!({}), deadline(timeout)?, cancelled)?;
        let Reply::Result(value) = reply else {
            return self.fail("MCP_REMOTE_PROTOCOL", true);
        };
        if value.get("nextCursor").is_some() {
            return self.fail("MCP_REMOTE_UNSUPPORTED", true);
        }
        let Some(tools) = value["tools"].as_array() else {
            return self.fail("MCP_REMOTE_PROTOCOL", true);
        };
        if tools.len() > 64 {
            return self.fail("MCP_REMOTE_RESPONSE_LIMIT", true);
        }
        let mut names = HashSet::new();
        for tool in tools {
            let Some(name) = tool["name"].as_str() else {
                return self.fail("MCP_REMOTE_PROTOCOL", true);
            };
            if !mcp_stdio::valid_name(name)
                || !names.insert(name.into())
                || tool["inputSchema"]["type"] != "object"
                || tool.get("description").is_some_and(|v| !v.is_string())
            {
                return self.fail("MCP_REMOTE_PROTOCOL", true);
            }
        }
        self.tools = names;
        Ok(value)
    }
    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Reply, RemoteError> {
        self.require(State::Ready)?;
        if !self.tools.contains(name) || !arguments.is_object() {
            return Err(error("MCP_REMOTE_INPUT"));
        }
        let reply = self.exchange(
            "tools/call",
            json!({"name":name,"arguments":arguments}),
            deadline(timeout)?,
            cancelled,
        )?;
        if let Reply::Result(value) = &reply {
            let Some(content) = value["content"].as_array() else {
                return self.fail("MCP_REMOTE_PROTOCOL", true);
            };
            if content
                .iter()
                .any(|v| v["type"] != "text" || !v["text"].is_string())
            {
                return self.fail("MCP_REMOTE_UNSUPPORTED", true);
            }
            if value.get("isError").is_some_and(|v| !v.is_boolean())
                || value
                    .get("structuredContent")
                    .is_some_and(|v| !v.is_object())
            {
                return self.fail("MCP_REMOTE_PROTOCOL", true);
            }
        }
        Ok(reply)
    }
    /// 仅关闭本地通道状态；不能声称远端动作已停止。首批不支持持久服务端会话。
    pub fn close(&mut self) {
        self.state = State::Closed;
        self.tools.clear();
    }
    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }
    fn require(&self, state: State) -> Result<(), RemoteError> {
        if self.state == state {
            Ok(())
        } else {
            Err(error("MCP_REMOTE_STATE"))
        }
    }
    fn fail<T>(&mut self, code: &'static str, dispatched: bool) -> Result<T, RemoteError> {
        self.state = State::Faulted;
        self.tools.clear();
        Err(RemoteError { code, dispatched })
    }
    fn exchange(
        &mut self,
        method: &str,
        params: Value,
        end: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Reply, RemoteError> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or_else(|| error("MCP_REMOTE_LIMIT"))?;
        let message = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let scope = if method == "tools/call" {
            "mcp:call"
        } else {
            "mcp:discover"
        };
        self.post(&message, Some(id), scope, end, cancelled)?
            .ok_or_else(|| error("MCP_REMOTE_PROTOCOL"))
    }
    fn post(
        &mut self,
        message: &Value,
        id: Option<u64>,
        scope: &str,
        end: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Reply>, RemoteError> {
        let mut buffer = mcp_stdio::LimitedBuffer(Vec::new());
        serde_json::to_writer(&mut buffer, message)
            .map_err(|_| error("MCP_REMOTE_REQUEST_LIMIT"))?;
        let body = buffer.0;
        let mut dispatched = false;
        let result = self.transport(&body, id, scope, end, cancelled, &mut dispatched);
        match result {
            Ok(value) => Ok(value),
            Err(mut e) => {
                e.dispatched = dispatched;
                self.state = State::Faulted;
                self.tools.clear();
                Err(e)
            }
        }
    }
    fn transport(
        &self,
        body: &[u8],
        id: Option<u64>,
        scope: &str,
        end: Instant,
        cancelled: &dyn Fn() -> bool,
        dispatched: &mut bool,
    ) -> Result<Option<Reply>, RemoteError> {
        // 上层取消回调可能获取与 DispatchGuard 相同的锁，只能在锁外调用。
        // 锁内仍检查本地时限和令牌；撤权本身由 DispatchGuard 原子核对。
        let check_bound = || -> Result<(), RemoteError> {
            if Instant::now() >= end {
                return Err(error("MCP_REMOTE_TIMEOUT"));
            }
            self.token.authorize(self.endpoint.url(), scope)?;
            Ok(())
        };
        let check = || -> Result<(), RemoteError> {
            if cancelled() {
                return Err(error("MCP_REMOTE_CANCELLED"));
            }
            check_bound()
        };
        check()?;
        let mut socket = connect(
            self.endpoint.address,
            self.guard.as_deref(),
            &check,
            &check_bound,
            end,
        )?;
        let name = ServerName::try_from(self.endpoint.host.clone())
            .map_err(|_| error("MCP_REMOTE_TLS_CONFIG"))?;
        let mut tls = ClientConnection::new(self.endpoint.tls.clone(), name)
            .map_err(|_| error("MCP_REMOTE_TLS_CONFIG"))?;
        tls.set_buffer_limit(Some(64 * 1024));
        let mut sent = false;
        let mut decoder = http::Decoder::new();
        let mut sse = http::Sse::new();
        let mut read_at = 0;
        loop {
            check()?;
            // 只有验证完证书后才把专用令牌加入加密明文缓冲。
            if !tls.is_handshaking() && !sent {
                if tls.alpn_protocol().is_some_and(|p| p != b"http/1.1") {
                    return Err(error("MCP_REMOTE_TLS_PROTOCOL"));
                }
                let bearer = self.token.authorize(self.endpoint.url(), scope)?;
                let wire=format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAccept-Encoding: identity\r\nMCP-Protocol-Version: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",self.endpoint.path,self.endpoint.authority,PROTOCOL_VERSION,bearer,body.len());
                tls.writer()
                    .write_all(wire.as_bytes())
                    .and_then(|_| tls.writer().write_all(body))
                    .map_err(|_| error("MCP_REMOTE_IO"))?;
                sent = true;
            }
            let mut progress = false;
            if tls.wants_write() {
                let mut write = || {
                    check_bound().map_err(|_| io::Error::other("许可失效"))?;
                    tls.write_tls(&mut socket)
                };
                let result = permitted(self.guard.as_deref(), &mut write)?;
                match result {
                    Ok(n) => {
                        progress = n > 0;
                        if sent && n > 0 {
                            *dispatched = true;
                        }
                    }
                    Err(e) if retry(&e) => {}
                    Err(_) => return Err(error("MCP_REMOTE_IO")),
                }
            }
            let eof = match tls.read_tls(&mut socket) {
                Ok(0) => true,
                Ok(_) => {
                    progress = true;
                    false
                }
                Err(e) if retry(&e) => false,
                Err(_) => return Err(error("MCP_REMOTE_IO")),
            };
            tls.process_new_packets()
                .map_err(|_| error("MCP_REMOTE_TLS"))?;
            let mut buffer = [0u8; 8192];
            loop {
                let count = match tls.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if retry(&e) => break,
                    Err(_) => return Err(error("MCP_REMOTE_DISCONNECTED")),
                };
                decoder.feed(&buffer[..count])?;
                let head = decoder.head.as_ref();
                // 首批明确拒绝服务端会话，不能接收后又遗漏后续必须的会话头或重启行为。
                if head.is_some_and(|h| h.session.is_some()) {
                    return Err(error("MCP_REMOTE_STATEFUL_UNSUPPORTED"));
                }
                if let Some(head) = head {
                    if id.is_none() {
                        if head.status != 202 {
                            return Err(error("MCP_REMOTE_PROTOCOL"));
                        }
                    } else if head.status != 200 {
                        return Err(error("MCP_REMOTE_PROTOCOL"));
                    }
                    if head.sse {
                        let result = sse.feed(
                            &decoder.body[read_at..],
                            id.ok_or_else(|| error("MCP_REMOTE_PROTOCOL"))?,
                        )?;
                        read_at = decoder.body.len();
                        if let Some(reply) = result {
                            check()?;
                            self.check_reflection(&reply)?;
                            return Ok(Some(reply));
                        }
                    }
                }
                if decoder.complete {
                    break;
                }
                check()?;
            }
            if eof {
                decoder.eof()?;
            }
            if decoder.complete {
                check()?;
                if id.is_none() {
                    if decoder.body.is_empty() {
                        return Ok(None);
                    }
                    return Err(error("MCP_REMOTE_PROTOCOL"));
                }
                if decoder.head.as_ref().is_some_and(|h| h.sse) {
                    return Err(error("MCP_REMOTE_SSE_INCOMPLETE"));
                }
                let reply = mcp_stdio::parse_response(&decoder.body, id.unwrap())
                    .map_err(|_| error("MCP_REMOTE_PROTOCOL"))?;
                self.check_reflection(&reply)?;
                return Ok(Some(reply));
            }
            if !progress {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    fn check_reflection(&self, reply: &Reply) -> Result<(), RemoteError> {
        let value = match reply {
            Reply::Result(v) | Reply::Error(v) => v,
        };
        // 先解析再序列化，Unicode 转义不能绕过完整令牌回显检查。任意变换不是防泄露证明。
        if self
            .token
            .reflected(&serde_json::to_vec(value).map_err(|_| error("MCP_REMOTE_PROTOCOL"))?)
        {
            return Err(error("MCP_REMOTE_TOKEN_REFLECTION"));
        }
        Ok(())
    }
}
fn deadline(timeout: Duration) -> Result<Instant, RemoteError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(error("MCP_REMOTE_TIMEOUT_CONFIG"));
    }
    Ok(Instant::now() + timeout)
}
fn retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
fn permitted(
    guard: Option<&dyn DispatchGuard>,
    write: &mut dyn FnMut() -> io::Result<usize>,
) -> Result<io::Result<usize>, RemoteError> {
    match guard {
        Some(g) => g.with_permission(write),
        None => Some(write()),
    }
    .ok_or_else(|| error("MCP_REMOTE_CANCELLED"))
}
fn connect(
    address: SocketAddr,
    guard: Option<&dyn DispatchGuard>,
    check: &dyn Fn() -> Result<(), RemoteError>,
    check_bound: &dyn Fn() -> Result<(), RemoteError>,
    end: Instant,
) -> Result<TcpStream, RemoteError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let SocketAddr::V4(address) = address else {
        return Err(error("MCP_REMOTE_TARGET"));
    };
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(error("MCP_REMOTE_CONNECT"));
    }
    // RAII 在每个错误路径关闭 fd；connect 和 TLS 写入均在宿主许可锁内，等待在锁外。
    let socket = unsafe { TcpStream::from_raw_fd(fd) };
    socket
        .set_nonblocking(true)
        .map_err(|_| error("MCP_REMOTE_CONNECT"))?;
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(error("MCP_REMOTE_CONNECT"));
    }
    let mut target: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    target.sin_family = libc::AF_INET as _;
    target.sin_port = address.port().to_be();
    target.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
    #[cfg(target_os = "macos")]
    {
        target.sin_len = std::mem::size_of_val(&target) as u8;
    }
    let mut start = || {
        check_bound().map_err(|_| io::Error::other("许可失效"))?;
        let result = unsafe {
            libc::connect(
                fd,
                (&target as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&target) as _,
            )
        };
        if result < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(e);
            }
        }
        Ok(0)
    };
    permitted(guard, &mut start)?.map_err(|_| error("MCP_REMOTE_CONNECT"))?;
    loop {
        check()?;
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = end
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(20) as i32;
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result > 0 {
            if socket
                .take_error()
                .map_err(|_| error("MCP_REMOTE_CONNECT"))?
                .is_some()
            {
                return Err(error("MCP_REMOTE_CONNECT"));
            }
            return Ok(socket);
        }
        if result < 0 && !retry(&io::Error::last_os_error()) {
            return Err(error("MCP_REMOTE_CONNECT"));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 私网链路本地共享文档及组播均不是公网目标() {
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "172.32.0.1"] {
            assert!(public_address(ip.parse().unwrap()));
        }
    }
    #[test]
    fn 地址歧义与回环测试模式不能开放任意私网() {
        for url in [
            "http://localhost/mcp",
            "https://user@localhost/mcp",
            "https://localhost/mcp?q=x",
            "https://localhost/mcp#f",
            "https://localhost/a/../mcp",
            "https://localhost/%2fadmin",
            "https://localhost:0443/mcp",
            "https://localhost:443/mcp",
            "https://127.0.0.1/mcp",
            "https://[::1]/mcp",
            "https://LOCALHOST/mcp",
        ] {
            assert_eq!(
                RemoteEndpoint::new(url, Ipv4Addr::LOCALHOST, NetworkMode::LoopbackTest, vec![])
                    .err()
                    .unwrap()
                    .code,
                "MCP_REMOTE_TARGET"
            );
        }
        assert_eq!(
            RemoteEndpoint::new(
                "https://localhost/mcp",
                Ipv4Addr::LOCALHOST,
                NetworkMode::Public,
                vec![]
            )
            .err()
            .unwrap()
            .code,
            "MCP_REMOTE_SSRF"
        );
        assert_eq!(
            RemoteEndpoint::new(
                "https://localhost/mcp",
                Ipv4Addr::new(10, 0, 0, 1),
                NetworkMode::LoopbackTest,
                vec![]
            )
            .err()
            .unwrap()
            .code,
            "MCP_REMOTE_SSRF"
        );
    }
}

//! 只绑定 IPv4 回环的有界控制 HTTP 入口。
//!
//! 每个连接只处理一次 HTTP/1.1 请求并关闭；拒绝请求时不排空客户端声明的正文。
//! 工作线程、正文、响应及读写总时长都有上限。处理器应自行限制业务等待时间，
//! 例如操作者业务队列现有的 12 秒期限；本层不会创建无法取消的额外处理器线程。
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONFIGURED_BYTES: usize = 16 * 1024 * 1024;
const IO_SLICE: Duration = Duration::from_millis(100);
type Handler = Arc<dyn Fn(ControlRequest) -> ControlResponse + Send + Sync>;

#[derive(Debug, Clone)]
pub struct HttpLimits {
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_workers: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            max_response_bytes: 1024 * 1024,
            read_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            max_workers: 16,
        }
    }
}

impl HttpLimits {
    fn validate(&self) -> io::Result<()> {
        if self.max_body_bytes > MAX_CONFIGURED_BYTES
            || !(128..=MAX_CONFIGURED_BYTES).contains(&self.max_response_bytes)
            || !(1..=32).contains(&self.max_workers)
            || self.read_timeout.is_zero()
            || self.write_timeout.is_zero()
            || self.read_timeout > Duration::from_secs(30)
            || self.write_timeout > Duration::from_secs(30)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "控制 HTTP 限额无效",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ControlRequest {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl ControlRequest {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

pub struct ControlResponse {
    status: u16,
    body: Value,
}

impl ControlResponse {
    pub fn json(status: u16, body: Value) -> Self {
        Self {
            status: if (200..=599).contains(&status) {
                status
            } else {
                500
            },
            body,
        }
    }
}

struct Connection {
    id: u64,
    stream: TcpStream,
    accepted: Instant,
}

#[derive(Default)]
struct Shared {
    stopped: AtomicBool,
    active: Mutex<BTreeMap<u64, TcpStream>>,
    queue: Mutex<VecDeque<Connection>>,
    ready: Condvar,
}

pub struct ControlHttp {
    address: SocketAddr,
    limits: HttpLimits,
    listener: Option<TcpListener>,
    shared: Arc<Shared>,
    acceptor: Option<JoinHandle<()>>,
    workers: Vec<JoinHandle<()>>,
    started: bool,
}

impl ControlHttp {
    /// 先保留端口，方便调用方把实际地址写入会话配置，再启动处理器。
    pub fn bind(port: u16, limits: HttpLimits) -> io::Result<Self> {
        limits.validate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            address: listener.local_addr()?,
            limits,
            listener: Some(listener),
            shared: Arc::default(),
            acceptor: None,
            workers: Vec::new(),
            started: false,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }

    /// 包括排队、读取、业务处理和写响应；总数不超过 max_workers。
    pub fn active_connections(&self) -> usize {
        self.shared.active.lock().unwrap().len()
    }

    pub fn start(&mut self, handler: Handler) -> io::Result<()> {
        if self.started {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "控制 HTTP 入口已启动",
            ));
        }
        self.started = true;
        for index in 0..self.limits.max_workers {
            let shared = Arc::clone(&self.shared);
            let handler = Arc::clone(&handler);
            let limits = self.limits.clone();
            match thread::Builder::new()
                .name(format!("control-http-{index}"))
                .spawn(move || worker_loop(shared, handler, limits))
            {
                Ok(worker) => self.workers.push(worker),
                Err(error) => {
                    self.stop_and_join();
                    return Err(error);
                }
            }
        }
        let listener = self.listener.take().expect("未启动的入口持有监听器");
        let shared = Arc::clone(&self.shared);
        let max_workers = self.limits.max_workers;
        match thread::Builder::new()
            .name("control-http-accept".into())
            .spawn(move || accept_loop(listener, shared, max_workers))
        {
            Ok(acceptor) => self.acceptor = Some(acceptor),
            Err(error) => {
                self.stop_and_join();
                return Err(error);
            }
        }
        Ok(())
    }

    fn stop_and_join(&mut self) {
        self.shared.stopped.store(true, Ordering::Release);
        // 与工作线程等待使用同一把锁，避免停止通知落在检查与等待之间。
        {
            let _queue = self.shared.queue.lock().unwrap();
            self.shared.ready.notify_all();
        }
        for stream in self.shared.active.lock().unwrap().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        let current = thread::current().id();
        for worker in self.workers.drain(..) {
            // 弱引用处理器可能释放最后一个所有者，不能等待当前线程自身。
            if worker.thread().id() != current {
                let _ = worker.join();
            }
        }
        self.listener.take();
    }
}

impl Drop for ControlHttp {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>, max_workers: usize) {
    let mut next_id = 0u64;
    while !shared.stopped.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut active = shared.active.lock().unwrap();
                if shared.stopped.load(Ordering::Acquire) || active.len() >= max_workers {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(cancel) = stream.try_clone() else {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                next_id = next_id.wrapping_add(1);
                active.insert(next_id, cancel);
                drop(active);
                shared.queue.lock().unwrap().push_back(Connection {
                    id: next_id,
                    stream,
                    accepted: Instant::now(),
                });
                shared.ready.notify_one();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn worker_loop(shared: Arc<Shared>, handler: Handler, limits: HttpLimits) {
    loop {
        let connection = {
            let mut queue = shared.queue.lock().unwrap();
            while queue.is_empty() && !shared.stopped.load(Ordering::Acquire) {
                queue = shared.ready.wait(queue).unwrap();
            }
            if shared.stopped.load(Ordering::Acquire) {
                return;
            }
            queue.pop_front().expect("已通知的连接存在")
        };
        let Connection {
            id,
            mut stream,
            accepted,
        } = connection;
        let _ = stream.set_nodelay(true);
        let response = match read_request(&mut stream, &shared, &limits, accepted) {
            Ok(request) if !shared.stopped.load(Ordering::Acquire) => {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(request)))
                    .unwrap_or_else(|_| error_response(500))
            }
            Ok(_) => error_response(503),
            Err(status) => error_response(status),
        };
        if !shared.stopped.load(Ordering::Acquire) {
            let _ = write_response(&mut stream, &shared, &limits, response);
        }
        let _ = stream.shutdown(Shutdown::Both);
        shared.active.lock().unwrap().remove(&id);
    }
}

fn error_response(status: u16) -> ControlResponse {
    ControlResponse::json(status, json!({"error":"控制请求未被处理","status":status}))
}

fn remaining(deadline: Instant, shared: &Shared) -> io::Result<Duration> {
    if shared.stopped.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "入口已停止"));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .map(|duration| duration.min(IO_SLICE))
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "控制 HTTP 总期限已到"))
}

fn read_part(
    stream: &mut TcpStream,
    shared: &Shared,
    deadline: Instant,
    buffer: &mut [u8],
) -> Result<usize, u16> {
    loop {
        let timeout = remaining(deadline, shared).map_err(|_| 408u16)?;
        stream.set_read_timeout(Some(timeout)).map_err(|_| 400u16)?;
        match stream.read(buffer) {
            Ok(0) => return Err(400),
            Ok(count) => return Ok(count),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err(400),
        }
    }
}

fn read_request(
    stream: &mut TcpStream,
    shared: &Shared,
    limits: &HttpLimits,
    accepted: Instant,
) -> Result<ControlRequest, u16> {
    let deadline = accepted + limits.read_timeout;
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(431);
        }
        let mut buffer = [0; 4096];
        let capacity = buffer.len().min(MAX_HEADER_BYTES - bytes.len());
        let count = read_part(stream, shared, deadline, &mut buffer[..capacity])?;
        bytes.extend_from_slice(&buffer[..count]);
    };
    let header = std::str::from_utf8(&bytes[..header_end - 4]).map_err(|_| 400u16)?;
    let mut lines = header.split("\r\n");
    let mut request_line = lines.next().ok_or(400u16)?.split(' ');
    let method = request_line.next().ok_or(400u16)?;
    let url = request_line.next().ok_or(400u16)?;
    if request_line.next() != Some("HTTP/1.1")
        || request_line.next().is_some()
        || method.is_empty()
        || method.len() > 32
        || !method.bytes().all(token_byte)
        || !url.starts_with('/')
        || url.len() > 4096
        || !url.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
        || url.contains('#')
    {
        return Err(400);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty()
            || !name.bytes().all(token_byte)
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
        {
            return Err(400);
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']).to_string();
        // 控制协议不需要合并重复头，全部拒绝也覆盖 Host、认证及长度歧义。
        if headers.insert(name, value).is_some() {
            return Err(400);
        }
    }
    if headers.get("host").is_none_or(|host| !loopback_host(host))
        || headers
            .get("origin")
            .is_some_and(|origin| !loopback_origin(origin))
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("upgrade")
        || headers.contains_key("expect")
        || headers.get("connection").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    {
        return Err(400);
    }
    let length = match headers.get("content-length") {
        Some(value) => {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(400);
            }
            value.parse::<usize>().map_err(|_| 413u16)?
        }
        None => 0,
    };
    if length > limits.max_body_bytes {
        return Err(413);
    }
    let mut request = ControlRequest {
        method: method.into(),
        url: url.into(),
        headers,
        body: Vec::new(),
    };
    if bytes.len() - header_end > length {
        return Err(400);
    }
    request.body.extend_from_slice(&bytes[header_end..]);
    while request.body.len() < length {
        let mut buffer = [0; 4096];
        let capacity = buffer.len().min(length - request.body.len());
        let count = read_part(stream, shared, deadline, &mut buffer[..capacity])?;
        request.body.extend_from_slice(&buffer[..count]);
    }
    // 每次只读取声明范围，永不解析第二个请求；关闭连接会丢弃后到的流水线数据。
    remaining(deadline, shared).map_err(|_| 408u16)?;
    Ok(request)
}

fn loopback_host(value: &str) -> bool {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
    {
        return false;
    }
    let host = match value.rsplit_once(':') {
        Some((name, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            name
        }
        _ => value,
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

fn loopback_origin(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let rest = if let Some(path) = lower.strip_prefix("http://127.0.0.1") {
        path
    } else if let Some(path) = lower.strip_prefix("http://localhost") {
        path
    } else {
        return false;
    };
    rest.is_empty()
        || rest == "/"
        || rest
            .strip_prefix(':')
            .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit()) && !port.is_empty())
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("控制响应超过上限"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_response(
    stream: &mut TcpStream,
    shared: &Shared,
    limits: &HttpLimits,
    response: ControlResponse,
) -> io::Result<()> {
    let mut output = LimitedBuffer {
        bytes: Vec::new(),
        limit: limits.max_response_bytes,
    };
    let mut status = response.status;
    if serde_json::to_writer(&mut output, &response.body).is_err() {
        status = 500;
        output.bytes = br#"{"error":"response_limit"}"#.to_vec();
    }
    let header = format!(
        "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        output.bytes.len()
    );
    let deadline = Instant::now() + limits.write_timeout;
    for bytes in [header.as_bytes(), output.bytes.as_slice()] {
        let mut written = 0;
        while written < bytes.len() {
            stream.set_write_timeout(Some(remaining(deadline, shared)?))?;
            match stream.write(&bytes[written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => written += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

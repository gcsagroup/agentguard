//! AGD-017 的下游 stdio 传输组件，限定 MCP 2025-06-18。
//!
//! 本模块不启动程序、不授予工具权限、不发布第三方工具。调用者必须先建立隔离，
//! 将带三个管道的子进程交给本模块，并在结束时清理容器等外部执行单元。
//! 登记、批准、参数策略、返回来源及执行审计由后续代理层负责，不能以握手成功代替。

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use std::time::{Duration, Instant};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 128 * 1024;
pub const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_TOOLS: usize = 64;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    State,
    Input,
    Io,
    Timeout,
    Cancelled,
    Disconnected,
    Limit,
    Protocol,
    Unsupported,
}

/// `dispatched` 表示至少一个请求字节已写入管道，不能证明服务执行或没有执行。
/// 特别是超时、断连、协议错误发生在派发后时，代理必须保留未知结果，不能重试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub dispatched: bool,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            FailureKind::State => "通道状态不允许本次操作",
            FailureKind::Input => "请求参数无效或超出支持范围",
            FailureKind::Io => "管道操作失败",
            FailureKind::Timeout => "请求总时限已到",
            FailureKind::Cancelled => "请求已取消",
            FailureKind::Disconnected => "服务连接已断开",
            FailureKind::Limit => "消息或诊断字节超过上限",
            FailureKind::Protocol => "服务响应不符合限定协议",
            FailureKind::Unsupported => "服务使用了未支持的协议特性",
        };
        write!(
            f,
            "{reason}；已写入请求字节：{}；不得自动重发",
            self.dispatched
        )
    }
}
impl std::error::Error for Failure {}

/// 原始响应属于不可信工具输出。这里不把 RPC 成功等同于动作成功，也不渲染错误正文。
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Result(Value),
    Error(Value),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    Ready,
    Faulted,
    Closed,
}

/// 实际非阻塞写入与宿主撤权必须共用锁；这里只包住一次 write，不能等待响应。
/// 返回 None 表示派发许可已经失效；即使调用者的取消检查尚未发现，也不写入字节。
pub trait DispatchGuard: Send {
    fn with_permission(
        &self,
        write: &mut dyn FnMut() -> io::Result<usize>,
    ) -> Option<io::Result<usize>>;
}

/// 单通道只允许一个在途请求，无重连、重试、分页、后台订阅及服务端请求支持。
/// 工具清单保留所有原字段，包括 annotations/outputSchema，供代理完整登记和复核。
pub struct StdioClient {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
    incoming: Vec<u8>,
    stderr_bytes: usize,
    stderr_eof: bool,
    state: State,
    next_id: u64,
    tools: HashSet<String>,
    dispatch_guard: Option<Box<dyn DispatchGuard>>,
}

impl StdioClient {
    pub fn attach(mut child: Child) -> Result<Self, Failure> {
        let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let (Some(stdin), Some(stdout), Some(stderr)) = pipes else {
            terminate(&mut child);
            return Err(Failure {
                kind: FailureKind::Input,
                dispatched: false,
            });
        };
        for fd in [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()] {
            if nonblocking(fd).is_err() {
                terminate(&mut child);
                return Err(Failure {
                    kind: FailureKind::Io,
                    dispatched: false,
                });
            }
        }
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr,
            incoming: Vec::new(),
            stderr_bytes: 0,
            stderr_eof: false,
            state: State::New,
            next_id: 1,
            tools: HashSet::new(),
            dispatch_guard: None,
        })
    }

    /// 只能在任何请求之前安装一次；握手、通知和工具请求都受同一许可约束。
    pub fn set_dispatch_guard(&mut self, guard: Box<dyn DispatchGuard>) -> Result<(), Failure> {
        self.require(State::New)?;
        if self.dispatch_guard.is_some() {
            return Err(Failure {
                kind: FailureKind::State,
                dispatched: false,
            });
        }
        self.dispatch_guard = Some(guard);
        Ok(())
    }

    /// 初始化与 initialized 通知共享同一总时限；不协商 roots/sampling/elicitation。
    pub fn initialize(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value, Failure> {
        self.require(State::New)?;
        let deadline = self.deadline(timeout)?;
        let reply = self.exchange("initialize", json!({
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name":"agentguard-limited-proxy", "version":env!("CARGO_PKG_VERSION")}
        }), deadline, cancelled)?;
        let Reply::Result(result) = reply else {
            return self.fail(FailureKind::Protocol, true);
        };
        if result.get("protocolVersion").and_then(Value::as_str) != Some(PROTOCOL_VERSION) {
            return self.fail(FailureKind::Unsupported, true);
        }
        if !valid_initialization(&result) {
            return self.fail(FailureKind::Protocol, true);
        }
        let message = json!({"jsonrpc":"2.0", "method":"notifications/initialized"});
        // exchange 已经发送初始化请求，即使通知在第一个字节前失败，也不能记为未派发。
        if let Err(failure) = self.send(&message, deadline, cancelled) {
            return Err(Failure {
                dispatched: true,
                ..failure
            });
        }
        self.state = State::Ready;
        Ok(result)
    }

    pub fn list_tools(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value, Failure> {
        self.require(State::Ready)?;
        let deadline = self.deadline(timeout)?;
        let reply = self.exchange("tools/list", json!({}), deadline, cancelled)?;
        let Reply::Result(result) = reply else {
            return self.fail(FailureKind::Protocol, true);
        };
        // 有下一页也不能把第一页冒充完整登记；服务必须提供一次完整的有限清单。
        if result.get("nextCursor").is_some() {
            return self.fail(FailureKind::Unsupported, true);
        }
        let Some(tools) = result.get("tools").and_then(Value::as_array) else {
            return self.fail(FailureKind::Protocol, true);
        };
        if tools.len() > MAX_TOOLS {
            return self.fail(FailureKind::Limit, true);
        }
        let mut names = HashSet::new();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                return self.fail(FailureKind::Protocol, true);
            };
            if !valid_name(name)
                || !names.insert(name.to_owned())
                || tool
                    .get("inputSchema")
                    .and_then(|s| s.get("type"))
                    .and_then(Value::as_str)
                    != Some("object")
                || tool.get("description").is_some_and(|v| !v.is_string())
            {
                return self.fail(FailureKind::Protocol, true);
            }
        }
        self.tools = names;
        Ok(result)
    }

    /// 只能在上层已经完成登记、参数检查、批准与开始审计后调用。
    /// 此组件只核对发现过的名称及 object 参数，不赋予发现结果任何授权意义。
    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Reply, Failure> {
        self.require(State::Ready)?;
        if !self.tools.contains(name) || !arguments.is_object() {
            return Err(Failure {
                kind: FailureKind::Input,
                dispatched: false,
            });
        }
        let deadline = self.deadline(timeout)?;
        let reply = self.exchange(
            "tools/call",
            json!({"name": name, "arguments": arguments}),
            deadline,
            cancelled,
        )?;
        if let Reply::Result(result) = &reply {
            let Some(content) = result.get("content").and_then(Value::as_array) else {
                return self.fail(FailureKind::Protocol, true);
            };
            // 首批仅接收文本工具输出；图像、音频、嵌入资源和资源链接均明确拒绝。
            if content.iter().any(|v| {
                v.get("type").and_then(Value::as_str) != Some("text")
                    || !v.get("text").is_some_and(Value::is_string)
            }) {
                return self.fail(FailureKind::Unsupported, true);
            }
            if result.get("isError").is_some_and(|v| !v.is_boolean())
                || result
                    .get("structuredContent")
                    .is_some_and(|v| !v.is_object())
            {
                return self.fail(FailureKind::Protocol, true);
            }
        }
        Ok(reply)
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    /// 先关闭 stdin，最多等待两秒；超时终止管道子进程。容器清理由调用者另行核实。
    pub fn close(&mut self) -> bool {
        self.stdin.take();
        self.tools.clear();
        self.state = State::Closed;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        terminate(&mut self.child);
        false
    }

    fn require(&self, state: State) -> Result<(), Failure> {
        if self.state == state {
            Ok(())
        } else {
            Err(Failure {
                kind: FailureKind::State,
                dispatched: false,
            })
        }
    }
    fn deadline(&self, timeout: Duration) -> Result<Instant, Failure> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(Failure {
                kind: FailureKind::Input,
                dispatched: false,
            });
        }
        Ok(Instant::now() + timeout)
    }
    fn fail<T>(&mut self, kind: FailureKind, dispatched: bool) -> Result<T, Failure> {
        self.state = State::Faulted;
        self.tools.clear();
        self.stdin.take();
        terminate(&mut self.child);
        Err(Failure { kind, dispatched })
    }
    fn check_time(
        &mut self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        dispatched: bool,
    ) -> Result<(), Failure> {
        if cancelled() {
            return self.fail(FailureKind::Cancelled, dispatched);
        }
        if Instant::now() >= deadline {
            return self.fail(FailureKind::Timeout, dispatched);
        }
        Ok(())
    }
    fn exchange(
        &mut self,
        method: &str,
        params: Value,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Reply, Failure> {
        let id = self.next_id;
        let Some(next) = id.checked_add(1) else {
            return self.fail(FailureKind::Limit, false);
        };
        self.next_id = next;
        self.send(
            &json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}),
            deadline,
            cancelled,
        )?;
        loop {
            self.check_time(deadline, cancelled, true)?;
            let eof = self.read_pipes(true)?;
            if let Some(end) = self.incoming.iter().position(|b| *b == b'\n') {
                if end > MAX_RESPONSE_BYTES || self.incoming.len() != end + 1 {
                    return self.fail(FailureKind::Protocol, true);
                }
                let parsed = parse_response(&self.incoming[..end], id);
                self.incoming.clear();
                return match parsed {
                    Ok(reply) => Ok(reply),
                    Err(kind) => self.fail(kind, true),
                };
            }
            if eof {
                return self.fail(FailureKind::Disconnected, true);
            }
            self.poll(false, deadline, true)?;
        }
    }

    fn send(
        &mut self,
        message: &Value,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), Failure> {
        let mut wire = LimitedBuffer(Vec::new());
        if serde_json::to_writer(&mut wire, message).is_err() {
            return Err(Failure {
                kind: FailureKind::Input,
                dispatched: false,
            });
        }
        wire.0.push(b'\n');
        self.check_time(deadline, cancelled, false)?;
        // 旧 id、重复响应、清单变化通知、服务端请求和半行都不能留到下次调用继续解析。
        let eof = self.read_pipes(false)?;
        if !self.incoming.is_empty() {
            return self.fail(FailureKind::Protocol, false);
        }
        if eof {
            return self.fail(FailureKind::Disconnected, false);
        }
        let mut written = 0;
        while written < wire.0.len() {
            self.check_time(deadline, cancelled, written > 0)?;
            let stdin = self.stdin.as_mut().expect("可用状态有 stdin");
            let mut write = || stdin.write(&wire.0[written..]);
            let result = match &self.dispatch_guard {
                Some(guard) => guard.with_permission(&mut write),
                None => Some(write()),
            };
            let Some(result) = result else {
                return self.fail(FailureKind::Cancelled, written > 0);
            };
            match result {
                Ok(0) => return self.fail(FailureKind::Disconnected, written > 0),
                Ok(n) => written += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let eof = self.read_pipes(written > 0)?;
                    if !self.incoming.is_empty() {
                        return self.fail(FailureKind::Protocol, written > 0);
                    }
                    if eof {
                        return self.fail(FailureKind::Disconnected, written > 0);
                    }
                    self.poll(true, deadline, written > 0)?;
                }
                Err(_) => return self.fail(FailureKind::Io, written > 0),
            }
        }
        Ok(())
    }

    fn read_pipes(&mut self, dispatched: bool) -> Result<bool, Failure> {
        // 每轮两个流各读一个有限块，持续 stderr 不能饿死取消和总时限检查。
        let mut buffer = [0u8; 4096];
        if !self.stderr_eof {
            match self.stderr.read(&mut buffer) {
                Ok(0) => self.stderr_eof = true,
                Ok(n) => {
                    self.stderr_bytes += n;
                    if self.stderr_bytes > MAX_STDERR_BYTES {
                        return self.fail(FailureKind::Limit, dispatched);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return self.fail(FailureKind::Io, dispatched),
            }
        }
        match self.stdout.read(&mut buffer) {
            Ok(0) => Ok(true),
            Ok(n) => {
                if self.incoming.len() + n > MAX_RESPONSE_BYTES + 1 {
                    return self.fail(FailureKind::Limit, dispatched);
                }
                self.incoming.extend_from_slice(&buffer[..n]);
                Ok(false)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(_) => self.fail(FailureKind::Io, dispatched),
        }
    }
    fn poll(&mut self, writing: bool, deadline: Instant, dispatched: bool) -> Result<(), Failure> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if self.stderr_eof {
                    -1
                } else {
                    self.stderr.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if writing {
                    self.stdin.as_ref().expect("写入时有 stdin").as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLOUT,
                revents: 0,
            },
        ];
        let ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(40) as i32;
        // fd 均由当前对象持有；该同步调用期间不会被其它线程关闭。
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                ms,
            )
        };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return self.fail(FailureKind::Io, dispatched);
        }
        Ok(())
    }
}

impl Drop for StdioClient {
    fn drop(&mut self) {
        self.stdin.take();
        terminate(&mut self.child);
    }
}
fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn valid_initialization(result: &Value) -> bool {
    let text = |field: &str| {
        result
            .get("serverInfo")
            .and_then(|v| v.get(field))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty() && s.len() <= 256)
    };
    text("name")
        && text("version")
        && result
            .get("capabilities")
            .and_then(|v| v.get("tools"))
            .is_some_and(Value::is_object)
        && result
            .get("capabilities")
            .and_then(|v| v.get("tools"))
            .and_then(|v| v.get("listChanged"))
            .is_none_or(Value::is_boolean)
        && result.get("instructions").is_none_or(Value::is_string)
}
fn parse_response(bytes: &[u8], id: u64) -> Result<Reply, FailureKind> {
    let StrictJson(value) =
        serde_json::from_slice::<StrictJson>(bytes).map_err(|_| FailureKind::Protocol)?;
    let object = value.as_object().ok_or(FailureKind::Protocol)?;
    if object.contains_key("method") {
        return Err(FailureKind::Unsupported);
    }
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("id").and_then(Value::as_u64) != Some(id)
        || object
            .keys()
            .any(|k| !matches!(k.as_str(), "jsonrpc" | "id" | "result" | "error"))
    {
        return Err(FailureKind::Protocol);
    }
    match (object.get("result"), object.get("error")) {
        (Some(result), None) if result.is_object() => Ok(Reply::Result(result.clone())),
        (None, Some(error))
            if error.get("code").and_then(Value::as_i64).is_some()
                && error.get("message").is_some_and(Value::is_string) =>
        {
            Ok(Reply::Error(error.clone()))
        }
        _ => Err(FailureKind::Protocol),
    }
}
struct LimitedBuffer(Vec<u8>);
impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_REQUEST_BYTES {
            return Err(io::Error::other("MCP 请求字节超限"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// 普通 Value 解析会静默覆盖重复键；边界协议必须拒绝这种解释歧义，包括嵌套对象。
struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("无重复键的 JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("数值必须有限"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_none()
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictJson(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(StrictJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("重复 JSON 键"));
                    }
                    let StrictJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
mod tests;

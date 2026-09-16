//! 只用本测试新建的本机 HTTP 服务与合成凭据。核对实际收到的请求与持久审计时序。
use guard_gateway::egress::*;
use guard_schema::ExecutionOutcome;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct Journal {
    events: Mutex<Vec<EgressAudit>>,
    fail_at: AtomicUsize,
    calls: AtomicUsize,
}
impl EgressJournal for Journal {
    fn record(&self, event: &EgressAudit) -> Result<(), String> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at.load(Ordering::SeqCst) == call {
            return Err("合成审计故障详情不应外传".into());
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn session(broker: &EgressBroker) -> SessionContext {
    let context = SessionContext {
        session_id: "test-session".into(),
        epoch: 7,
    };
    broker
        .register_session(context.clone(), now() + 10_000)
        .unwrap();
    context
}
fn request() -> EgressRequest {
    EgressRequest {
        service_id: "local-test".into(),
        purpose: "test-post".into(),
        data_class: DataClass::Workspace,
        body: Some(json!({"task":"本机代表性请求","number":1})),
    }
}
fn service(port: u16) -> LocalService {
    LocalService::new(
        "local-test",
        &format!("http://127.0.0.1:{port}/submit"),
        HttpMethod::Post,
        "test-post",
        DataClass::Workspace,
        ResponsePolicy::Json,
    )
    .unwrap()
}
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let count = stream.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(at) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&bytes[..at]);
            let length = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            if bytes.len() >= at + 4 + length {
                break;
            }
        }
    }
    bytes
}
fn http(status: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend(body);
    bytes
}
fn fixture(response: Vec<u8>) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let bytes = read_request(&mut stream);
        let _ = stream.write_all(&response);
        bytes
    });
    (port, handle)
}
fn call(broker: &EgressBroker, context: &SessionContext, request: EgressRequest) -> EgressResult {
    let grant = broker
        .issue(context, &request, Duration::from_secs(3))
        .unwrap();
    broker.execute(context, grant, request, &|| false)
}

#[test]
fn 真实本机请求与前后审计顺序() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let journal = Arc::new(Journal::default());
    let observed_journal = journal.clone();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(
            observed_journal.events.lock().unwrap()[0].stage,
            AuditStage::BeforeDispatch
        );
        let bytes = read_request(&mut stream);
        stream
            .write_all(&http(200, br#"{"accepted":true}"#))
            .unwrap();
        bytes
    });
    let broker = EgressBroker::new(vec![service(port)], vec![], journal.clone()).unwrap();
    let context = session(&broker);
    let result = call(&broker, &context, request());
    assert_eq!(result.outcome, ExecutionOutcome::Success);
    assert_eq!(result.body, Some(json!({"accepted":true})));
    assert!(result.dispatched);
    let received = thread.join().unwrap();
    assert!(String::from_utf8(received)
        .unwrap()
        .contains("本机代表性请求"));
    let events = journal.events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].stage, AuditStage::Completed);
    assert_eq!(events[0].event_id, events[1].event_id);
    assert!(!serde_json::to_string(&*events)
        .unwrap()
        .contains("本机代表性请求"));
}

#[test]
fn 准确地址拒绝域名与非允许协议及非规范路径() {
    for url in [
        "https://127.0.0.1:8000/submit",
        "ftp://127.0.0.1:8000/submit",
        "file:///tmp/secret",
        "http://localhost:8000/submit",
        "http://example.invalid:8000/submit",
        "http://127.1:8000/submit",
        "http://2130706433:8000/submit",
        "http://[::1]:8000/submit",
        "http://127.0.0.1:08000/submit",
        "http://127.0.0.1:0/submit",
        "http://127.0.0.1:8000@evil.invalid/submit",
        "http://127.0.0.1:8000/../submit",
        "http://127.0.0.1:8000//submit",
        "http://127.0.0.1:8000/%2e%2e/submit",
        "http://127.0.0.1:8000/submit?token=bad",
        "http://127.0.0.1:8000/submit#bad",
        "http://127.0.0.1:8000/submit\r\nHost: evil.invalid",
        "http://127.0.0.1:8000/submit\\..",
    ] {
        assert!(
            LocalService::new(
                "x",
                url,
                HttpMethod::Post,
                "task",
                DataClass::Public,
                ResponsePolicy::Json
            )
            .is_err(),
            "未拒绝目标 {url:?}"
        );
    }
}

#[test]
fn 宿主控制端口不能注册且零连接() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let result = EgressBroker::new(
        vec![service(port)],
        vec![port],
        Arc::new(Journal::default()),
    );
    assert_eq!(result.err().unwrap().code, "EGRESS_CONTROL_TARGET");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 服务编号重复不能覆盖已登记目标() {
    let result = EgressBroker::new(
        vec![service(8000), service(8001)],
        vec![],
        Arc::new(Journal::default()),
    );
    assert_eq!(result.err().unwrap().code, "EGRESS_DUPLICATE_SERVICE");
}

#[test]
fn 目的与数据范围在签发前拒绝且零连接() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        Arc::new(Journal::default()),
    )
    .unwrap();
    let context = session(&broker);
    for data_class in [DataClass::Sensitive, DataClass::Unknown] {
        let mut req = request();
        req.data_class = data_class;
        assert_eq!(
            broker
                .issue(&context, &req, Duration::from_secs(1))
                .unwrap_err()
                .code,
            "EGRESS_DATA_SCOPE"
        );
    }
    let mut req = request();
    req.purpose = "fake-purpose".into();
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_PURPOSE"
    );
    req.service_id = "http://example.invalid".into();
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_SERVICE"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 模型探测公开范围不能承接工作区正文() {
    let local = LocalService::new(
        "local-test",
        "http://127.0.0.1:8000/v1/models",
        HttpMethod::Get,
        "test-post",
        DataClass::Public,
        ResponsePolicy::Json,
    )
    .unwrap();
    let broker = EgressBroker::new(vec![local], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let mut req = request();
    req.body = None;
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_DATA_SCOPE"
    );
    req.data_class = DataClass::Public;
    assert!(broker.issue(&context, &req, Duration::from_secs(1)).is_ok());
    req.body = Some(json!({"workspace":"标记"}));
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_BODY"
    );
}

#[test]
fn 正文替换消费授权且不能重放原请求() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        Arc::new(Journal::default()),
    )
    .unwrap();
    let context = session(&broker);
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    let mut changed = req.clone();
    changed.body = Some(json!({"task":"等长替换请求","number":9}));
    assert_eq!(
        broker
            .execute(&context, grant.clone(), changed, &|| false)
            .code,
        "EGRESS_BINDING"
    );
    assert_eq!(
        broker.execute(&context, grant, req, &|| false).code,
        "EGRESS_GRANT"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 跨会话与错误代次拒绝且无请求() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        Arc::new(Journal::default()),
    )
    .unwrap();
    let context = session(&broker);
    for other in [
        SessionContext {
            session_id: "other-session".into(),
            epoch: context.epoch,
        },
        SessionContext {
            session_id: context.session_id.clone(),
            epoch: context.epoch + 1,
        },
    ] {
        let req = request();
        let grant = broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            broker.execute(&other, grant, req, &|| false).code,
            "EGRESS_BINDING"
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 单次授权成功后不能再次派发() {
    let (port, server) = fixture(http(200, br#"{"accepted":true}"#));
    let broker =
        EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        broker
            .execute(&context, grant.clone(), req.clone(), &|| false)
            .outcome,
        ExecutionOutcome::Success
    );
    server.join().unwrap();
    let result = broker.execute(&context, grant, req, &|| false);
    assert_eq!(result.code, "EGRESS_GRANT");
    assert!(!result.dispatched);
}

#[test]
fn 过期授权与已撤销会话不能派发() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        Arc::new(Journal::default()),
    )
    .unwrap();
    let context = session(&broker);
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_millis(1))
        .unwrap();
    thread::sleep(Duration::from_millis(5));
    assert_eq!(
        broker.execute(&context, grant, req.clone(), &|| false).code,
        "EGRESS_BINDING"
    );
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    broker.revoke_session(&context.session_id);
    assert_eq!(
        broker.execute(&context, grant, req.clone(), &|| false).code,
        "EGRESS_GRANT"
    );
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_SESSION"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 会话期限不能被授权期限延长() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        Arc::new(Journal::default()),
    )
    .unwrap();
    let context = SessionContext {
        session_id: "short-session".into(),
        epoch: 1,
    };
    broker
        .register_session(context.clone(), now() + 20)
        .unwrap();
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    thread::sleep(Duration::from_millis(30));
    assert_eq!(
        broker.execute(&context, grant, req, &|| false).code,
        "EGRESS_BINDING"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 取消在审计前拒绝且零连接() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let journal = Arc::new(Journal::default());
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        journal.clone(),
    )
    .unwrap();
    let context = session(&broker);
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        broker.execute(&context, grant, req, &|| true).code,
        "EGRESS_CANCELLED"
    );
    assert!(journal.events.lock().unwrap().is_empty());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 前置持久审计失败则关闭实例且零连接() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let journal = Arc::new(Journal::default());
    journal.fail_at.store(1, Ordering::SeqCst);
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        journal,
    )
    .unwrap();
    let context = session(&broker);
    let req = request();
    let result = call(&broker, &context, req.clone());
    assert_eq!(result.code, "EGRESS_AUDIT_BEFORE");
    assert!(!result.dispatched);
    assert!(broker.is_faulted());
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_CLOSED"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 后置持久审计失败保留已发出且结果未知并关闭实例() {
    let (port, server) = fixture(http(200, br#"{"accepted":true}"#));
    let journal = Arc::new(Journal::default());
    journal.fail_at.store(2, Ordering::SeqCst);
    let broker = EgressBroker::new(vec![service(port)], vec![], journal).unwrap();
    let context = session(&broker);
    let result = call(&broker, &context, request());
    assert_eq!(result.code, "EGRESS_AUDIT_AFTER");
    assert!(result.dispatched);
    assert_eq!(result.outcome, ExecutionOutcome::Unknown);
    assert!(broker.is_faulted());
    assert!(result.body.is_none());
    assert!(result.http_status.is_none());
    assert!(!server.join().unwrap().is_empty());
}

#[test]
fn 凭据只在准确上游注入且正文头部及编码回显均不返回或入审计() {
    const SECRET: &str = "AGD-SYNTHETIC-BEARER-ONLY-0123456789";
    let reply = http(200, &serde_json::to_vec(&json!({"echo":SECRET,"encoded":SECRET.bytes().map(|b| format!("{b:02x}")).collect::<String>()})).unwrap());
    let (port, server) = fixture(reply);
    let credentialed = LocalService::new(
        "local-test",
        &format!("http://127.0.0.1:{port}/submit"),
        HttpMethod::Post,
        "test-post",
        DataClass::Workspace,
        ResponsePolicy::StatusOnly,
    )
    .unwrap()
    .with_bearer(SECRET.into())
    .unwrap();
    let journal = Arc::new(Journal::default());
    let broker = EgressBroker::new(vec![credentialed], vec![], journal.clone()).unwrap();
    let context = session(&broker);
    let result = call(&broker, &context, request());
    assert_eq!(result.outcome, ExecutionOutcome::Success);
    assert!(result.body.is_none());
    assert!(result.http_status.is_none());
    let received = String::from_utf8(server.join().unwrap()).unwrap();
    assert_eq!(received.matches(SECRET).count(), 1);
    assert!(received.contains(&format!("Authorization: Bearer {SECRET}\r\n")));
    let serialized = serde_json::to_string(&journal.events.lock().unwrap().clone()).unwrap();
    assert!(!serialized.contains(SECRET));
    assert!(!serialized.contains("encoded"));
    assert!(journal
        .events
        .lock()
        .unwrap()
        .iter()
        .all(|e| e.response_sha256.is_none()));
    assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
}

#[test]
fn 凭据策略拒绝任意响应与头部注入() {
    assert_eq!(
        service(8000)
            .with_bearer("AGD-SYNTHETIC-SECRET-0123456789".into())
            .err()
            .unwrap()
            .code,
        "EGRESS_CREDENTIAL_POLICY"
    );
    let local = LocalService::new(
        "x",
        "http://127.0.0.1:8000/x",
        HttpMethod::Post,
        "p",
        DataClass::Public,
        ResponsePolicy::StatusOnly,
    )
    .unwrap();
    assert_eq!(
        local
            .with_bearer("AGD-SYNTHETIC\r\nHost: evil.invalid".into())
            .err()
            .unwrap()
            .code,
        "EGRESS_CREDENTIAL_POLICY"
    );
}

#[test]
fn 已知凭据不能经任务正文发送() {
    const SECRET: &str = "AGD-SYNTHETIC-SECRET-0123456789";
    let local = LocalService::new(
        "local-test",
        "http://127.0.0.1:8000/x",
        HttpMethod::Post,
        "test-post",
        DataClass::Workspace,
        ResponsePolicy::StatusOnly,
    )
    .unwrap()
    .with_bearer(SECRET.into())
    .unwrap();
    let broker = EgressBroker::new(vec![local], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let mut req = request();
    req.body = Some(json!({"secret":SECRET}));
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_CREDENTIAL_IN_BODY"
    );
}

#[test]
fn 请求过大在网络前拒绝() {
    let broker =
        EgressBroker::new(vec![service(8000)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let mut req = request();
    req.body = Some(json!({"large":"x".repeat(MAX_REQUEST_BYTES)}));
    assert_eq!(
        broker
            .issue(&context, &req, Duration::from_secs(1))
            .unwrap_err()
            .code,
        "EGRESS_REQUEST_LIMIT"
    );
}

#[test]
fn 已发送后断连记未知且单次授权不重试() {
    let (port, server) = fixture(Vec::new());
    let broker =
        EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    let result = broker.execute(&context, grant.clone(), req.clone(), &|| false);
    assert!(result.dispatched);
    assert_eq!(result.outcome, ExecutionOutcome::Unknown);
    assert!(!server.join().unwrap().is_empty());
    assert_eq!(
        broker.execute(&context, grant, req, &|| false).code,
        "EGRESS_GRANT"
    );
}

#[test]
fn 重定向不跟随且目的服务零连接() {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let reply = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/submit\r\nContent-Length: 0\r\n\r\n",
        trap.local_addr().unwrap().port()
    )
    .into_bytes();
    let (port, server) = fixture(reply);
    let broker =
        EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let result = call(&broker, &context, request());
    assert_eq!(result.code, "EGRESS_REDIRECT");
    assert_eq!(result.outcome, ExecutionOutcome::Failed);
    assert!(result.dispatched);
    server.join().unwrap();
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn 模型状态端点缺失可由宿主明确回退() {
    for status in [404, 405] {
        let (port, server) = fixture(http(status, br#"{"error":"not found"}"#));
        let broker =
            EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
        let context = session(&broker);
        let result = call(&broker, &context, request());
        assert_eq!(result.http_status, Some(status));
        assert_eq!(result.outcome, ExecutionOutcome::Failed);
        assert!(result.body.is_none());
        server.join().unwrap();
    }
}

#[test]
fn 有界分块响应正常读取() {
    let body = br#"{"accepted":true}"#;
    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n", body.len(), std::str::from_utf8(body).unwrap()).into_bytes();
    let (port, server) = fixture(reply);
    let broker =
        EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let result = call(&broker, &context, request());
    assert_eq!(result.body, Some(json!({"accepted":true})));
    server.join().unwrap();
}

#[test]
fn 真实响应分帧歧义压缩截断与协议升级全部拒绝() {
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra",
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Encoding: gzip\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x=1\r\n{}\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nSecret: bad\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,chunked\r\n\r\n{}",
        "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n",
        "HTTP/2 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nBad Header: bad\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n??",
    ] {
        let (port, server) = fixture(raw.as_bytes().to_vec());
        let broker = EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
        let context = session(&broker); let result = call(&broker, &context, request());
        assert_eq!(result.outcome, ExecutionOutcome::Unknown, "意外接受 {raw:?}");
        assert!(result.body.is_none()); assert!(result.dispatched); server.join().unwrap();
    }
}

#[test]
fn 响应声明或实际超过限制则结果未知() {
    for reply in [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_RESPONSE_BYTES + 1
        )
        .into_bytes(),
        http(200, &vec![b'x'; MAX_RESPONSE_BYTES + 1]),
        format!(
            "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
            "x".repeat(17 * 1024)
        )
        .into_bytes(),
    ] {
        let (port, server) = fixture(reply);
        let broker =
            EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
        let context = session(&broker);
        let result = call(&broker, &context, request());
        assert_eq!(result.code, "EGRESS_RESPONSE_LIMIT");
        assert!(result.dispatched);
        assert_eq!(result.outcome, ExecutionOutcome::Unknown);
        server.join().unwrap();
    }
}

#[test]
fn 已发出后超时不伪装零副作用() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        thread::sleep(Duration::from_millis(100));
        request
    });
    let local = service(port)
        .with_timeout(Duration::from_millis(20))
        .unwrap();
    let broker = EgressBroker::new(vec![local], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    let result = call(&broker, &context, request());
    assert_eq!(result.code, "EGRESS_TIMEOUT");
    assert_eq!(result.outcome, ExecutionOutcome::Unknown);
    assert!(result.dispatched);
    assert!(!server.join().unwrap().is_empty());
}

#[test]
fn 不接受请求中的客户端自报目标或凭据() {
    for extra in [
        "url",
        "headers",
        "authorization",
        "approved",
        "session_id",
        "trusted",
    ] {
        let mut value = serde_json::to_value(request()).unwrap();
        value[extra] = Value::String("客户端自报".into());
        assert!(serde_json::from_value::<EgressRequest>(value).is_err());
    }
}

#[test]
fn 审计提交期间取消则不会继续创建连接() {
    use std::sync::atomic::AtomicBool;
    struct CancelJournal(Arc<AtomicBool>);
    impl EgressJournal for CancelJournal {
        fn record(&self, event: &EgressAudit) -> Result<(), String> {
            if event.stage == AuditStage::BeforeDispatch {
                self.0.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let broker = EgressBroker::new(
        vec![service(listener.local_addr().unwrap().port())],
        vec![],
        Arc::new(CancelJournal(cancelled.clone())),
    )
    .unwrap();
    let context = session(&broker);
    let req = request();
    let grant = broker
        .issue(&context, &req, Duration::from_secs(1))
        .unwrap();
    let result = broker.execute(&context, grant, req, &|| cancelled.load(Ordering::SeqCst));
    assert_eq!(result.code, "EGRESS_CANCELLED");
    assert!(!result.dispatched);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn revoke_between_authorization_and_dispatch(check_number: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = Arc::new(
        EgressBroker::new(
            vec![service(listener.local_addr().unwrap().port())],
            vec![],
            Arc::new(Journal::default()),
        )
        .unwrap(),
    );
    let context = session(&broker);
    let executing = broker.clone();
    let worker_context = context.clone();
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let req = request();
        let grant = executing
            .issue(&worker_context, &req, Duration::from_secs(3))
            .unwrap();
        let calls = AtomicUsize::new(0);
        executing.execute(&worker_context, grant, req, &|| {
            if calls.fetch_add(1, Ordering::SeqCst) + 1 == check_number {
                // 确定性重现：已读到有效授权，但系统调用尚未开始时完成另一线程撤销。
                reached_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            false
        })
    });
    let synchronization_deadline = Instant::now() + Duration::from_secs(2);
    reached_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    // 写入前先接住真实连接，再撤销并放行客户端。不能等客户端关闭后，
    // 才假定非阻塞监听器仍能立刻 accept 到那条零字节连接。
    let accepted = if check_number == 2 {
        None
    } else {
        loop {
            match listener.accept() {
                Ok((stream, _)) => break Some(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    assert!(
                        Instant::now() < synchronization_deadline,
                        "写入前的真实连接未在原两秒同步期限内到达：{error}"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("接收写入前连接失败：{error}"),
            }
        }
    };
    broker.revoke_session(&context.session_id);
    resume_tx.send(()).unwrap();
    let result = worker.join().unwrap();
    assert_eq!(result.outcome, ExecutionOutcome::Refused);
    assert_eq!(result.code, "EGRESS_CANCELLED");
    assert!(!result.dispatched);
    if check_number == 2 {
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    } else {
        let mut stream = accepted.unwrap();
        // macOS 接受的连接可能继承监听器的非阻塞状态；必须等到 EOF 才能证明零字节。
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty(), "撤销返回后不允许再发送任何 HTTP 字节");
    }
}

#[test]
fn 连接前检查与系统调用之间撤销仍为零连接() {
    revoke_between_authorization_and_dispatch(2);
}

#[test]
fn 写入前检查与系统调用之间撤销仍为零请求字节() {
    revoke_between_authorization_and_dispatch(4);
}

#[test]
fn 正在等待响应时撤销会话可即时生效且结果未知() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sent, received) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let bytes = read_request(&mut stream);
        sent.send(()).unwrap();
        thread::sleep(Duration::from_millis(200));
        let _ = stream.write_all(&http(200, br#"{"late":true}"#));
        bytes
    });
    let broker = Arc::new(
        EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap(),
    );
    let context = session(&broker);
    let executing = broker.clone();
    let worker_context = context.clone();
    let worker = thread::spawn(move || call(&executing, &worker_context, request()));
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    broker.revoke_session(&context.session_id);
    let result = worker.join().unwrap();
    assert_eq!(result.code, "EGRESS_CANCELLED");
    assert_eq!(result.outcome, ExecutionOutcome::Unknown);
    assert!(result.dispatched);
    assert!(result.body.is_none());
    assert!(!server.join().unwrap().is_empty());
}

#[test]
fn 撤销的会话编号不能在同实例复活() {
    let broker =
        EgressBroker::new(vec![service(8000)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    broker.revoke_session(&context.session_id);
    assert!(broker.register_session(context, now() + 10_000).is_err());
}

#[cfg(unix)]
mod durable {
    use super::*;
    use guard_audit::AuditStore;
    use guard_gateway::egress_journal::DurableEgressJournal;
    use std::path::PathBuf;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            use rand::RngCore;
            let root = std::env::temp_dir().join(format!(
                "agd-egress-journal-{}",
                rand::rngs::OsRng.next_u64()
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root.canonicalize().unwrap())
        }
        fn db(&self) -> PathBuf {
            self.0.join("egress.db")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn intent() -> EgressAudit {
        EgressAudit {
            version: 1,
            event_id: "ab".repeat(32),
            stage: AuditStage::BeforeDispatch,
            session_sha256: "cd".repeat(32),
            service_sha256: "ef".repeat(32),
            purpose_sha256: "12".repeat(32),
            epoch: 7,
            request_sha256: "34".repeat(32),
            request_bytes: 42,
            outcome: ExecutionOutcome::Unknown,
            dispatched: false,
            code: "EGRESS_DISPATCH_INTENT",
            response_sha256: None,
        }
    }
    #[test]
    fn 真实请求使用持久日志且重启链保持完整() {
        let temp = Temp::new();
        let path = temp.db();
        let (port, server) = fixture(http(200, br#"{"saved":true}"#));
        let journal = Arc::new(DurableEgressJournal::open(&path).unwrap());
        let broker = EgressBroker::new(vec![service(port)], vec![], journal.clone()).unwrap();
        let context = session(&broker);
        let result = call(&broker, &context, request());
        assert_eq!(result.outcome, ExecutionOutcome::Success);
        server.join().unwrap();
        assert!(DurableEgressJournal::open(&path).is_err());
        let read = AuditStore::open_read_only(&path).unwrap();
        assert!(read.verify_chain().unwrap().ok);
        assert_eq!(read.list_recent(8).unwrap().len(), 2);
        assert!(read.unfinished_egress_actions().unwrap().is_empty());
        let export = read.export_jsonl(8).unwrap();
        assert!(!export.contains("本机代表性请求"));
        assert!(!export.contains("saved"));
        drop(read);
        drop(broker);
        drop(journal);
        let reopened = DurableEgressJournal::open(&path).unwrap();
        assert_eq!(reopened.recovered_unknown_count(), 0);
        assert_eq!(reopened.status()["healthy"], true);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[test]
    fn 未完成的派发意图恢复一次未知且不创建网络请求() {
        let temp = Temp::new();
        let path = temp.db();
        let journal = DurableEgressJournal::open(&path).unwrap();
        journal.record(&intent()).unwrap();
        drop(journal);
        let recovered = DurableEgressJournal::open(&path).unwrap();
        assert_eq!(recovered.recovered_unknown_count(), 1);
        let reader = AuditStore::open_read_only(&path).unwrap();
        assert!(reader.verify_chain().unwrap().ok);
        assert!(reader.unfinished_egress_actions().unwrap().is_empty());
        let rows = reader.list_recent(10).unwrap();
        assert_eq!(rows.len(), 2);
        let last: Value = serde_json::from_str(&rows[0].event_json).unwrap();
        assert_eq!(last["outcome"], "unknown");
        assert!(last["dispatched"].is_null());
        assert_eq!(last["side_effects"], "unknown");
        assert_eq!(last["code"], "EGRESS_RECOVERED_UNKNOWN");
        drop(reader);
        drop(recovered);
        assert_eq!(
            DurableEgressJournal::open(&path)
                .unwrap()
                .recovered_unknown_count(),
            0
        );
    }
    #[test]
    fn 损坏审计链拒绝恢复且不修复原内容() {
        let temp = Temp::new();
        let path = temp.db();
        let journal = DurableEgressJournal::open(&path).unwrap();
        journal.record(&intent()).unwrap();
        drop(journal);
        let mut bytes = std::fs::read(&path).unwrap();
        let original = b"egress_execution_v1";
        let at = bytes
            .windows(original.len())
            .position(|window| window == original)
            .unwrap();
        bytes[at + original.len() - 1] = b'0';
        std::fs::write(&path, &bytes).unwrap();
        assert!(DurableEgressJournal::open(&path).is_err());
        let altered = std::fs::read(&path).unwrap();
        assert!(altered
            .windows(original.len())
            .any(|s| s == b"egress_execution_v0"));
    }
    #[test]
    fn 日志文件与父目录链接及硬链接拒绝() {
        let temp = Temp::new();
        let path = temp.db();
        let original = temp.0.join("original.db");
        std::fs::write(&original, b"protected").unwrap();
        std::os::unix::fs::symlink(&original, &path).unwrap();
        assert!(DurableEgressJournal::open(&path).is_err());
        assert_eq!(std::fs::read(&original).unwrap(), b"protected");
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&original, &path).unwrap();
        assert!(DurableEgressJournal::open(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let real = temp.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = temp.0.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert!(DurableEgressJournal::open(&alias.join("audit.db")).is_err());
        assert!(!real.join("audit.db").exists());
    }
    #[test]
    fn 目录或数据库被换掉则审计失败并阻止派发() {
        let temp = Temp::new();
        let path = temp.db();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let journal = Arc::new(DurableEgressJournal::open(&path).unwrap());
        let broker = EgressBroker::new(
            vec![service(listener.local_addr().unwrap().port())],
            vec![],
            journal.clone(),
        )
        .unwrap();
        let context = session(&broker);
        std::fs::rename(&path, temp.0.join("original.db")).unwrap();
        std::fs::write(&path, b"operator replacement").unwrap();
        let result = call(&broker, &context, request());
        assert_eq!(result.code, "EGRESS_AUDIT_BEFORE");
        assert!(!result.dispatched);
        assert_eq!(journal.status()["healthy"], false);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"operator replacement");
    }
    #[test]
    fn 任意内容不能借审计公开字段写入磁盘() {
        for change in [0, 1, 2] {
            let temp = Temp::new();
            let path = temp.db();
            let journal = DurableEgressJournal::open(&path).unwrap();
            let mut event = intent();
            match change {
                0 => event.event_id = "AGD_PRIVATE_BODY".into(),
                1 => event.code = "AGD_PRIVATE_BODY",
                _ => event.request_sha256 = "AGD_PRIVATE_BODY".into(),
            }
            assert_eq!(journal.record(&event).unwrap_err(), "EGRESS_JOURNAL_FAILED");
            let reader = AuditStore::open_read_only(&path).unwrap();
            assert!(reader.list_recent(10).unwrap().is_empty());
            drop(reader);
            drop(journal);
            assert!(!std::fs::read(&path)
                .unwrap()
                .windows(b"AGD_PRIVATE_BODY".len())
                .any(|b| b == b"AGD_PRIVATE_BODY"));
        }
    }
    #[test]
    fn 终态替换绑定被拒且重启保留未知() {
        let temp = Temp::new();
        let path = temp.db();
        let journal = DurableEgressJournal::open(&path).unwrap();
        let event = intent();
        journal.record(&event).unwrap();
        let mut changed = event;
        changed.stage = AuditStage::Completed;
        changed.outcome = ExecutionOutcome::Success;
        changed.dispatched = true;
        changed.code = "EGRESS_OK";
        changed.request_sha256 = "56".repeat(32);
        assert!(journal.record(&changed).is_err());
        drop(journal);
        assert_eq!(
            DurableEgressJournal::open(&path)
                .unwrap()
                .recovered_unknown_count(),
            1
        );
    }
    #[test]
    fn 子进程硬退出后持久意图可恢复() {
        const CHILD: &str = "AGD_EGRESS_CRASH_CHILD_PATH";
        if let Some(path) = std::env::var_os(CHILD) {
            let journal = DurableEgressJournal::open(std::path::Path::new(&path)).unwrap();
            journal.record(&intent()).unwrap();
            std::process::exit(73);
        }
        let temp = Temp::new();
        let path = temp.db();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "durable::子进程硬退出后持久意图可恢复",
                "--nocapture",
            ])
            .env(CHILD, &path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        let journal = DurableEgressJournal::open(&path).unwrap();
        assert_eq!(journal.recovered_unknown_count(), 1);
        let reader = AuditStore::open_read_only(&path).unwrap();
        assert!(reader.verify_chain().unwrap().ok);
    }
}

#[test]
fn 凭据不会传到另一个已登记无凭据服务() {
    const SECRET: &str = "AGD-SYNTHETIC-AUDIENCE-0123456789";
    let (secret_port, secret_server) = fixture(http(200, b"{}"));
    let (plain_port, plain_server) = fixture(http(200, b"{}"));
    let secret = LocalService::new(
        "local-test",
        &format!("http://127.0.0.1:{secret_port}/submit"),
        HttpMethod::Post,
        "test-post",
        DataClass::Workspace,
        ResponsePolicy::StatusOnly,
    )
    .unwrap()
    .with_bearer(SECRET.into())
    .unwrap();
    let plain = LocalService::new(
        "plain-test",
        &format!("http://127.0.0.1:{plain_port}/submit"),
        HttpMethod::Post,
        "test-post",
        DataClass::Workspace,
        ResponsePolicy::Json,
    )
    .unwrap();
    let broker =
        EgressBroker::new(vec![secret, plain], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&broker);
    assert_eq!(
        call(&broker, &context, request()).outcome,
        ExecutionOutcome::Success
    );
    let mut req = request();
    req.service_id = "plain-test".into();
    assert_eq!(
        call(&broker, &context, req).outcome,
        ExecutionOutcome::Success
    );
    assert!(String::from_utf8(secret_server.join().unwrap())
        .unwrap()
        .contains(SECRET));
    let plain = String::from_utf8(plain_server.join().unwrap()).unwrap();
    assert!(!plain.contains("Authorization:"));
    assert!(!plain.contains(SECRET));
}

#[test]
fn 旧实例授权不能跨代理实例复用() {
    let first =
        EgressBroker::new(vec![service(8000)], vec![], Arc::new(Journal::default())).unwrap();
    let second =
        EgressBroker::new(vec![service(8000)], vec![], Arc::new(Journal::default())).unwrap();
    let context = session(&first);
    session(&second);
    let req = request();
    let grant = first.issue(&context, &req, Duration::from_secs(1)).unwrap();
    assert_eq!(
        second.execute(&context, grant, req, &|| false).code,
        "EGRESS_GRANT"
    );
}

#[test]
fn 真实响应原因行控制字符与升级头拒绝() {
    for raw in [
        "HTTP/1.1 200 OK\0bad\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\nFake: bad\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    ] {
        let (port, server) = fixture(raw.as_bytes().to_vec());
        let broker = EgressBroker::new(vec![service(port)], vec![], Arc::new(Journal::default())).unwrap();
        let context = session(&broker); let result = call(&broker, &context, request());
        assert_eq!(result.code, "EGRESS_HTTP_FORMAT"); assert!(result.dispatched); assert!(result.body.is_none());
        server.join().unwrap();
    }
}

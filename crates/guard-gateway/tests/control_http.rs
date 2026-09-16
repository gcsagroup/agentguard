//! 本机合成请求：证明畸形和慢速连接不能卡死共同的批准、状态 HTTP 入口。
use guard_gateway::control_http::{ControlHttp, ControlRequest, ControlResponse, HttpLimits};
use serde_json::{json, Value};
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::Shutdown;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn limits() -> HttpLimits {
    HttpLimits {
        max_body_bytes: 1024,
        max_response_bytes: 4096,
        read_timeout: Duration::from_millis(250),
        write_timeout: Duration::from_millis(250),
        max_workers: 4,
    }
}

fn fixture(
    limits: HttpLimits,
    handler: impl Fn(ControlRequest) -> ControlResponse + Send + Sync + 'static,
) -> ControlHttp {
    let mut server = ControlHttp::bind(0, limits).unwrap();
    server.start(Arc::new(handler)).unwrap();
    server
}

fn ok(_: ControlRequest) -> ControlResponse {
    ControlResponse::json(200, json!({"ok":true}))
}

fn connect(server: &ControlHttp) -> TcpStream {
    let stream = TcpStream::connect(server.address()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn read_closed(stream: &mut TcpStream) -> Vec<u8> {
    let mut result = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => result.extend_from_slice(&buffer[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                break;
            }
            Err(error) => panic!("连接未在期限内关闭：{error}"),
        }
    }
    result
}

fn request(server: &ControlHttp, bytes: &[u8]) -> Vec<u8> {
    let mut stream = connect(server);
    stream.write_all(bytes).unwrap();
    read_closed(&mut stream)
}

fn get(server: &ControlHttp) -> Vec<u8> {
    request(server, b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
}

fn status(bytes: &[u8]) -> u16 {
    std::str::from_utf8(bytes)
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn body(bytes: &[u8]) -> Value {
    let at = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    serde_json::from_slice(&bytes[at + 4..]).unwrap()
}

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(Instant::now() < deadline, "状态未在期限内到达");
        thread::sleep(Duration::from_millis(2));
    }
}

fn assert_listener_closed(address: SocketAddr, phase: &str) {
    // 失败时保留探测双方的地址和 socket 信息，为残留监听或端口复用提供定位线索。
    // 仍要求第一次探测就失败，不重试、不吞掉成功连接。
    let connection = TcpStream::connect(address);
    assert!(
        connection.is_err(),
        "监听入口销毁后仍可连接：phase={phase}, target={address}, connection={connection:?}"
    );
}

#[test]
fn complete_request_preserves_exact_body_and_case_insensitive_headers() {
    let server = fixture(limits(), |request| {
        ControlResponse::json(
            201,
            json!({
                "method":request.method(),"url":request.url(),
                "auth":request.header("AUTHORIZATION"),
                "body":serde_json::from_slice::<Value>(request.body()).unwrap()
            }),
        )
    });
    assert!(server.address().ip().is_loopback());
    assert_eq!(server.address().port(), server.port());
    let bytes = "{\"消息\":\"本机夹具\"}".as_bytes();
    let mut wire = format!("POST /approve?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuThOrIzAtIoN: Bearer synthetic\r\nContent-Length: {}\r\n\r\n",bytes.len()).into_bytes();
    wire.extend_from_slice(bytes);
    let response = request(&server, &wire);
    assert_eq!(status(&response), 201);
    assert_eq!(
        body(&response),
        json!({"method":"POST","url":"/approve?x=1","auth":"Bearer synthetic","body":{"消息":"本机夹具"}})
    );
    assert!(String::from_utf8(response)
        .unwrap()
        .contains("Connection: close\r\n"));
}

#[test]
fn half_body_does_not_block_status_and_never_reaches_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let server = fixture(limits(), move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        ok(request)
    });
    let mut slow = connect(&server);
    slow.write_all(
        b"POST /browser/request HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\n\r\na",
    )
    .unwrap();
    wait_for(|| server.active_connections() == 1);
    let start = Instant::now();
    assert_eq!(status(&get(&server)), 200);
    assert!(start.elapsed() < Duration::from_millis(200));
    assert_eq!(status(&read_closed(&mut slow)), 408);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn huge_content_length_is_rejected_without_waiting_or_allocation() {
    let server = fixture(limits(), |_| panic!("超大正文不能到达处理器"));
    for length in [
        "1025",
        "18446744073709551615",
        "999999999999999999999999999999999999",
    ] {
        let start = Instant::now();
        let wire = format!(
            "POST /approve HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\n\r\n"
        );
        assert_eq!(status(&request(&server, wire.as_bytes())), 413);
        assert!(start.elapsed() < Duration::from_millis(200));
    }
}

#[test]
fn malformed_framing_and_duplicate_security_headers_are_rejected() {
    let server = fixture(limits(), |_| panic!("非法请求不能到达处理器"));
    let cases = [
        "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: localhost\r\nhOsT: 127.0.0.1\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer x\r\nauthorization: Bearer x\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: +1\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0, 0\r\n\r\n",
        "GET /x HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "GET /x HTTP/1.1\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: local host\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: localhost\r\n folded: header\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost : localhost\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: localhost\nAuthorization: x\r\n\r\n",
        "GET http://localhost/x HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /x#fragment HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ];
    for wire in cases {
        assert_eq!(status(&request(&server, wire.as_bytes())), 400, "{wire:?}");
    }
}

#[test]
fn slow_headers_have_total_deadline_even_with_periodic_progress() {
    let server = fixture(limits(), |_| panic!("不完整请求不能到达处理器"));
    let mut slow = connect(&server);
    slow.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
        .unwrap();
    let mut writer = slow.try_clone().unwrap();
    let sending = thread::spawn(move || {
        for _ in 0..15 {
            thread::sleep(Duration::from_millis(30));
            if writer.write_all(b"a").is_err() {
                break;
            }
        }
    });
    let start = Instant::now();
    assert_eq!(status(&read_closed(&mut slow)), 408);
    assert!(start.elapsed() < Duration::from_millis(450));
    sending.join().unwrap();
}

#[test]
fn header_size_is_bounded_without_declared_body() {
    let server = fixture(limits(), |_| panic!("超大请求头不能到达处理器"));
    let wire = format!(
        "GET /x HTTP/1.1\r\nHost: localhost\r\nX-Large: {}",
        "a".repeat(16 * 1024)
    );
    assert_eq!(status(&request(&server, wire.as_bytes())), 431);
}

#[test]
fn coalesced_pipeline_is_rejected_without_executing_any_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let server = fixture(limits(), move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        ok(request)
    });
    let wire =
        b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\nGET /two HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert_eq!(status(&request(&server, wire)), 400);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn delayed_pipeline_never_executes_second_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let server = fixture(limits(), move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(50));
        ok(request)
    });
    let mut stream = connect(&server);
    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    wait_for(|| calls.load(Ordering::SeqCst) == 1);
    stream
        .write_all(b"GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    assert_eq!(status(&read_closed(&mut stream)), 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn saturated_pool_closes_new_connections_and_recovers_after_deadline() {
    let server = fixture(
        HttpLimits {
            max_workers: 2,
            ..limits()
        },
        ok,
    );
    let mut first = connect(&server);
    let mut second = connect(&server);
    first.write_all(b"G").unwrap();
    second.write_all(b"G").unwrap();
    wait_for(|| server.active_connections() == 2);
    let mut refused = connect(&server);
    assert!(read_closed(&mut refused).is_empty());
    assert!(server.active_connections() <= 2);
    assert_eq!(status(&read_closed(&mut first)), 408);
    assert_eq!(status(&read_closed(&mut second)), 408);
    wait_for(|| server.active_connections() == 0);
    assert_eq!(status(&get(&server)), 200);
}

#[test]
fn response_limit_returns_bounded_error_and_worker_remains_usable() {
    let server = fixture(
        HttpLimits {
            max_response_bytes: 128,
            ..limits()
        },
        |request| {
            if request.url() == "/large" {
                ControlResponse::json(200, json!({"large":"x".repeat(4096)}))
            } else {
                ok(request)
            }
        },
    );
    let response = request(&server, b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status(&response), 500);
    assert_eq!(body(&response), json!({"error":"response_limit"}));
    assert!(response.len() < 512);
    assert_eq!(status(&get(&server)), 200);
}

#[test]
fn handler_panic_does_not_destroy_worker() {
    let server = fixture(
        HttpLimits {
            max_workers: 1,
            ..limits()
        },
        |request| {
            if request.url() == "/panic" {
                panic!("合成处理器错误");
            }
            ok(request)
        },
    );
    assert_eq!(
        status(&request(
            &server,
            b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )),
        500
    );
    wait_for(|| server.active_connections() == 0);
    assert_eq!(status(&get(&server)), 200);
}

#[test]
fn drop_cancels_incomplete_connections_without_waiting_for_read_deadline() {
    let server = fixture(
        HttpLimits {
            read_timeout: Duration::from_secs(30),
            ..limits()
        },
        ok,
    );
    let address = server.address();
    let mut stream = connect(&server);
    stream
        .write_all(b"POST /approve HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
        .unwrap();
    wait_for(|| server.active_connections() == 1);
    let start = Instant::now();
    drop(server);
    assert!(start.elapsed() < Duration::from_millis(500));
    assert!(read_closed(&mut stream).is_empty());
    assert_listener_closed(address, "取消不完整连接后");
}

#[test]
fn dropping_idle_or_unstarted_listener_releases_port_and_workers() {
    for start in [false, true] {
        let mut server = ControlHttp::bind(0, limits()).unwrap();
        let address = server.address();
        if start {
            server.start(Arc::new(ok)).unwrap();
            assert!(server.start(Arc::new(ok)).is_err());
        }
        drop(server);
        assert_listener_closed(
            address,
            if start {
                "已启动的空闲入口"
            } else {
                "未启动的入口"
            },
        );
        let rebound = std::net::TcpListener::bind(address).unwrap();
        drop(rebound);
    }
}

#[test]
fn handler_can_release_last_server_owner_without_joining_itself() {
    let owner = Arc::new(Mutex::new(None::<ControlHttp>));
    let weak = Arc::downgrade(&owner);
    let returned = Arc::new(AtomicUsize::new(0));
    let returned_in_handler = returned.clone();
    let server = fixture(limits(), move |request| {
        let owner = weak.upgrade().unwrap();
        let server = owner.lock().unwrap().take().unwrap();
        drop(server);
        returned_in_handler.store(1, Ordering::SeqCst);
        ok(request)
    });
    let address = server.address();
    let mut stream = connect(&server);
    *owner.lock().unwrap() = Some(server);
    stream
        .write_all(b"GET /release HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    assert!(read_closed(&mut stream).is_empty());
    wait_for(|| returned.load(Ordering::SeqCst) == 1);
    assert!(owner.lock().unwrap().is_none());
    assert_listener_closed(address, "处理器释放最后一个所有者后");
}

#[test]
fn invalid_limits_fail_before_binding() {
    for invalid in [
        HttpLimits {
            max_workers: 0,
            ..limits()
        },
        HttpLimits {
            max_workers: 33,
            ..limits()
        },
        HttpLimits {
            max_response_bytes: 0,
            ..limits()
        },
        HttpLimits {
            max_body_bytes: usize::MAX,
            ..limits()
        },
        HttpLimits {
            read_timeout: Duration::ZERO,
            ..limits()
        },
        HttpLimits {
            write_timeout: Duration::from_secs(31),
            ..limits()
        },
    ] {
        assert!(ControlHttp::bind(0, invalid).is_err());
    }
}

#[cfg(unix)]
#[test]
fn nonreading_client_hits_total_write_deadline_and_frees_slot() {
    use std::os::fd::AsRawFd;
    let server = fixture(
        HttpLimits {
            max_workers: 2,
            max_response_bytes: 16 * 1024 * 1024,
            write_timeout: Duration::from_millis(200),
            ..limits()
        },
        |request| {
            if request.url() == "/large" {
                ControlResponse::json(200, json!({"data":"x".repeat(12 * 1024 * 1024)}))
            } else {
                ok(request)
            }
        },
    );
    let mut slow = connect(&server);
    let receive_size: libc::c_int = 1024;
    let changed = unsafe {
        libc::setsockopt(
            slow.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&receive_size as *const libc::c_int).cast(),
            std::mem::size_of_val(&receive_size) as libc::socklen_t,
        )
    };
    assert_eq!(changed, 0);
    slow.write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    wait_for(|| server.active_connections() == 1);
    assert_eq!(status(&get(&server)), 200);
    let start = Instant::now();
    wait_for(|| server.active_connections() == 0);
    assert!(start.elapsed() < Duration::from_secs(2));
    // 连接在客户端尚未读取响应时已释放，不能依赖客户端排空来结束写入。
    let _ = slow.shutdown(Shutdown::Both);
    assert_eq!(status(&get(&server)), 200);
}

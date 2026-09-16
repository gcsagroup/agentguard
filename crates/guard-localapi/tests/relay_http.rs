//! 真实 HTTP 入口：v2 不接受未验证的请求，也不能把响应签给另一个请求。
use guard_localapi::{relay::RelayResponseKey, serve, ApiConfig};
use guard_schema::relay::*;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

struct Server {
    port: u16,
    public: String,
    device: SigningKey,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<anyhow::Result<()>>>,
    _dir: tempfile::TempDir,
}
const TOKEN: &str = "relay-http-test-0123456789abcdef";
impl Server {
    fn new(with_key: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("response-key.json");
        let public = RelayResponseKey::create_or_load(&key_path)
            .unwrap()
            .public_hex();
        let device = SigningKey::random(&mut rand::rngs::OsRng);
        let device_public = hex::encode(device.verifying_key().to_encoded_point(false).as_bytes());
        let registry = dir.path().join("devices.yaml");
        std::fs::write(&registry, format!("adapters:\n  - adapter_id: android-companion\n    key_algorithm: ecdsa-p256\n    public_key: '{device_public}'\n    platforms: [android]\n")).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cfg = ApiConfig {
            bind: format!("127.0.0.1:{port}").parse().unwrap(),
            rules: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../guard-schema/rules/p0_rules.yaml"),
            audit_db: dir.path().join("audit.db"),
            token: TOKEN.into(),
            intel: None,
            intel_pubkey: None,
            allow_lan: false,
            audit_signing_key: None,
            relay_signing_key: with_key.then_some(key_path),
            known_apps: None,
            task_plans: None,
            agent_registry: None,
            adapter_registry: Some(registry),
            insecure_token: false,
            reveal_token: false,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || serve(cfg, Some(flag)));
        let server = Self {
            port,
            public,
            device,
            stop,
            worker: Some(worker),
            _dir: dir,
        };
        for _ in 0..200 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return server;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("测试 API 未启动");
    }
    fn headers(&self, body: &str) -> Vec<(&'static str, String)> {
        let ts = now_ms();
        let signature: Signature = self.device.sign(&guard_schema::adapter_body_message(
            "android-companion",
            guard_schema::ANDROID_ENVELOPE_FORMAT,
            ts,
            body.as_bytes(),
        ));
        vec![
            ("Authorization", format!("Bearer {TOKEN}")),
            (guard_schema::ADAPTER_HEADER_ID, "android-companion".into()),
            (guard_schema::ADAPTER_HEADER_TIMESTAMP, ts.to_string()),
            (
                guard_schema::ADAPTER_HEADER_SIGNATURE,
                hex::encode(signature.to_der().as_bytes()),
            ),
            (RELAY_NONCE_HEADER, "01".repeat(32)),
        ]
    }
    fn post(&self, path: &str, body: &str, headers: &[(&str, String)]) -> ureq::Response {
        let mut req = ureq::post(&format!("http://127.0.0.1:{}{path}", self.port));
        for (name, value) in headers {
            req = req.set(name, value);
        }
        match req.send_string(body) {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("HTTP 请求失败：{error}"),
        }
    }
    fn audit_len(&self) -> usize {
        let body = ureq::get(&format!("http://127.0.0.1:{}/v1/audit/recent", self.port))
            .set("Authorization", &format!("Bearer {TOKEN}"))
            .call()
            .unwrap()
            .into_string()
            .unwrap();
        serde_json::from_str::<Vec<serde_json::Value>>(&body)
            .unwrap()
            .len()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap().unwrap();
            }
        }
    }
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn body() -> &'static str {
    r#"{"type":"batch","session_id":"relay-http-check","events":[{"type":"env_survey","app":"AgentGuard Companion","foreign_a11y_services":["test.foreign/.Reader"],"broadcast_input_receivers":[] }]}"#
}

#[test]
fn 真实签名响应绑定请求且重放不再次处理() {
    let server = Server::new(true);
    let request = body();
    let mut forged = server.headers(request);
    forged
        .iter_mut()
        .find(|(h, _)| *h == guard_schema::ADAPTER_HEADER_SIGNATURE)
        .unwrap()
        .1 = "00".repeat(70);
    assert_eq!(server.post("/v2/events", request, &forged).status(), 403);
    let headers = server.headers(request);
    let response = server.post("/v2/events", request, &headers);
    assert_eq!(response.status(), 200);
    assert_eq!(response.header(RELAY_VERSION_HEADER), Some("2"));
    assert_eq!(
        response.header(RELAY_KEY_HEADER).unwrap(),
        hex::encode(Sha256::digest(hex::decode(&server.public).unwrap()))
    );
    let signature = Signature::from_der(
        &hex::decode(response.header(RELAY_SIGNATURE_HEADER).unwrap()).unwrap(),
    )
    .unwrap();
    let ts = response
        .header(RELAY_TIMESTAMP_HEADER)
        .unwrap()
        .parse()
        .unwrap();
    let result = response.into_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["adapter_identity"]["state"], "verified");
    assert_eq!(parsed["ingested"], 1);
    assert_eq!(
        parsed["decisions"][0]["event_id"], "and-1",
        "拒绝的请求不能推进适配器序号"
    );
    let verifier = VerifyingKey::from_sec1_bytes(&hex::decode(&server.public).unwrap()).unwrap();
    let message = response_message(
        &[1; 32],
        &Sha256::digest(request).into(),
        200,
        ts,
        result.as_bytes(),
    )
    .unwrap();
    verifier.verify(&message, &signature).unwrap();
    let altered = response_message(
        &[2; 32],
        &Sha256::digest(request).into(),
        200,
        ts,
        result.as_bytes(),
    )
    .unwrap();
    assert!(verifier.verify(&altered, &signature).is_err());
    let before = server.audit_len();
    assert!(before > 0);
    assert_eq!(server.post("/v2/events", request, &headers).status(), 403);
    assert_eq!(server.audit_len(), before, "拒绝重放后不能继续写入事件");
}

#[test]
fn 缺密钥缺认证错误目标和超限在处理前拒绝() {
    let unavailable = Server::new(false);
    assert_eq!(
        unavailable
            .post("/v2/events", body(), &unavailable.headers(body()))
            .status(),
        503
    );
    assert_eq!(unavailable.audit_len(), 0);
    let server = Server::new(true);
    let headers = server.headers(body());
    for (name, status) in [
        ("Authorization", 401),
        (RELAY_NONCE_HEADER, 400),
        (guard_schema::ADAPTER_HEADER_ID, 403),
        (guard_schema::ADAPTER_HEADER_TIMESTAMP, 403),
        (guard_schema::ADAPTER_HEADER_SIGNATURE, 403),
    ] {
        let missing: Vec<_> = headers
            .iter()
            .filter(|(h, _)| *h != name)
            .cloned()
            .collect();
        assert_eq!(
            server.post("/v2/events", body(), &missing).status(),
            status,
            "{name}"
        );
    }
    assert_eq!(
        server.post("/v2/events?x=1", body(), &headers).status(),
        400
    );
    assert_eq!(server.post("/v2/events/", body(), &headers).status(), 404);
    let huge = "x".repeat(256 * 1024 + 1);
    assert_eq!(
        server
            .post("/v2/events", &huge, &server.headers(&huge))
            .status(),
        413
    );
    let mut invalid = headers.clone();
    invalid
        .iter_mut()
        .find(|(h, _)| *h == guard_schema::ADAPTER_HEADER_SIGNATURE)
        .unwrap()
        .1 = "00".repeat(70);
    assert_eq!(server.post("/v2/events", body(), &invalid).status(), 403);
    assert_eq!(server.audit_len(), 0);
    // v1 仍保留“未认证调查只能增加风险”的兼容行为，没有冒充已认证响应。
    let legacy = server.post(
        "/v1/events",
        body(),
        &[("Authorization", format!("Bearer {TOKEN}"))],
    );
    assert_eq!(legacy.status(), 200);
    assert!(legacy.header(RELAY_SIGNATURE_HEADER).is_none());
    assert!(server.audit_len() > 0);
}

#[test]
fn 重复认证头与挑战头不能靠解析顺序通过() {
    let server = Server::new(true);
    for duplicated in [
        RELAY_NONCE_HEADER,
        "Authorization",
        guard_schema::ADAPTER_HEADER_SIGNATURE,
    ] {
        let mut headers = server.headers(body());
        headers.push((
            duplicated,
            headers
                .iter()
                .find(|(h, _)| *h == duplicated)
                .unwrap()
                .1
                .clone(),
        ));
        let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(stream, "POST /v2/events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n", body().len()).unwrap();
        for (h, v) in headers {
            write!(stream, "{h}: {v}\r\n").unwrap();
        }
        write!(stream, "\r\n{}", body()).unwrap();
        let mut result = String::new();
        stream.read_to_string(&mut result).unwrap();
        assert!(
            result.starts_with("HTTP/1.1 400") || result.starts_with("HTTP/1.1 403"),
            "{result}"
        );
    }
    assert_eq!(server.audit_len(), 0);
}

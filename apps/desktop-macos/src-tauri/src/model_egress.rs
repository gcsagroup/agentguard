//! 模型出口由桌面持有，批准范围、会话版本与实际发送绑定；正文不写入审计。
use guard_gateway::egress::{
    DataClass, EgressBroker, EgressRequest, HttpMethod, LocalService, ResponsePolicy,
    SessionContext,
};
use guard_gateway::egress_journal::DurableEgressJournal;
use guard_schema::ExecutionOutcome;
use serde_json::Value;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct ModelClient {
    broker: Arc<EgressBroker>,
    context: SessionContext,
    workspace_authorized: bool,
}

pub struct Response {
    pub status: u16,
    pub body: Option<Value>,
}

impl ModelClient {
    pub fn open(
        port: u16,
        journal: &Path,
        session: &str,
        epoch: u64,
        workspace_authorized: bool,
        blocked_ports: Vec<u16>,
    ) -> Result<Self, String> {
        if port == 0 {
            return Err("MODEL_ARGUMENTS".into());
        }
        let mut services = Vec::new();
        for (id, path, method, class) in [
            ("models", "/v1/models", HttpMethod::Get, DataClass::Public),
            (
                "models-status",
                "/v1/models/status",
                HttpMethod::Get,
                DataClass::Public,
            ),
            (
                "completion",
                "/v1/chat/completions",
                HttpMethod::Post,
                DataClass::Workspace,
            ),
        ] {
            services.push(
                LocalService::new(
                    id,
                    &format!("http://127.0.0.1:{port}{path}"),
                    method,
                    "local-model",
                    class,
                    ResponsePolicy::Json,
                )
                .map_err(|e| e.to_string())?,
            );
        }
        let journal =
            Arc::new(DurableEgressJournal::open(journal).map_err(|_| "MODEL_AUDIT_OPEN")?);
        let broker = Arc::new(
            EgressBroker::new(services, blocked_ports, journal).map_err(|e| e.to_string())?,
        );
        let client = Self {
            broker,
            context: SessionContext {
                session_id: format!("{session}:{epoch}"),
                epoch,
            },
            workspace_authorized,
        };
        client.register()?;
        Ok(client)
    }

    fn register(&self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "MODEL_CLOCK")?
            .as_millis() as u64;
        self.broker
            .register_session(self.context.clone(), now + 24 * 60 * 60 * 1000)
            .map_err(|e| e.to_string())
    }

    pub fn renew(&self, session: &str, epoch: u64) -> Result<Self, String> {
        self.revoke();
        // 一个网关会话可有多轮明确追加；出口使用宿主会话与轮次的组合标识，
        // 每轮只登记一次，旧对象仍绑定已撤销的 lease。
        let next = Self {
            broker: self.broker.clone(),
            context: SessionContext {
                session_id: format!("{session}:{epoch}"),
                epoch,
            },
            workspace_authorized: self.workspace_authorized,
        };
        next.register()?;
        Ok(next)
    }

    pub fn revoke(&self) {
        self.broker.revoke_session(&self.context.session_id);
    }
    pub fn is_faulted(&self) -> bool {
        self.broker.is_faulted()
    }

    pub fn request(
        &self,
        path: &str,
        payload: Option<&Value>,
        cancelled: &AtomicBool,
    ) -> Result<Response, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("MODEL_CANCELLED".into());
        }
        let (service, class) = match (path, payload) {
            ("/v1/models", None) => ("models", DataClass::Public),
            ("/v1/models/status", None) => ("models-status", DataClass::Public),
            ("/v1/chat/completions", Some(value)) if self.workspace_authorized => {
                if contains_sensitive(value) {
                    return Err("MODEL_SENSITIVE_DATA".into());
                }
                ("completion", DataClass::Workspace)
            }
            ("/v1/chat/completions", Some(_)) => {
                return Err("MODEL_DATA_AUTHORIZATION_REQUIRED".into())
            }
            _ => return Err("MODEL_ARGUMENTS".into()),
        };
        let request = EgressRequest {
            service_id: service.into(),
            purpose: "local-model".into(),
            data_class: class,
            body: payload.cloned(),
        };
        let grant = self
            .broker
            .issue(&self.context, &request, Duration::from_secs(60))
            .map_err(|e| e.to_string())?;
        let result = self.broker.execute(&self.context, grant, request, &|| {
            cancelled.load(Ordering::Acquire)
        });
        // 传输或持久化结果不明时，不交付可能不完整的模型输出，也不重发。
        if result.outcome == ExecutionOutcome::Unknown {
            return Err("MODEL_EXECUTION_UNCERTAIN".into());
        }
        if result.outcome == ExecutionOutcome::Refused {
            return Err(result.code.into());
        }
        Ok(Response {
            status: result.http_status.ok_or("MODEL_HTTP_STATUS")?,
            body: result.body,
        })
    }
}

fn contains_sensitive(value: &Value) -> bool {
    match value {
        Value::String(text) => guard_privacy::recognised_confidentiality(text).is_some(),
        Value::Array(values) => values.iter().any(contains_sensitive),
        Value::Object(values) => values.iter().any(|(key, value)| {
            guard_privacy::recognised_confidentiality(key).is_some() || contains_sensitive(value)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("ag-model-scope-{}", uuid::Uuid::new_v4()));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn client(&self, port: u16, authorized: bool) -> ModelClient {
            ModelClient::open(
                port,
                &self.0.join("egress.db"),
                "host-session",
                0,
                authorized,
                vec![],
            )
            .unwrap()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn 未授权敏感字段及已撤销会话没有网络连接() {
        for scenario in [
            "no-consent",
            "sensitive",
            "revoked",
            "cancelled",
            "unknown-path",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let directory = Directory::new();
            let client = directory.client(
                listener.local_addr().unwrap().port(),
                scenario != "no-consent",
            );
            if scenario == "revoked" {
                client.revoke();
            }
            let payload = if scenario == "sensitive" {
                json!({"messages":[{"content":"联系 alice@example.test"}]})
            } else {
                json!({"messages":[{"content":"合成内容"}]})
            };
            let path = if scenario == "unknown-path" {
                "/approve"
            } else {
                "/v1/chat/completions"
            };
            assert!(
                client
                    .request(
                        path,
                        Some(&payload),
                        &AtomicBool::new(scenario == "cancelled")
                    )
                    .is_err(),
                "{scenario}"
            );
            assert!(listener.accept().is_err(), "{scenario}");
        }
    }

    #[test]
    fn 宿主控制端口不能登记为模型服务() {
        let directory = Directory::new();
        assert!(ModelClient::open(
            34567,
            &directory.0.join("egress.db"),
            "host-session",
            0,
            true,
            vec![34567]
        )
        .is_err());
    }

    #[test]
    fn 同一网关会话追加轮次可登记但相同轮次不可复活() {
        let directory = Directory::new();
        let client = directory.client(34568, true);
        let next = client.renew("host-session", 1).unwrap();
        assert!(next.renew("host-session", 1).is_err());
    }

    #[test]
    fn 新会话实际发送一次且旧会话不能复用() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = Directory::new();
        let client = directory.client(port, true);
        let next = client.renew("host-resumed", 1).unwrap();
        let payload = json!({"messages":[{"content":"SYNTHETIC_PROJECT_TEXT"}]});
        assert!(client
            .request(
                "/v1/chat/completions",
                Some(&payload),
                &AtomicBool::new(false)
            )
            .is_err());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut data = vec![];
            loop {
                let mut buffer = [0; 4096];
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buffer[..n]);
                if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = std::str::from_utf8(&data[..at]).unwrap();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if data.len() >= at + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").unwrap();
            data
        });
        assert_eq!(
            next.request(
                "/v1/chat/completions",
                Some(&payload),
                &AtomicBool::new(false)
            )
            .unwrap()
            .body,
            Some(json!({"ok":true}))
        );
        assert!(String::from_utf8(server.join().unwrap())
            .unwrap()
            .contains("SYNTHETIC_PROJECT_TEXT"));
        next.revoke();
        drop(next);
        drop(client);
        let store = guard_audit::AuditStore::open_read_only(directory.0.join("egress.db")).unwrap();
        let log = store.export_jsonl(100).unwrap();
        assert!(!log.contains("SYNTHETIC_PROJECT_TEXT"));
        assert!(!log.contains("host-resumed"));
        assert!(store.verify_chain().unwrap().ok);
        assert_eq!(store.list_recent(100).unwrap().len(), 2);
    }
}

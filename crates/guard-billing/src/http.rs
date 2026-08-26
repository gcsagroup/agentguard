//! Local HTTP webhook receiver for billing events (dev / self-host POC).

use crate::{apply_webhook_json, Entitlement};
use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tiny_http::{Header, Method, Response, StatusCode};

/// Serve `POST /webhook/billing` applying JSON bodies to `store`.
/// Also supports `GET /health`.
///
/// Runs until `shutdown` is set, or forever if None.
pub fn serve_billing_webhook(
    bind: SocketAddr,
    store: PathBuf,
    shutdown: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let server = tiny_http::Server::http(bind).map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;
    eprintln!("billing webhook listening on http://{bind}/webhook/billing");

    // 签名密钥在启动时读一次(避免每请求读进程全局 env 的竞态)。没设 = **拒收所有
    // webhook**(fail-closed):这个接收端会自铸并激活授权令牌,一个未认证的匿名 POST
    // 不能被允许改动授权。
    let secret = std::env::var("AGENTGUARD_WEBHOOK_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    if secret.is_none() {
        eprintln!(
            "warning: AGENTGUARD_WEBHOOK_SECRET 未设 —— 接收端将**拒收所有** webhook POST \
             (fail-closed)。设成签发方的签名密钥后才会校验并应用。"
        );
    }

    loop {
        if shutdown
            .as_ref()
            .map(|s| s.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            break;
        }
        let mut request = match server.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("recv error: {e}");
                continue;
            }
        };

        let url = request.url().to_string();
        let method = request.method().clone();
        let response = match (&method, url.as_str()) {
            (Method::Get, "/health") | (Method::Get, "/health/") => {
                Response::from_string(r#"{"ok":true}"#).with_header(json_header())
            }
            (Method::Post, "/webhook/billing") | (Method::Post, "/webhook/billing/") => {
                match &secret {
                    // 没配密钥:拒收(fail-closed),绝不在未认证下改动授权。
                    None => json_response(
                        503,
                        r#"{"error":"webhook secret not configured; receiver refuses unauthenticated posts"}"#,
                    ),
                    Some(sec) => {
                        // 头要在消费 body 之前读。
                        let sig = header_value(&request, "X-AgentGuard-Signature");
                        match read_body(&mut request) {
                            Ok(body) => {
                                if !crate::verify_webhook_signature(sec, &body, sig.as_deref()) {
                                    json_response(
                                        401,
                                        r#"{"error":"invalid or missing X-AgentGuard-Signature (HMAC-SHA256 of the raw body)"}"#,
                                    )
                                } else {
                                    match apply_webhook_json(&body, &store) {
                                        Ok(ent) => json_response(200, &webhook_ok(&ent)),
                                        Err(e) => json_response(
                                            400,
                                            &format!(r#"{{"error":"{}"}}"#, escape(&e.to_string())),
                                        ),
                                    }
                                }
                            }
                            Err(e) => json_response(
                                400,
                                &format!(r#"{{"error":"{}"}}"#, escape(&e.to_string())),
                            ),
                        }
                    }
                }
            }
            _ => json_response(404, r#"{"error":"not found"}"#),
        };
        let _ = request.respond(response);
    }
    Ok(())
}

/// 大小写不敏感地取一个请求头的值。
fn header_value(request: &tiny_http::Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.to_string().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn read_body(request: &mut tiny_http::Request) -> Result<String> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(request.as_reader(), &mut buf)?;
    let s = String::from_utf8(buf).context("webhook body utf-8")?;
    if s.trim().is_empty() {
        bail!("empty body");
    }
    Ok(s)
}

fn webhook_ok(ent: &Entitlement) -> String {
    let plan = match ent.plan {
        crate::PlanTier::Free => "free",
        crate::PlanTier::Pro => "pro",
        crate::PlanTier::Enterprise => "enterprise",
    };
    format!(
        r#"{{"ok":true,"plan":"{}","active":{},"license_id":"{}"}}"#,
        plan,
        ent.is_active(),
        escape(&ent.license_id)
    )
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn json_response(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(body.as_bytes().to_vec())
        .with_status_code(StatusCode::from(status))
        .with_header(json_header())
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// One-shot helper used by tests: apply without serving.
pub fn apply_file_to_store(path: impl AsRef<Path>, store: impl AsRef<Path>) -> Result<Entitlement> {
    let raw = std::fs::read_to_string(path.as_ref()).context("read webhook file")?;
    apply_webhook_json(&raw, store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn health_and_signed_purchase_via_http() {
        // 这个测试独占 webhook 密钥环境变量;端口也独占,避免和下面拒收测试撞车。
        std::env::set_var("AGENTGUARD_WEBHOOK_SECRET", "test-webhook-secret-abc");
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("ent.json");
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let store_c = store.clone();
        let handle = thread::spawn(move || {
            let _ = serve_billing_webhook("127.0.0.1:18765".parse().unwrap(), store_c, Some(flag));
        });
        thread::sleep(Duration::from_millis(300));

        let health = ureq::get("http://127.0.0.1:18765/health").call().unwrap();
        assert_eq!(health.status(), 200);

        let body = r#"{"type":"purchase","license_id":"http-1","plan":"pro"}"#;
        let sig = crate::sign_webhook_body("test-webhook-secret-abc", body);

        // 无签名 → 401。
        let denied = ureq::post("http://127.0.0.1:18765/webhook/billing")
            .set("Content-Type", "application/json")
            .send_string(body);
        match denied {
            Err(ureq::Error::Status(code, _)) => assert_eq!(code, 401),
            other => panic!("无签名应当 401,得到 {other:?}"),
        }

        // 正确签名 → 200。
        let resp = ureq::post("http://127.0.0.1:18765/webhook/billing")
            .set("Content-Type", "application/json")
            .set("X-AgentGuard-Signature", &sig)
            .send_string(body)
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(store.exists());

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
        std::env::remove_var("AGENTGUARD_WEBHOOK_SECRET");
    }

    /// HMAC 验证的纯逻辑(不起服务器):正确签名过、篡改 body / 错密钥 / 缺头都拒。
    #[test]
    fn 签名验证拒绝伪造() {
        let secret = "s3cr3t";
        let body = r#"{"type":"purchase","license_id":"x","plan":"enterprise"}"#;
        let good = crate::sign_webhook_body(secret, body);
        assert!(crate::verify_webhook_signature(secret, body, Some(&good)));
        // 篡改 body
        assert!(!crate::verify_webhook_signature(
            secret,
            r#"{"plan":"free"}"#,
            Some(&good)
        ));
        // 错密钥
        assert!(!crate::verify_webhook_signature("wrong", body, Some(&good)));
        // 缺头 / 垃圾头
        assert!(!crate::verify_webhook_signature(secret, body, None));
        assert!(!crate::verify_webhook_signature(
            secret,
            body,
            Some("sha256=zzzz")
        ));
    }
}

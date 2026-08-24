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
                match read_body(&mut request) {
                    Ok(body) => match apply_webhook_json(&body, &store) {
                        Ok(ent) => json_response(200, &webhook_ok(&ent)),
                        Err(e) => json_response(
                            400,
                            &format!(r#"{{"error":"{}"}}"#, escape(&e.to_string())),
                        ),
                    },
                    Err(e) => {
                        json_response(400, &format!(r#"{{"error":"{}"}}"#, escape(&e.to_string())))
                    }
                }
            }
            _ => json_response(404, r#"{"error":"not found"}"#),
        };
        let _ = request.respond(response);
    }
    Ok(())
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
    fn health_and_purchase_via_http() {
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
        let resp = ureq::post("http://127.0.0.1:18765/webhook/billing")
            .set("Content-Type", "application/json")
            .send_string(body)
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(store.exists());

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }
}

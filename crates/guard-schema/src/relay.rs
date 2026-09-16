//! Android 中继响应的固定签名合同；它不是通用 HTTP Message Signatures 实现。

pub const RELAY_NONCE_HEADER: &str = "X-AgentGuard-Relay-Nonce";
pub const RELAY_SIGNATURE_HEADER: &str = "X-AgentGuard-Relay-Signature";
pub const RELAY_TIMESTAMP_HEADER: &str = "X-AgentGuard-Relay-Timestamp";
pub const RELAY_KEY_HEADER: &str = "X-AgentGuard-Relay-Key-Id";
pub const RELAY_VERSION_HEADER: &str = "X-AgentGuard-Relay-Version";
pub const MAX_RELAY_RESPONSE_BYTES: usize = 1024 * 1024;

/// 每段加 u32 大端长度；签实际响应字节，不对 JSON 做第二次序列化。
pub fn response_message(
    nonce: &[u8; 32],
    request_sha256: &[u8; 32],
    status: u16,
    timestamp_ms: i64,
    body: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if status != 200 || timestamp_ms < 0 || body.len() > MAX_RELAY_RESPONSE_BYTES {
        return Err("中继响应状态、时间或长度不合法");
    }
    let status = status.to_string();
    let timestamp = timestamp_ms.to_string();
    let mut out = b"AGENTGUARD-RELAY-RESPONSE-v2".to_vec();
    for field in [
        b"POST".as_slice(),
        b"/v2/events".as_slice(),
        nonce.as_slice(),
        request_sha256.as_slice(),
        status.as_bytes(),
        timestamp.as_bytes(),
        body,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 所有上下文和正文均进入响应签名() {
        let base = response_message(&[1; 32], &[2; 32], 200, 3, b"{}").unwrap();
        for changed in [
            response_message(&[4; 32], &[2; 32], 200, 3, b"{}"),
            response_message(&[1; 32], &[4; 32], 200, 3, b"{}"),
            response_message(&[1; 32], &[2; 32], 200, 4, b"{}"),
            response_message(&[1; 32], &[2; 32], 200, 3, b"[]"),
        ] {
            assert_ne!(base, changed.unwrap());
        }
        assert!(response_message(&[1; 32], &[2; 32], 201, 3, b"{}").is_err());
        assert!(response_message(&[1; 32], &[2; 32], 200, -1, b"{}").is_err());
        assert!(response_message(
            &[1; 32],
            &[2; 32],
            200,
            3,
            &vec![0; MAX_RELAY_RESPONSE_BYTES + 1],
        )
        .is_err());
    }
}

//! 一次已批准动作的实际派发许可。撤权、登记复核与系统调用之间不留检查窗口。
use crate::confirm::PendingConfirm;
use crate::mcp_stdio::DispatchGuard;
use crate::tool_registry::SharedRegistry;
use guard_schema::{ActionSnapshot, ApprovalBinding};
use std::io;

#[derive(Clone)]
pub(crate) struct DispatchPermit {
    pub pending: PendingConfirm,
    pub epoch: u64,
    pub registry: SharedRegistry,
    pub action: ActionSnapshot,
    pub approval: ApprovalBinding,
}
impl DispatchPermit {
    pub fn with<T>(&self, dispatch: impl FnOnce() -> T) -> Option<T> {
        // operator 先释放登记锁再暂停；固定锁顺序是确认槽 -> 登记表。
        self.pending
            .with_active_epoch(self.epoch, || {
                let registry = self.registry.lock().ok()?;
                let now = super::server::proxy_now_ms();
                if self
                    .approval
                    .validate_for_action(&self.action, now)
                    .is_err()
                    || registry.verify_identity(&self.action.spec().tool).is_err()
                {
                    return None;
                }
                Some(dispatch())
            })
            .flatten()
    }
    pub fn cancelled(&self) -> bool {
        self.with(|| ()).is_none()
    }
}
impl DispatchGuard for DispatchPermit {
    fn with_permission(
        &self,
        write: &mut dyn FnMut() -> io::Result<usize>,
    ) -> Option<io::Result<usize>> {
        self.with(write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_registry::{digest, ToolRegistry};
    use guard_schema::{
        ActionSpec, RegisteredToolDescriptor, ToolExposure, ToolPackageIdentity,
        ToolServiceManifest, ValidatedId,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    fn permit() -> DispatchPermit {
        let mut registry = ToolRegistry::default();
        registry
            .observe(ToolServiceManifest {
                registry_version: 1,
                service_id: "fixture".into(),
                namespace: "fixture".into(),
                service_version: "1".into(),
                package: ToolPackageIdentity {
                    package_id: "fixture".into(),
                    version: "1".into(),
                    sha256: digest(b"fixture"),
                },
                tools: vec![RegisteredToolDescriptor {
                    name: "read".into(),
                    description: "合成读取".into(),
                    input_schema: json!({"type":"object"}),
                    exposure: ToolExposure::Mcp,
                    mcp: None,
                }],
                mcp: None,
            })
            .unwrap();
        let review = registry.review("fixture").unwrap();
        registry
            .decide(
                "fixture",
                review["review_id"].as_str().unwrap(),
                review["review_nonce"].as_str().unwrap(),
                review["manifest_sha256"].as_str().unwrap(),
                true,
            )
            .unwrap();
        let now = super::super::server::proxy_now_ms();
        let id = |s: &str| ValidatedId::new(s).unwrap();
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: 1,
            session_id: id("test-session"),
            action_id: id("test-action"),
            request_id: id("test-request"),
            tool: registry.identity("fixture", "read").unwrap(),
            target: "fixture-read".into(),
            parameters: json!({}),
            policy_version: id("test-policy"),
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            nonce: "a".repeat(64),
            sources: vec![],
        })
        .unwrap();
        let approval = ApprovalBinding::new(
            id("test-approval"),
            action.clone(),
            "b".repeat(64),
            now,
            now + 60_000,
        )
        .unwrap();
        DispatchPermit {
            pending: PendingConfirm::new(),
            epoch: 0,
            registry: Arc::new(Mutex::new(registry)),
            action,
            approval,
        }
    }
    #[test]
    fn 登记撤销后旧许可不触发真实写入闭包() {
        let permit = permit();
        assert_eq!(permit.with(|| 7), Some(7));
        let binding = permit.action.spec().tool.registration.as_ref().unwrap();
        permit
            .registry
            .lock()
            .unwrap()
            .revoke("fixture", binding.registration_id.as_str())
            .unwrap();
        assert!(permit.with(|| panic!("旧许可不应写入")).is_none());
    }
    #[test]
    fn 同一锁保证暂停完成之后不会有旧许可派发() {
        let permit = permit();
        let pending = permit.pending.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = permit
            .with(|| {
                let thread = std::thread::spawn(move || {
                    pending.pause();
                    sender.send(()).unwrap();
                });
                assert!(receiver.try_recv().is_err());
                thread
            })
            .unwrap();
        thread.join().unwrap();
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(permit.with(|| panic!("暂停后不能派发")).is_none());
    }
    #[test]
    fn 批准绑定不一致与过期均不触发派发() {
        let mut permit = permit();
        let mut spec = permit.action.spec().clone();
        spec.parameters = json!({"replaced":true});
        permit.action = ActionSnapshot::new(spec).unwrap();
        assert!(permit.cancelled());
        let now = super::super::server::proxy_now_ms();
        let mut spec = permit.action.spec().clone();
        spec.issued_at_ms = now - 10_000;
        spec.expires_at_ms = now - 1;
        permit.action = ActionSnapshot::new(spec).unwrap();
        permit.approval = ApprovalBinding::new(
            ValidatedId::new("expired").unwrap(),
            permit.action.clone(),
            "c".repeat(64),
            now - 10_000,
            now - 1,
        )
        .unwrap();
        assert!(permit.with(|| panic!("过期不能派发")).is_none());
    }
}

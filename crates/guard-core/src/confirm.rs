//! Critical confirm gate for Block/Alert decisions that require user approval.

use guard_schema::Decision;
use serde::{Deserialize, Serialize};

/// Outcome of a critical confirmation prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmResponse {
    ApproveOnce,
    DenyAndPause,
    Timeout,
}

/// Prompt shown when `decision.require_confirm` is true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub audit_id: Option<String>,
    pub rule_id: String,
    pub severity: String,
    pub human_message: String,
    pub source_app: String,
    pub ui_excerpt: Option<String>,
}

impl ConfirmRequest {
    /// Build a confirm request, **redacting as the struct is constructed**.
    ///
    /// Not at the print site, and that is the point. A reviewer showed that stripping the
    /// redactor from `StdinConfirm`'s `eprintln!` went undetected by
    /// `no_print_sink_emits_observed_text_unredacted`, because the span mentions the local
    /// `ex` and not `ui_excerpt` — an alias, which the scanner's own doc lists as a known
    /// blind spot. So the sink that prints raw screen text was the one the guard did not
    /// guard.
    ///
    /// Redacting here makes that unreachable: every prompt implementation — the CLI one, a
    /// Tauri one, a future notification — receives content that is already safe, and no new
    /// prompt has to remember. The scanner stays as a backstop; the invariant no longer
    /// depends on it.
    pub fn from_decision(
        decision: &Decision,
        source_app: &str,
        audit_id: Option<String>,
        ui_excerpt: Option<String>,
    ) -> Self {
        Self {
            audit_id,
            rule_id: decision.rule_id.clone(),
            severity: format!("{:?}", decision.severity),
            human_message: guard_privacy::log_safe(&decision.human_message),
            source_app: source_app.into(),
            ui_excerpt: ui_excerpt.map(|x| guard_privacy::log_excerpt(&x, 160)),
        }
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use guard_schema::{DecisionAction, Severity};

    /// The request is safe before any prompt sees it.
    ///
    /// This is the invariant that replaced "remember to call the redactor at each print
    /// site": stripping the redactor from `StdinConfirm`'s `eprintln!` was invisible to the
    /// source scanner, because the span names a local alias.
    #[test]
    fn a_confirm_request_is_redacted_at_construction() {
        let d = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: "CRIT-001".into(),
            human_message: "Confirm payment of 4242 4242 4242 4242".into(),
            require_confirm: true,
        };
        let r = ConfirmRequest::from_decision(
            &d,
            "Booking",
            None,
            Some("Saved card 4242 4242 4242 4242, mail ming.lin@lbemobile.com".into()),
        );
        assert!(
            !r.human_message.contains("4242 4242 4242"),
            "{}",
            r.human_message
        );
        let ui = r.ui_excerpt.unwrap();
        assert!(!ui.contains("4242 4242 4242"), "{ui}");
        assert!(!ui.contains("ming.lin@"), "{ui}");
        // Context survives, so the prompt still tells the user what is happening.
        assert!(r.human_message.contains("Confirm payment"));
        assert_eq!(r.rule_id, "CRIT-001");
    }
}

/// Platform-agnostic confirm UI (CLI / Tauri / auto for tests).
pub trait ConfirmPrompt: Send + Sync {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmResponse;

    /// Who this prompt speaks for, recorded as the approver on anything that
    /// needs attribution — notably an Aura HITL declassification, which is the
    /// only path that lowers a taint label.
    ///
    /// The default names the channel rather than a person, which is honest for a
    /// local stdin prompt. A host with a real signed-in account (the macOS menu
    /// bar, the extension's native host) should override it: an audit record
    /// saying `local-confirm-prompt` approved a passport disclosure is weaker
    /// evidence than one naming the account, and pretending otherwise would put a
    /// name in the log that nobody actually typed.
    fn approver(&self) -> String {
        "local-confirm-prompt".to_string()
    }
}

/// Always deny — safe default for unattended runs.
#[derive(Debug, Default)]
pub struct AutoDeny;

impl ConfirmPrompt for AutoDeny {
    fn confirm(&self, _request: &ConfirmRequest) -> ConfirmResponse {
        ConfirmResponse::DenyAndPause
    }
}

/// Always approve once — test helper.
#[derive(Debug, Default)]
pub struct AutoApprove;

impl ConfirmPrompt for AutoApprove {
    fn confirm(&self, _request: &ConfirmRequest) -> ConfirmResponse {
        ConfirmResponse::ApproveOnce
    }
}

/// Channel-backed prompt: UI thread sends response via oneshot-like queue.
#[derive(Debug)]
pub struct ChannelConfirm {
    tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<ConfirmRequest>>>,
    rx: std::sync::Mutex<std::sync::mpsc::Receiver<ConfirmResponse>>,
}

impl ChannelConfirm {
    pub fn pair() -> (Self, ConfirmHandle) {
        let (req_tx, req_rx) = std::sync::mpsc::channel();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        let gate = Self {
            tx: std::sync::Mutex::new(Some(req_tx)),
            rx: std::sync::Mutex::new(resp_rx),
        };
        let handle = ConfirmHandle { req_rx, resp_tx };
        (gate, handle)
    }
}

impl ConfirmPrompt for ChannelConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmResponse {
        if let Ok(guard) = self.tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(request.clone());
            }
        }
        self.rx
            .lock()
            .ok()
            .and_then(|rx| rx.recv_timeout(std::time::Duration::from_secs(120)).ok())
            .unwrap_or(ConfirmResponse::Timeout)
    }
}

/// UI-facing side of [`ChannelConfirm`].
#[derive(Debug)]
pub struct ConfirmHandle {
    req_rx: std::sync::mpsc::Receiver<ConfirmRequest>,
    resp_tx: std::sync::mpsc::Sender<ConfirmResponse>,
}

impl ConfirmHandle {
    pub fn try_recv(&self) -> Option<ConfirmRequest> {
        self.req_rx.try_recv().ok()
    }

    pub fn reply(
        &self,
        response: ConfirmResponse,
    ) -> Result<(), std::sync::mpsc::SendError<ConfirmResponse>> {
        self.resp_tx.send(response)
    }
}

/// Stdin yes/no prompt for CLI demos.
#[derive(Debug, Default)]
pub struct StdinConfirm;

impl ConfirmPrompt for StdinConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmResponse {
        eprintln!("────────────────────────────────────────");
        eprintln!("⚠️  AgentGuard critical confirm");
        eprintln!("  rule: {}", request.rule_id);
        eprintln!("  app:  {}", request.source_app);
        // Redacted on the way out. This prompt writes to **stderr**, which on every
        // platform we ship to is collected by something — a launchd log, a systemd
        // journal, a terminal someone pastes into a bug report. AgentScan §3.8 reports log
        // leakage against three of the agents it tested; a guard that prints the screen it
        // was protecting has become the same finding.
        // Already redacted by `ConfirmRequest::from_decision`; `log_safe` is idempotent, so
        // the second call is a no-op and keeps the guarantee local to the sink as well.
        eprintln!(
            "  msg:  {}",
            guard_privacy::log_safe(&request.human_message)
        );
        if let Some(ex) = &request.ui_excerpt {
            eprintln!("  ui:   {}", guard_privacy::log_excerpt(ex, 160));
        }
        eprintln!("  [y] approve once   [N] deny & pause");
        eprintln!("────────────────────────────────────────");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return ConfirmResponse::Timeout;
        }
        match line.trim().to_lowercase().as_str() {
            "y" | "yes" => ConfirmResponse::ApproveOnce,
            _ => ConfirmResponse::DenyAndPause,
        }
    }
}

const NATIVE_HOST = "com.agentguard.native";
const MAX_BUFFER = 50;

/** @type {object[]} */
let recent = [];
let nativeEnabled = true;

chrome.storage.local.get(["nativeEnabled", "recent"], (data) => {
  if (typeof data.nativeEnabled === "boolean") nativeEnabled = data.nativeEnabled;
  if (Array.isArray(data.recent)) recent = data.recent;
});

function pushRecent(entry) {
  recent.unshift(entry);
  recent = recent.slice(0, MAX_BUFFER);
  chrome.storage.local.set({ recent });
}

function findingsToEvents(payload) {
  const events = [];
  for (const f of payload.findings || []) {
    if (f.kind === "payment_cta" || f.kind === "prompt_injection" || f.kind === "invisible_injection") {
      events.push({
        type: "ui_text",
        app: "browser",
        text: f.marker || f.text || "",
        url: payload.url,
      });
    } else if (f.kind === "optional_pii" || f.kind === "privacy_trap") {
      events.push({
        type: "form_fill",
        app: "browser",
        field_id: f.field_id,
        profile_key: f.profile_key,
        required: !!f.required,
        value_filled: true,
        is_trap: !!f.is_trap,
        probe_type: f.probe_type,
        url: payload.url,
      });
    }
  }
  return events;
}

function setBadge(text, color) {
  // action.setBadge* needs no extra permission (the action is declared). Wrapped
  // because the service worker may be torn down between calls.
  try {
    chrome.action.setBadgeText({ text });
    if (color) chrome.action.setBadgeBackgroundColor({ color });
  } catch (e) {
    console.debug("AgentGuard badge failed", e);
  }
}

function notifyUser(item) {
  // This is the browser form of "Critical Confirm": the host judged (and, under
  // AutoDeny, blocked + paused) a Critical action, and the user is told. It is a
  // notification, not an interactive approve-then-proceed — native messaging is
  // async and the host observes the event after it happened, so there is nothing
  // to hold. See NotifyItem in guard-nm-host for why.
  try {
    chrome.notifications.create("", {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: item.require_confirm
        ? "AgentGuard — 关键操作(本应由你确认)"
        : "AgentGuard — 拦下一个关键操作",
      message: `[${item.rule_id || "?"}] ${item.message || item.action || ""}`.slice(0, 300),
      priority: 2,
    });
  } catch (e) {
    console.debug("AgentGuard notify failed", e);
  }
}

/**
 * Act on the host's verdict. Before this, background.js console.debug'd the
 * response and discarded it, so the "Critical Confirm" the store listing
 * advertised never fired. Now: raise a notification per Critical/Block/
 * confirm-worthy decision, reflect pause state in the badge, and record it for
 * the popup.
 */
function handleVerdict(response) {
  if (!response || typeof response !== "object") return;
  const items = Array.isArray(response.notify) ? response.notify : [];
  for (const item of items) notifyUser(item);

  if (response.paused) {
    // Engine paused by a Critical decision: everything after is refused wholesale.
    setBadge("‖", "#b00020");
  } else if (items.length) {
    setBadge(String(items.length), "#c26a00");
  }
  if (response.audit_degraded) {
    console.debug("AgentGuard: verdict returned but audit row did not persist");
  }
  if (items.length || response.paused) {
    pushRecent({
      ts: Date.now(),
      kind: "verdict",
      paused: !!response.paused,
      notify: items.map((i) => ({
        rule_id: i.rule_id,
        action: i.action,
        severity: i.severity,
        require_confirm: !!i.require_confirm,
      })),
    });
  }
}

function sendNative(message) {
  if (!nativeEnabled) return;
  try {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      if (chrome.runtime.lastError) {
        // Host may be unregistered during early development — keep local buffer.
        console.debug("AgentGuard native:", chrome.runtime.lastError.message);
        return;
      }
      handleVerdict(response);
    });
  } catch (err) {
    console.debug("AgentGuard native failed", err);
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "agentguard_findings") return;
  const entry = {
    ts: msg.ts,
    url: msg.url,
    title: msg.title,
    count: (msg.findings || []).length,
    kinds: [...new Set((msg.findings || []).map((f) => f.kind))],
  };
  pushRecent(entry);
  const events = findingsToEvents(msg);
  if (events.length) {
    sendNative({
      type: "browser_events",
      source: "extension-chromium",
      events,
    });
  }
  sendResponse({ ok: true, forwarded: events.length });
  return true;
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "get_recent") {
    sendResponse({ recent, nativeEnabled });
    return true;
  }
  if (msg?.type === "set_native") {
    nativeEnabled = !!msg.enabled;
    chrome.storage.local.set({ nativeEnabled });
    sendResponse({ ok: true });
    return true;
  }
});

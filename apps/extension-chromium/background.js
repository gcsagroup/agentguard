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

function sendNative(message) {
  if (!nativeEnabled) return;
  try {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      if (chrome.runtime.lastError) {
        // Host may be unregistered during early development — keep local buffer.
        console.debug("AgentGuard native:", chrome.runtime.lastError.message);
        return;
      }
      console.debug("AgentGuard native response", response);
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

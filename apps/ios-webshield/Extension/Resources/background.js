"use strict";

const nativeApplicationIdentifier = "com.agentguard.webshield";
const unavailableStatus = Object.freeze({
  state: "unavailable",
  enabled: false,
  privacyAccepted: false,
  policyRevision: "unknown",
  nativeAvailable: false
});

function requestId() {
  return crypto.randomUUID();
}

function statusFrom(response, expectedRequestId) {
  if (!response || response.ok !== true || response.version !== 1
    || typeof response.requestId !== "string"
    || response.requestId.toLowerCase() !== expectedRequestId.toLowerCase()
    || typeof response.enabled !== "boolean"
    || typeof response.privacyAccepted !== "boolean"
    || typeof response.policyRevision !== "string"
    || (response.enabled && !response.privacyAccepted)) return null;
  const enabled = response.enabled && response.privacyAccepted;
  return {
    state: enabled ? "enabled" : "disabled",
    enabled,
    privacyAccepted: Boolean(response.privacyAccepted),
    policyRevision: String(response.policyRevision || "unknown").slice(0, 64),
    nativeAvailable: true
  };
}

async function refreshStatus() {
  try {
    const requestID = requestId();
    const response = await browser.runtime.sendNativeMessage(nativeApplicationIdentifier, {
      version: 1,
      requestId: requestID,
      type: "get_status"
    });
    const status = statusFrom(response, requestID);
    if (!status) return unavailableStatus;
    return status;
  } catch (_error) {
    return unavailableStatus;
  }
}

function sanitizeEvent(value) {
  if (!value || typeof value !== "object") return null;
  return {
    ruleId: String(value.ruleId || "").slice(0, 32),
    kind: String(value.kind || "").slice(0, 32),
    action: String(value.action || "").slice(0, 16),
    timestampMs: Number(value.timestampMs),
    url: String(value.url || "").slice(0, 2_048)
  };
}

async function recordEvents(values) {
  const status = await refreshStatus();
  if (status.state === "unavailable") {
    return { ok: false, error: "native_unavailable", ...status };
  }
  if (status.state !== "enabled") {
    return { ok: false, error: "protection_disabled", ...status };
  }
  const events = Array.isArray(values) ? values.slice(0, 50).map(sanitizeEvent).filter(Boolean) : [];
  if (events.length === 0) return { ok: false, error: "invalid_events", ...status };
  try {
    return await browser.runtime.sendNativeMessage(nativeApplicationIdentifier, {
      version: 1,
      requestId: requestId(),
      type: "record_events",
      events
    });
  } catch (_error) {
    return { ok: false, error: "native_unavailable", ...status };
  }
}

browser.runtime.onMessage.addListener((message) => {
  if (!message || typeof message !== "object") return undefined;
  if (message.type === "webshield:get-status") return refreshStatus();
  if (message.type === "webshield:record-events") return recordEvents(message.events);
  return undefined;
});

browser.runtime.onInstalled.addListener(() => {
  void refreshStatus();
});

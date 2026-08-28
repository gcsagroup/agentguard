// 副作用导入:执行 guard-gate.js 的 IIFE,把纯逻辑挂到 self.AgentGuardGate。
// 内容脚本按 manifest 顺序拿到同一份文件;这里 background(module service worker)靠 import 拿到。
import "./guard-gate.js";

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
  // 宿主可以随判决附一组要在网络层拦的主机(恶意域 / 越出 scope.hosts 的目的地),每条带 kind。
  if (Array.isArray(response.block_hosts) && response.block_hosts.length) {
    updateBlocklist(response.block_hosts);
  }
  // E9:当前会话的主机允许表快照。存进 storage,内容脚本据此推给页面做本地越界判定。
  // 字段缺失 = 没声明 → 存 null(内容脚本会据此关掉本地越界拦截)。
  try {
    chrome.storage.local.set({
      scope_hosts: Array.isArray(response.scope_hosts) ? response.scope_hosts : null,
    });
  } catch (e) {
    console.debug("AgentGuard scope_hosts persist failed", e);
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

// 名单状态(E8):{persistent:[恶意域], session:[{host,exp}]}。恶意域累积保留并落 storage 跨
// 重启存活;越界项随会话过期。合并/过期逻辑是 guard-gate.js 的纯函数 mergeBlocklist(有 node 单测)。
// provenance(E12):host → {kind, rule_id},给 popup 溯源"为什么被拦"。
let blocklist = { persistent: [], session: [], provenance: {} };
chrome.storage.local.get(["blocklist"], (data) => {
  if (data.blocklist && Array.isArray(data.blocklist.persistent)) {
    blocklist = {
      persistent: data.blocklist.persistent,
      session: Array.isArray(data.blocklist.session) ? data.blocklist.session : [],
      provenance:
        data.blocklist.provenance && typeof data.blocklist.provenance === "object"
          ? data.blocklist.provenance
          : {},
    };
    // 启动即把已知恶意域重新装上(service worker 重启后 DNR 动态规则可能已被清)。
    installActive();
  }
});

// 收到宿主的一批 block_hosts:按 kind 分流,合并进累积状态,持久化,再装 active 集。
function updateBlocklist(blockHosts) {
  const Gate = self.AgentGuardGate;
  if (!Gate) return;
  const malicious = [];
  const outOfScope = [];
  const provenance = { ...blocklist.provenance };
  for (const b of blockHosts) {
    if (!b || !b.host) continue;
    const host = String(b.host).trim().toLowerCase();
    provenance[host] = { kind: b.kind, rule_id: b.rule_id || "" };
    if (b.kind === "malicious") malicious.push(b.host);
    else if (b.kind === "out_of_scope") outOfScope.push(b.host);
  }
  const merged = Gate.mergeBlocklist(blocklist, malicious, outOfScope, Date.now());
  blocklist = { persistent: merged.persistent, session: merged.session, provenance };
  try {
    chrome.storage.local.set({ blocklist });
  } catch (e) {
    console.debug("AgentGuard blocklist persist failed", e);
  }
  installActive();
}

// 把当前 active 主机集(持久 ∪ 未过期会话)装进 DNR。重算 active 时顺带过期会话项。
async function installActive() {
  const Gate = self.AgentGuardGate;
  if (!Gate || !chrome.declarativeNetRequest) return;
  // 用一次空合并把过期项剪掉,拿到当前 active 与清理后的 session。
  const merged = Gate.mergeBlocklist(blocklist, [], [], Date.now());
  blocklist = {
    persistent: merged.persistent,
    session: merged.session,
    provenance: blocklist.provenance || {},
  };
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.map((r) => r.id);
    const addRules = Gate.buildBlockRules(merged.active);
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  } catch (e) {
    // fail-open 在这里是**有意**的且已声明:DNR 是对内容脚本同步门的**加**一层,不是唯一防线。
    // 装不上就记一条,不假装拦住了——一个连不上 DNR 的扩展不该让用户整个浏览器都上不了网。
    console.debug("AgentGuard DNR install failed", e);
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
  if (msg?.type !== "agentguard_prevented") return;
  // 内容脚本在页面上同步拦下了一次动作(付款/陷阱提交)。记进最近列表,并转给宿主进签名审计
  // ——一次"执行前阻断"和一次判决一样,是应当留痕的事件。
  pushRecent({
    ts: msg.ts,
    url: msg.url,
    title: msg.title,
    kind: "prevented",
    reason: msg.reason,
    prevented_kind: msg.kind,
  });
  setBadge("!", "#b00020");
  sendNative({
    type: "browser_events",
    source: "extension-chromium",
    events: [
      {
        type: "ui_text",
        app: "browser",
        text: `[AG_PREVENTED:${msg.kind}] ${msg.reason || ""}`,
        url: msg.url,
      },
    ],
  });
  sendResponse({ ok: true });
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
  // E10:popup 管理面读当前拦截名单。先剪掉过期会话项(installActive 里那次空合并),再回。
  if (msg?.type === "get_blocklist") {
    const Gate = self.AgentGuardGate;
    if (Gate) {
      const merged = Gate.mergeBlocklist(blocklist, [], [], Date.now());
      blocklist = { persistent: merged.persistent, session: merged.session };
    }
    const prov = blocklist.provenance || {};
    sendResponse({
      malicious: blocklist.persistent.slice(),
      out_of_scope: blocklist.session.map((e) => e.host),
      // E12:每个主机的溯源 {kind, rule_id},popup 用它显示"为什么被拦"。
      provenance: prov,
    });
    return true;
  }
  // E10:用户手动解除一条——从两个集合里都删掉,持久化,重装 DNR。
  if (msg?.type === "unblock_host" && typeof msg.host === "string") {
    const h = msg.host.trim().toLowerCase();
    const provenance = { ...(blocklist.provenance || {}) };
    delete provenance[h];
    blocklist = {
      persistent: blocklist.persistent.filter((x) => x !== h),
      session: blocklist.session.filter((e) => e.host !== h),
      provenance,
    };
    try {
      chrome.storage.local.set({ blocklist });
    } catch (e) {
      console.debug("AgentGuard blocklist persist failed", e);
    }
    installActive();
    sendResponse({ ok: true });
    return true;
  }
});

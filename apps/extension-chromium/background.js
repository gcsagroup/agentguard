// 副作用导入:执行 guard-gate.js / guard-strings.js 的 IIFE,把纯逻辑挂到
// self.AgentGuardGate / self.AgentGuardStrings。内容脚本按 manifest 顺序拿到
// 同一份文件;这里 background(module:Chromium service worker / Firefox event page)靠 import 拿到。
import "./guard-gate.js";
import "./guard-mail.js";
import "./guard-strings.js";

const NATIVE_HOST = "com.agentguard.native";
const MAX_BUFFER = 50;
// 首个 GA 不把尚未完成相互认证的 Native Messaging 边界交付给用户。是否可用只由
// 打包 manifest 决定，不能由 storage 中旧版本遗留的 true 或页面消息重新打开。
const NATIVE_AVAILABLE = (chrome.runtime.getManifest().permissions || []).includes(
  "nativeMessaging"
);

/* 通知语言:跟 popup 同一个设置。 */
let bgLocale = self.AgentGuardStrings
  ? self.AgentGuardStrings.pickLocale(null, chrome.i18n.getUILanguage())
  : "en";
chrome.storage.local.get(["localeOverride"], (data) => {
  if (self.AgentGuardStrings) {
    bgLocale = self.AgentGuardStrings.pickLocale(
      data && data.localeOverride,
      chrome.i18n.getUILanguage()
    );
  }
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.localeOverride && self.AgentGuardStrings) {
    bgLocale = self.AgentGuardStrings.pickLocale(
      changes.localeOverride.newValue,
      chrome.i18n.getUILanguage()
    );
  }
});

/* E17a:首次安装打开引导页——用户装完至少知道它保护什么、被拦时长什么样。
 * 只在 reason === "install" 时打开;升级/浏览器重启不打扰。 */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason !== "install") return;
  try {
    chrome.tabs.create({ url: chrome.runtime.getURL("onboarding.html") });
  } catch (e) {
    console.debug("AgentGuard onboarding open failed", e);
  }
});

/** @type {object[]} */
let recent = [];
// P1-1:默认**不**转发。以前默认 true——用户装上扩展、什么都没点,浏览的每个页面的发现就
// 已经在往本机宿主发了,而文档说这是"可选"。现在默认 false,用户在设置里打开才转发。
let nativeEnabled = false;
// P1-1:storage 是异步加载的。以前加载完成之前 nativeEnabled 是编译期默认值,先到的事件按
// 默认值转发——现在加载完之前的信封先排队,加载完再按用户设置决定发不发(fail-closed)。
let settingsLoaded = false;
let pendingBeforeLoad = [];
const PENDING_BEFORE_LOAD_MAX = 20;
/* 引擎是否处于 Critical 暂停。持久化(P1-2):宿主进程重启它那份就没了,我们这份留着,
 * 重连时用 hello 把它带回去——扩展徽章说"暂停"的时候,宿主也真的在暂停。 */
let enginePaused = false;

chrome.storage.local.get(["nativeEnabled", "recent", "enginePaused"], (data) => {
  if (NATIVE_AVAILABLE) {
    nativeEnabled = typeof data.nativeEnabled === "boolean" ? data.nativeEnabled : false;
    if (typeof data.enginePaused === "boolean") enginePaused = data.enginePaused;
  } else {
    nativeEnabled = false;
    // 首个 GA 已撤销 Native 能力。升级时旧版的 pause 只能来自已删除的 host，
    // 继续恢复会制造一个没有恢复入口的永久“‖”状态。
    enginePaused = false;
    chrome.storage.local.set({ nativeEnabled: false, enginePaused: false });
    setBadge("", null);
  }
  if (Array.isArray(data.recent)) recent = data.recent;
  settingsLoaded = true;
  const queued = pendingBeforeLoad;
  pendingBeforeLoad = [];
  if (nativeEnabled) {
    for (const m of queued) sendNative(m);
  }
  if (enginePaused) setBadge("‖", "#b00020");
});

/** 出站/落盘前的 URL 最小化(P1-1)。Gate 没加载到就宁可不带 URL。 */
function safeUrl(raw) {
  if (self.AgentGuardMail.providerForUrl(raw)) return new URL(raw).origin;
  const Gate = self.AgentGuardGate;
  return Gate ? Gate.minimizeUrl(raw) : "";
}
function safeTitle(raw, url) {
  if (self.AgentGuardMail.providerForUrl(url)) return "";
  const Gate = self.AgentGuardGate;
  return Gate ? Gate.clampTitle(raw) : "";
}

function pushRecent(entry) {
  recent.unshift(entry);
  recent = recent.slice(0, MAX_BUFFER);
  chrome.storage.local.set({ recent });
}

function findingsToEvents(payload) {
  const events = [];
  // 邮箱检查没有 Native 转发授权，通用信封也不能夹带原邮件内容。
  if (self.AgentGuardMail.providerForUrl(payload.url)) return events;
  for (const f of payload.findings || []) {
    if (f.kind === "payment_cta" || f.kind === "prompt_injection" || f.kind === "invisible_injection") {
      events.push({
        type: "ui_text",
        app: "browser",
        text: f.marker || f.text || "",
        url: safeUrl(payload.url),
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
        url: safeUrl(payload.url),
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
  // E17c 人话化:标题走三语词表;正文第一眼是规则的人话名(词典认识的话),
  // 引擎的 human_message 跟在后面,技术 ID 收进末尾括号——不再是 "[CRIT-001] …" 开头。
  try {
    const S = self.AgentGuardStrings;
    const ui = S ? S.ui(bgLocale) : null;
    const rule = S && item.rule_id ? S.ruleText(item.rule_id, bgLocale) : null;
    const title = ui
      ? (item.require_confirm ? ui.notifyConfirm : ui.notifyBlocked)
      : "AgentGuard";
    const human = rule ? rule.title : (ui ? ui.criticalAction : "");
    const engine = item.message || item.action || "";
    const message = `${human}${engine ? ` — ${engine}` : ""}(${item.rule_id || "?"})`.slice(0, 300);
    chrome.notifications.create("", {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title,
      message,
      priority: 2,
    });
  } catch (e) {
    console.debug("AgentGuard notify failed", e);
  }
}

/**
 * DOM 阻断的可信状态面。页面内提示可被站点改样式或移除，所以它不能作为安全 UI；
 * 这个浏览器通知只说明“已阻断”，没有可交互的放行按钮，并复用固定 id 避免点击风暴堆通知。
 */
function notifyDomBlocked(kind) {
  try {
    const S = self.AgentGuardStrings;
    const ui = S ? S.ui(bgLocale) : null;
    const info = S ? S.kindText(kind, bgLocale) : null;
    chrome.notifications.create("agentguard-dom-blocked", {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: ui ? ui.notifyBlocked : "AgentGuard",
      message: info ? info.detail : (ui ? ui.criticalAction : "Blocked action"),
      priority: 2,
    });
  } catch (e) {
    console.debug("AgentGuard DOM-block notification failed", e);
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
  if (!NATIVE_AVAILABLE) return;
  if (!response || typeof response !== "object") return;
  const items = Array.isArray(response.notify) ? response.notify : [];
  for (const item of items) notifyUser(item);

  enginePaused = !!response.paused;
  persistPaused();
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
  if (!NATIVE_AVAILABLE) {
    // 旧版 Native host 生成的动态主机规则不属于首个 GA。升级必须同时清状态和
    // 浏览器里的动态 DNR，不能留下用户无法解释/解除的幽灵拦截。
    blocklist = { persistent: [], session: [], provenance: {} };
    chrome.storage.local.set({ blocklist });
    clearDynamicRules();
    return;
  }
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
  if (!NATIVE_AVAILABLE) return;
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
  if (!NATIVE_AVAILABLE) {
    await clearDynamicRules();
    return;
  }
  const Gate = self.AgentGuardGate;
  if (!Gate || !chrome.declarativeNetRequest) return;
  // 用一次空合并把过期项剪掉,拿到当前 active 与清理后的 session。
  const merged = Gate.pruneBlocklist(blocklist, Date.now());
  blocklist = {
    persistent: merged.persistent,
    session: merged.session,
    provenance: merged.provenance,
  };
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.map((r) => r.id);
    const addRules = Gate.buildBlockRules(merged.active);
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  } catch (e) {
    // 这里只安装宿主判决产生的动态主机名单。失败时如实降级,不会影响独立打包、默认启用的
    // payment_shape_block 静态规则；也不能把动态规则失败说成仍已拦住该主机。
    console.debug("AgentGuard DNR install failed", e);
  }
}

async function clearDynamicRules() {
  if (!chrome.declarativeNetRequest) return;
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.map((rule) => rule.id);
    if (removeRuleIds.length) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: [] });
    }
  } catch (e) {
    console.debug("AgentGuard legacy DNR cleanup failed", e);
  }
}

function persistPaused() {
  try {
    chrome.storage.local.set({ enginePaused });
  } catch (e) {
    console.debug("AgentGuard pause persist failed", e);
  }
}

// ---------------------------------------------------------------------------
// P1-2:宿主长连接(connectNative),不再每条消息 sendNativeMessage 起一个新进程。
//
// 一次性消息的问题是**状态不连续**:每次页面扫描都可能启动全新宿主,pause / taint /
// trajectory / session 全部从零开始——徽章还写着「暂停」,下一条请求已经由一个不知道暂停的
// 新引擎处理了。长连接让宿主进程活到端口断开;断开时:
//   - 退避重连(1s → 60s),不在每次扫描时敲它;
//   - 我们这份 enginePaused 保留,重连的 hello 把它带回去(宿主据此重新 pause);
//   - 徽章不清——断线期间没有人在判,不能显示成一切正常。
// P1-3:每个连接一个随机 nonce,每帧一个单调 seq;宿主拒绝 nonce 不对 / seq 不增的帧。
// 这挡的是**重放和乱序**,不是调用方身份——一个已经拿到宿主 stdin 的本地进程不受它约束,
// 那条边界见 STORE.md「本机 host 安全边界」。
// ---------------------------------------------------------------------------
const link = {
  port: null,
  nonce: null,
  seq: 0,
  attempts: 0,
  nextRetryAt: 0,
  lastOk: 0,
  lastError: "",
};

function postFrame(port, message) {
  link.seq += 1;
  port.postMessage({ ...message, nonce: link.nonce, seq: link.seq });
}

function dropPort(why) {
  link.port = null;
  link.nonce = null;
  link.seq = 0;
  link.lastError = why || "";
}

function ensurePort() {
  if (!NATIVE_AVAILABLE) return null;
  if (link.port) return link.port;
  if (Date.now() < link.nextRetryAt) return null;
  const Gate = self.AgentGuardGate;
  if (!Gate) return null;
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    link.port = port;
    link.nonce = Gate.newNonce();
    link.seq = 0;
    port.onMessage.addListener((response) => {
      if (response && response.ok) {
        link.lastOk = Date.now();
        link.attempts = 0;
        link.lastError = "";
      } else if (response && response.error) {
        link.lastError = String(response.error).slice(0, 200);
      }
      handleVerdict(response);
    });
    port.onDisconnect.addListener(() => {
      const why = chrome.runtime.lastError ? chrome.runtime.lastError.message : "disconnected";
      dropPort(why);
      link.attempts += 1;
      link.nextRetryAt = Date.now() + Gate.backoffMs(link.attempts - 1);
      console.debug("AgentGuard native link down:", why);
    });
    postFrame(port, {
      type: "hello",
      paused: enginePaused,
      extension_version: chrome.runtime.getManifest().version,
    });
    return port;
  } catch (err) {
    dropPort(String(err));
    link.attempts += 1;
    link.nextRetryAt = Date.now() + Gate.backoffMs(link.attempts - 1);
    console.debug("AgentGuard native connect failed", err);
    return null;
  }
}

function disconnectPort() {
  if (link.port) {
    try {
      link.port.disconnect();
    } catch (e) {
      console.debug("AgentGuard native disconnect failed", e);
    }
  }
  dropPort("");
  link.attempts = 0;
  link.nextRetryAt = 0;
}

function sendNative(message) {
  if (!NATIVE_AVAILABLE) return;
  if (!settingsLoaded) {
    // fail-closed:还不知道用户开没开,先不发。
    if (pendingBeforeLoad.length < PENDING_BEFORE_LOAD_MAX) pendingBeforeLoad.push(message);
    return;
  }
  if (!nativeEnabled) return;
  const port = ensurePort();
  if (!port) return;
  try {
    postFrame(port, message);
  } catch (err) {
    console.debug("AgentGuard native post failed", err);
    dropPort(String(err));
  }
}

function linkState() {
  return {
    available: NATIVE_AVAILABLE,
    enabled: nativeEnabled,
    connected: !!link.port,
    lastOk: link.lastOk,
    lastError: link.lastError,
    host: NATIVE_HOST,
  };
}

// 设置只能由扩展自己的弹窗修改；不接受网页或内容脚本伪造的开关消息。
function mailControlSender(sender) {
  return sender?.id === chrome.runtime.id && sender.url === chrome.runtime.getURL("popup.html");
}
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "get_mail_settings" || msg?.type === "set_mail_settings") {
    if (!mailControlSender(sender)) { sendResponse({ ok: false }); return; }
    if (msg.type === "get_mail_settings") {
      chrome.storage.local.get(["webmailProtection"], (data) => {
        const ok = !chrome.runtime.lastError;
        sendResponse({ ok, settings: ok ? self.AgentGuardMail.settings(data?.webmailProtection) : null });
      });
    } else {
      if (typeof msg.enabled !== "boolean") { sendResponse({ ok: false }); return; }
      chrome.storage.local.set({ webmailProtection: { version: 1, enabled: msg.enabled } }, () => {
        sendResponse({ ok: !chrome.runtime.lastError });
      });
    }
    return true;
  }
  if (msg?.type !== "agentguard_mail_event") return;
  const provider = self.AgentGuardMail.providerForUrl(sender?.url);
  if (sender?.id !== chrome.runtime.id || !provider || !self.AgentGuardMail.KINDS.includes(msg.kind) ||
      typeof msg.blocked !== "boolean") { sendResponse({ ok: false }); return; }
  pushRecent({
    ts: Date.now(),
    url: new URL(sender.url).origin,
    title: provider === "gmail" ? "Gmail" : "Outlook",
    ...(msg.blocked ? { kind: "prevented", prevented_kind: msg.kind } : { count: 1, kinds: [msg.kind] }),
  });
  setBadge("!", "#b00020");
  if (msg.blocked) notifyDomBlocked(msg.kind);
  sendResponse({ ok: true });
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "agentguard_findings") return;
  const entry = {
    ts: msg.ts,
    url: safeUrl(msg.url),
    title: safeTitle(msg.title, msg.url),
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
    url: safeUrl(msg.url),
    title: safeTitle(msg.title, msg.url),
    kind: "prevented",
    reason: msg.reason,
    prevented_kind: msg.kind,
  });
  setBadge("!", "#b00020");
  notifyDomBlocked(msg.kind);
  sendNative({
    type: "browser_events",
    source: "extension-chromium",
    events: [
      {
        type: "ui_text",
        app: "browser",
        text: `[AG_PREVENTED:${msg.kind}] ${msg.reason || ""}`,
        url: safeUrl(msg.url),
      },
    ],
  });
  sendResponse({ ok: true });
  return true;
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "get_recent") {
    // 打开 popup 就是"看过了":清掉徽章(E18)。此前 "!"/计数一旦点亮就永远挂着,
    // 用户没有任何办法消掉它。暂停徽章「‖」例外——暂停还在,提醒就还该在。
    if (!enginePaused) setBadge("", null);
    sendResponse({ recent, nativeAvailable: NATIVE_AVAILABLE, nativeEnabled, link: linkState() });
    return true;
  }
  if (msg?.type === "set_native") {
    nativeEnabled = NATIVE_AVAILABLE && !!msg.enabled;
    chrome.storage.local.set({ nativeEnabled });
    if (!nativeEnabled) disconnectPort();
    sendResponse({
      ok: NATIVE_AVAILABLE,
      error: NATIVE_AVAILABLE ? "" : "native_messaging_disabled_in_release",
      link: linkState(),
    });
    return true;
  }
  // E10:popup 管理面读当前拦截名单。先剪掉过期会话项(installActive 里那次空合并),再回。
  if (msg?.type === "get_blocklist") {
    const Gate = self.AgentGuardGate;
    if (Gate) {
      const merged = Gate.pruneBlocklist(blocklist, Date.now());
      blocklist = {
        persistent: merged.persistent,
        session: merged.session,
        provenance: merged.provenance,
      };
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

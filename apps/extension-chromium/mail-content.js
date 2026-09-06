/* 邮箱页面适配候选。只在 isolated world 读 DOM、同步阻断明确支持的事件。
 * 页面不是提交字节的可信来源：直接 API、未识别控件、闭合 Shadow 等仍可能绕过。
 * 首版没有批准、重放、自动发送或附件内容扫描；正常文本也不是安全背书。
 */
(function () {
  "use strict";
  const Mail = self.AgentGuardMail;
  if (!Mail || !Mail.providerForUrl(`${location.origin}/mail/`)) return;

  let policy = { ready: false, enabled: false };
  const provider = () => Mail.providerForUrl(location.href);
  const active = () => !!provider() && policy.ready && policy.enabled;
  const guarded = () => !!provider() && (!policy.ready || policy.enabled);
  const reported = new Map();
  const readingKinds = new Set();
  let scanTimer = null;
  let notice = null;

  function sendEvent(kind, blocked) {
    if (!Mail.KINDS.includes(kind)) return;
    const key = `${kind}:${blocked}`;
    const now = Date.now();
    if (now - (reported.get(key) || 0) < 1000) return;
    reported.set(key, now);
    try {
      // 不发正文、主题、收件人、附件名、链接或邮箱页标题。
      chrome.runtime.sendMessage({ type: "agentguard_mail_event", kind, blocked }, () => {
        void chrome.runtime.lastError;
      });
    } catch (_) { /* 记录失败不改变已阻断的事件。 */ }
  }

  function block(event, kind) {
    event.preventDefault();
    event.stopImmediatePropagation();
    sendEvent(kind, true);
    if (self.AgentGuardModal && !notice?.element?.isConnected) {
      if (notice) notice.close();
      notice = self.AgentGuardModal.showBlocked({ kind });
    }
  }

  function boundedText(element) {
    if (!element) return null;
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let text = "";
    let count = 0;
    let node;
    while ((node = walker.nextNode())) {
      if (++count > 10000 || text.length + node.nodeValue.length > Mail.MAX_TEXT) return null;
      text += node.nodeValue;
    }
    return text;
  }

  function recipientRole(element) {
    const name = (element.getAttribute("name") || "").toLowerCase();
    if (["to", "cc", "bcc"].includes(name)) return name;
    const label = (element.getAttribute("aria-label") || "").trim();
    if (/^(?:To|收件人|收件者|收件地址)[:：]?$/i.test(label)) return "to";
    if (/^(?:Cc|抄送|副本)[:：]?$/i.test(label)) return "cc";
    if (/^(?:Bcc|密送|密件副本)[:：]?$/i.test(label)) return "bcc";
    return "";
  }

  function recipientFields(container) {
    const fields = container.querySelectorAll('input, textarea, [role="combobox"], [role="listbox"]');
    if (fields.length > 500) return [];
    return [...fields].filter((el) => !!recipientRole(el));
  }

  function isBody(element) {
    if (element.getAttribute("contenteditable") !== "true") return false;
    if (provider() === "gmail" && element.getAttribute("g_editable") === "true") return true;
    return /^(?:Message body|邮件正文|郵件正文|郵件內文|郵件本文)(?:$|[,，(（])/i
      .test(element.getAttribute("aria-label") || "");
  }

  function composeFrom(element) {
    let current = element && element.nodeType === Node.ELEMENT_NODE ? element : element?.parentElement;
    for (let depth = 0; current && depth < 16; depth += 1) {
      const editors = current.querySelectorAll('[contenteditable="true"]');
      if (editors.length > 100) return null;
      const bodies = [...editors].filter(isBody);
      if (isBody(current)) bodies.unshift(current);
      if (bodies.length === 1) {
        const fields = recipientFields(current);
        if (fields.some((el) => recipientRole(el) === "to")) return { container: current, body: bodies[0], fields };
      }
      const parent = current.parentElement;
      current = parent || current.getRootNode()?.host || null;
    }
    return null;
  }

  function snapshot(compose) {
    if (!compose) return { complete: false };
    const { container, body, fields } = compose;
    const text = boundedText(body);
    if (text === null) return { complete: false };
    const subjects = container.querySelectorAll('input[name="subjectbox"], input[name="subject"], input[aria-label="Add a subject" i], input[placeholder="Add a subject" i], input[aria-label="主题"], input[aria-label="主旨"]');
    if (subjects.length !== 1) return { complete: false };
    const recipients = [];
    const seen = new Set();
    function add(role, value) {
      const trimmed = value.trim();
      if (!trimmed) return;
      const key = `${role}:${trimmed}`;
      if (!seen.has(key)) { seen.add(key); recipients.push({ role, value: trimmed }); }
    }
    for (const field of fields) {
      const role = recipientRole(field);
      if (typeof field.value === "string" && field.value.trim()) {
        if (field.value.length > 4096) return { complete: false };
        // 只拆明文地址列表；复杂显示名交给纯检查保守拒绝，不忽略坏条目。
        for (const value of field.value.split(/[;,；]/)) add(role, value);
      }
      const row = field.closest('[role="listbox"]') || field.closest("tr") || field.parentElement;
      if (!row || !container.contains(row) || row.contains(body)) continue;
      const chips = row.querySelectorAll('[email], [data-email-address], [data-hovercard-id], [role="option"]');
      if (chips.length > Mail.MAX_RECIPIENTS) return { complete: false };
      for (const chip of chips) {
        const value = chip.getAttribute("email") || chip.getAttribute("data-email-address") ||
          chip.getAttribute("data-hovercard-id") || chip.getAttribute("title") || boundedText(chip);
        if (value === null) return { complete: false };
        add(role, value);
      }
      if (field.getAttribute("contenteditable") === "true" && chips.length === 0) {
        const value = boundedText(field);
        if (value === null) return { complete: false };
        add(role, value);
      }
    }
    const attached = container.querySelectorAll('[data-attachment-id], .aQH .aV3, [aria-label^="Attachment:" i], [aria-label^="附件："]');
    const fileSelected = [...container.querySelectorAll('input[type="file"]')].some((el) => el.files?.length > 0);
    return {
      complete: true,
      subject: subjects[0]?.value || "",
      body: text,
      recipients,
      attachments: attached.length + Number(fileSelected),
      nonText: !!body.querySelector("img, svg, canvas, video, audio, object, embed, iframe"),
    };
  }

  function actionFrom(event, selector) {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [event.target];
    for (const node of path) {
      if (node?.nodeType === Node.ELEMENT_NODE) {
        const element = node.closest(selector);
        if (element) return element;
      }
    }
    return null;
  }

  function isSend(element) {
    if (!element) return false;
    const labels = [element.getAttribute("aria-label"), element.getAttribute("data-tooltip"), element.getAttribute("title"), element.value, element.textContent];
    return labels.some((label) => typeof label === "string" && label.length <= 200 &&
      /^(?:Send|Send now|发送|发送邮件|立即发送|傳送|傳送郵件|立即傳送|寄送|立即寄送)(?:$|\s*[（(])/.test(label.trim()));
  }

  function inspectSend(event, element) {
    const kind = policy.ready ? Mail.classifySend(snapshot(composeFrom(element))) : "mail_uninspectable";
    if (kind) block(event, kind);
  }

  const READ_SELECTOR = '.a3s, [role="document"]';
  for (const type of ["pointerdown", "mousedown", "touchstart", "click", "auxclick"]) {
    window.addEventListener(type, (event) => {
      if (!guarded()) return;
      if (typeof event.button === "number" && event.button > 1) return;
      const file = actionFrom(event, 'input[type="file"]');
      if (file) { block(event, policy.ready ? "mail_attachment" : "mail_uninspectable"); return; }
      const button = actionFrom(event, 'button, [role="button"], input[type="submit"]');
      if (isSend(button)) { inspectSend(event, button); return; }
      const link = actionFrom(event, "a[href]");
      if (link && link.closest(READ_SELECTOR)) {
        const kind = policy.ready ? Mail.classifyLink(link.href, boundedText(link)) : "mail_uninspectable";
        if (kind) block(event, kind);
      }
    }, { capture: true, passive: false });
  }
  for (const type of ["keydown", "keypress", "keyup"]) {
    window.addEventListener(type, (event) => {
      if (!guarded()) return;
      const enter = event.key === "Enter" && (event.ctrlKey || event.metaKey);
      const outlookSend = provider() === "outlook" && event.altKey && event.key?.toLowerCase() === "s";
      if (enter || outlookSend) inspectSend(event, event.target);
    }, true);
  }
  window.addEventListener("submit", (event) => {
    if (!guarded() || !event.target?.querySelectorAll) return;
    const compose = composeFrom(event.target);
    const sends = [...event.target.querySelectorAll('button, [role="button"], input[type="submit"]')].some(isSend);
    if (compose || sends || isSend(event.submitter)) inspectSend(event, event.target);
  }, true);
  for (const type of ["input", "change", "drop", "paste"]) {
    window.addEventListener(type, (event) => {
      if (!guarded()) return;
      const transfer = event.dataTransfer || event.clipboardData;
      const selected = event.target?.matches?.('input[type="file"]') && event.target.files?.length;
      const files = selected || transfer?.files?.length || [...(transfer?.types || [])].includes("Files");
      if (!files) return;
      if (selected) event.target.value = "";
      block(event, policy.ready ? "mail_attachment" : "mail_uninspectable");
    }, true);
  }

  function scanReading() {
    scanTimer = null;
    if (!active()) return;
    const areas = document.querySelectorAll(READ_SELECTOR);
    if (areas.length > 100) { sendEvent("mail_uninspectable", false); return; }
    for (const area of areas) {
      if (area.closest('[contenteditable="true"]')) continue;
      const text = boundedText(area);
      const kinds = text === null ? ["mail_uninspectable"] : Mail.inspectText(text).filter((kind) => kind !== "mail_sensitive");
      for (const kind of kinds) {
        if (!readingKinds.has(kind)) { readingKinds.add(kind); sendEvent(kind, false); }
      }
    }
  }
  function scheduleReading() {
    if (active() && scanTimer === null) scanTimer = setTimeout(scanReading, 1000);
  }
  chrome.storage.local.get(["webmailProtection"], (data) => {
    if (chrome.runtime.lastError) return;
    policy = Mail.settings(data?.webmailProtection);
    scheduleReading();
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.webmailProtection) return;
    policy = Mail.settings(changes.webmailProtection.newValue);
    readingKinds.clear();
    scheduleReading();
  });
  const observer = new MutationObserver(scheduleReading);
  if (document.documentElement) observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (message?.type !== "mail_page_status" || sender.id !== chrome.runtime.id ||
        sender.url !== chrome.runtime.getURL("popup.html")) return;
    // 仅返回适配候选与设置是否就绪，不把 DOM 识别当作实际投递路径已验证。
    respond({ provider: provider(), ready: policy.ready, enabled: policy.enabled });
  });
})();

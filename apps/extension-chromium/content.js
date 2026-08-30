/**
 * AgentGuard content script — local DOM probes (no page data uploaded by default).
 * Findings are posted to the extension background; optional Native Messaging forward.
 */

const INJECTION_PATTERNS = [
  /ignore\s+previous\s+instructions/i,
  /忽略之前的指令/,
  /system\s+override/i,
  /\[AG_INVISIBLE_TEXT\]/,
  /\[AG_TRANSPARENT_OVERLAY\]/,
];

const TRAP_LABELS = [
  /priority\s+scheduling/i,
  /vip\s+express/i,
  /get\s+coupons\s+with\s+phone/i,
  /营销订阅/,
  /newsletter/i,
];

const PII_NAME_HINTS = [
  /phone|mobile|tel|email|address|dob|birth|passport|ssn|身份证|手机|邮箱|地址|生日/i,
];

function cssInvisible(el) {
  const s = getComputedStyle(el);
  const opacity = parseFloat(s.opacity || "1");
  const fontSize = parseFloat(s.fontSize || "16");
  const off =
    (el.offsetWidth === 0 && el.offsetHeight === 0) ||
    s.visibility === "hidden" ||
    s.display === "none";
  return opacity < 0.05 || fontSize < 1 || off;
}

function textNodesUnder(root) {
  const out = [];
  const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walk.nextNode())) {
    const t = (n.nodeValue || "").trim();
    if (t.length > 0) out.push(n);
  }
  return out;
}

function scanHiddenInjection() {
  const findings = [];
  for (const node of textNodesUnder(document.body || document.documentElement)) {
    const parent = node.parentElement;
    if (!parent) continue;
    const text = node.nodeValue || "";
    const matched = INJECTION_PATTERNS.find((re) => re.test(text));
    if (!matched) continue;
    const invisible = cssInvisible(parent);
    findings.push({
      kind: invisible ? "invisible_injection" : "prompt_injection",
      text: text.slice(0, 200),
      marker: invisible ? "[AG_INVISIBLE_TEXT]" : text.slice(0, 80),
    });
  }
  return findings;
}

function fieldMeta(el) {
  const name = `${el.name || ""} ${el.id || ""} ${el.getAttribute("autocomplete") || ""} ${
    el.getAttribute("aria-label") || ""
  } ${el.placeholder || ""}`;
  const labelText = (() => {
    if (el.id) {
      const lab = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (lab) return lab.textContent || "";
    }
    return "";
  })();
  const blob = `${name} ${labelText}`;
  const required = el.required || el.getAttribute("aria-required") === "true";
  const pii = PII_NAME_HINTS.some((re) => re.test(blob));
  const trap = TRAP_LABELS.some((re) => re.test(blob) || re.test(document.body?.innerText?.slice(0, 2000) || ""));
  return { required, pii, trap, blob: blob.slice(0, 120) };
}

function scanFormOverfill() {
  const findings = [];
  const fields = document.querySelectorAll("input, textarea, select");
  for (const el of fields) {
    if (el.type === "hidden" || el.type === "submit" || el.type === "button") continue;
    const value = (el.value || "").trim();
    if (!value) continue;
    const meta = fieldMeta(el);
    if (meta.trap && meta.pii) {
      findings.push({
        kind: "privacy_trap",
        field_id: el.id || el.name || "unknown",
        profile_key: guessKey(meta.blob),
        required: false,
        is_trap: true,
        probe_type: "trap_resistance",
      });
    } else if (!meta.required && meta.pii) {
      findings.push({
        kind: "optional_pii",
        field_id: el.id || el.name || "unknown",
        profile_key: guessKey(meta.blob),
        required: false,
        is_trap: false,
        probe_type: "form_minimization",
      });
    }
  }
  return findings;
}

function guessKey(blob) {
  if (/phone|mobile|tel|手机/i.test(blob)) return "phone_number";
  if (/email|邮箱/i.test(blob)) return "email";
  if (/address|地址/i.test(blob)) return "home_address";
  if (/dob|birth|生日/i.test(blob)) return "date_of_birth";
  if (/passport|护照/i.test(blob)) return "passport_number";
  return "unknown_pii";
}

function scanPaymentCta() {
  const findings = [];
  const clickables = document.querySelectorAll("button, a, [role='button'], input[type='submit']");
  for (const el of clickables) {
    const text = (el.innerText || el.value || "").trim();
    if (/确认支付|Confirm Payment|Pay now|Complete purchase|立即支付/i.test(text)) {
      findings.push({ kind: "payment_cta", text: text.slice(0, 80) });
    }
  }
  return findings;
}

function runScan() {
  const findings = [
    ...scanHiddenInjection(),
    ...scanFormOverfill(),
    ...scanPaymentCta(),
  ];
  if (findings.length === 0) return;
  chrome.runtime.sendMessage({
    type: "agentguard_findings",
    url: location.href,
    title: document.title,
    findings,
    ts: Date.now(),
  });
}

let debounceTimer = null;
function scheduleScan() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runScan, 400);
}

runScan();
document.addEventListener("input", scheduleScan, true);
document.addEventListener("change", scheduleScan, true);
const mo = new MutationObserver(scheduleScan);
if (document.body) {
  mo.observe(document.body, { childList: true, subtree: true, characterData: true });
}

/* ---------------------------------------------------------------------------
 * 执行前阻断(E2)。
 *
 * scanX 是**事后**的:它上报已经填好的表单、已经在页面上的付款按钮。这一段不同——它在捕获阶段
 * 同步拦住 submit / 付款 CTA 的 click,在动作**真正发生之前** preventDefault 把它按住,弹一个
 * 本地确认;只有用户点"允许一次"才放行。判决用的是 guard-gate.js 的纯逻辑(可在 node 里单测)。
 *
 * 覆盖的是页面自己的 DOM 动作;拦不了直接 fetch() 的脚本(除非命中 DNR 主机规则)和原生 app。
 * 见 guard-gate.js 头部的"覆盖什么、不覆盖什么"。
 * ------------------------------------------------------------------------- */

const PAYMENT_CTA_RE = /确认支付|Confirm Payment|Pay now|Complete purchase|立即支付/i;
// 已被用户批准放行一次的元素/表单。放行后我们程序化重放动作,重放会再次进这个监听器,
// 用这个 WeakSet 认出"这是刚批准的那次"并直接放过,避免死循环。
const gateApproved = new WeakSet();

function ctaText(el) {
  return PAYMENT_CTA_RE.test((el && (el.innerText || el.value)) || "");
}

function nearestActionable(el) {
  return el && el.closest
    ? el.closest("button, a, [role='button'], input[type='submit']")
    : null;
}

function formHasTrapPII(form) {
  for (const el of form.querySelectorAll("input, textarea, select")) {
    if (el.type === "hidden" || el.type === "submit" || el.type === "button") continue;
    if (!(el.value || "").trim()) continue;
    const meta = fieldMeta(el);
    if (meta.trap && meta.pii) return true;
  }
  return false;
}

function reportPrevented(reason, kind) {
  try {
    chrome.runtime.sendMessage({
      type: "agentguard_prevented",
      url: location.href,
      title: document.title,
      reason,
      kind,
      ts: Date.now(),
    });
  } catch (e) {
    console.debug("AgentGuard prevented-report failed", e);
  }
}

/* 确认层的语言:跟 popup 同一个设置(localeOverride),没设置就看浏览器语言。
 * 上一版整个弹层硬编码中文 —— 英文用户在最关键的 10 秒里看到的是看不懂的字。 */
let gateLocale = self.AgentGuardStrings
  ? self.AgentGuardStrings.pickLocale(null, navigator.language)
  : "en";
try {
  chrome.storage.local.get(["localeOverride"], (data) => {
    if (self.AgentGuardStrings) {
      gateLocale = self.AgentGuardStrings.pickLocale(data && data.localeOverride, navigator.language);
    }
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.localeOverride && self.AgentGuardStrings) {
      gateLocale = self.AgentGuardStrings.pickLocale(
        changes.localeOverride.newValue,
        navigator.language
      );
    }
  });
} catch (e) {
  console.debug("AgentGuard locale bootstrap failed", e);
}

// 本地确认层。preventDefault 之后 DOM 已经被按住了,所以这个可以是异步的——
// 批准回调里再程序化重放动作。刻意不用 window.confirm(某些页面会覆盖它)。
//
// 消费者化改造(E16)之后的设计原则:
//   - 标题和正文来自人话词典(guard-strings.js),不再出现「执行前拦截」这类内部术语;
//   - 两个按钮各自写明后果;「先不要」是视觉主按钮 + 默认焦点 + Esc —— 安全的选择最顺手;
//   - 「为什么拦住我?」可展开,解释和技术标识收在里面(留给排障),不占第一眼。
// spec = { kind, reason, host }:kind 查词典;词典不认识时退回 reason 原文,不会哑掉。
function askAllowOnce(spec, onAllow, onCancel) {
  // 用离散的 style 属性赋值,不用 el.style.cssText(那是"把字符串当 CSS 解析"的 sink,仓库
  // 不变量测试禁掉整个 API)。也不用 innerHTML —— 全程 createElement + textContent。
  const S = self.AgentGuardStrings || null;
  const ui = S ? S.ui(gateLocale) : null;
  const gate = S && spec && spec.kind ? S.gateText(spec.kind, gateLocale, { host: spec.host || "" }) : null;
  const kindInfo = S && spec && spec.kind ? S.kindText(spec.kind, gateLocale) : null;
  const reasonText = (spec && spec.reason) || "";

  const host = document.createElement("div");
  Object.assign(host.style, {
    position: "fixed",
    inset: "0",
    zIndex: "2147483647",
    background: "rgba(0,0,0,.45)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    font: "14px/1.5 system-ui,sans-serif",
  });
  const card = document.createElement("div");
  Object.assign(card.style, {
    maxWidth: "440px",
    background: "#fff",
    color: "#111",
    borderRadius: "12px",
    padding: "20px",
    boxShadow: "0 10px 40px rgba(0,0,0,.3)",
  });
  const brand = document.createElement("div");
  Object.assign(brand.style, {
    fontSize: "12px",
    color: "#8a5a00",
    background: "#fff7e6",
    display: "inline-block",
    padding: "2px 8px",
    borderRadius: "999px",
    marginBottom: "10px",
  });
  brand.textContent = ui ? ui.brand : "AgentGuard";
  const h = document.createElement("div");
  Object.assign(h.style, { fontWeight: "600", fontSize: "16px", marginBottom: "8px" });
  h.textContent = (gate && gate.title) || reasonText || "AgentGuard";
  const p = document.createElement("div");
  p.style.marginBottom = "10px";
  p.textContent = (gate && gate.body) || reasonText;
  // 两个按钮各自的后果,先说清楚再让人选。
  const consequences = document.createElement("div");
  Object.assign(consequences.style, { fontSize: "12.5px", color: "#555", marginBottom: "12px" });
  if (gate) {
    const cancelLine = document.createElement("div");
    cancelLine.textContent = gate.cancel;
    const allowLine = document.createElement("div");
    allowLine.textContent = gate.allow;
    consequences.append(cancelLine, allowLine);
  }
  // 「为什么拦住我?」——解释 + 技术标识收在这里。
  const why = document.createElement("details");
  why.style.marginBottom = "14px";
  const whySummary = document.createElement("summary");
  Object.assign(whySummary.style, { cursor: "pointer", fontSize: "12.5px", color: "#2f6df6" });
  whySummary.textContent = ui ? ui.why : "?";
  const whyBody = document.createElement("div");
  Object.assign(whyBody.style, { fontSize: "12.5px", color: "#555", marginTop: "6px" });
  const whyDetail = document.createElement("div");
  whyDetail.textContent = (kindInfo && kindInfo.detail) || reasonText;
  const whyTech = document.createElement("div");
  Object.assign(whyTech.style, { color: "#999", marginTop: "4px" });
  whyTech.textContent = `${ui ? ui.whyTech : "id"}: ${(spec && spec.kind) || "-"}`;
  whyBody.append(whyDetail, whyTech);
  why.append(whySummary, whyBody);

  const row = document.createElement("div");
  Object.assign(row.style, {
    display: "flex",
    gap: "8px",
    justifyContent: "flex-end",
  });
  // 「先不要」是主按钮:深色实心、默认焦点、Esc。放行是危险动作,做成红字描边的次按钮。
  const cancel = document.createElement("button");
  cancel.textContent = ui ? ui.cancel : "Not now";
  Object.assign(cancel.style, {
    padding: "8px 16px",
    borderRadius: "8px",
    border: "0",
    background: "#1f2937",
    color: "#fff",
    cursor: "pointer",
    fontWeight: "600",
  });
  const allow = document.createElement("button");
  allow.textContent = ui ? ui.allow : "Allow once";
  Object.assign(allow.style, {
    padding: "8px 16px",
    borderRadius: "8px",
    border: "1px solid #d99",
    background: "#fff",
    color: "#b02a2a",
    cursor: "pointer",
  });
  const onKey = (e) => {
    if (e.key === "Escape") {
      e.stopImmediatePropagation();
      doCancel();
    }
  };
  const close = () => {
    document.removeEventListener("keydown", onKey, true);
    host.remove();
  };
  const doCancel = () => {
    close();
    if (typeof onCancel === "function") {
      try {
        onCancel();
      } catch (e) {
        console.debug("AgentGuard cancel handler failed", e);
      }
    }
  };
  document.addEventListener("keydown", onKey, true);
  cancel.addEventListener("click", doCancel);
  allow.addEventListener("click", () => {
    close();
    try {
      onAllow();
    } catch (e) {
      console.debug("AgentGuard allow-once replay failed", e);
    }
  });
  row.append(allow, cancel);
  card.append(brand, h, p, consequences, why, row);
  host.append(card);
  (document.body || document.documentElement).append(host);
  try {
    cancel.focus();
  } catch (e) {
    console.debug("AgentGuard focus failed", e);
  }
}

function gateEvent(e, findings, replay) {
  const Gate = self.AgentGuardGate;
  if (!Gate) return; // 纯逻辑没加载(不该发生);不静默改变页面行为。
  const d = Gate.gateForFindings(findings);
  if (!d.block) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  reportPrevented(d.reason, d.kind);
  askAllowOnce({ kind: d.kind, reason: d.reason }, replay);
}

document.addEventListener(
  "click",
  (e) => {
    const el = nearestActionable(e.target) || e.target;
    if (!el) return;
    if (gateApproved.has(el)) {
      gateApproved.delete(el);
      return; // 这是刚批准后重放的那次点击,放过。
    }
    const findings = ctaText(el) ? [{ kind: "payment_cta" }] : [];
    gateEvent(e, findings, () => {
      gateApproved.add(el);
      el.click();
    });
  },
  true
);

document.addEventListener(
  "submit",
  (e) => {
    const form = e.target;
    if (!form || gateApproved.has(form)) {
      if (form) gateApproved.delete(form);
      return;
    }
    const findings = [];
    if (formHasTrapPII(form)) findings.push({ kind: "privacy_trap" });
    if (e.submitter && ctaText(e.submitter)) findings.push({ kind: "payment_cta" });
    gateEvent(e, findings, () => {
      gateApproved.add(form);
      // form.submit() 不触发 submit 事件,所以不会再进这个监听器——这里的 WeakSet 只是防御性。
      form.submit();
    });
  },
  true
);

/* 页面上下文(guard-page.js,MAIN world)拦到一个付款形状的直发 fetch/XHR,通过 window.postMessage
 * 来要一个"允许/拒绝"。内容脚本在隔离世界,能弹确认 UI、能连扩展,所以由它作答并留痕。 */
const AG_REQ = "__agentguard_req_gate__";
const AG_DECISION = "__agentguard_req_decision__";
const AG_SCOPE = "__agentguard_scope__";

// E9:把任务主机允许表(background 从宿主判决里拿到、存进 storage)推给页面世界的 guard-page.js。
// 允许表是**策略**、不是浏览历史——推给页面本地判越界,不回传任何 URL。
function pushScopeToPage(allowlist) {
  window.postMessage(
    { type: AG_SCOPE, allowlist: Array.isArray(allowlist) ? allowlist : null },
    "*"
  );
}
try {
  chrome.storage.local.get(["scope_hosts"], (data) => {
    pushScopeToPage(data && data.scope_hosts);
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.scope_hosts) {
      pushScopeToPage(changes.scope_hosts.newValue);
    }
  });
} catch (e) {
  console.debug("AgentGuard scope relay unavailable", e);
}
window.addEventListener("message", (ev) => {
  if (ev.source !== window) return;
  const d = ev.data;
  if (!d || d.type !== AG_REQ || typeof d.id !== "number") return;
  const reason = d.reason || "这个请求看起来在发起一次付款/转账";
  reportPrevented(reason, "outbound_request");
  // guard-page 的关卡带来了结构化的门种类(payment_request / out_of_scope_host / no_egress)
  // 和目的地主机 —— 确认层据此查人话词典;老消息没有 kind 时退回 reason 原文。
  askAllowOnce(
    { kind: d.kind || "payment_request", reason, host: d.host || "" },
    () => window.postMessage({ type: AG_DECISION, id: d.id, allow: true }, "*"),
    () => window.postMessage({ type: AG_DECISION, id: d.id, allow: false }, "*")
  );
});

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

// 极简的本地确认层。preventDefault 之后 DOM 已经被按住了,所以这个可以是异步的——
// 批准回调里再程序化重放动作。刻意不用 window.confirm(某些页面会覆盖它)。
function askAllowOnce(reason, onAllow) {
  // 用离散的 style 属性赋值,不用 el.style.cssText(那是"把字符串当 CSS 解析"的 sink,仓库
  // 不变量测试禁掉整个 API)。也不用 innerHTML —— 全程 createElement + textContent。
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
    maxWidth: "420px",
    background: "#fff",
    color: "#111",
    borderRadius: "12px",
    padding: "20px",
    boxShadow: "0 10px 40px rgba(0,0,0,.3)",
  });
  const h = document.createElement("div");
  Object.assign(h.style, { fontWeight: "600", marginBottom: "8px" });
  h.textContent = "AgentGuard — 执行前拦截";
  const p = document.createElement("div");
  p.style.marginBottom = "16px";
  p.textContent = `${reason}。是否允许这一次?`;
  const row = document.createElement("div");
  Object.assign(row.style, {
    display: "flex",
    gap: "8px",
    justifyContent: "flex-end",
  });
  const cancel = document.createElement("button");
  cancel.textContent = "取消";
  Object.assign(cancel.style, {
    padding: "8px 14px",
    borderRadius: "8px",
    border: "1px solid #ccc",
    background: "#f5f5f5",
    cursor: "pointer",
  });
  const allow = document.createElement("button");
  allow.textContent = "允许一次";
  Object.assign(allow.style, {
    padding: "8px 14px",
    borderRadius: "8px",
    border: "0",
    background: "#b02a2a",
    color: "#fff",
    cursor: "pointer",
  });
  const close = () => host.remove();
  cancel.addEventListener("click", close);
  allow.addEventListener("click", () => {
    close();
    try {
      onAllow();
    } catch (e) {
      console.debug("AgentGuard allow-once replay failed", e);
    }
  });
  row.append(cancel, allow);
  card.append(h, p, row);
  host.append(card);
  (document.body || document.documentElement).append(host);
}

function gateEvent(e, findings, replay) {
  const Gate = self.AgentGuardGate;
  if (!Gate) return; // 纯逻辑没加载(不该发生);不静默改变页面行为。
  const d = Gate.gateForFindings(findings);
  if (!d.block) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  reportPrevented(d.reason, d.kind);
  askAllowOnce(d.reason, replay);
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

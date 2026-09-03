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

function scanHiddenInjection(root) {
  const findings = [];
  for (const node of textNodesUnder(root || document.body || document.documentElement)) {
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

/* ---------------------------------------------------------------------------
 * 告警风暴(真机报告 P2-3):以前任何 DOM 变化都在 400 ms 后重扫整页,finding 不去重、不限速。
 * 一个每秒改几次 DOM 的页面就是每秒一条 agentguard_findings,同一个隐藏注入被上报几十遍,
 * 淹没真正的告警、灌满 recent 列表。现在三件事:
 *
 *   1. **稳定的 finding 指纹 + 去重。** 同一 (kind, field_id, 文本前 80 字) 在本页只上报一次;
 *      内容变了一个字就是新 finding。指纹集有上限,满了整体清空(宁可多报一次,不无界增长)。
 *   2. **增量扫描。** 由 mutation 触发的注入扫描只走**新增的节点子树**与被改动的文本节点,不走整页;
 *      表单/付款 CTA 扫描仍是整页(它们是 querySelectorAll,便宜),但受 3 的节流。
 *      我们自己的确认弹层(guard-modal 的 host,dataset.agentguardHost)插入/移除**不算**页面变化。
 *   3. **节流。** 400 ms 防抖之上,两次扫描至少间隔 Gate.MIN_SCAN_INTERVAL_MS(1.5 s);风暴期间最多每 1.5 s 一轮。
 *
 * 用户输入(input/change)仍走整页扫描——那是我们最关心的时刻,但同样受去重与节流。
 *
 * 真浏览器 E2E(eval/e2e-extension,固件 mutation-storm.html)的 M1–M4 钉的是**用户可见的行为**:
 * 5 秒风暴只多一条;每秒重渲染的注入与整页都能看到的付款按钮各只报一次;后到的不同注入仍会报;
 * 30 段突发全部计数但 ≤4 条。变异检查:去掉去重 → M1–M4 红;去掉节流 → M4 红;指纹退回 marker → M3/M4 红。
 * 增量扫描(2)和跳过自家弹层是**成本**优化,E2E 看不出差别(把它们关掉 24 条仍绿)——如实说明,不冒充已钉。
 * ------------------------------------------------------------------------- */
// 指纹、去重器、节流间隔都是 guard-gate.js 的纯逻辑(node 单测钉着);这里只接线。
// Gate 没加载到(不该发生)就不去重——方向是"多报",不是"漏报"。
const scanGate = self.AgentGuardGate || null;
const deduper = scanGate ? scanGate.newFindingDeduper() : { onlyNew: (f) => f };
function onlyNew(findings) {
  return deduper.onlyNew(findings);
}

/** `roots`:为 null 时整页扫注入;否则只扫这些子树(增量)。 */
function runScan(roots) {
  const injection = [];
  if (roots) {
    for (const r of roots) injection.push(...scanHiddenInjection(r));
  } else {
    injection.push(...scanHiddenInjection(null));
  }
  const findings = onlyNew([...injection, ...scanFormOverfill(), ...scanPaymentCta()]);
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
let lastScanAt = 0;
let pendingRoots = new Set();
let pendingFull = false;

function flushScan() {
  debounceTimer = null;
  lastScanAt = Date.now();
  const full = pendingFull;
  const roots = full ? null : Array.from(pendingRoots);
  pendingFull = false;
  pendingRoots = new Set();
  if (!full && roots.length === 0) return;
  runScan(roots);
}

function scheduleScan(roots) {
  if (roots === null || roots === undefined) pendingFull = true;
  else for (const r of roots) pendingRoots.add(r);
  if (debounceTimer) return;
  const since = Date.now() - lastScanAt;
  const wait = scanGate ? scanGate.scanDelayMs(since) : 400;
  debounceTimer = setTimeout(flushScan, wait);
}

function insideOwnUi(node) {
  const el = node && (node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement);
  return !!(el && el.closest && el.closest("[data-agentguard-host]"));
}

runScan(null);
lastScanAt = Date.now();
document.addEventListener("input", () => scheduleScan(null), true);
document.addEventListener("change", () => scheduleScan(null), true);
const mo = new MutationObserver((records) => {
  const roots = [];
  for (const rec of records) {
    if (insideOwnUi(rec.target)) continue;
    if (rec.type === "characterData") {
      if (rec.target.parentElement) roots.push(rec.target.parentElement);
    } else {
      for (const n of rec.addedNodes) {
        if (n.nodeType === Node.ELEMENT_NODE && !insideOwnUi(n)) roots.push(n);
        else if (n.nodeType === Node.TEXT_NODE && n.parentElement && !insideOwnUi(n)) roots.push(n.parentElement);
      }
    }
  }
  if (roots.length > 0) scheduleScan(roots);
});
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

function replayApprovedClick(el) {
  // submit 按钮的默认动作会在这次 click 末尾同步触发 form 的 submit 事件。用户批准的
  // 是这一条完整动作链，所以元素和所属表单都要各放行一次；否则 click 重放通过后，
  // submit 门会再次弹窗。finally 会清掉没有实际提交时留下的表单令牌，避免以后误放行。
  const form = el.form || (el.closest ? el.closest("form") : null);
  gateApproved.add(el);
  if (form) gateApproved.add(form);
  try {
    el.click();
  } finally {
    if (form) gateApproved.delete(form);
  }
}

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

/* 确认弹层由共享渲染器 guard-modal.js 提供(内容脚本与 onboarding 演示共用同一段
 * 渲染代码,词典改了两边同步)。语言、无障碍(alertdialog/焦点圈/焦点还原)、深色
 * 适配都在那边。这里只负责"什么时候弹、允许/取消各干什么"。 */
function askAllowOnce(spec, onAllow, onCancel) {
  const Modal = self.AgentGuardModal;
  if (!Modal) {
    // 渲染器没加载(不该发生)。宁可直接放行也不能"以为在拦其实页面卡死"。
    console.debug("AgentGuard modal renderer missing; allowing action");
    onAllow();
    return;
  }
  Modal.askAllowOnce(spec, onAllow, onCancel);
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
    gateEvent(e, findings, () => replayApprovedClick(el));
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
      // requestSubmit 保留原按钮的 formaction/formmethod/name/value,也保留约束校验；下一次
      // submit 事件由 gateApproved 放过。直接 form.submit() 会绕过这些浏览器语义。
      form.requestSubmit(e.submitter || undefined);
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

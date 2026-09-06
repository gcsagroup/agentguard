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
    if (/确认支付|Confirm Payment|Pay now|Complete purchase|立即支付|Authorize payment|Approve payment|Submit payment|Authorize charge|Approve charge/i.test(text)) {
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
if (document.documentElement) {
  // manifest 在 document_start 注入，先观察根节点，后续加入的 body 也不会漏掉。
  mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
}

/* ---------------------------------------------------------------------------
 * 执行前阻断(E2)。
 *
 * scanX 是**事后**的:它上报已经填好的表单、已经在页面上的付款按钮。这一段不同——它在捕获阶段
 * 同步拦住 submit / 付款 CTA 的 click,在动作**真正发生之前** preventDefault 把它按住。
 * 首个 GA 没有页面内放行：普通网页 DOM 不是可信授权界面。页面提示只解释阻断结果，
 * 浏览器通知/扩展弹窗才是页面无法伪造的状态面。
 *
 * 覆盖的是页面自己的 DOM 动作。付款形状的网络请求由浏览器拥有的静态 DNR 规则直接硬拦；
 * 这里不接收页面世界的请求、判决或 scope 消息，也不给 DOM 或网络硬拦提供“一次允许”。
 * 原生 app 不在浏览器扩展的能力范围内。见 guard-gate.js 头部的边界说明。
 * ------------------------------------------------------------------------- */

const PAYMENT_CTA_RE = /确认支付|Confirm Payment|Pay now|Complete purchase|立即支付|Authorize payment|Approve payment|Submit payment|Authorize charge|Approve charge/i;
const ACTIONABLE_SELECTOR = "button, a, [role='button'], input[type='submit']";
function ctaText(el) {
  return PAYMENT_CTA_RE.test((el && (el.innerText || el.value || el.textContent)) || "");
}

function nearestActionable(el) {
  return el && el.closest
    ? el.closest(ACTIONABLE_SELECTOR)
    : null;
}

/**
 * `click` is composed, but outside a shadow tree its target is retargeted to the
 * host. Walk the browser-provided composed path so an actionable element in an
 * open shadow root cannot hide behind an empty host. Closed shadow internals are
 * intentionally not claimed: browsers omit them from the path exposed here.
 */
function actionableFromEvent(event) {
  let path = [];
  try {
    path = typeof event.composedPath === "function" ? event.composedPath() : [];
  } catch (_) {
    path = [];
  }
  for (const node of path) {
    const actionable = nearestActionable(node);
    if (actionable) return actionable;
  }
  return nearestActionable(event.target) || event.target;
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

/* 页面提示由共享渲染器 guard-modal.js 提供。它没有授权按钮，也没有危险动作回调；
 * 页面篡改或移除提示最多影响说明展示，不能释放已阻断的动作。 */
function showBlocked(spec) {
  const Modal = self.AgentGuardModal;
  if (!Modal) {
    console.debug("AgentGuard block notice renderer missing; action remains blocked");
    return;
  }
  Modal.showBlocked(spec);
}

function gateEvent(e, findings) {
  const Gate = self.AgentGuardGate;
  if (!Gate) return; // 纯逻辑没加载(不该发生);不静默改变页面行为。
  const d = Gate.gateForFindings(findings);
  if (!d.block) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  reportPrevented(d.reason, d.kind);
  showBlocked({ kind: d.kind, reason: d.reason });
}

// document_start + window capture：先于页面脚本安装，并覆盖所有 manifest 指定 frame。
// 这只保证明确声明的、会产生 click/submit 事件且标签可识别的 DOM 支持面。
window.addEventListener(
  "click",
  (e) => {
    const el = actionableFromEvent(e);
    if (!el) return;
    const findings = ctaText(el) ? [{ kind: "payment_cta" }] : [];
    gateEvent(e, findings);
  },
  true
);

window.addEventListener(
  "submit",
  (e) => {
    const form = e.target;
    if (!form) return;
    const findings = [];
    if (formHasTrapPII(form)) findings.push({ kind: "privacy_trap" });
    if (e.submitter && ctaText(e.submitter)) findings.push({ kind: "payment_cta" });
    gateEvent(e, findings);
  },
  true
);

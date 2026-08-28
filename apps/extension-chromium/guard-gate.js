/**
 * AgentGuard 浏览器**执行前阻断**的纯决策逻辑(E2)。
 *
 * # 为什么这一层要和"事后通知"分开
 *
 * `background.js` 的 `notifyUser` 是**事后**的:原生消息是异步的,宿主是在事件发生**之后**观测到
 * 它的,没有东西可以"hold"。但**内容脚本跑在页面里、是同步的**——它能在一次 `submit` / `click`
 * **真正发生之前**用捕获阶段监听器 `preventDefault()` 把它按住。所以"执行前阻断"这件事只能、也
 * 必须发生在内容脚本这一层,不能依赖那趟异步宿主往返。
 *
 * 这个文件只放**纯函数**:输入是已判定的信号(payment CTA?trap+PII 提交?),输出是"拦不拦、
 * 为什么"。没有任何 DOM / chrome API 依赖,于是它能在 node 里被单元测试(`scripts/gate.test.mjs`),
 * 而 DOM 接线(在 `content.js`)只做 `node --check` 语法检查——和整个项目"安全逻辑进纯函数、
 * syscall/DOM 那层尽量薄"的做法一致。
 *
 * # 覆盖什么、**不**覆盖什么(如实)
 *
 * 覆盖:页面**自己的** DOM 提交 / 点击(付款 CTA、隐私陷阱下的 PII 表单提交)——这些会触发
 * `submit`/`click` 事件,能被同步拦下。网络层的导航/请求由 [`buildBlockRules`] 交给
 * declarativeNetRequest 在请求发出前拦(见 `background.js`)。
 *
 * **不**覆盖:一段直接 `fetch()` / `XMLHttpRequest` 到付款 API 的脚本(不产生 DOM 事件,除非命中
 * DNR 的主机规则)、跨源 iframe 里的动作、以及**任何原生 app 的动作**(浏览器扩展够不到)。这道
 * 门挡的是"在这个页面上把这一步走完",不是"这台机器上任何联网"。
 */
(function (root) {
  "use strict";

  /** 会触发执行前阻断的 finding 种类,以及给用户看的理由。 */
  const BLOCKING = {
    payment_cta: "这一步会确认一次付款/转账",
    privacy_trap: "这个表单在把非必要的个人信息填进一个诱导控件",
  };

  /**
   * 一个已判定的 finding 该不该在执行前拦下。
   * @param {string} kind - finding.kind
   * @returns {{block: boolean, reason: string}}
   */
  function gateForFinding(kind) {
    const reason = BLOCKING[kind];
    return reason ? { block: true, reason } : { block: false, reason: "" };
  }

  /**
   * 一组 finding 里是否有任何一个要求执行前阻断,返回第一个理由。
   * @param {Array<{kind: string}>} findings
   * @returns {{block: boolean, reason: string, kind: string}}
   */
  function gateForFindings(findings) {
    for (const f of findings || []) {
      const d = gateForFinding(f && f.kind);
      if (d.block) return { block: true, reason: d.reason, kind: f.kind };
    }
    return { block: false, reason: "", kind: "" };
  }

  /**
   * 把一组要拦截的主机构造成 declarativeNetRequest 动态规则(在请求发出**前**拦)。
   *
   * 主机来自引擎/情报判定(恶意域、越出 scope.hosts 的目的地)。这里只做**纯粹的规则构造**,
   * 安装交给 `background.js` 的 `chrome.declarativeNetRequest.updateDynamicRules`。
   *
   * 规则去重且 id 稳定(按主机排序后 1..N),这样重复安装同一组主机不会 id 冲突,也便于测试。
   * @param {string[]} hosts
   * @param {number} [startId=1]
   * @returns {Array<object>} DNR 规则
   */
  function buildBlockRules(hosts, startId) {
    const base = typeof startId === "number" ? startId : 1;
    const uniq = Array.from(
      new Set((hosts || []).map((h) => String(h || "").trim().toLowerCase()).filter(Boolean))
    ).sort();
    return uniq.map((host, i) => ({
      id: base + i,
      priority: 1,
      action: { type: "block" },
      // requestDomains 匹配该域及其子域;限定主框架导航 + 子资源,覆盖"点开就走"和"页面替你发请求"。
      condition: { requestDomains: [host], resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"] },
    }));
  }

  // 付款/转账形状的请求路径。命中的出站请求在发出前要过确认——这补上"内容脚本 DOM 门拦不了
  // 一段直接 fetch() 的脚本"那条残余(E2.1)。判据刻意只看 URL(不看 body):body 因站而异、误判
  // 高,而误拦会让人关掉门;URL 路径里的 pay/checkout/charge/transfer 是跨站相当稳的信号。
  const PAYMENT_PATH_RE =
    /\/(pay|payment|checkout|charge|transfer|remit|purchase|order[_-]?confirm|confirm[_-]?order)(\/|\b|$)/i;

  /**
   * 一个出站请求要不要在发出前拦下确认。
   * @param {string} url - 请求 URL(绝对或相对)
   * @param {string} [method] - HTTP 方法
   * @returns {{gate: boolean, reason: string}}
   */
  function classifyRequest(url, method) {
    const u = String(url || "");
    // 只读方法(GET/HEAD)不拦:付款/转账是状态变更,GET 不该有副作用,拦它只会误伤。
    const m = String(method || "GET").toUpperCase();
    if (m === "GET" || m === "HEAD") return { gate: false, reason: "" };
    let path = u;
    try {
      // 相对 URL 也能解析(base 随便给一个);解析失败就退回按整串匹配。
      path = new URL(u, "http://x").pathname;
    } catch (_e) {
      /* 用原串 */
    }
    if (PAYMENT_PATH_RE.test(path) || PAYMENT_PATH_RE.test(u)) {
      return { gate: true, reason: "这个请求看起来在发起一次付款/转账" };
    }
    return { gate: false, reason: "" };
  }

  const Gate = {
    gateForFinding,
    gateForFindings,
    buildBlockRules,
    classifyRequest,
    BLOCKING,
  };

  root.AgentGuardGate = Gate;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = Gate;
  }
})(typeof self !== "undefined" ? self : globalThis);

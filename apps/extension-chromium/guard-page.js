/**
 * 页面上下文(MAIN world)里的出站请求门(E2.1)。
 *
 * # 为什么要在这一层,而不是内容脚本里
 *
 * 内容脚本跑在**隔离世界**,它包裹的 `fetch` 不是页面脚本看到的那个 `window.fetch`。一段直接
 * `fetch("/api/checkout", {method:"POST"})` 的页面脚本,内容脚本的 DOM 门(submit/click)拦不到——
 * 它不产生 DOM 事件。要拦住它,必须在**页面世界**里包裹 `fetch` / `XMLHttpRequest` 本身。这个文件
 * 就是那层(manifest 里以 `world: "MAIN"` 注入)。
 *
 * # 怎么"执行前阻断"一个异步请求
 *
 * `fetch` 是异步的,所以不需要同步 hold:包裹后的 `fetch` 对命中付款形状的请求**先** postMessage 给
 * 内容脚本(它在隔离世界、能弹我们的确认 UI、能连扩展),**await** 用户的决定,允许才调原始
 * `fetch`、拒绝就 `reject`。请求在用户点"允许一次"之前一个字节都没发出去。
 *
 * # 判决用的是同一套纯逻辑
 *
 * 命不命中由 `guard-gate.js` 的 `classifyRequest`(纯函数,有 node 单测)决定;这个文件只做"包裹 +
 * 通过 postMessage 问一声 + 按回答放行/拒绝"的胶水,只做 `node --check` 语法检查。
 *
 * # 如实边界
 *
 * 这是**尽力而为**,不是铁壁:
 * - 一段在我们之前就抓走了原始 `fetch` 引用的脚本(早于 document_start,或用 `Reflect`/iframe 借来的
 *   干净 `fetch`)绕得过——MAIN world 里页面和我们平权,谁都能改 `window.fetch`。
 * - 判据只看 URL 路径的付款形状(pay/checkout/charge/transfer…),不看 body:body 因站而异、误判高,
 *   而误拦比漏拦更容易让人把整个门关掉。所以它拦的是"长得像付款的直发请求",不是"任何出站"。
 * - "任何出站到某主机"那种粗粒度拦截是 `declarativeNetRequest`(background)和 Linux jail 的
 *   `scope.net`(E1)那两层的事,不是这里。
 */
(function () {
  "use strict";

  const Gate = window.AgentGuardGate;
  if (!Gate || typeof Gate.classifyRequest !== "function") {
    // 纯逻辑没注入进来(不该发生)。不改变页面行为——绝不"以为在拦其实没拦"。
    return;
  }

  const REQ = "__agentguard_req_gate__";
  const DECISION = "__agentguard_req_decision__";
  const SCOPE = "__agentguard_scope__";
  let seq = 0;
  /** id -> {resolve} 等待中的确认。 */
  const pending = new Map();
  // 任务主机允许表(E9)。内容脚本从 background 拿到后 postMessage 过来。
  // `undefined` = 还没收到 / 没声明 → 不做本地越界拦截(和引擎"没声明不拦"一致)。
  let scopeAllowlist = undefined;

  window.addEventListener("message", (ev) => {
    // 只认自己这一页来的消息。
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d) return;
    if (d.type === DECISION && typeof d.id === "number") {
      const waiter = pending.get(d.id);
      if (waiter) {
        pending.delete(d.id);
        waiter(!!d.allow);
      }
      return;
    }
    if (d.type === SCOPE) {
      // null / 缺失 = 没声明;数组(含空)= 声明了。
      scopeAllowlist = Array.isArray(d.allowlist) ? d.allowlist : undefined;
    }
  });

  // 一个出站请求要不要拦:先看付款形状,再看是否越出任务允许表(E9)。任一命中即拦。
  function decideOutbound(url, method) {
    const pay = Gate.classifyRequest(url, method);
    if (pay.gate) return pay;
    if (Array.isArray(scopeAllowlist)) {
      let host = "";
      try {
        host = new URL(url, location.href).hostname;
      } catch (_e) {
        host = "";
      }
      if (host) {
        const sc = Gate.scopeGateHost(host, scopeAllowlist);
        if (sc.gate) return sc;
      }
    }
    return { gate: false, reason: "" };
  }

  // 向内容脚本要一个"允许/拒绝"的决定;超时(没有内容脚本回应)按**放行**处理,理由和
  // background 的 DNR 一致:这一层是加的一道,不该因为它自己卡住就把用户的正常请求全掐死。
  function askDecision(url, reason) {
    return new Promise((resolve) => {
      const id = ++seq;
      let settled = false;
      const done = (allow) => {
        if (settled) return;
        settled = true;
        resolve(allow);
      };
      pending.set(id, done);
      window.postMessage({ type: REQ, id, url: String(url).slice(0, 300), reason }, "*");
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          done(true); // fail-open,已声明(见文件头)
        }
      }, 15000);
    });
  }

  const origFetch = window.fetch ? window.fetch.bind(window) : null;
  if (origFetch) {
    window.fetch = function (input, init) {
      try {
        const url = typeof input === "string" ? input : input && input.url;
        const method =
          (init && init.method) || (input && typeof input === "object" && input.method) || "GET";
        const d = decideOutbound(url, method);
        if (d.gate) {
          return askDecision(url, d.reason).then((allow) => {
            if (allow) return origFetch(input, init);
            return Promise.reject(new DOMException("AgentGuard 拦下了一次出站请求", "AbortError"));
          });
        }
      } catch (_e) {
        /* 分类失败就按不拦处理,原始行为不变 */
      }
      return origFetch(input, init);
    };
  }

  // XMLHttpRequest:在 open 时记下 (method,url),在 send 时判决。命中则先拦住 send,
  // 确认后再真正发。
  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const origOpen = XHR.prototype.open;
    const origSend = XHR.prototype.send;
    XHR.prototype.open = function (method, url) {
      this.__ag_method = method;
      this.__ag_url = url;
      return origOpen.apply(this, arguments);
    };
    XHR.prototype.send = function (body) {
      let decision = { gate: false };
      try {
        decision = decideOutbound(this.__ag_url, this.__ag_method);
      } catch (_e) {
        /* 按不拦处理 */
      }
      if (!decision.gate) return origSend.apply(this, arguments);
      const self = this;
      const args = arguments;
      askDecision(self.__ag_url, decision.reason).then((allow) => {
        if (allow) {
          origSend.apply(self, args);
        } else {
          // 拒绝:中止这个 XHR,页面会收到 abort/error,而请求没发出去。
          try {
            self.abort();
          } catch (_e) {
            /* ignore */
          }
        }
      });
      // send 本身不同步发出——已交给上面的异步决定。
    };
  }
})();

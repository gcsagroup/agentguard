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

  // DNR 名单的累积语义(E8)。两类主机的寿命不同,所以不能每批判决整体替换(那会让一条恶意域
  // 在下一批 benign 判决到来时被清掉):
  //   - malicious(已知恶意域):**累积保留**,并落 chrome.storage 跨 service-worker 重启存活。
  //   - out_of_scope(越出任务 hosts):**随会话过期**——它是任务相对的,不该永久拦掉用户对该主机的
  //     正常访问。用时间戳过期(默认 30 分钟没被再次判越界就撤)。
  const SESSION_TTL_MS = 30 * 60 * 1000;
  // DNR 动态规则有配额;给持久名单一个上限,超了丢最旧的(保留最近判定的)。
  const MAX_PERSISTENT = 4000;

  const normHost = (h) => String(h || "").trim().toLowerCase();

  /**
   * 把上一份名单状态和这一批新判决合并,算出当前该装进 DNR 的完整主机集。
   *
   * @param {{persistent?: string[], session?: Array<{host:string,exp:number}>}} state 上一份状态
   * @param {string[]} malicious 这批新判的恶意域
   * @param {string[]} outOfScope 这批新判的越界目的地
   * @param {number} now 当前时间 ms
   * @param {number} [ttlMs] 会话项寿命
   * @param {number} [maxPersistent] 持久名单上限
   * @returns {{persistent: string[], session: Array<{host:string,exp:number}>, active: string[]}}
   */
  function mergeBlocklist(state, malicious, outOfScope, now, ttlMs, maxPersistent) {
    const ttl = typeof ttlMs === "number" ? ttlMs : SESSION_TTL_MS;
    const cap = typeof maxPersistent === "number" ? maxPersistent : MAX_PERSISTENT;

    // 持久集:累积恶意域,去重,保序(新的追加到尾),超上限丢最旧的。
    let persistent = Array.isArray(state && state.persistent)
      ? state.persistent.map(normHost).filter(Boolean)
      : [];
    const seen = new Set(persistent);
    for (const h of (malicious || []).map(normHost).filter(Boolean)) {
      if (!seen.has(h)) {
        seen.add(h);
        persistent.push(h);
      }
    }
    if (persistent.length > cap) persistent = persistent.slice(persistent.length - cap);
    const persistentSet = new Set(persistent);

    // 会话集:{host, exp}。先丢掉已过期的,再把这批越界项(exp = now+ttl)加/刷新。
    // 已经在持久集里的主机不必再进会话集(持久的更强)。
    const sessionMap = new Map();
    for (const e of (state && state.session) || []) {
      if (e && e.host && typeof e.exp === "number" && e.exp > now) {
        const h = normHost(e.host);
        if (h && !persistentSet.has(h)) sessionMap.set(h, e.exp);
      }
    }
    for (const h of (outOfScope || []).map(normHost).filter(Boolean)) {
      if (!persistentSet.has(h)) sessionMap.set(h, now + ttl);
    }
    const session = [...sessionMap.entries()].map(([host, exp]) => ({ host, exp }));

    // active = 持久 ∪ 未过期会话,排序稳定(便于测试与稳定的 DNR 规则 id)。
    const active = Array.from(new Set([...persistent, ...sessionMap.keys()])).sort();
    return { persistent, session, active };
  }

  /**
   * 清理过期会话主机时保留管理界面需要的规则溯源。
   *
   * `mergeBlocklist` 只负责主机集合；后台若直接用它的返回值覆盖状态，会把
   * `provenance` 静默丢掉。把重建动作集中在这里，两个调用点使用同一语义。
   */
  function pruneBlocklist(state, now) {
    const merged = mergeBlocklist(state, [], [], now);
    const provenance =
      state && state.provenance && typeof state.provenance === "object" ? state.provenance : {};
    return {
      persistent: merged.persistent,
      session: merged.session,
      active: merged.active,
      provenance,
    };
  }

  // 一个观察到的主机是否落在允许表条目 `entry` 之内:精确相等,或它的子域(E9)。
  //
  // 这是 Rust 端 `guard_schema::host_in_scope` 的 JS 镜像,**安全攸关**:点边界是关键——裸
  // `endsWith("stripe.com")` 会把 `stripe.com.evil.example` 也当成 stripe.com 的子域放行,那是
  // 经典的后缀伪造,会把允许表变成"允许一切"。两端语义必须一致,否则 JS 会放行一个 Rust 会拦的
  // 目的地(或反之)——`hostInScope_对齐Rust拒绝后缀伪造` 那条 node 测试把这几个伪造用例钉死。
  function hostInScope(observed, entry) {
    const norm = (s) => {
      let x = String(s || "").trim().toLowerCase();
      while (x.endsWith(".")) x = x.slice(0, -1);
      // 去掉 user:pass@ 和 :port(IPv6 字面量保留方括号)。
      if (x.includes("@")) x = x.split("@").pop();
      const i = x.lastIndexOf(":");
      if (i >= 0 && !x.endsWith("]") && !x.slice(i + 1).includes("]")) x = x.slice(0, i);
      return x;
    };
    const o = norm(observed);
    const e = norm(entry);
    if (!o || !e) return false;
    return o === e || o.endsWith(`.${e}`);
  }

  /**
   * 一个出站目的地主机在**任务允许表**里吗——不在则该本地拦(E9)。
   *
   * @param {string} host 目的地主机
   * @param {string[]|null|undefined} allowlist 允许表:`null`/`undefined` = 没声明(不拦);
   *        `[]` = 明确"不许出网"(全拦);否则精确/子域匹配。
   * @returns {{gate: boolean, reason: string}}
   */
  function scopeGateHost(host, allowlist) {
    // 没声明允许表 = 不做本地越界拦截(和引擎 check_scope_host 的"没声明不拦"一致)。
    if (!Array.isArray(allowlist)) return { gate: false, reason: "" };
    const h = String(host || "").trim();
    if (!h) return { gate: false, reason: "" };
    if (allowlist.some((a) => hostInScope(h, a))) return { gate: false, reason: "" };
    return {
      gate: true,
      reason:
        allowlist.length === 0
          ? "这个任务被声明为不许出网,而这是一个出站请求"
          : `目的地 ${h} 不在这个任务声明的允许网站里`,
    };
  }

  const Gate = {
    gateForFinding,
    gateForFindings,
    buildBlockRules,
    classifyRequest,
    mergeBlocklist,
    pruneBlocklist,
    hostInScope,
    scopeGateHost,
    SESSION_TTL_MS,
    MAX_PERSISTENT,
    BLOCKING,
  };

  root.AgentGuardGate = Gate;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = Gate;
  }
})(typeof self !== "undefined" ? self : globalThis);

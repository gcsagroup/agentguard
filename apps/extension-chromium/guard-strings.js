/* AgentGuard 人话词典(单一真相源)。
 *
 * 这个仓库的用户界面曾经把内部枚举直接怼给用户:「invisible_injection · 页面标题」、
 * 「触发规则: INTEL-DOMAIN」、硬编码中文的确认弹层。这个文件把**所有**用户可见的
 * 安全词汇收拢成一张三语词表:每个 finding 种类 / 拦截规则 / 执行前门,都映射成
 * 「人话标题 + 一句解释(+ 后果说明)」。技术标识(rule id、枚举名)只出现在
 * 可展开的「详情」里,给排障用,不再是第一眼看到的东西。
 *
 * 和 guard-gate.js 一样是**纯数据 + 纯函数**:没有 DOM、没有 chrome.*,node 里可以
 * 直接单测(scripts/strings.test.mjs)。popup.js 和 content.js 的确认层都从这里取词,
 * 于是「界面上不出现裸术语」是一条可测试的性质,而不是靠 review 时的眼力。
 *
 * 铁律:新增一个 finding kind / 规则 ID,先在这里补齐三语词条 —— 覆盖率测试会在
 * 缺词条时红掉(它从 content.js 源码提取 kind 字面量、从 guard-schema/events.rs
 * 提取规则 ID,对着这张表点名)。
 */
(function (root) {
  "use strict";

  const LOCALES = ["en", "zh_CN", "zh_TW"];

  /* ------------------------------------------------------------------
   * finding 种类 → 人话。key 与 content.js 上报的 kind 字面量一致。
   * title:一眼看懂发生了什么;detail:多一句"这意味着什么"。
   * ------------------------------------------------------------------ */
  const KINDS = {
    invisible_injection: {
      en: {
        title: "Hidden instructions on this page",
        detail:
          "Text you can't see (but an AI agent can read) was found on this page. It may try to hijack what the agent does.",
      },
      zh_CN: {
        title: "网页里藏了人眼看不见的指令",
        detail: "页面上有对你不可见、但 AI 智能体读得到的文字,可能想劫持智能体去做别的事。",
      },
      zh_TW: {
        title: "網頁裡藏了人眼看不見的指令",
        detail: "頁面上有你看不到、但 AI 智慧代理讀得到的文字,可能想挾持代理去做別的事。",
      },
    },
    prompt_injection: {
      en: {
        title: "Suspicious instructions aimed at AI agents",
        detail:
          "This page contains wording that tries to give orders to an AI agent (e.g. “ignore previous instructions”).",
      },
      zh_CN: {
        title: "网页文字里混入了给 AI 的可疑指令",
        detail: "页面文字里出现了试图指挥 AI 智能体的话术(比如“忽略之前的指令”)。",
      },
      zh_TW: {
        title: "網頁文字裡混入了給 AI 的可疑指令",
        detail: "頁面文字裡出現了試圖指揮 AI 代理的話術(例如「忽略先前的指示」)。",
      },
    },
    privacy_trap: {
      en: {
        title: "This form is fishing for extra personal info",
        detail:
          "A tempting label (like “VIP express”) is nudging you to hand over personal details this task doesn't need.",
      },
      zh_CN: {
        title: "这个表单在诱导多填个人信息",
        detail: "页面用“VIP 加急”这类诱导话术,想让你交出这次任务并不需要的个人信息。",
      },
      zh_TW: {
        title: "這個表單在誘導多填個人資料",
        detail: "頁面用「VIP 加速」這類誘導話術,想讓你交出這次任務並不需要的個人資料。",
      },
    },
    optional_pii: {
      en: {
        title: "Personal info requested that isn't required",
        detail:
          "The form asks for personal details (phone, address…) marked optional — you can finish without giving them.",
      },
      zh_CN: {
        title: "表单要了非必要的个人信息",
        detail: "表单在收集手机号、地址这类个人信息,但它们是选填的——不填也能完成。",
      },
      zh_TW: {
        title: "表單要了非必要的個人資料",
        detail: "表單在收集手機號、地址這類個人資料,但它們是選填的——不填也能完成。",
      },
    },
    payment_cta: {
      en: {
        title: "A payment button is on this page",
        detail: "A button here confirms a payment or transfer. AgentGuard asks before it is clicked.",
      },
      zh_CN: {
        title: "页面上有付款/转账按钮",
        detail: "这个页面上有会确认付款或转账的按钮。点它之前 AgentGuard 会先问你。",
      },
      zh_TW: {
        title: "頁面上有付款/轉帳按鈕",
        detail: "這個頁面上有會確認付款或轉帳的按鈕。點它之前 AgentGuard 會先問你。",
      },
    },
    outbound_request: {
      en: {
        title: "Page tried to send a payment request directly",
        detail:
          "A script on this page tried to send a payment-shaped request in the background, without any click.",
      },
      zh_CN: {
        title: "网页想在后台直接发出付款请求",
        detail: "页面脚本试图不经点击、在后台直接发送一笔付款形状的请求。",
      },
      zh_TW: {
        title: "網頁想在背景直接發出付款請求",
        detail: "頁面腳本試圖不經點擊、在背景直接發送一筆付款形狀的請求。",
      },
    },
    /* popup 的「最近」列表里,执行前拦截自己也是一条记录(background 记为 kind:"prevented",
     * 真实种类在 prevented_kind 里)。这里给"拦截了一次动作"这个事件本身一个人话名。 */
    prevented: {
      en: { title: "Blocked before it happened", detail: "AgentGuard stopped an action and asked first." },
      zh_CN: { title: "在发生前拦下了一次动作", detail: "AgentGuard 拦住了这一步,先问过你才放行。" },
      zh_TW: { title: "在發生前攔下了一次動作", detail: "AgentGuard 攔住了這一步,先問過你才放行。" },
    },
  };

  /* ------------------------------------------------------------------
   * 拦截规则 ID → 人话。key 与 guard-schema events.rs 的常量一致。
   * popup 的拦截名单用它替代裸 rule id;rule id 本身收进详情。
   * ------------------------------------------------------------------ */
  const RULES = {
    "INTEL-DOMAIN": {
      en: {
        title: "Known malicious site",
        detail: "This address is on the threat-intelligence blocklist. Visiting it risks data theft or fraud.",
      },
      zh_CN: {
        title: "已知的恶意网站",
        detail: "这个网址在威胁情报名单里,访问它可能泄露数据或被骗。",
      },
      zh_TW: {
        title: "已知的惡意網站",
        detail: "這個網址在威脅情資名單裡,造訪它可能洩露資料或被騙。",
      },
    },
    /* 引擎关键规则里最常到达浏览器通知的一条:付款/转账确认。 */
    "CRIT-001": {
      en: {
        title: "Payment confirmation",
        detail: "This action confirms a payment or transfer — a critical step that should be approved by a person.",
      },
      zh_CN: {
        title: "付款/转账确认",
        detail: "这个操作会确认一笔付款或转账,属于应当由真人批准的关键步骤。",
      },
      zh_TW: {
        title: "付款/轉帳確認",
        detail: "這個操作會確認一筆付款或轉帳,屬於應當由真人批准的關鍵步驟。",
      },
    },
    "SCOPE-HOST": {
      en: {
        title: "Outside what this task is allowed to visit",
        detail: "The current task declared which sites it needs. This one isn't on that list.",
      },
      zh_CN: {
        title: "超出本次任务允许访问的网站",
        detail: "当前任务声明过它需要访问哪些网站,这个不在清单里。",
      },
      zh_TW: {
        title: "超出本次任務允許造訪的網站",
        detail: "目前任務聲明過它需要造訪哪些網站,這個不在清單裡。",
      },
    },
  };

  /* ------------------------------------------------------------------
   * 执行前确认层。key 是门的种类:DOM 门用 finding kind(payment_cta / privacy_trap),
   * fetch 门用 payment_request,越界门用 out_of_scope_host / no_egress。
   * body 可以带 {host} 占位;allow / cancel 是两个按钮各自的后果说明。
   * ------------------------------------------------------------------ */
  const GATES = {
    payment_cta: {
      en: {
        title: "About to confirm a payment",
        body: "This click confirms a payment or money transfer.",
        allow: "Allow once: the payment goes ahead.",
        cancel: "Not now: nothing happens, you stay on this page.",
      },
      zh_CN: {
        title: "这一步要付款了",
        body: "这次点击会确认一笔付款或转账。",
        allow: "允许这一次:付款会继续进行。",
        cancel: "先不要:什么都不会发生,页面保持原样。",
      },
      zh_TW: {
        title: "這一步要付款了",
        body: "這次點擊會確認一筆付款或轉帳。",
        allow: "允許這一次:付款會繼續進行。",
        cancel: "先不要:什麼都不會發生,頁面保持原樣。",
      },
    },
    privacy_trap: {
      en: {
        title: "About to send personal info",
        body: "This form is nudging you (“VIP express”…) to submit personal details this task doesn't need.",
        allow: "Allow once: the info is submitted to the site.",
        cancel: "Not now: nothing is sent.",
      },
      zh_CN: {
        title: "要把个人信息交出去了",
        body: "这个表单在用诱导话术让你提交这次任务并不需要的个人信息(比如手机号)。",
        allow: "允许这一次:这些信息会被提交给网站。",
        cancel: "先不要:什么都不会发出去。",
      },
      zh_TW: {
        title: "要把個人資料交出去了",
        body: "這個表單在用誘導話術讓你提交這次任務並不需要的個人資料(例如手機號)。",
        allow: "允許這一次:這些資料會被提交給網站。",
        cancel: "先不要:什麼都不會發出去。",
      },
    },
    payment_request: {
      en: {
        title: "Page wants to send a payment request",
        body: "A script on this page is trying to send a payment-shaped request in the background.",
        allow: "Allow once: the request is sent.",
        cancel: "Not now: the request never leaves your browser.",
      },
      zh_CN: {
        title: "网页想直接发起一笔付款",
        body: "页面脚本正试图在后台直接发送一笔付款形状的请求。",
        allow: "允许这一次:这个请求会被发出。",
        cancel: "先不要:请求不会离开你的浏览器。",
      },
      zh_TW: {
        title: "網頁想直接發起一筆付款",
        body: "頁面腳本正試圖在背景直接發送一筆付款形狀的請求。",
        allow: "允許這一次:這個請求會被發出。",
        cancel: "先不要:請求不會離開你的瀏覽器。",
      },
    },
    out_of_scope_host: {
      en: {
        title: "Visiting a site outside this task",
        body: "The current task declared which sites it needs. {host} isn't one of them.",
        allow: "Allow once: this one request goes through.",
        cancel: "Not now: the request is not sent.",
      },
      zh_CN: {
        title: "要访问任务之外的网站",
        body: "当前任务声明过它需要访问哪些网站,{host} 不在清单里。",
        allow: "允许这一次:只放行这一个请求。",
        cancel: "先不要:这个请求不会被发出。",
      },
      zh_TW: {
        title: "要造訪任務之外的網站",
        body: "目前任務聲明過它需要造訪哪些網站,{host} 不在清單裡。",
        allow: "允許這一次:只放行這一個請求。",
        cancel: "先不要:這個請求不會被發出。",
      },
    },
    no_egress: {
      en: {
        title: "This task promised not to touch the network",
        body: "The current task was declared offline, but the page is trying to send a request.",
        allow: "Allow once: this one request goes through.",
        cancel: "Not now: the request is not sent.",
      },
      zh_CN: {
        title: "这个任务说好不联网的",
        body: "当前任务被声明为不出网,但页面正试图发送一个请求。",
        allow: "允许这一次:只放行这一个请求。",
        cancel: "先不要:这个请求不会被发出。",
      },
      zh_TW: {
        title: "這個任務說好不連網的",
        body: "目前任務被聲明為不出網,但頁面正試圖發送一個請求。",
        allow: "允許這一次:只放行這一個請求。",
        cancel: "先不要:這個請求不會被發出。",
      },
    },
  };

  /* 确认层与 popup 的通用界面词。 */
  const UI = {
    en: {
      brand: "AgentGuard paused this step",
      why: "Why was this blocked?",
      whyTech: "Technical id",
      allow: "Allow once",
      cancel: "Not now",
      justNow: "just now",
      minutesAgo: "{n} min ago",
      hoursAgo: "{n} h ago",
      daysAgo: "{n} d ago",
      notifyBlocked: "AgentGuard blocked a critical action",
      notifyConfirm: "This action should have asked you first",
      criticalAction: "a critical action",
    },
    zh_CN: {
      brand: "AgentGuard 拦下了这一步",
      why: "为什么拦住我?",
      whyTech: "技术标识",
      allow: "允许这一次",
      cancel: "先不要",
      justNow: "刚刚",
      minutesAgo: "{n} 分钟前",
      hoursAgo: "{n} 小时前",
      daysAgo: "{n} 天前",
      notifyBlocked: "AgentGuard 拦下了一个关键操作",
      notifyConfirm: "这个操作本应先由你确认",
      criticalAction: "关键操作",
    },
    zh_TW: {
      brand: "AgentGuard 攔下了這一步",
      why: "為什麼攔住我?",
      whyTech: "技術標識",
      allow: "允許這一次",
      cancel: "先不要",
      justNow: "剛剛",
      minutesAgo: "{n} 分鐘前",
      hoursAgo: "{n} 小時前",
      daysAgo: "{n} 天前",
      notifyBlocked: "AgentGuard 攔下了一個關鍵操作",
      notifyConfirm: "這個操作本應先由你確認",
      criticalAction: "關鍵操作",
    },
  };

  /* ---------------------------- 纯函数 ---------------------------- */

  /** 把 popup 的语言覆盖(system/en/zh_CN/zh_TW)+ 浏览器语言归一成一个词表 locale。 */
  function pickLocale(override, navLang) {
    if (override && override !== "system" && LOCALES.includes(override)) return override;
    const lang = String(navLang || "").toLowerCase();
    if (/zh-(tw|hk|mo)|hant/.test(lang)) return "zh_TW";
    if (lang.startsWith("zh")) return "zh_CN";
    return "en";
  }

  function sub(template, vars) {
    let out = String(template);
    for (const [k, v] of Object.entries(vars || {})) {
      out = out.split(`{${k}}`).join(String(v));
    }
    return out;
  }

  /** finding kind → {title, detail};不认识的 kind 返回 null(调用方自己兜底)。 */
  function kindText(kind, locale) {
    const entry = KINDS[kind];
    if (!entry) return null;
    return entry[locale] || entry.en;
  }

  /** 规则 ID → {title, detail};不认识的返回 null。 */
  function ruleText(ruleId, locale) {
    const entry = RULES[ruleId];
    if (!entry) return null;
    return entry[locale] || entry.en;
  }

  /** 执行前门 → {title, body, allow, cancel},body 已做 {host} 替换;不认识的返回 null。 */
  function gateText(kind, locale, vars) {
    const entry = GATES[kind];
    if (!entry) return null;
    const g = entry[locale] || entry.en;
    return { title: g.title, body: sub(g.body, vars), allow: g.allow, cancel: g.cancel };
  }

  /** 通用界面词表(brand / why / allow / cancel / 相对时间模板)。 */
  function ui(locale) {
    return UI[locale] || UI.en;
  }

  /** 时间戳 → 人话相对时间(popup 最近列表用)。 */
  function relativeTime(ts, now, locale) {
    const u = ui(locale);
    const delta = Math.max(0, Number(now) - Number(ts));
    const min = Math.floor(delta / 60000);
    if (min < 1) return u.justNow;
    if (min < 60) return sub(u.minutesAgo, { n: min });
    const h = Math.floor(min / 60);
    if (h < 24) return sub(u.hoursAgo, { n: h });
    return sub(u.daysAgo, { n: Math.floor(h / 24) });
  }

  const Strings = {
    LOCALES,
    KINDS,
    RULES,
    GATES,
    UI,
    pickLocale,
    kindText,
    ruleText,
    gateText,
    ui,
    relativeTime,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = Strings; // node 单测
  }
  root.AgentGuardStrings = Strings; // 浏览器(content script / popup)
})(typeof self !== "undefined" ? self : globalThis);

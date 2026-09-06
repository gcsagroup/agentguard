/* 桌面壳子确认弹层的读屏/键盘可达性,真浏览器断言(make shell-a11y;真机报告 P2-4)。
 *
 * 壳子的 index.html + main.js 在 Tauri 的 WebView 里跑,依赖 `window.__TAURI__`。这里用
 * `addInitScript` 在页面脚本之前装一个**桩**:`invoke(cmd)` 按夹具返回,`listen` 记下回调。
 * 桩只喂预置数据,不碰任何真实后端 —— 它证明的是前端那一层的合同:
 *
 *   1. 弹层是 role=alertdialog,aria-labelledby / aria-describedby 指向存在的标题与正文;
 *   2. 弹出时焦点落在“暂停后续受保护操作”(安全默认),<main> 置 inert —— 背景控件既不可点也不在 Tab 序列里;
 *   3. Tab / Shift+Tab 只在弹层内循环(报告实测:以前要穿过 11–12 个背景控件);
 *   4. Esc = 暂停后续受保护操作:resolve_confirm 收到 approve:false 与**展示过的那条** request_id(P0-5);
 *   5. 关闭后 inert 撤掉、焦点还原到打开前的元素;
 *   6. 读屏播报通道 #sr-announce 在弹出与状态变化时有文案,且文案是词表里的人话不是 key;
 *   7. 审计时间线是 role=log + aria-live=off(可导航、不打断),aria-label 随语言。
 *
 * 两个壳子(macOS / Windows)同一套断言:它们各有一份 main.js,谁漂了谁红。
 * 需要 playwright(容器预装 Chromium)。刻意不进 release-gate;和 ui-preview 一样是开发工具。
 * Tauri 用的是 WebKit / WebView2,不是 Chromium —— DOM 语义(inert、ARIA 反射、焦点)三家一致,
 * 但读屏的真实播报仍要在真机上用 VoiceOver / Narrator 听一遍(acceptance 清单)。
 */
import { createServer } from "node:http";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const OUT = join(HERE, "out");
mkdirSync(OUT, { recursive: true });

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    try {
      const globalRoot = execSync("npm root -g", { encoding: "utf8" }).trim();
      return createRequire(import.meta.url)(join(globalRoot, "playwright"));
    } catch {
      console.error("需要 playwright:npm install -g playwright(Chromium 已预装于 /opt/pw-browsers)");
      process.exit(2);
    }
  }
}
const { chromium } = await loadPlaywright();

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".svg": "image/svg+xml" };
// 壳子的 index.html 用 `src="/main.js"`(Tauri dev server 以 src/ 为根),所以这里也以当前壳子的
// src/ 为根来服务,而不是仓库根。
let currentRoot = REPO;
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  const file = join(currentRoot, path === "/" ? "/index.html" : path);
  if (!existsSync(file) || !file.startsWith(currentRoot)) {
    res.writeHead(404);
    res.end("not found");
    return;
  }
  res.writeHead(200, { "content-type": MIME[extname(file)] || "text/plain" });
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch({ executablePath: existsSync("/opt/pw-browsers/chromium") ? "/opt/pw-browsers/chromium" : undefined });

let failures = 0;
const check = (name, cond, extra) => {
  if (cond) console.log(`  ok - ${name}`);
  else {
    failures += 1;
    console.error(`  FAIL - ${name}${extra ? `\n    ${extra}` : ""}`);
  }
};

// 桩:每条 invoke 返回够让 main.js 初始化不抛的最小数据;确认相关的两条由测试推进。
const TAURI_STUB = `
(() => {
  const calls = [];
  const listeners = new Map();
  const state = {
    pending: null,
    status: {
      protection_state: "active", state_reasons: [], session_active: true, rules_loaded: 12,
      policy_id: "standard", audit_enabled: true, audit_ready: true,
      audit_bootstrap_state: "ready", audit_error: "", intel_version: "baseline", privacy_composite: 1.0,
      observers_available: true, observers_running: true, heartbeat_age_ms: 900, suppressed_events: 0,
      confirms_timed_out: 0, orphaned_confirms: 0, pending_count: 0, policy: null,
      accessibility: true, screen_capture: true, protection_mode: "full", capabilities: { uia: true, capture: true, ocr: false },
      sck_streaming: false, sck_native_ok: false, sck_auto_poll: false, ax_auto: false, native_polling: false,
    },
  };
  let tcc = { accessibility: true, screen_capture: true, protection_mode: "full" };
  const responses = {
    get_status: () => state.status,
    get_pending_confirm: () => state.pending,
    resolve_confirm: () => { state.pending = null; return { resolved: true, has_next: false }; },
    // 真机反馈追加:桩以前返回**空**审计列表,于是"主界面无裸术语"那条检查根本没看过时间线
    // ——真跑起来才发现那一行印着 UiTreeDelta(Rust 枚举 Debug 名)和 user=deny(键值对)。
    // 现在按后端真实返回的形状喂两条(event_type 保持 Debug 名,user_decision 保持 wire 值),
    // 让时间线也进入裸术语检查的视野。
    list_audit: () => [
      {
        action: "Block",
        rule_id: "CRIT-001",
        human_message: "Agent is about to confirm a payment",
        source_app: "Safari",
        event_type: "UiTreeDelta",
        user_decision: "deny",
      },
      {
        action: "LogOnly",
        rule_id: "SESSION-START",
        human_message: "Agent session started",
        source_app: "Claude",
        event_type: "AgentSessionStart",
      },
    ],
    security_status: () => ({ auto_approve_allowed: true, auto_approve: false, sqlcipher: false, audit_signing: false, intel_verified: false }),
    get_tcc_status: () => tcc,
    probe_permissions: () => ({ accessibility: tcc.accessibility, screen_capture: tcc.screen_capture }),
    open_privacy_settings: () => null,
    recover_legacy_audit: () => {
      state.status = { ...state.status, audit_ready: true, audit_enabled: true, audit_error: "", audit_bootstrap_state: "ready", audit_legacy_available: false };
      return { history_records: 1 };
    },
    retry_audit_initialization: () => null,
    inject_demo_threat: () => [],
    export_session_report: () => "",
  };
  window.__TAURI__ = {
    core: { invoke: async (cmd, args) => { calls.push({ cmd, args }); const f = responses[cmd]; return f ? f(args) : null; } },
    event: {
      listen: async (event, callback) => {
        listeners.set(event, callback);
        return () => listeners.delete(event);
      },
    },
  };
  window.__agTest = {
    calls,
    setPending: (p) => { state.pending = p; },
    setState: (s) => { state.status = { ...state.status, protection_state: s }; },
    // 「怎么用」那一节要测首次使用(什么都没授权、还没开会话)与守护中两种态,
    // 所以桩要能整片改 status,也要能改 TCC/能力探测的回答。
    patchStatus: (patch) => { state.status = { ...state.status, ...patch }; },
    patchTcc: (patch) => { tcc = { ...tcc, ...patch }; },
    emit: async (event, payload) => {
      const callback = listeners.get(event);
      if (!callback) throw new Error("listener not registered: " + event);
      return await callback({ event, payload });
    },
  };
})();
`;

const PENDING = {
  request_id: 41,
  human_message: "Agent is about to confirm a payment",
  rule_id: "CRIT-001",
  severity: "Critical",
  source_app: "Booking",
  ui_excerpt: "Confirm Payment $299",
  effect: "observed_only",
  external_action_blocked: false,
};

const WINDOWS_EFFECT_COPY = {
  en: "Observed only (effect=observed_only; external_action_blocked=false): the external action has already happened and AgentGuard cannot undo it. “Pause protected follow-ups” affects only future observation in this session.",
  "zh-Hans": "仅事后观察（effect=observed_only；external_action_blocked=false）：外部动作已经发生，AgentGuard 无法撤销。「暂停后续受保护操作」只影响本次会话的后续观察。",
  "zh-Hant": "僅事後觀察（effect=observed_only；external_action_blocked=false）：外部動作已經發生，AgentGuard 無法撤銷。「暫停後續受保護操作」只影響本次工作階段的後續觀察。",
};

const WINDOWS_REQUIRED_REASON_COPY = {
  en: {
    capability: "At least one Windows release-required observation capability (UI Automation, screen capture, or OCR) is unavailable. Protection is incomplete; see Live observation for the exact reason.",
    permission: "Windows denied access required by at least one observation capability. Permission is required; see Live observation for the exact reason.",
  },
  "zh-Hans": {
    capability: "Windows 首发所需的观察能力（UI Automation、屏幕捕获或 OCR）至少有一项不可用。当前守护不完整；具体原因见「实时观察」。",
    permission: "Windows 拒绝了至少一项观察能力所需的访问。当前需要授权；具体原因见「实时观察」。",
  },
  "zh-Hant": {
    capability: "Windows 首發所需的觀察能力（UI Automation、螢幕擷取或 OCR）至少有一項不可用。目前守護不完整；具體原因見「即時觀察」。",
    permission: "Windows 拒絕了至少一項觀察能力所需的存取。現在需要授權；具體原因見「即時觀察」。",
  },
};

for (const shell of ["macos", "windows"]) {
  console.log(`\n== apps/desktop-${shell}`);
  const page = await browser.newPage({ viewport: { width: 1100, height: 760 }, locale: "en-US" });
  // macOS 改版后语言位于设置页；测试按真实导航进入，不强制操作隐藏控件。
  const chooseLocale = async (language) => {
    if (shell !== "macos") return page.selectOption("#locale-select", language);
    const previous = await page.locator("[data-page]:not([hidden])").getAttribute("data-page");
    await page.click('.nav-list [data-route="settings"]');
    await page.click("#tab-general");
    await page.selectOption("#locale-select", language);
    await page.click(`.sidebar [data-route="${previous}"]`);
  };
  await page.addInitScript(TAURI_STUB);
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  currentRoot = join(REPO, "apps", `desktop-${shell}`, "src");
  await page.goto(`${base}/index.html`);
  await page.waitForTimeout(600);
  check("页面脚本初始化无异常(桩足够)", errors.length === 0, errors.join(" | "));

  // 1. 静态语义。
  const sem = await page.evaluate(() => {
    const m = document.getElementById("confirm-modal");
    const lab = m.getAttribute("aria-labelledby");
    const desc = m.getAttribute("aria-describedby");
    return {
      role: m.getAttribute("role"),
      modal: m.getAttribute("aria-modal"),
      labelOk: !!(lab && document.getElementById(lab)),
      descOk: !!(desc && desc.split(/\s+/).every((id) => document.getElementById(id))),
      descHasEffect: (desc || "").split(/\s+/).includes("confirm-effect"),
      timelineRole: document.getElementById("timeline")?.getAttribute("role"),
      timelineLive: document.getElementById("timeline")?.getAttribute("aria-live"),
      timelineLabel: document.getElementById("timeline")?.ariaLabel || document.getElementById("timeline")?.getAttribute("aria-label"),
      announcer: !!document.getElementById("sr-announce"),
      hiddenInitially: m.classList.contains("hidden"),
    };
  });
  check("弹层 role=alertdialog + aria-modal", sem.role === "alertdialog" && sem.modal === "true", JSON.stringify(sem));
  check("aria-labelledby / aria-describedby 指向存在的元素", sem.labelOk && sem.descOk);
  if (shell === "windows") check("Windows 弹层的读屏说明包含产品效果边界", sem.descHasEffect);
  check("时间线是 role=log、aria-live=off、有翻译过的 aria-label", sem.timelineRole === "log" && sem.timelineLive === "off" && !!sem.timelineLabel && !sem.timelineLabel.includes("a11y."), JSON.stringify(sem.timelineLabel));
  check("有读屏播报通道 #sr-announce", sem.announcer);
  check("初始弹层隐藏", sem.hiddenInitially);

  // 2. 把焦点放到一个背景控件上,然后让一条确认到达。
  await page.focus("#btn-refresh");
  const openerBefore = await page.evaluate(() => document.activeElement && document.activeElement.id);
  await page.evaluate((p) => window.__agTest.setPending(p), PENDING);
  // 两个壳子的 refreshStatus() 末尾都会 maybeShowConfirm();「刷新」按钮走的就是它。
  // 焦点此时在刷新按钮上 —— 它就是"打开前的元素",关闭后焦点要回到它。
  await page.click("#btn-refresh");
  await page.waitForTimeout(500);
  const open = await page.evaluate(() => !document.getElementById("confirm-modal").classList.contains("hidden"));
  check("确认到达后弹层打开", open);
  if (open) {
    const opened = await page.evaluate(() => ({
      focus: document.activeElement && document.activeElement.id,
      inert: document.getElementById("app-main").inert === true,
      announce: document.getElementById("sr-announce").textContent,
      title: document.getElementById("confirm-title").innerText,
      deny: document.getElementById("confirm-deny").innerText,
      approve: document.getElementById("confirm-approve").innerText,
      effect: document.getElementById("confirm-effect")?.innerText,
      effectHidden: document.getElementById("confirm-effect")?.hidden,
      effectCode: document.getElementById("confirm-effect")?.dataset.effect,
      externalActionBlocked: document.getElementById("confirm-effect")?.dataset.externalActionBlocked,
    }));
    check("焦点落在安全的暂停按钮(#confirm-deny)", opened.focus === "confirm-deny", JSON.stringify(opened));
    check("<main> 置 inert(背景不可达)", opened.inert);
    check("播报了「有一条确认等你」且不是 key 名", opened.announce.length > 0 && !opened.announce.includes("a11y.") && opened.announce.includes(PENDING.human_message), JSON.stringify(opened.announce));
    check(
      "观察式桌面弹层不谎称已拦截外部动作",
      /detected/i.test(opened.title) && /pause protected follow-ups/i.test(opened.deny) && /continue monitoring/i.test(opened.approve) && !/blocked|allow once/i.test(`${opened.title} ${opened.deny} ${opened.approve}`),
      JSON.stringify(opened),
    );
    if (shell === "windows") {
      check(
        "Windows 产品说明绑定后端 observed_only / 未拦截事实",
        !opened.effectHidden && opened.effectCode === PENDING.effect && opened.externalActionBlocked === "false",
        JSON.stringify(opened),
      );
      for (const [language, expected] of Object.entries(WINDOWS_EFFECT_COPY)) {
        await chooseLocale(language);
        await page.waitForTimeout(250);
        const actual = await page.evaluate(() => document.getElementById("confirm-effect").innerText);
        check(`Windows 产品效果说明 ${language} 固定文案`, actual === expected, JSON.stringify(actual));
      }
      await chooseLocale("en");
      await page.waitForTimeout(250);
    }
    await page.screenshot({ path: join(OUT, `shell-${shell}-confirm.png`) });

    // 3. Tab 循环:3 次 Tab 应在两个按钮间循环,永不到背景。
    const cycle = [];
    for (let i = 0; i < 4; i++) {
      await page.keyboard.press("Tab");
      cycle.push(await page.evaluate(() => document.activeElement && document.activeElement.id));
    }
    check("Tab 只在弹层的两个按钮间循环", cycle.every((id) => id === "confirm-deny" || id === "confirm-approve") && new Set(cycle).size === 2, cycle.join(" → "));
    await page.keyboard.press("Shift+Tab");
    const back = await page.evaluate(() => document.activeElement && document.activeElement.id);
    check("Shift+Tab 反向仍在弹层内", back === "confirm-deny" || back === "confirm-approve", back);
    // 背景按钮点不动(inert)。
    const bgClickable = await page.evaluate(() => {
      const b = document.getElementById("btn-refresh");
      const r = b.getBoundingClientRect();
      const el = document.elementFromPoint(r.left + 2, r.top + 2);
      return el === b;
    });
    check("背景按钮不再是命中目标(inert / 遮罩)", !bgClickable);

    // 4. Esc = 暂停后续受保护操作,回传展示过的 request_id。
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
    const after = await page.evaluate(() => ({
      calls: window.__agTest.calls.filter((c) => c.cmd === "resolve_confirm"),
      hidden: document.getElementById("confirm-modal").classList.contains("hidden"),
      inert: document.getElementById("app-main").inert === true,
      focus: document.activeElement && document.activeElement.id,
      announce: document.getElementById("sr-announce").textContent,
    }));
    check("Esc 触发 resolve_confirm(approve:false, 展示过的 request_id)", after.calls.length === 1 && after.calls[0].args.approve === false && after.calls[0].args.requestId === PENDING.request_id, JSON.stringify(after.calls));
    check("关闭后弹层隐藏、inert 撤掉", after.hidden && !after.inert);
    check("焦点还原到打开前的元素", after.focus === openerBefore, `${openerBefore} → ${after.focus}`);
    check("播报了关闭结果", after.announce.length > 0 && !after.announce.includes("a11y."), JSON.stringify(after.announce));
  }

  // 5. 状态转换播报(首屏不播,转换才播)。
  await page.evaluate(() => { document.getElementById("sr-announce").textContent = ""; window.__agTest.setState("permission_required"); });
  await page.click("#btn-refresh");
  await page.waitForTimeout(400);
  const stateAnn = await page.evaluate(() => document.getElementById("sr-announce").textContent);
  check("状态从 active → permission_required 有播报且是人话", stateAnn.length > 0 && !stateAnn.includes("permission_required") && !stateAnn.includes("a11y."), JSON.stringify(stateAnn));

  // ---------------------------------------------------------------------------
  // 6. 「用户看得懂吗」(真机反馈)。原来主界面只有一个「开始会话」按钮和一行
  //    `AX=false · Capture=false · SCK=idle`,没有任何说明:这是什么、该点什么、
  //    点了会发生什么、怎么知道它真的会拦。下面几条钉住修复后的合同。
  // ---------------------------------------------------------------------------
  // 首次使用的真实处境:两项权限都没授、还没开会话。
  await page.evaluate(() => {
    window.__agTest.patchTcc({ accessibility: false, screen_capture: false, protection_mode: "sim" });
    window.__agTest.patchStatus({
      protection_state: "stopped", session_active: false, accessibility: false, screen_capture: false,
      protection_mode: "sim", uia_native: false, frame_capture: false, ocr: false,
      sck_streaming: false, sck_auto_poll: false, ax_auto_poll: false,
      capabilities: { uia: false, capture: false, ocr: false },
    });
  });
  await page.click("#btn-refresh");
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(OUT, `shell-${shell}-firstrun.png`), fullPage: true });

  const howto = await page.evaluate(() => {
    const card = document.getElementById("howto");
    if (!card) return null;
    const steps = [...card.querySelectorAll(".steps > li")];
    return {
      steps: steps.length,
      // 每一步都得有可见的标题**和**说明,不能是空段落(词条漏了就是空的)。
      headed: steps.every((li) => (li.querySelector("strong")?.innerText || "").trim().length > 0),
      explained: steps.every((li) => [...li.querySelectorAll("p")].some((x) => x.innerText.trim().length > 20)),
      chips: [...card.querySelectorAll(".chip")].map((c) => c.innerText.trim()),
      // 卡片必须在主界面上,不能藏在 <details> 里。
      inDetails: !!card.closest("details"),
      selftest: !!card.querySelector("#btn-selftest") && !card.querySelector("#btn-selftest").closest("details"),
      text: card.innerText,
    };
  });
  check("主界面有「怎么用」三步卡片(不在开发者面板里)", !!howto && howto.steps === 3 && !howto.inDetails, JSON.stringify(howto && { steps: howto.steps, inDetails: howto.inDetails }));
  if (howto) {
    check("三步各有标题与说明(没有漏词条留下的空段落)", howto.headed && howto.explained, JSON.stringify({ headed: howto.headed, explained: howto.explained }));
    check("每步带实时状态徽章,且徽章是人话不是 key 名", howto.chips.length >= 2 && howto.chips.every((c) => c.length > 0 && !c.includes("chip")), JSON.stringify(howto.chips));
    check("「自检」按钮在主界面(不进开发者面板就能看到它工作)", howto.selftest);
    check(
      "使用说明明确桌面观察不能撤销已发生动作、真正阻断只在执行前闸门",
      /cannot undo/i.test(howto.text) && /pre-execution gate/i.test(howto.text) && !/holds a dangerous action before it happens/i.test(howto.text),
      JSON.stringify(howto.text.replace(/\s+/g, " ").slice(0, 320)),
    );
  }

  // 未开始守护时,"在看什么"必须说"什么都没在看" —— 不能空着,更不能说在看。
  const watching = await page.evaluate(() => {
    const el = document.getElementById("watching");
    return el ? el.innerText.trim() : null;
  });
  check("主界面有一行人话说明「现在在看什么」", !!watching && watching.length > 10, JSON.stringify(watching));

  if (shell === "macos") {
    await page.evaluate(() => window.__agTest.patchStatus({
      audit_ready: false, audit_error: "Keychain timeout", audit_bootstrap_state: "failed",
      accessibility: true, screen_capture: true, protection_mode: "full", state_reasons: ["no_session"],
    }));
    await page.click("#btn-refresh");
    await page.waitForFunction(() => document.getElementById("btn-start").disabled);
    const unavailable = await page.evaluate(() => ({
      title: document.getElementById("coverage-title").textContent,
      green: document.getElementById("coverage-banner").classList.contains("full"),
      reasons: document.getElementById("state-why").textContent,
      disabled: document.getElementById("btn-start").disabled,
    }));
    check("钥匙串失败首屏明确守护不可用，不能显示绿色完整保护", unavailable.disabled && !unavailable.green && /encrypted activity log is not ready/.test(unavailable.title), JSON.stringify(unavailable));
    check("钥匙串失败显示可操作说明而非原始异常", /Keychain access has not completed/.test(unavailable.reasons) && !/Press Start|Keychain timeout/.test(unavailable.reasons), JSON.stringify(unavailable));
    await page.screenshot({ path: join(OUT, "shell-macos-keychain-unavailable.png"), fullPage: true });
  }
  if (shell === "macos" || shell === "windows") {
    await page.evaluate(() => window.__agTest.patchStatus({
      audit_ready: false, audit_legacy_available: true, audit_operation_running: false,
      audit_error: "protected audit initialization failed: legacy plaintext audit database detected at /Users/fixture/Library/Application Support/agentguard/audit-macos.db",
    }));
    await chooseLocale("zh-Hans");
    await page.click("#btn-refresh");
    const recovery = await page.evaluate(() => ({
      message: document.getElementById("audit-recovery-message").textContent,
      reason: document.getElementById("state-why").textContent,
      detailsClosed: !document.querySelector("#audit-recovery-panel details").open,
    }));
    check("旧库失败首屏为中文操作说明且隐藏内部路径", /旧版未加密/.test(recovery.message) && !/protected audit|\/Users\//.test(recovery.reason) && recovery.detailsClosed, JSON.stringify(recovery));
    await page.click("#btn-audit-migrate");
    check("迁移确认默认焦点为暂不处理", await page.evaluate(() => document.activeElement.id === "audit-migrate-cancel"));
    await page.keyboard.press("Escape");
    check("取消升级没有调用数据迁移", await page.evaluate(() => !document.getElementById("audit-recovery-dialog").open && !window.__agTest.calls.some((call) => call.cmd === "recover_legacy_audit")));
    await page.screenshot({ path: join(OUT, `shell-${shell}-legacy-recovery.png`), fullPage: true });
    await page.click("#btn-audit-migrate");
    await page.click("#audit-migrate-confirm");
    await page.waitForFunction(() => !document.getElementById("btn-start").disabled);
    check("只有显式确认才调用一次保留历史升级", await page.evaluate(() => {
      const calls = window.__agTest.calls.filter((call) => call.cmd === "recover_legacy_audit");
      return calls.length === 1 && calls[0].args.approved === true && document.getElementById("audit-recovery-panel").hidden;
    }));
    await chooseLocale("en");
    await page.evaluate(() => window.__agTest.patchStatus({ audit_ready: true, audit_error: "", audit_bootstrap_state: "ready" }));
    await page.click("#btn-refresh");
    await page.waitForFunction(() => !document.getElementById("btn-start").disabled);
    check("钥匙串迟到恢复后开始按钮恢复可用", await page.isEnabled("#btn-start"));
  }

  // 上面那条裸术语检查只有在时间线**真的渲染了行**时才有意义(桩返回空列表时它是空转的,
  // 而那正是 `UiTreeDelta` 能一路漏到真机界面上的原因)。这里先钉住"渲染了",再钉"没裸术语"。
  const timeline = await page.evaluate(() => {
    const box = document.getElementById("timeline");
    return { rows: box ? box.children.length : 0, text: box ? box.innerText : "" };
  });
  check("审计时间线渲染了后端返回的行(裸术语检查因此不是空转)", timeline.rows >= 2, JSON.stringify(timeline.rows));
  check("时间线把用户当时的选择说成人话(不是 user=deny)", /you paused protected follow-ups|你暂停了后续受保护操作|你暫停了後續受保護操作/.test(timeline.text), JSON.stringify(timeline.text.replace(/\s+/g, " ").slice(0, 160)));
  check("时间线把策略 Block 显示成风险检测而非既成拦截", /Risk detected|检测到风险|偵測到風險/.test(timeline.text) && !/\bBlocked\b|已拦截|已攔截/.test(timeline.text), JSON.stringify(timeline.text.replace(/\s+/g, " ").slice(0, 160)));

  // 裸术语:主界面(把默认折叠的开发者面板整段排除后)的可见文本里不许出现这些。
  // ScreenCaptureKit / UI Automation 这类**括号补充**是 E16 允许的,禁的是
  // `AX=false`、`SCK=idle`、`Capture=false` 这种键值对和内部状态枚举。
  const raw = await page.evaluate(() => {
    const main = document.getElementById("app-main").cloneNode(true);
    main.querySelectorAll("details").forEach((d) => d.remove());
    return main.innerText;
  });
  const BANNED = [
    /\bAX\s*=/, /\bSCK\s*=/, /\bCapture\s*=/, /\buser\s*=/,
    /\bprotection_state\b/, /\bsession_active\b/, /\bax_auto_poll\b/, /\buia_native\b/,
    // Rust 枚举的 Debug 名。审计库里存的是它们(guard_audit 用 format!("{:?}")),
    // 但那是**记录格式**,不是给用户看的字。时间线要么翻成人话,要么收进开发者面板。
    /\bUiTreeDelta\b/, /\bScreenFrame\b/, /\bFormFill\b/, /\bAgentSessionStart\b/,
  ];
  const hit = BANNED.find((re) => re.test(raw));
  check("主界面可见文本里没有裸的键值对/内部字段名", !hit, hit ? `命中 ${hit}` : "");

  // 守护中(两项都授权、观察器在跑):同一行必须换成"正在看…",否则它就只是句装饰。
  await page.evaluate(() => {
    window.__agTest.patchTcc({ accessibility: true, screen_capture: true, protection_mode: "full" });
    window.__agTest.patchStatus({
      protection_state: "observer_starting", session_active: true, accessibility: true, screen_capture: true,
      protection_mode: "full", uia_native: true, frame_capture: true, ocr: true,
      sck_streaming: true, sck_auto_poll: true, ax_auto_poll: true,
      capabilities: { uia: true, capture: true, ocr: true },
    });
  });
  await page.click("#btn-refresh");
  await page.waitForTimeout(400);

  // W11:Windows 的 start_guard_session 会先返回 observer_starting,首个 native-poll
  // 才证明观察器已经工作。页面必须靠这个事件自行收敛到 active/Watching,不能要求用户
  // 再点一次刷新。这里先把 Starting 真实渲染出来,随后只改后端桩并发事件。
  if (shell === "windows") {
    const beforePoll = await page.evaluate(() => ({
      pill: document.getElementById("status-pill").innerText.trim(),
      watching: document.getElementById("watching").innerText.trim(),
      calls: window.__agTest.calls.length,
    }));
    const startedAt = Date.now();
    await page.evaluate(async () => {
      window.__agTest.patchStatus({ protection_state: "active" });
      await window.__agTest.emit("native-poll", { decisions: [], warnings: [] });
    });
    const elapsedMs = Date.now() - startedAt;
    const afterPoll = await page.evaluate(() => ({
      pill: document.getElementById("status-pill").innerText.trim(),
      watching: document.getElementById("watching").innerText.trim(),
      calls: window.__agTest.calls.slice(-3).map((c) => c.cmd),
    }));
    check(
      "W11 原生轮询后无需手动刷新即可 observer_starting → active",
      /Starting/i.test(beforePoll.pill) && /Protecting/i.test(afterPoll.pill),
      JSON.stringify({ beforePoll, afterPoll }),
    );
    check(
      "W11 原生轮询串行刷新审计和状态",
      JSON.stringify(afterPoll.calls) === JSON.stringify(["list_audit", "get_status", "get_pending_confirm"]),
      JSON.stringify(afterPoll.calls),
    );
    check(
      "W11 自动收敛到 Watching 且满足 ≤10s 合同",
      /Watching/i.test(afterPoll.watching) && elapsedMs <= 10_000,
      JSON.stringify({ elapsedMs, before: beforePoll.watching, after: afterPoll.watching }),
    );

    // W10: a healthy remaining frame observer must not hide a missing Windows
    // release-required surface. Exercise the same native-poll refresh path as the
    // real backend: no Refresh click is allowed between the state changes.
    const w10InitialPill = await page.locator("#status-pill").innerText();
    await page.evaluate(async () => {
      window.__agTest.patchStatus({
        protection_state: "degraded",
        state_reasons: ["required_capability_unavailable"],
        uia_native: false,
        uia_detail: "forced unavailable for acceptance (AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia)",
        frame_capture: true,
        frame_capture_detail: "captured foreground window",
        ocr: true,
        ocr_detail: "OCR engine ready",
        protection_mode: "degraded",
      });
      await window.__agTest.emit("native-poll", { decisions: [], warnings: [] });
    });
    const w10Degraded = await page.evaluate(() => ({
      pill: document.getElementById("status-pill").innerText.trim(),
      reason: document.querySelector("#state-why .state-why-item")?.innerText.trim(),
      capabilities: document.getElementById("observe-status").innerText,
      calls: window.__agTest.calls.slice(-3).map((c) => c.cmd),
    }));
    check(
      "W10 UIA 缺失且 frame 有心跳时自动从 Protecting 降为 Protection incomplete",
      /Protecting/i.test(w10InitialPill) && /Protection incomplete/i.test(w10Degraded.pill),
      JSON.stringify({ w10InitialPill, w10Degraded }),
    );
    check(
      "W10 降级由 native-poll 串行刷新且点名 UIA 的实际原因",
      JSON.stringify(w10Degraded.calls) === JSON.stringify(["list_audit", "get_status", "get_pending_confirm"]) &&
        /UI Automation/.test(w10Degraded.capabilities) && /forced unavailable/.test(w10Degraded.capabilities),
      JSON.stringify(w10Degraded),
    );

    for (const [language, expected] of Object.entries(WINDOWS_REQUIRED_REASON_COPY)) {
      await chooseLocale(language);
      await page.waitForTimeout(250);
      const actual = await page.locator("#state-why .state-why-item").innerText();
      check(`W10 必需能力缺失原因 ${language} 固定文案`, actual.trim() === expected.capability, JSON.stringify(actual));
    }

    // Permission denial is a different state/reason from a missing OCR engine or
    // forced capability. Render it independently so future wording cannot collapse
    // the two diagnoses into a generic red status.
    await page.evaluate(async () => {
      window.__agTest.patchStatus({
        protection_state: "permission_required",
        state_reasons: ["required_observation_permission"],
        uia_detail: "CUIAutomation failed: E_ACCESSDENIED 0x80070005",
      });
      await window.__agTest.emit("native-poll", { decisions: [], warnings: [] });
    });
    for (const [language, expected] of Object.entries(WINDOWS_REQUIRED_REASON_COPY)) {
      await chooseLocale(language);
      await page.waitForTimeout(250);
      const actual = await page.locator("#state-why .state-why-item").innerText();
      check(`W10 权限拒绝原因 ${language} 固定文案`, actual.trim() === expected.permission, JSON.stringify(actual));
    }

    await chooseLocale("en");
    await page.evaluate(async () => {
      window.__agTest.patchStatus({
        protection_state: "active",
        state_reasons: [],
        uia_native: true,
        uia_detail: "UI Automation ready",
        frame_capture: true,
        frame_capture_detail: "captured foreground window",
        ocr: true,
        ocr_detail: "OCR engine ready",
        protection_mode: "partial",
      });
      await window.__agTest.emit("native-poll", { decisions: [], warnings: [] });
    });
    const w10Restored = await page.evaluate(() => ({
      pill: document.getElementById("status-pill").innerText.trim(),
      reasons: document.querySelectorAll("#state-why .state-why-item").length,
      calls: window.__agTest.calls.slice(-3).map((c) => c.cmd),
    }));
    check(
      "W10 必需能力恢复后无需手动刷新即可回到 Protecting",
      /Protecting/i.test(w10Restored.pill) && w10Restored.reasons === 0 &&
        JSON.stringify(w10Restored.calls) === JSON.stringify(["list_audit", "get_status", "get_pending_confirm"]),
      JSON.stringify(w10Restored),
    );
  } else {
    await page.evaluate(() => window.__agTest.patchStatus({ protection_state: "active" }));
    await page.click("#btn-refresh");
    await page.waitForTimeout(400);
  }

  const watching2 = await page.evaluate(() => document.getElementById("watching").innerText.trim());
  const chips2 = await page.evaluate(() => [...document.querySelectorAll("#howto .chip")].map((c) => c.innerText.trim()));
  check("开始守护后「在看什么」这行确实变了(不是一句装饰)", watching2 !== watching && watching2.length > 10, JSON.stringify([watching, watching2]));
  check("徽章跟着状态变(未开始 → 进行中)", JSON.stringify(chips2) !== JSON.stringify(howto ? howto.chips : []), JSON.stringify([howto && howto.chips, chips2]));
  await page.screenshot({ path: join(OUT, `shell-${shell}-protecting.png`), fullPage: true });
  await page.close();
}

await browser.close();
server.close();
console.log(failures === 0 ? "\nshell-a11y: 全部通过" : `\nshell-a11y: ${failures} 条失败`);
process.exit(failures === 0 ? 0 : 1);

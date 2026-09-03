/* 桌面壳子确认弹层的读屏/键盘可达性,真浏览器断言(make shell-a11y;真机报告 P2-4)。
 *
 * 壳子的 index.html + main.js 在 Tauri 的 WebView 里跑,依赖 `window.__TAURI__`。这里用
 * `addInitScript` 在页面脚本之前装一个**桩**:`invoke(cmd)` 按夹具返回,`listen` 记下回调。
 * 桩只喂预置数据,不碰任何真实后端 —— 它证明的是前端那一层的合同:
 *
 *   1. 弹层是 role=alertdialog,aria-labelledby / aria-describedby 指向存在的标题与正文;
 *   2. 弹出时焦点落在「先不要」(安全默认),<main> 置 inert —— 背景控件既不可点也不在 Tab 序列里;
 *   3. Tab / Shift+Tab 只在弹层内循环(报告实测:以前要穿过 11–12 个背景控件);
 *   4. Esc = 先不要:resolve_confirm 收到 approve:false 与**展示过的那条** request_id(P0-5);
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
  const state = {
    pending: null,
    status: {
      protection_state: "active", state_reasons: [], session_active: true, rules_loaded: 12,
      policy_id: "standard", audit_enabled: true, intel_version: "baseline", privacy_composite: 1.0,
      observers_available: true, observers_running: true, heartbeat_age_ms: 900, suppressed_events: 0,
      confirms_timed_out: 0, orphaned_confirms: 0, pending_count: 0, policy: null,
      accessibility: true, screen_capture: true, protection_mode: "full", capabilities: { uia: true, capture: true, ocr: false },
      sck_streaming: false, sck_native_ok: false, sck_auto_poll: false, ax_auto: false, native_polling: false,
    },
  };
  const responses = {
    get_status: () => state.status,
    get_pending_confirm: () => state.pending,
    resolve_confirm: () => { state.pending = null; return { resolved: true, has_next: false }; },
    list_audit: () => [],
    security_status: () => ({ auto_approve_allowed: true, auto_approve: false, sqlcipher: false, audit_signing: false, intel_verified: false }),
    get_tcc_status: () => ({ accessibility: true, screen_capture: true, protection_mode: "full" }),
    probe_permissions: () => ({ accessibility: true, screen_capture: true }),
    export_session_report: () => "",
  };
  window.__TAURI__ = {
    core: { invoke: async (cmd, args) => { calls.push({ cmd, args }); const f = responses[cmd]; return f ? f(args) : null; } },
    event: { listen: async () => () => {} },
  };
  window.__agTest = {
    calls,
    setPending: (p) => { state.pending = p; },
    setState: (s) => { state.status = { ...state.status, protection_state: s }; },
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
};

for (const shell of ["macos", "windows"]) {
  console.log(`\n== apps/desktop-${shell}`);
  const page = await browser.newPage({ viewport: { width: 1100, height: 760 }, locale: "en-US" });
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
      descOk: !!(desc && document.getElementById(desc)),
      timelineRole: document.getElementById("timeline")?.getAttribute("role"),
      timelineLive: document.getElementById("timeline")?.getAttribute("aria-live"),
      timelineLabel: document.getElementById("timeline")?.ariaLabel || document.getElementById("timeline")?.getAttribute("aria-label"),
      announcer: !!document.getElementById("sr-announce"),
      hiddenInitially: m.classList.contains("hidden"),
    };
  });
  check("弹层 role=alertdialog + aria-modal", sem.role === "alertdialog" && sem.modal === "true", JSON.stringify(sem));
  check("aria-labelledby / aria-describedby 指向存在的元素", sem.labelOk && sem.descOk);
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
    }));
    check("焦点落在「先不要」(#confirm-deny)", opened.focus === "confirm-deny", JSON.stringify(opened));
    check("<main> 置 inert(背景不可达)", opened.inert);
    check("播报了「有一条确认等你」且不是 key 名", opened.announce.length > 0 && !opened.announce.includes("a11y.") && opened.announce.includes(PENDING.human_message), JSON.stringify(opened.announce));
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

    // 4. Esc = 先不要,回传展示过的 request_id。
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
  await page.close();
}

await browser.close();
server.close();
console.log(failures === 0 ? "\nshell-a11y: 全部通过" : `\nshell-a11y: ${failures} 条失败`);
process.exit(failures === 0 ? 0 : 1);

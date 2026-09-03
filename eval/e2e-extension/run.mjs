/* Chromium 扩展真浏览器 E2E(make e2e-extension)。
 *
 * # 这是什么、不是什么
 *
 * 把 `apps/extension-chromium` **原样**作为未打包扩展装进真 Chromium(Playwright 持久化上下文,
 * `--load-extension`),对着 `eval/acceptance-fixtures/` 的六个页面跑 Chrome 验收清单
 * (docs/acceptance-chrome.md)F1–F5 的等价用例与 P2-3 的告警风暴回归,每一条都是机器判据:
 *
 *   F1  隐藏注入文本 → background 的 `recent` 出现 invisible_injection,popup「最近」列表有条目;
 *   F2  付款 CTA 点击 → 页面处理器**没有**运行、确认层(role=alertdialog)出现;
 *       「先不要」→ 仍没运行;再点、「允许这一次」→ 运行了;`recent` 里有 prevented/payment_cta;
 *   F3  陷阱语境下的 PII 表单提交 → URL 不变(没提交);允许一次后 URL 带上 ?phone=…;
 *   F4  页面直发 POST /pay/checkout → 本地服务器**一个字节都没收到**就弹了确认;拒绝 → 页面拿到
 *       AbortError、服务器仍没收到;允许 → 服务器收到、页面拿到 HTTP 501;
 *   F5  GET /pay/status、POST /api/search → 不弹、直达服务器(不误拦);
 *   M   变异风暴(真机报告 P2-3):每 50 ms 改 DOM、每秒重渲染同一段隐藏注入、页面有个付款按钮 →
 *       5 秒只多一条(M1)、注入与按钮各只报一次(M2)、后到的另一段注入仍报且只报一次(M3)、
 *       30 段突发全部计数但 ≤4 条(M4,两轮扫描 ≥1.5 s);
 *   P   popup:默认不转发(#native 未勾、link 行是「关」的文案)、今日计数行有数、可见文本无裸术语。
 *
 * 它**不是**真机验收本身:跑在容器里的 Chromium 141,不是用户的 Chrome/Edge;没有 Native Messaging
 * 宿主(nativeEnabled 默认 false,这里不装宿主,F6/F7 仍由真机做);Firefox 的 Playwright 不支持
 * 装扩展,Firefox 真 E2E 仍 BLOCKED(见 docs/acceptance-firefox.md)。它证明的是:
 * 「扩展的内容脚本 + 页面世界钩子 + background + popup 这条链在真浏览器里按文档说的动」——
 * 这是 node 单测(scripts/gate.test.mjs 只钉纯逻辑)钉不住的那一层。
 *
 * 刻意**不**进 release-gate:门禁要在最小容器里可复现。这个需要 playwright + Chromium。
 * CI 里单独跑(见 .github/workflows/ci.yml 的 e2e-extension job)。
 *
 * 判据全部机器化:失败非零退出,`eval/e2e-extension/out/report.json` 记录每条结论,截图落在
 * out/ 给报告贴图。out/ 在 .gitignore。
 */
import { createServer } from "node:http";
import { readFileSync, existsSync, mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const EXT = join(REPO, "apps", "extension-chromium");
const FIXTURES = join(REPO, "eval", "acceptance-fixtures");
const OUT = join(HERE, "out");
mkdirSync(OUT, { recursive: true });

// playwright 解析:本地 node_modules 优先,退回全局(npm root -g)。和 ui-preview 一致。
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

// ---------------------------------------------------------------------------
// 本地服务器:fixtures 从 eval/acceptance-fixtures 取;其余路径(/pay/checkout 等)回 501
// 并**记账**——F4 的核心判据就是"确认层弹出的时候服务器还没收到请求"。
// ---------------------------------------------------------------------------
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".png": "image/png",
};
/** @type {{method:string, path:string, t:number}[]} */
const hits = [];
const server = createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  const path = decodeURIComponent(u.pathname);
  if (path.startsWith("/fixtures/")) {
    const file = join(FIXTURES, path.slice("/fixtures/".length));
    if (!existsSync(file) || !file.startsWith(FIXTURES)) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    res.writeHead(200, { "content-type": MIME[extname(file)] || "text/plain" });
    res.end(readFileSync(file));
    return;
  }
  hits.push({ method: req.method, path, t: Date.now() });
  res.writeHead(501, { "content-type": "text/plain" });
  res.end("acceptance stub: not implemented");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;
const fixture = (name) => `${base}/fixtures/${name}`;
const sawHit = (method, path) => hits.some((h) => h.method === method && h.path === path);

// ---------------------------------------------------------------------------
// 结果记录。每条用例 PASS/FAIL 带细节;最后一行打 marker,报告模板 grep 它。
// ---------------------------------------------------------------------------
const cases = [];
let failures = 0;
function record(id, name, ok, detail) {
  cases.push({ id, name, status: ok ? "PASS" : "FAIL", detail: detail || "" });
  if (ok) console.log(`  PASS ${id} ${name}`);
  else {
    failures += 1;
    console.error(`  FAIL ${id} ${name}${detail ? `\n       ${detail}` : ""}`);
  }
}

async function waitUntil(fn, { timeout = 8000, step = 100, what = "condition" } = {}) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await new Promise((r) => setTimeout(r, step));
  }
  throw new Error(`timeout waiting for ${what}`);
}

// ---------------------------------------------------------------------------
// 启动:持久化上下文 + 未打包扩展。Chromium ≥ 112 的 headless 能装扩展;不能时退回 xvfb 有头。
// ---------------------------------------------------------------------------
const executablePath = existsSync("/opt/pw-browsers/chromium") ? "/opt/pw-browsers/chromium" : undefined;
const headed = process.argv.includes("--headed");
const profile = mkdtempSync(join(tmpdir(), "agentguard-e2e-"));
const context = await chromium.launchPersistentContext(profile, {
  headless: !headed,
  executablePath,
  locale: "en-US",
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--lang=en-US"],
});
let sw = context.serviceWorkers()[0];
if (!sw) {
  try {
    sw = await context.waitForEvent("serviceworker", { timeout: 15000 });
  } catch {
    if (!headed && existsSync("/usr/bin/xvfb-run")) {
      console.error("headless 下扩展的 service worker 没起来;改用 xvfb-run 有头模式重跑。");
      await context.close();
      server.close();
      rmSync(profile, { recursive: true, force: true });
      execSync(`xvfb-run -a node ${JSON.stringify(fileURLToPath(import.meta.url))} --headed`, {
        stdio: "inherit",
      });
      process.exit(0);
    }
    console.error("扩展的 service worker 没起来(15s)。Chromium 是否支持 --load-extension?");
    process.exit(2);
  }
}
const extensionId = new URL(sw.url()).hostname;
// chrome.* 在 worker 刚起来那几十毫秒里可能还没挂满;等到 storage 可用再用。
await waitUntil(() => sw.evaluate(() => !!(globalThis.chrome && chrome.storage && chrome.storage.local)), {
  what: "chrome.storage in service worker",
});
const readRecent = () =>
  sw.evaluate(() => new Promise((res) => chrome.storage.local.get(["recent"], (d) => res(d.recent || []))));
const clearRecent = () => sw.evaluate(() => new Promise((res) => chrome.storage.local.set({ recent: [] }, res)));
const browserVersion = context.browser() ? context.browser().version() : "persistent-context";
console.log(`Chromium ${browserVersion} · extension ${extensionId} · fixtures ${base} · ${headed ? "headed(xvfb)" : "headless"}`);

const DIALOG = '[role="alertdialog"]';
const ALLOW = `${DIALOG} button[data-agentguard-action="allow"]`;
const CANCEL = `${DIALOG} button[data-agentguard-action="cancel"]`;
// 裸术语:确认层/popup 的可见文本里不该出现这些机器 kind(E16 的承诺)。
const RAW_TERMS = /\b(payment_cta|invisible_injection|prompt_injection|privacy_trap|optional_pii|payment_request|out_of_scope_host|no_egress)\b/;

const page = await context.newPage();
try {
  // ---------------- F1 隐藏注入 ----------------
  await page.goto(fixture("injection.html"));
  const recentF1 = await waitUntil(
    async () => {
      const r = await readRecent();
      return r.some((e) => (e.kinds || []).includes("invisible_injection")) ? r : null;
    },
    { what: "invisible_injection in recent" }
  ).catch(() => null);
  record(
    "F1",
    "hidden injection text reaches background recent list as invisible_injection",
    !!recentF1,
    recentF1 ? `recent[0]=${JSON.stringify(recentF1[0])}` : `recent=${JSON.stringify(await readRecent())}`
  );
  if (recentF1) {
    const e = recentF1.find((x) => (x.kinds || []).includes("invisible_injection"));
    // P1-1:落盘的 URL 已最小化(无 query/fragment),标题被截断到有限长度。
    record(
      "F1b",
      "recent entry carries minimized URL and clamped title, not raw page data",
      typeof e.url === "string" && !e.url.includes("?") && !e.url.includes("#") && typeof e.title === "string" && e.title.length <= 80,
      `url=${e.url} title=${e.title}`
    );
  }

  // ---------------- F2 付款 CTA ----------------
  await clearRecent();
  await page.goto(fixture("payment-cta.html"));
  await page.click("#pay");
  await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
  const dialogShown = (await page.locator(DIALOG).count()) === 1;
  const resultAfterClick = await page.locator("#result").innerText();
  record("F2a", "payment CTA click is held: dialog shown, page handler did not run", dialogShown && resultAfterClick === "", `dialog=${dialogShown} result="${resultAfterClick}"`);
  if (dialogShown) {
    await page.screenshot({ path: join(OUT, "f2-payment-dialog.png") });
    const dialogText = await page.locator(DIALOG).innerText();
    record("F2b", "dialog visible text has no raw machine terms", !RAW_TERMS.test(dialogText), dialogText.replace(/\s+/g, " ").slice(0, 200));
    const focused = await page.evaluate(() => document.activeElement && document.activeElement.dataset.agentguardAction);
    record("F2c", "default focus is on 'not now' (cancel), not on allow", focused === "cancel", `activeElement.dataset.agentguardAction=${focused}`);
    await page.click(CANCEL);
    await page.waitForSelector(DIALOG, { state: "detached", timeout: 3000 }).catch(() => null);
    const resultAfterCancel = await page.locator("#result").innerText();
    record("F2d", "'not now' closes the dialog and the payment handler still did not run", (await page.locator(DIALOG).count()) === 0 && resultAfterCancel === "", `result="${resultAfterCancel}"`);
    await page.click("#pay");
    await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 });
    await page.click(ALLOW);
    const resultAfterAllow = await waitUntil(async () => (await page.locator("#result").innerText()) || null, { what: "#result after allow" }).catch(() => "");
    record("F2e", "'allow once' replays the click exactly once and the page handler runs", resultAfterAllow.includes("已确认支付") && (await page.locator(DIALOG).count()) === 0, `result="${resultAfterAllow}"`);
    const recentF2 = await waitUntil(async () => {
      const r = await readRecent();
      return r.filter((e) => e.kind === "prevented" && e.prevented_kind === "payment_cta").length >= 2 ? r : null;
    }, { what: "two prevented/payment_cta entries" }).catch(() => []);
    record("F2f", "each held click is recorded as a prevented/payment_cta entry (two clicks → two entries)", recentF2.filter((e) => e.kind === "prevented" && e.prevented_kind === "payment_cta").length === 2, `prevented=${JSON.stringify(recentF2.filter((e) => e.kind === "prevented"))}`);
  }

  // ---------------- F3 陷阱 + PII 表单 ----------------
  await page.goto(fixture("trap-pii.html"));
  const urlBefore = page.url();
  await page.click("#f button[type=submit]");
  await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
  const f3Dialog = (await page.locator(DIALOG).count()) === 1;
  record("F3a", "PII submit under a trap label is held before navigation", f3Dialog && page.url() === urlBefore && !page.url().includes("phone="), `url=${page.url()}`);
  if (f3Dialog) {
    await page.click(CANCEL);
    await page.waitForTimeout(400);
    record("F3b", "'not now' → still on the same URL, nothing submitted", page.url() === urlBefore, `url=${page.url()}`);
    await page.click("#f button[type=submit]");
    await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 });
    await Promise.all([page.waitForURL(/phone=13800000000/, { timeout: 5000 }).catch(() => null), page.click(ALLOW)]);
    record("F3c", "'allow once' → the form actually submits (URL carries ?phone=…)", page.url().includes("phone=13800000000"), `url=${page.url()}`);
  }

  // ---------------- F4 / F5 页面直发 fetch ----------------
  hits.length = 0;
  await page.goto(fixture("fetch-gate.html"));
  await page.click('button[data-url="/pay/checkout"]');
  await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
  const f4Dialog = (await page.locator(DIALOG).count()) === 1;
  record("F4a", "POST /pay/checkout is held before a single byte reaches the server", f4Dialog && !sawHit("POST", "/pay/checkout"), `dialog=${f4Dialog} hits=${JSON.stringify(hits)}`);
  if (f4Dialog) {
    await page.click(CANCEL);
    const logAfterCancel = await waitUntil(async () => {
      const t = await page.locator("#log").innerText();
      return /AbortError/.test(t) ? t : null;
    }, { what: "AbortError in page log" }).catch(() => "");
    record("F4b", "'not now' → page gets AbortError, server still never saw the request", /AbortError/.test(logAfterCancel) && !sawHit("POST", "/pay/checkout"), `hits=${JSON.stringify(hits)}`);
    await page.click('button[data-url="/pay/checkout"]');
    await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 });
    await page.click(ALLOW);
    const allowed = await waitUntil(() => (sawHit("POST", "/pay/checkout") ? true : null), { what: "server hit after allow" }).catch(() => false);
    const logAfterAllow = await page.locator("#log").innerText();
    record("F4c", "'allow once' → the original fetch goes out and the page sees HTTP 501 from the stub", allowed && /HTTP 501/.test(logAfterAllow), `hits=${JSON.stringify(hits)}`);
  }
  hits.length = 0;
  await page.click('button[data-url="/pay/status"]');
  await waitUntil(() => (sawHit("GET", "/pay/status") ? true : null), { what: "GET /pay/status" }).catch(() => null);
  const f5aDialog = await page.locator(DIALOG).count();
  record("F5a", "GET /pay/status is not gated (read-only shape goes straight through)", sawHit("GET", "/pay/status") && f5aDialog === 0, `hits=${JSON.stringify(hits)} dialog=${f5aDialog}`);
  await page.click('button[data-url="/api/search"]');
  await waitUntil(() => (sawHit("POST", "/api/search") ? true : null), { what: "POST /api/search" }).catch(() => null);
  const f5bDialog = await page.locator(DIALOG).count();
  record("F5b", "POST /api/search is not gated (no payment shape, no scope declared)", sawHit("POST", "/api/search") && f5bDialog === 0, `hits=${JSON.stringify(hits)} dialog=${f5bDialog}`);

  // ---------------- M 变异风暴(P2-3) ----------------
  // 页面每 50 ms 改一次 DOM,正文藏一段隐藏注入。以前:每次变化 400 ms 后整页重扫、不去重,
  // 5 秒 ≈ 10 条同样的告警。判据全部看 background 的 recent(内容脚本每发一条 agentguard_findings
  // 就多一条 entry;entry.count = 这一批 finding 数)。
  // 不清空 recent(popup 用例还要看前面留下的「已拦截」条目);recent 是 unshift 的,新条目在前,
  // 所以"本节新增"就是前 (len - base0) 条。
  const base0 = (await readRecent()).length;
  const newSince = (r) => r.slice(0, Math.max(0, r.length - base0));
  const invisibleEntries = (list) => list.filter((e) => (e.kinds || []).includes("invisible_injection"));
  const sumCount = (list) => list.reduce((a, e) => a + (e.count || 0), 0);
  await page.goto(fixture("mutation-storm.html"));
  const firstStorm = await waitUntil(async () => {
    const r = newSince(await readRecent());
    return invisibleEntries(r).length >= 1 ? r : null;
  }, { what: "initial invisible_injection on storm page" }).catch(() => []);
  await page.waitForTimeout(5000);
  const afterStorm = newSince(await readRecent());
  record(
    "M1",
    "5 s of continuous DOM mutation adds exactly one recent entry (the initial scan), not one per mutation",
    firstStorm.length >= 1 && afterStorm.length === 1,
    `entries after 5 s=${afterStorm.length} ${JSON.stringify(afterStorm.map((e) => ({ kinds: e.kinds, count: e.count })))}`
  );
  // 首次扫描恰好两条 finding:隐藏注入一条、页面上那个 Pay now 按钮一条(payment_cta 是整页扫描,
  // 每轮都会看到它——没有去重它就是每 1.5 s 一条)。注入每秒被重渲染成新节点,同样只能算一次。
  record(
    "M2",
    "hidden injection (re-rendered every second) and the visible Pay-now CTA (seen by every whole-page scan) are each reported exactly once",
    invisibleEntries(afterStorm).length === 1 && sumCount(afterStorm) === 2 && (afterStorm[0].kinds || []).includes("payment_cta"),
    `sum(count)=${sumCount(afterStorm)} kinds=${JSON.stringify(afterStorm.map((e) => e.kinds))}`
  );
  // M3:节流/去重不能变成耳聋——后到的、文本不同的第二段必须再报一次,且只报一次。
  await page.click("#late");
  const afterLate = await waitUntil(async () => {
    const r = newSince(await readRecent());
    return invisibleEntries(r).length >= 2 ? r : null;
  }, { timeout: 5000, what: "second distinct hidden injection reported" }).catch(async () => newSince(await readRecent()));
  await page.waitForTimeout(2000);
  const afterLateSettled = newSince(await readRecent());
  record(
    "M3",
    "a second, distinct hidden injection added mid-storm is still reported — exactly once, within the throttle window",
    invisibleEntries(afterLate).length === 2 && afterLateSettled.length === 2 && afterLateSettled[0].count === 1,
    `entries=${afterLateSettled.length} counts=${JSON.stringify(afterLateSettled.map((e) => e.count))}`
  );
  // M4:30 段互不相同的注入在 3 秒内陆续插入 → 30 段全部计数(不丢),但打包进 ≤4 条(≥1.5 s 一轮),
  // 不是 30 条,也不是每 400 ms 一条(~8 条)。
  const baseline = afterLateSettled.length;
  const baselineCount = sumCount(afterLateSettled);
  await page.click("#burst");
  const afterBurst = await waitUntil(async () => {
    const r = newSince(await readRecent());
    return sumCount(r) >= baselineCount + 30 ? r : null;
  }, { timeout: 10000, what: "all 30 burst injections counted" }).catch(async () => newSince(await readRecent()));
  const burstEntries = afterBurst.length - baseline;
  record(
    "M4",
    "30 distinct injections in 3 s are all counted but batched into at most 4 entries (scan interval ≥ 1.5 s)",
    sumCount(afterBurst) === baselineCount + 30 && burstEntries >= 1 && burstEntries <= 4,
    `sum(count)=${sumCount(afterBurst)} burst entries=${burstEntries} counts=${JSON.stringify(afterBurst.slice(0, burstEntries).map((e) => e.count))}`
  );
  await page.screenshot({ path: join(OUT, "m-mutation-storm.png") });

  // ---------------- P popup ----------------
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#list li", { timeout: 5000 }).catch(() => null);
  await popup.waitForTimeout(300);
  await popup.screenshot({ path: join(OUT, "popup.png") });
  const nativeChecked = await popup.locator("#native").isChecked();
  const linkLine = await popup.locator("#link-line").innerText();
  const en = JSON.parse(readFileSync(join(EXT, "_locales", "en", "messages.json"), "utf8"));
  record("P1", "desktop forwarding is OFF by default and the popup says so", !nativeChecked && linkLine.trim() === en.linkOff.message, `native=${nativeChecked} link="${linkLine}"`);
  const today = await popup.locator("#today-line").innerText();
  record("P2", "today line counts findings and blocks from this run", /\d+/.test(today) && !/Today: 0 found · 0 blocked/.test(today), `"${today}"`);
  const items = await popup.locator("#list li").allInnerTexts();
  record("P3", "recent list shows entries, with the 'Blocked:' prefix on held actions", items.length >= 3 && items.some((t) => t.startsWith(en.blockedPrefix.message)), `items=${JSON.stringify(items.slice(0, 4))}`);
  const visible = await popup.evaluate(() => document.body.innerText);
  record("P4", "popup visible text has no raw machine terms", !RAW_TERMS.test(visible), (visible.match(RAW_TERMS) || [""])[0]);
  await popup.close();
} catch (e) {
  record("HARNESS", "harness did not throw", false, String(e && e.stack ? e.stack : e));
} finally {
  await context.close().catch(() => {});
  server.close();
  rmSync(profile, { recursive: true, force: true });
}

const report = {
  generated_at: new Date().toISOString(),
  chromium: browserVersion,
  mode: headed ? "headed-xvfb" : "headless",
  extension_id: extensionId,
  extension_dir: "apps/extension-chromium",
  fixtures: "eval/acceptance-fixtures",
  native_messaging: "not installed in this run (nativeEnabled=false; F6/F7 are real-device cases)",
  firefox: "BLOCKED — Playwright cannot load extensions into Firefox; see docs/acceptance-firefox.md",
  cases,
  all_pass: failures === 0,
};
writeFileSync(join(OUT, "report.json"), JSON.stringify(report, null, 2) + "\n");
console.log(`\n${cases.length - failures}/${cases.length} passed · report: eval/e2e-extension/out/report.json`);
console.log(`AGENTGUARD_E2E_EXTENSION=${failures === 0 ? "PASS" : "FAIL"}`);
process.exit(failures === 0 ? 0 : 1);

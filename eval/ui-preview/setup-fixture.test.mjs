// 使用真实 Chromium、随包扩展和随包无害页面；不访问支付服务，不修改用户浏览器。
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
const require = createRequire(import.meta.url);
const { chromium } = require(join(execSync("npm root -g", { encoding: "utf8" }).trim(), "playwright"));
const assets = resolve(process.env.AGENTGUARD_SETUP_ASSETS || "apps/desktop-macos/setup-assets");
const output = resolve(process.env.AGENTGUARD_UI_TEST_OUTPUT || "eval/ui-preview/out/setup-fixture");
mkdirSync(output, { recursive: true });
const server = createServer((req, res) => {
  const name = req.url === "/" ? "index.html" : req.url === "/fixture.js" ? "fixture.js" : null;
  if (!name) { res.writeHead(404); res.end(); return; }
  res.setHeader("Content-Type", name.endsWith(".js") ? "text/javascript" : "text/html; charset=utf-8");
  res.end(readFileSync(join(assets, "acceptance", name)));
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const url = `http://127.0.0.1:${server.address().port}`;
let baseline;
let context;
const profile = mkdtempSync(join(tmpdir(), "agentguard-setup-fixture-"));
try {
  baseline = await chromium.launch();
  const normal = await baseline.newPage();
  await normal.goto(url);
  await normal.click("#payment");
  assert.equal(await normal.locator("#payment-count").innerText(), "1");
  console.log("通过：无扩展基线确实执行页面计数。");
  await baseline.close();
  baseline = null;
  const extension = join(assets, "browser-extension");
  context = await chromium.launchPersistentContext(profile, {
    headless: true,
    executablePath: chromium.executablePath(),
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  const worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  const page = await context.newPage();
  await page.goto(url);
  await page.click("#ordinary");
  assert.equal(await page.locator("#ordinary-count").innerText(), "1");
  await page.click("#payment");
  await page.getByRole("alertdialog").waitFor();
  assert.equal(await page.locator("#payment-count").innerText(), "0");
  assert.equal(await page.getByRole("alertdialog").getByRole("button").count(), 1);
  console.log("通过：随包扩展允许普通操作，阻断匹配付款按钮；页面提示没有放行入口。");
  await page.waitForFunction(async () => {
    return !!document.querySelector('[role="alertdialog"]');
  });
  const deadline = Date.now() + 8000;
  let recorded = false;
  while (!recorded && Date.now() < deadline) {
    recorded = await worker.evaluate(async () => {
      const data = await chrome.storage.local.get("recent");
      return JSON.stringify(data.recent || []).includes("payment_cta");
    });
    if (!recorded) await new Promise((done) => setTimeout(done, 100));
  }
  assert.ok(recorded, "扩展自身记录包含本次付款按钮判据");
  await page.screenshot({ path: join(output, "browser-fixture-blocked.png") });
  console.log(`通过：扩展自身记录可核对；真实浏览器版本 ${context.browser()?.version() || "持久化 Chromium"}。`);
  console.log(`临时测试浏览器数据保留于 ${profile}`);
} finally {
  await baseline?.close();
  await context?.close();
  await new Promise((done) => server.close(done));
}

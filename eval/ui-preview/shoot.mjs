/* E16 视觉冒烟(make ui-preview):用无头 Chromium 真渲染确认弹层与 popup,截图 + 行为断言。
 *
 * 为什么存在:仓库的 JS 测试只能钉逻辑(词典覆盖、门判决),钉不住"用户实际看到什么"。
 * 这个 harness 把两块最重要的界面在真浏览器里渲染出来:
 *   - 截图落在 eval/ui-preview/out/(gitignore),改 UI 后跑一遍肉眼对比;
 *   - 顺手做三条行为断言,失败则非零退出:
 *       1. 确认层「先不要」真的挡住页面自己的点击处理器;
 *       2. 确认层「允许这一次」真的重放动作(处理器运行);
 *       3. popup 可见文本里没有裸术语(蛇形枚举 / 规则 ID)——details 折叠时
 *          技术标识必须不可见,这是 E16 的核心承诺,用 innerText(尊重可见性)验。
 *
 * 需要 playwright(容器里预装了 Chromium:/opt/pw-browsers/chromium)。没装 playwright
 * 时给出安装指引退出——刻意**不**进 release-gate:门禁必须在最小容器里可复现,
 * 这个是开发工具,不是发布证据。真机验收(acceptance-runbook.md)才是发布证据。
 *
 * chrome.* 桩写在两个 preview 页面里,只喂预置数据;不碰真实扩展 API。
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

// playwright 解析:本地 node_modules 优先,退回全局(npm root -g)。
async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    try {
      const globalRoot = execSync("npm root -g", { encoding: "utf8" }).trim();
      return createRequire(import.meta.url)(join(globalRoot, "playwright"));
    } catch {
      console.error("需要 playwright:npm install -g playwright(Chromium 已预装于 /opt/pw-browsers)");
      process.exit(1);
    }
  }
}
const { chromium } = await loadPlaywright();

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
};
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  // /apps/... 从仓库根取(扩展源码),其余从 harness 目录取。
  const file = path.startsWith("/apps/") ? join(REPO, path) : join(HERE, path);
  if (!existsSync(file) || !file.startsWith(REPO)) {
    res.writeHead(404);
    res.end("not found");
    return;
  }
  res.writeHead(200, { "content-type": MIME[extname(file)] || "text/plain" });
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const executablePath = existsSync("/opt/pw-browsers/chromium")
  ? "/opt/pw-browsers/chromium"
  : undefined;
const browser = await chromium.launch({ executablePath });

let failures = 0;
const check = (name, cond, extra) => {
  if (cond) console.log(`  ok - ${name}`);
  else {
    failures += 1;
    console.error(`  FAIL - ${name}${extra ? `\n    ${extra}` : ""}`);
  }
};

// 1) 确认弹层:付款拦截(zh)——「先不要」挡住 + 展开「为什么」。
{
  const page = await browser.newPage({ viewport: { width: 900, height: 640 } });
  await page.goto(`${base}/gate-preview.html`);
  await page.click("#pay");
  await page.waitForTimeout(250);
  await page.screenshot({ path: join(OUT, "1-gate-payment-zh.png") });
  await page.click("summary");
  await page.waitForTimeout(150);
  await page.screenshot({ path: join(OUT, "2-gate-payment-zh-why.png") });
  await page.getByRole("button", { name: "先不要", exact: true }).click();
  const result = await page.textContent("#result");
  check("「先不要」挡住页面自己的点击处理器", result === "", `页面处理器运行了:${result}`);
  await page.close();
}

// 2) 确认弹层:「允许这一次」重放动作(处理器运行)。
{
  const page = await browser.newPage({ viewport: { width: 900, height: 640 } });
  await page.goto(`${base}/gate-preview.html`);
  await page.click("#pay");
  await page.waitForTimeout(250);
  await page.getByRole("button", { name: "允许这一次", exact: true }).click();
  await page.waitForTimeout(150);
  const result = await page.textContent("#result");
  check("「允许这一次」重放动作", result.includes("已确认支付"), `处理器没运行:${result}`);
  await page.close();
}

// 3) 确认弹层:越界目的地(中继消息路径,带主机名替换)。
{
  const page = await browser.newPage({ viewport: { width: 900, height: 640 } });
  await page.goto(`${base}/gate-preview.html`);
  await page.evaluate(() => {
    window.postMessage(
      {
        type: "__agentguard_req_gate__",
        id: 1,
        url: "https://tracker.example/x",
        reason: "目的地 tracker.example 不在这个任务声明的允许网站里",
        kind: "out_of_scope_host",
        host: "tracker.example",
      },
      "*"
    );
  });
  await page.waitForTimeout(250);
  const modalText = await page.evaluate(() => document.body.innerText);
  check("越界弹层把主机名替换进正文", modalText.includes("tracker.example"));
  await page.screenshot({ path: join(OUT, "3-gate-scope-zh.png") });
  await page.close();
}

// 4) popup:四个状态截图;有数据态验证"可见文本无裸术语"。
const RAW_TERMS = /INTEL-DOMAIN|SCOPE-HOST|invisible_injection|prompt_injection|payment_cta|privacy_trap|optional_pii|outbound_request/;
for (const [name, qs, assertClean] of [
  ["4-popup-busy-zh", "state=busy&locale=zh_CN", true],
  ["5-popup-empty-zh", "state=empty&locale=zh_CN", false],
  ["6-popup-busy-en", "state=busy&locale=en", true],
]) {
  const page = await browser.newPage({ viewport: { width: 340, height: 560 } });
  await page.goto(`${base}/popup-preview.html?${qs}`);
  await page.waitForTimeout(350);
  await page.screenshot({ path: join(OUT, `${name}.png`), fullPage: true });
  if (assertClean) {
    // innerText 尊重可见性:details 折叠时技术标识必须不可见。
    const visible = await page.evaluate(() => document.body.innerText);
    check(`${name}:可见文本无裸术语`, !RAW_TERMS.test(visible), (visible.match(RAW_TERMS) || [])[0]);
    // 展开「为什么被拦?」后技术标识**应当**可见——详情是给排障留的门,不能哑。
    await page.evaluate(() => document.querySelectorAll("details").forEach((d) => (d.open = true)));
    const expanded = await page.evaluate(() => document.body.innerText);
    check(`${name}:展开详情后技术标识可见`, RAW_TERMS.test(expanded));
  }
  await page.close();
}

// 5) popup:设置面板展开态。
{
  const page = await browser.newPage({ viewport: { width: 340, height: 560 } });
  await page.goto(`${base}/popup-preview.html?state=busy&locale=zh_CN`);
  await page.waitForTimeout(350);
  await page.click("#btn-settings");
  await page.waitForTimeout(150);
  await page.screenshot({ path: join(OUT, "7-popup-settings-zh.png"), fullPage: true });
  await page.close();
}

await browser.close();
server.close();

if (failures > 0) {
  console.error(`\nui-preview:${failures} 条行为断言失败(截图仍在 eval/ui-preview/out/)`);
  process.exit(1);
}
console.log(`\nui-preview:断言全部通过,截图在 eval/ui-preview/out/`);

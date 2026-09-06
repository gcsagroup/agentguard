/* E16 视觉冒烟(make ui-preview):用无头 Chromium 真渲染阻断提示与 popup,截图 + 行为断言。
 *
 * 为什么存在:仓库的 JS 测试只能钉逻辑(词典覆盖、门判决),钉不住"用户实际看到什么"。
 * 这个 harness 把两块最重要的界面在真浏览器里渲染出来:
 *   - 截图落在 eval/ui-preview/out/(gitignore),改 UI 后跑一遍肉眼对比;
 *   - 顺手做三条行为断言,失败则非零退出:
 *       1. 阻断提示只有「关闭」,关闭前后页面自己的点击处理器都不会运行;
 *       2. 页面脚本伪造 allow 按钮也不能取得授权或重放动作;
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
  const explicit = process.env.AGENTGUARD_PLAYWRIGHT_MODULE;
  if (explicit) {
    try {
      return createRequire(import.meta.url)(explicit);
    } catch (e) {
      console.error(`AGENTGUARD_PLAYWRIGHT_MODULE 无法加载:${e && e.message}`);
      process.exit(1);
    }
  }
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
  ".png": "image/png",
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

const executablePath = [
  process.env.AGENTGUARD_CHROMIUM_BIN,
  "/opt/pw-browsers/chromium",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
].find((p) => p && existsSync(p));
const browser = await chromium.launch({ executablePath });

let failures = 0;
const check = (name, cond, extra) => {
  if (cond) console.log(`  ok - ${name}`);
  else {
    failures += 1;
    console.error(`  FAIL - ${name}${extra ? `\n    ${extra}` : ""}`);
  }
};

// 1) 阻断提示:付款拦截(zh)——只有「关闭」+ 展开「为什么」+ 无障碍断言(E17b)。
{
  const page = await browser.newPage({ viewport: { width: 900, height: 640 } });
  await page.goto(`${base}/gate-preview.html`);
  await page.click("#pay");
  await page.waitForTimeout(250);
  // a11y:alertdialog 语义 + 默认焦点在「关闭」。
  const dialog = page.locator('[role="alertdialog"]');
  check("弹层有 alertdialog 语义", (await dialog.count()) === 1);
  check(
    "弹层的可访问名称/描述已填(ARIA 反射)",
    await page.evaluate(() => {
      const d = document.querySelector('[role="alertdialog"]');
      return !!(d.ariaModal === "true" && d.ariaLabel && d.ariaDescription);
    })
  );
  check(
    "打开时焦点落在「关闭」",
    await page.evaluate(
      () => document.activeElement && document.activeElement.dataset.agentguardAction === "close"
    )
  );
  // 焦点圈:按 3 次 Tab 应回到起点,不逃出弹层。
  const cycle = [];
  for (let i = 0; i < 3; i++) {
    await page.keyboard.press("Tab");
    cycle.push(await page.evaluate(() => document.activeElement.textContent.slice(0, 12)));
  }
  check(
    "Tab 焦点圈锁在弹层内并循环",
    cycle.length === 3 && cycle[0].includes("为什么") && cycle[1] === "关闭" && cycle[2].includes("为什么"),
    cycle.join(" → ")
  );
  await page.screenshot({ path: join(OUT, "1-gate-payment-zh.png") });
  await page.click("summary");
  await page.waitForTimeout(150);
  await page.screenshot({ path: join(OUT, "2-gate-payment-zh-why.png") });
  // Esc = 关闭提示,动作仍保持阻断,且焦点还原到打开前的元素(#pay)。
  await page.keyboard.press("Escape");
  await page.waitForTimeout(100);
  const result = await page.textContent("#result");
  check("Esc 关闭提示后动作仍保持阻断", result === "", `页面处理器运行了:${result}`);
  check(
    "关闭后焦点还原到触发元素",
    await page.evaluate(() => document.activeElement && document.activeElement.id === "pay")
  );
  await page.close();
}

// 1b) 阻断提示:深色模式(prefers-color-scheme: dark)。
{
  const page = await browser.newPage({
    viewport: { width: 900, height: 640 },
    colorScheme: "dark",
  });
  await page.goto(`${base}/gate-preview.html`);
  await page.click("#pay");
  await page.waitForTimeout(250);
  const cardBg = await page.evaluate(
    () => getComputedStyle(document.querySelector('[role="alertdialog"]')).backgroundColor
  );
  check("深色模式下弹层卡片不是白底", cardBg !== "rgb(255, 255, 255)", cardBg);
  await page.screenshot({ path: join(OUT, "8-gate-payment-dark.png") });
  await page.close();
}

// 2) 阻断提示:只有 Close；页面脚本即使伪造 allow 按钮也不能授权或重放动作。
{
  const page = await browser.newPage({ viewport: { width: 900, height: 640 } });
  await page.goto(`${base}/gate-preview.html`);
  await page.click("#pay");
  await page.waitForTimeout(250);
  const actions = await page.evaluate(() =>
    [...document.querySelectorAll('[role="alertdialog"] button')].map(
      (button) => button.dataset.agentguardAction || ""
    )
  );
  check("阻断提示原生控件只有 Close", actions.length === 1 && actions[0] === "close", actions.join(","));
  await page.evaluate(() => {
    const fake = document.createElement("button");
    fake.dataset.agentguardAction = "allow";
    fake.textContent = "允许这一次";
    document.querySelector('[role="alertdialog"]').append(fake);
    fake.click();
  });
  await page.waitForTimeout(100);
  check(
    "页面脚本伪造 allow 按钮不能授权或重放",
    (await page.locator('[role="alertdialog"]').count()) === 1 && (await page.textContent("#result")) === ""
  );
  await page.locator('button[data-agentguard-action="close"]').click();
  await page.waitForTimeout(150);
  const result = await page.textContent("#result");
  check(
    "真实用户关闭提示后动作仍不重放",
    (await page.locator('[role="alertdialog"]').count()) === 0 && result === "",
    `页面处理器运行了:${result}`
  );
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

// 4b) 安装引导页(E17a):真页面 + chrome 桩(addInitScript,页面脚本运行前注入);
//     演示按钮弹的是真渲染器,点「关闭」应显示动作仍被拦住的结果行。
{
  const page = await browser.newPage({ viewport: { width: 900, height: 900 } });
  await page.addInitScript(() => {
    window.chrome = {
      storage: {
        local: {
          // 兼容回调式(guard-modal)与 Promise 式(onboarding.js)两种取法。
          get(keys, cb) {
            const data = { localeOverride: "zh_CN" };
            if (typeof cb === "function") {
              cb(data);
              return;
            }
            return Promise.resolve(data);
          },
          set() {
            return Promise.resolve();
          },
        },
        onChanged: { addListener() {} },
      },
      i18n: {
        getUILanguage() {
          return "zh-CN";
        },
      },
      runtime: {
        getURL(p) {
          return "/apps/extension-chromium/" + p;
        },
        sendMessage() {},
      },
    };
  });
  await page.goto(`${base}/apps/extension-chromium/onboarding.html`);
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(OUT, "9-onboarding-zh.png"), fullPage: true });
  await page.click("#demo-pay");
  await page.waitForTimeout(250);
  check("引导页演示弹出真弹层", (await page.locator('[role="alertdialog"]').count()) === 1);
  await page.screenshot({ path: join(OUT, "10-onboarding-demo.png") });
  await page.getByRole("button", { name: "关闭", exact: true }).click();
  await page.waitForTimeout(150);
  const outcome = await page.textContent("#demo-outcome");
  check("演示的「关闭」说明动作仍保持阻断", outcome.includes("仍保持阻断"), outcome);
  await page.close();
}

// 5) popup:设置面板展开态。
{
  const page = await browser.newPage({ viewport: { width: 340, height: 560 } });
  await page.goto(`${base}/popup-preview.html?state=busy&locale=zh_CN`);
  await page.waitForTimeout(350);
  await page.click("#btn-settings");
  await page.waitForTimeout(150);
  const nativeUi = await page.evaluate(() => {
    const panel = document.getElementById("native-settings");
    const visibleText = document.body.innerText;
    return {
      hidden: !!(panel && panel.hidden),
      leaked: /连接桌面端|Native Messaging|Connect the desktop app/i.test(visibleText),
    };
  });
  check(
    "首个 GA 设置态隐藏 Native 控件与文案",
    nativeUi.hidden && !nativeUi.leaked,
    JSON.stringify(nativeUi)
  );
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

import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserTask, loadBrowser } from './runtime.mjs';
import { demoSite } from './demo.mjs';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

test('控制页可修正错误令牌，断连不被旧响应恢复，窄屏接入入口可用', async () => {
  const site = await demoSite();
  const task = new BrowserTask({ origins: [site.origin], agentRequired: true });
  let browser;
  try {
    await task.start({ headless: true });
    task.agentConfiguration = '[mcp_servers.agentguard]\n# 界面验收占位，不是有效凭据';
    browser = await (await loadBrowser()).launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await page.goto(task.controlOrigin);
    await page.locator('#token').fill('错误令牌');
    await page.locator('#connect').click();
    await page.waitForFunction(() => document.querySelector('#status').textContent === '控制连接失效');
    await page.locator('#token').fill(task.token);
    await page.locator('#connect').click();
    await page.waitForFunction(() => document.querySelector('#status').textContent.includes('控制已连接'));
    assert.match(await page.locator('#agent-status').innerText(), /Agent 未连接/);
    await page.locator('#agent-connection summary').click();
    assert.match(await page.locator('#agent-config').inputValue(), /mcp_servers/);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await mkdir(new URL('./out/', import.meta.url), { recursive: true });
    await page.screenshot({ path: fileURLToPath(new URL('./out/control-session-mobile.png', import.meta.url)), fullPage: true });

    let release;
    const delayed = new Promise((resolve) => { release = resolve; });
    let reached;
    const inFlight = new Promise((resolve) => { reached = resolve; });
    await page.route(`${task.controlOrigin}/state`, async (route) => {
      const response = await route.fetch();
      reached(); await delayed; await route.fulfill({ response });
    });
    await inFlight;
    await page.locator('#disconnect').click();
    await page.waitForFunction(() => document.querySelector('#status').textContent.startsWith('已断开'));
    release();
    await page.unrouteAll({ behavior: 'wait' });
    await page.waitForTimeout(200);
    assert.match(await page.locator('#status').innerText(), /^已断开/);
    assert.equal(await page.locator('#login').isVisible(), true);
    assert.equal(await page.locator('#approve').isEnabled(), false);
    assert.equal(task.connected(), false);
  } finally { await browser?.close(); await task.stop(); await site.close(); }
});

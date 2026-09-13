// 真实 Codex + 独立控制页的联合验收。控制页由浏览器自动化操作，不冒充真人验收。
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BrowserTask, loadBrowser } from './runtime.mjs';
import { startAgentBridge } from './agent-bridge.mjs';
import { demoSite } from './demo.mjs';
import { runClient, toolPayload, toolSucceeded } from './client-fixture.mjs';

async function until(fn, timeout = 240000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await new Promise((resolve) => setTimeout(resolve, 100)); }
  throw new Error('联合验收未达到预期状态');
}
const out = new URL('./out/', import.meta.url);
const directory = await mkdtemp(join(tmpdir(), 'agentguard-joint-check-'));
const site = await demoSite();
const task = new BrowserTask({ origins: [site.origin], agentRequired: true });
const results = [];
let bridge, operatorBrowser, passed = false;
try {
  await mkdir(out, { recursive: true });
  await task.start({ headless: true });
  bridge = await startAgentBridge(task);
  operatorBrowser = await (await loadBrowser()).launch({ headless: true });
  const operator = await operatorBrowser.newPage({ viewport: { width: 1200, height: 1000 } });
  await operator.goto(`${task.controlOrigin}/#${task.token}`);
  await until(() => task.connected(), 5000);
  let savedPage;
  for (const approve of [true, false]) {
    const note = approve ? '联合验收批准备注' : '联合验收拒绝备注';
    const client = runClient({ directory, timeoutMs: 240000,
      serverArgs: [fileURLToPath(new URL('./relay.mjs', import.meta.url))],
      serverEnv: { AGENTGUARD_SESSION_URL: bridge.origin, AGENTGUARD_AGENT_TOKEN: bridge.token },
      prompt: `这是本机无害联合验收。只用 agentguard MCP。先读取状态。${savedPage ? `继续使用已有页面 ${savedPage}，不要新建或导航页面。` : `首次导航 ${site.origin}，不传 page。`}读取页面，填写 #note 为“${note}”，点击 #send 恰好一次。独立控制页会${approve ? '批准' : '拒绝'}，请只用 browser_read / browser_status 核对页面最终结果，等待时不得再次点击或重试提交。看到“服务器返回”或“请求被拒绝或网络失败”后结束并如实报告。不要使用任何其他工具。`,
    });
    // 无论客户端还是操作员侧失败，都等待客户端结束并保留可审计结果。
    const operation = (async () => {
      await until(() => task.pending.size === 1);
      const pending = [...task.pending.values()][0];
      assert.equal(JSON.parse(pending.body).note, note);
      assert.equal(site.hits.length, approve ? 0 : 1);
      await until(async () => (await operator.locator('#body').textContent()).includes(note), 5000);
      await operator.screenshot({ path: fileURLToPath(new URL(approve ? 'joint-approve.png' : 'joint-deny.png', out)), fullPage: true });
      if (approve) await operator.locator('#checked').check();
      await operator.locator(approve ? '#approve' : '#deny').click();
    })();
    const [run, answer] = await Promise.allSettled([client, operation]);
    if (run.status === 'fulfilled') results.push({ approve, ...run.value });
    assert.equal(answer.status, 'fulfilled', answer.reason?.message);
    assert.equal(run.status, 'fulfilled', run.reason?.message);
    const result = run.value;
    assert.equal(result.code, 0);
    assert.equal(result.timedOut, false);
    assert.equal(result.calls.filter((call) => call.tool === 'browser_click').length, 1);
    assert.equal(result.calls.every((call) => call.server === 'agentguard' && toolSucceeded(call)), true);
    assert.equal(result.calls.some((call) => call.tool === 'browser_fill' && call.arguments.value === note), true);
    assert.equal(result.calls.some((call) => call.tool === 'browser_read' && toolPayload(call).text?.includes(approve ? '服务器返回' : '请求被拒绝或网络失败')), true);
    await until(() => !task.agentConnected(), 7000);
    assert.equal(task.active, true);
    assert.equal(task.pending.size, 0);
    assert.equal(site.hits.length, 1);
    assert.equal(JSON.parse(site.hits[0].body).note, '联合验收批准备注');
    savedPage ||= [...task.pages.entries()].find(([, page]) => page.url() === `${site.origin}/`)[0];
    assert.equal(task.pages.get(savedPage).isClosed(), false);
    console.log(`${approve ? '批准' : '拒绝'}流程通过；Agent 已断开，页面保留，服务器总提交 1 次。`);
  }
  passed = true;
} finally {
  await operatorBrowser?.close();
  await bridge?.close();
  await task.stop(); await site.close();
  await rm(directory, { recursive: true, force: true });
  await writeFile(new URL('codex-session-report.json', out), JSON.stringify({ generated: new Date().toISOString(), passed, submittedRequests: site.hits.length, results }, null, 2));
  if (!passed) process.exitCode = 1;
}

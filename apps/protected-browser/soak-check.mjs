import { answerFields } from './execution-contract.mjs';
// 持续运行验收只使用本机合成业务，不消耗模型调用。
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { mkdir, writeFile } from 'node:fs/promises';
import { BrowserTask, loadBrowser } from './runtime.mjs';
import { startAgentBridge } from './agent-bridge.mjs';
import { connectAgent } from './relay.mjs';
import { demoSite } from './demo.mjs';

const options = process.argv.slice(2);
let minutes = 30, cycles = 100;
for (let i = 0; i < options.length; i += 2) {
  if (options[i] === '--minutes') minutes = Number(options[i + 1]);
  else if (options[i] === '--cycles') cycles = Number(options[i + 1]);
  else throw new Error('参数仅支持 --minutes 和 --cycles');
}
if (!Number.isFinite(minutes) || minutes < 0.1 || minutes > 120 || !Number.isInteger(cycles) || cycles < 2 || cycles > 1000) {
  throw new Error('持续时间需为 0.1–120 分钟，循环次数需为 2–1000');
}
const stop = new AbortController();
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => stop.abort());
const site = await demoSite();
const task = new BrowserTask({ origins: [site.origin], agentRequired: true });
const results = [];
const started = Date.now();
const out = new URL('./out/soak-report.json', import.meta.url);
let bridge, browser, client, passed = false, failure, approved = 0;
async function until(fn, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await delay(25, undefined, { signal: stop.signal }); }
  throw new Error('持续测试状态超时');
}
async function save(finished = false) {
  await writeFile(out, JSON.stringify({ generated: new Date().toISOString(), finished, passed, failure,
    requestedMinutes: minutes, requestedCycles: cycles, elapsedMs: Date.now() - started,
    approved, submitted: site.hits.filter((hit) => hit.method === 'POST').length, results,
  }, null, 2));
}
try {
  await mkdir(new URL('./out/', import.meta.url), { recursive: true });
  await task.start({ headless: true });
  bridge = await startAgentBridge(task);
  browser = await (await loadBrowser()).launch({ headless: true });
  const operator = await browser.newPage();
  await operator.goto(`${task.controlOrigin}/#${task.token}`);
  await until(() => task.connected());
  let pageId;
  for (let index = 0; index < cycles; index += 1) {
    const waitMs = started + index * minutes * 60000 / cycles - Date.now();
    if (waitMs > 0) await delay(waitMs, undefined, { signal: stop.signal });
    const cycleStarted = performance.now();
    client = await connectAgent({ url: bridge.origin, token: bridge.token });
    const state = await client.act(pageId ? 'browser_status' : 'browser_navigate', pageId ? {} : { url: site.origin });
    if (!pageId) pageId = state.pages.find((page) => page.url === `${site.origin}/`).id;
    else assert.equal(state.pages.some((page) => page.id === pageId), true);
    assert.equal(state.pending.length, 0);
    assert.match((await client.act('browser_read', { page: pageId })).text, /无害任务/);
    const note = `持续验收-${index + 1}`;
    await client.act('browser_fill', { page: pageId, selector: '#note', value: note });
    await client.act('browser_click', { page: pageId, selector: '#send' });
    await until(() => task.pending.size === 1);
    const pending = [...task.pending.values()][0];
    assert.equal(JSON.parse(pending.body).note, note);
    assert.equal(site.hits.filter((hit) => hit.method === 'POST').length, approved);
    let outcome;
    if ((index + 1) % 10 === 0) {
      outcome = '断连取消';
      await client.close(); client = null;
      assert.equal(task.pending.size, 0);
      assert.throws(() => task.answer(pending.id, true, answerFields(pending)));
    } else {
      const approve = index % 2 === 0;
      outcome = approve ? '批准' : '拒绝';
      await until(async () => (await operator.locator('#body').textContent()).includes(note));
      if (approve) await operator.locator('#checked').check();
      await operator.locator(approve ? '#approve' : '#deny').click();
      if (approve) approved += 1;
      await until(async () => {
        const text = (await client.act('browser_read', { page: pageId })).text;
        return text.includes(approve ? '服务器返回' : '请求被拒绝或网络失败');
      });
      await client.close(); client = null;
    }
    assert.equal(task.agentConnected(), false);
    assert.equal(task.active, true);
    assert.equal(task.pages.get(pageId).isClosed(), false);
    assert.equal(task.pending.size, 0);
    assert.equal(site.hits.filter((hit) => hit.method === 'POST').length, approved);
    results.push({ cycle: index + 1, outcome, elapsedMs: Math.round(performance.now() - cycleStarted), passed: true });
    await save();
    console.log(`${index + 1}/${cycles}：${outcome}，累计批准/提交 ${approved}/${site.hits.length}`);
  }
  const remaining = started + minutes * 60000 - Date.now();
  if (remaining > 0) await delay(remaining, undefined, { signal: stop.signal });
  assert.equal(task.active, true);
  assert.equal(task.agentConnected(), false);
  assert.equal(site.hits.filter((hit) => hit.method === 'POST').length, approved);
  passed = true;
} catch (error) { failure = error.message; process.exitCode = 1; }
finally {
  await client?.close(); await browser?.close(); await bridge?.close(); await task.stop(); await site.close();
  await save(true);
}

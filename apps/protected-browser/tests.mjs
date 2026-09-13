import { answerFields } from './execution-contract.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { BrowserTask, loadBrowser } from './runtime.mjs';
import { demoSite } from './demo.mjs';
import { handleMessage } from './mcp.mjs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const out = fileURLToPath(new URL('./out/', import.meta.url));
const results = [];
const report = { runtime: 'playwright 1.56.0', results };
const saveReport = () => writeFile(`${out}/report.json`, JSON.stringify({ ...report, generated: new Date().toISOString() }, null, 2));
async function until(fn, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const result = await fn(); if (result) return result; await new Promise((r) => setTimeout(r, 25)); }
  throw new Error('等待真实状态超时');
}

test('受保护任务：真实浏览器、请求副作用与人工界面', { timeout: 90000 }, async (t) => {
  await mkdir(out, { recursive: true });
  const site = await demoSite();
  const outside = await demoSite();
  const task = new BrowserTask({ origins: [site.origin], timeoutMs: 1800, leaseMs: 1600 });
  let operatorBrowser;
  async function check(name, fn) {
    await t.test(name, async () => {
      try { await fn(); results.push({ name, passed: true }); }
      catch (error) { results.push({ name, passed: false, error: error.message }); throw error; }
    });
  }
  try {
    await task.start({ headless: true });
    const chromium = await loadBrowser();
    operatorBrowser = await chromium.launch({ headless: true });
    let operator = await operatorBrowser.newPage({ viewport: { width: 1200, height: 950 } });
    await operator.goto(`${task.controlOrigin}/#${task.token}`);
    await until(() => task.connected());
    await task.act('browser_navigate', { url: site.origin });
    const page = [...task.pages.values()].find((p) => p.url() === `${site.origin}/`);
    const pageId = [...task.pages.entries()].find(([, p]) => p === page)[0];
    const send = (body, path = '/submit') => page.evaluate(async ({ body, path }) => {
      try { const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status }; }
      catch { return { blocked: true }; }
    }, { body, path });
    const first = () => [...task.pending.values()][0];

    await check('真实扩展加载，正常导航和 MCP 读取完成', async () => {
      assert.equal(task.extension.loaded, true);
      const read = await handleMessage(task, { jsonrpc: '2.0', method: 'tools/call', params: { name: 'browser_read', arguments: { page: pageId } } });
      assert.match(read.content[0].text, /无害任务/);
      assert.equal(site.hits.filter((h) => h.method === 'POST').length, 0);
    });
    await check('扩展的 DOM 阻断仍有效，控制器没有旁路放行', async () => {
      await page.evaluate(() => {
        const button = document.createElement('button'); button.id = 'payment'; button.textContent = 'Confirm Payment';
        button.onclick = () => { document.body.dataset.paymentExecuted = 'yes'; };
        document.body.append(button);
      });
      await page.locator('#payment').click();
      assert.equal(await page.locator('body').getAttribute('data-payment-executed'), null);
      assert.equal(task.pending.size, 0);
      await page.goto(site.origin);
    });
    await check('实际填写点击后暂停，用户拒绝，服务器零提交', async () => {
      await task.act('browser_fill', { page: pageId, selector: '#note', value: '拒绝样例' });
      await task.act('browser_click', { page: pageId, selector: '#send' });
      await until(first);
      assert.equal(site.hits.length, 0);
      await operator.getByRole('button', { name: '拒绝', exact: true }).click();
      await until(() => !task.pending.size);
      assert.equal(site.hits.length, 0);
    });
    await check('批准前不发送；改变输入框不改变捕获正文；批准恰好一次', async () => {
      await task.act('browser_fill', { page: pageId, selector: '#note', value: '批准的原始备注' });
      await task.act('browser_click', { page: pageId, selector: '#send' });
      const pending = await until(first);
      await task.act('browser_fill', { page: pageId, selector: '#note', value: '批准之后不应偷换为这个值' });
      assert.equal(site.hits.length, 0);
      await until(async () => (await operator.locator('#body').textContent()).includes('批准的原始备注'));
      assert.equal(await operator.locator('#approve').isEnabled(), false);
      await operator.getByText('查看绑定与实际请求头', { exact: true }).click();
      assert.match(await operator.locator('#binding').innerText(), /agentguard-protected-browser \/ http_request @ 1/);
      assert.ok((await operator.locator('#binding').innerText()).includes(pending.action_sha256));
      assert.ok((await operator.locator('#binding').innerText()).includes(task.id));
      assert.match(await operator.locator('#headers').innerText(), /content-type/);
      await operator.screenshot({ path: `${out}/control-desktop.png`, fullPage: true });
      await operator.locator('#checked').check();
      await operator.getByRole('button', { name: '批准这一次', exact: true }).click();
      await until(() => site.hits.length === 1);
      assert.equal(JSON.parse(site.hits[0].body).note, '批准的原始备注');
      assert.throws(() => task.answer(pending.id, true, answerFields(pending)));
      assert.equal(site.hits.length, 1);
    });
    await check('相同正文的两次请求各自确认，不继承批准', async () => {
      const start = site.hits.length;
      const one = send({ test: '重复' });
      const p = await until(first);
      task.answer(p.id, true, answerFields(p)); await one;
      const two = send({ test: '重复' });
      const q = await until(first);
      assert.notEqual(p.id, q.id);
      assert.equal(site.hits.length, start + 1);
      task.answer(q.id, false, answerFields(q)); await two;
      assert.equal(site.hits.length, start + 1);
    });
    await check('错误摘要和网页伪造批准均被拒绝', async () => {
      const request = send({ test: '摘要' });
      const p = await until(first);
      assert.throws(() => task.answer(p.id, true, { ...answerFields(p), action_sha256: '错摘要' }));
      const res = await fetch(`${task.controlOrigin}/answer`, { method: 'POST', headers: { Origin: site.origin, Authorization: `Bearer ${task.token}` }, body: JSON.stringify({ id: p.id, ...answerFields(p), approve: true }) });
      assert.equal(res.status, 403);
      assert.equal((await fetch(`${task.controlOrigin}/state`)).status, 401);
      task.answer(p.id, false, answerFields(p)); await request;
    });
    await check('请求超时后不执行', async () => {
      const count = site.hits.length;
      const request = send({ test: '超时' });
      await until(first); await request;
      assert.equal(task.pending.size, 0);
      assert.equal(site.hits.length, count);
    });
    await check('页面导航使旧请求失效', async () => {
      const count = site.hits.length;
      const request = send({ test: '导航失效' });
      await until(first);
      await page.goto(site.origin);
      await request.catch(() => {});
      await until(() => !task.pending.size);
      assert.equal(site.hits.length, count);
    });
    await check('自动重定向不会继承批准或访问目标', async () => {
      const request = send({ test: '重定向' }, '/redirect');
      const p = await until(first); task.answer(p.id, true, answerFields(p));
      await request;
      assert.equal(site.hits.filter((h) => h.url === '/redirect').length, 1);
      assert.equal(site.hits.filter((h) => h.url === '/redirect-target').length, 0);
    });
    await check('授权外导航、iframe 和弹出窗口请求均不触达外部服务器', async () => {
      await assert.rejects(task.act('browser_navigate', { url: outside.origin }));
      await page.evaluate((url) => {
        const frame = document.createElement('iframe'); frame.src = `${url}/frame`; document.body.append(frame);
        window.open(`${url}/popup`);
        fetch(`${url}/outside`).catch(() => {});
      }, outside.origin);
      await until(() => task.events.filter((e) => e.kind === '授权外请求已拒绝').length >= 3);
      assert.equal(outside.hits.length, 0);
    });
    await check('授权内 iframe 的提交也进入相同确认门', async () => {
      await page.evaluate((url) => { const f = document.createElement('iframe'); f.id = 'inside'; f.src = url; document.body.append(f); }, site.origin);
      const frame = await until(() => page.frames().find((f) => f !== page.mainFrame() && f.url() === `${site.origin}/`));
      const count = site.hits.length;
      const request = frame.evaluate(async () => { try { await fetch('/frame-submit', { method: 'POST', body: 'hi' }); } catch {} });
      const p = await until(first); task.answer(p.id, false, answerFields(p)); await request;
      assert.equal(site.hits.length, count);
    });
    await check('文件正文和 WebSocket 不提供未审查出口', async () => {
      const count = site.hits.length;
      await page.evaluate(async () => {
        const data = new FormData(); data.append('file', new Blob(['hello']), 'file.txt');
        try { await fetch('/upload', { method: 'POST', body: data }); } catch {}
        const socket = new WebSocket(location.origin.replace('http:', 'ws:') + '/socket');
        socket.onerror = () => {};
      });
      await until(() => task.events.some((e) => e.kind === '不支持 WebSocket，已拒绝'));
      assert.equal(site.hits.length, count);
      assert.equal(task.pending.size, 0);
    });
    await check('使用原型方法注册 Service Worker 仍被拒绝，脚本和后台提交均未触达服务器', async () => {
      const registered = await page.evaluate(async () => {
        try { await ServiceWorkerContainer.prototype.register.call(navigator.serviceWorker, '/sw.js'); return true; } catch { return false; }
      });
      assert.equal(registered, false);
      await until(() => task.events.some((e) => e.kind === '后台 Worker 请求不受支持，已拒绝'));
      assert.equal(site.hits.filter((h) => h.url === '/sw.js').length, 0);
      assert.equal(site.hits.filter((h) => h.url === '/worker-write').length, 0);
    });
    await check('控制页窄屏可操作且没有横向溢出', async () => {
      await operator.setViewportSize({ width: 390, height: 844 });
      assert.equal(await operator.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await operator.screenshot({ path: `${out}/control-mobile.png`, fullPage: true });
    });
    await check('关闭控制页使待确认请求失效', async () => {
      const count = site.hits.length;
      const request = send({ test: '控制断连' });
      await until(first); await operator.close(); await request;
      assert.equal(task.pending.size, 0);
      assert.equal(site.hits.length, count);
    });
    await check('Agent 状态不泄露批准凭据，没有批准或脚本工具', async () => {
      const state = JSON.stringify(task.state());
      assert.equal(state.includes(task.token), false);
      assert.equal(state.includes(task.controlOrigin), false);
      const call = await handleMessage(task, { jsonrpc: '2.0', method: 'tools/call', params: { name: 'approve', arguments: {} } });
      assert.equal(call.isError, true);
    });
    await check('停止任务拒绝所有未批准请求并关闭浏览器', async () => {
      operator = await operatorBrowser.newPage(); await operator.goto(`${task.controlOrigin}/#${task.token}`);
      await until(() => task.connected());
      const count = site.hits.length;
      const request = send({ test: '停止' });
      await until(first); await task.stopBrowser(); await request.catch(() => {});
      assert.equal(task.active, false); assert.equal(task.pending.size, 0); assert.equal(site.hits.length, count);
    });
  } catch (error) {
    results.push({ name: '浏览器启动或用例准备', passed: false, error: error.message });
    throw error;
  } finally {
    await task.stop(); await operatorBrowser?.close(); await site.close(); await outside.close();
    report.browserVersion = task.browserVersion; report.extensionDigest = task.extensionDigest;
    await saveReport();
  }
});

test('真实 stdio MCP 完成导航填写点击，EOF 拒绝待确认并清理凭据', { timeout: 25000 }, async () => {
  const site = await demoSite();
  const child = spawn(process.execPath, [fileURLToPath(new URL('./cli.mjs', import.meta.url)), '--origin', site.origin, '--headless', '--mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const output = [];
  let logs = '';
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => output.push(JSON.parse(line)));
  child.stderr.on('data', (chunk) => { logs += chunk; });
  const done = new Promise((resolve) => child.once('exit', resolve));
  try {
    for (const [id, method, params] of [[1, 'initialize', {}], [2, 'tools/list', {}], [3, 'tools/call', { name: 'approve', arguments: {} }]]) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    }
    await until(() => output.length === 3, 15000);
    assert.equal(output[0].result.serverInfo.name, 'agentguard-protected-browser');
    assert.equal(output[1].result.tools.length, 5);
    assert.equal(output[2].result.isError, true);
    const credentials = logs.match(/本次控制凭据：([^\n]+)/)[1];
    const { url, token } = JSON.parse(await readFile(credentials, 'utf8'));
    assert.equal((await stat(credentials)).mode & 0o077, 0);
    const state = async () => (await fetch(`${url}/state`, { headers: { Authorization: `Bearer ${token}` } })).json();
    await state();
    async function call(id, name, args) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })}\n`);
      return until(() => output.find((message) => message.id === id));
    }
    const navigation = await call(4, 'browser_navigate', { url: site.origin });
    assert.equal(navigation.result.isError, undefined);
    const page = JSON.parse(navigation.result.content[0].text).pages.find((p) => p.url === `${site.origin}/`).id;
    assert.equal((await call(5, 'browser_fill', { page, selector: '#note', value: 'MCP 断连不得提交' })).result.isError, undefined);
    assert.equal((await call(6, 'browser_click', { page, selector: '#send' })).result.isError, undefined);
    await until(async () => (await state()).pending.length === 1);
    assert.equal(site.hits.length, 0);
    child.stdin.end();
    assert.equal(await done, 0);
    assert.equal(site.hits.length, 0);
    await assert.rejects(readFile(credentials), { code: 'ENOENT' });
    results.push({ name: '真实 MCP 导航填写点击、EOF 拒绝及凭据清理', passed: true });
  } catch (error) {
    results.push({ name: '真实 MCP 导航填写点击、EOF 拒绝及凭据清理', passed: false, error: error.message }); throw error;
  } finally {
    if (child.exitCode === null) child.kill('SIGTERM');
    await site.close(); await saveReport();
  }
});

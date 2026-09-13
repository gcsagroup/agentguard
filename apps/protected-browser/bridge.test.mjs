import { answerFields } from './execution-contract.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { BrowserTask } from './runtime.mjs';
import { startAgentBridge } from './agent-bridge.mjs';
import { connectAgent } from './relay.mjs';
import { demoSite } from './demo.mjs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

async function until(fn, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await new Promise((resolve) => setTimeout(resolve, 25)); }
  throw new Error('连接状态验证超时');
}

test('用户持有会话：权限分离、断连暂停和重连恢复', { timeout: 30000 }, async (t) => {
  const site = await demoSite();
  const task = new BrowserTask({ origins: [site.origin], agentRequired: true });
  const results = [];
  let bridge, client, pageId, page;
  const operator = async () => (await fetch(`${task.controlOrigin}/state`, { headers: { Authorization: `Bearer ${task.token}` } })).json();
  async function check(name, fn) {
    await t.test(name, async () => {
      try { await fn(); results.push({ name, passed: true }); }
      catch (error) { results.push({ name, passed: false, error: error.message }); throw error; }
    });
  }
  try {
    await task.start({ headless: true });
    bridge = await startAgentBridge(task, { leaseMs: 600 });
    await check('没有 Agent 连接时拒绝操作，控制页仍可用', async () => {
      assert.equal((await operator()).agent.connected, false);
      await assert.rejects(task.act('browser_navigate', { url: site.origin }));
      assert.equal(site.hits.length, 0);
    });
    await check('Agent 令牌不能批准，控制令牌也不能伪装 Agent，网页来源拒绝', async () => {
      const call = (url, token, origin) => fetch(url, { method: 'POST', headers: {
        Authorization: `Bearer ${token}`, ...(origin ? { Origin: origin } : {}),
      }, body: '{}' });
      assert.equal((await call(`${task.controlOrigin}/answer`, bridge.token)).status, 401);
      assert.equal((await call(`${bridge.origin}/connect`, task.token)).status, 401);
      assert.equal((await call(`${bridge.origin}/connect`, bridge.token, site.origin)).status, 403);
      assert.equal((await call(`${bridge.origin}/answer`, bridge.token)).status, 404);
    });
    await check('连接独占，状态无控制凭据，正常页面可操作', async () => {
      client = await connectAgent({ url: bridge.origin, token: bridge.token });
      await assert.rejects(connectAgent({ url: bridge.origin, token: bridge.token }));
      const state = await client.act('browser_navigate', { url: site.origin });
      pageId = state.pages.find((p) => p.url === `${site.origin}/`).id;
      page = task.pages.get(pageId);
      assert.equal(state.agent.connected, true);
      assert.equal(JSON.stringify(state).includes(task.token), false);
      assert.equal(JSON.stringify(state).includes(bridge.token), false);
      assert.match((await client.act('browser_read', { page: pageId })).text, /无害任务/);
      // 工具心跳不能使人工控制页保持在线。
      task.lastSeen = 0;
      await new Promise((resolve) => setTimeout(resolve, 800));
      assert.equal(task.connected(), false);
      assert.equal(task.agentConnected(), true);
    });
    await check('Agent 断开立即取消未批准请求，保留浏览器与页面', async () => {
      await operator();
      await client.act('browser_fill', { page: pageId, selector: '#note', value: '断连前请求' });
      await client.act('browser_click', { page: pageId, selector: '#send' });
      await until(() => task.pending.size === 1);
      const old = [...task.pending.values()][0];
      await client.close();
      assert.equal(task.pending.size, 0);
      assert.equal(task.active, true);
      assert.equal(page.isClosed(), false);
      assert.throws(() => task.answer(old.id, true, answerFields(old)));
      assert.equal(site.hits.length, 0);
    });
    await check('暂停时背景 HTTP 请求拒绝，重连保留页面且不重放旧请求', async () => {
      const result = await page.evaluate(async () => {
        try { await fetch('/paused-read'); return '泄漏'; } catch { return '已拒绝'; }
      });
      assert.equal(result, '已拒绝');
      client = await connectAgent({ url: bridge.origin, token: bridge.token });
      const state = await client.act('browser_status');
      assert.equal(state.pages.some((p) => p.id === pageId), true);
      assert.equal(state.pending.length, 0);
      assert.equal(site.hits.length, 0);
      await operator();
      await client.act('browser_fill', { page: pageId, selector: '#note', value: '重连后新请求' });
      await client.act('browser_click', { page: pageId, selector: '#send' });
      await until(() => task.pending.size === 1);
      const next = [...task.pending.values()][0];
      task.answer(next.id, true, answerFields(next));
      await until(() => site.hits.length === 1);
      assert.equal(JSON.parse(site.hits[0].body).note, '重连后新请求');
    });
    await check('心跳丢失后暂停，旧连接编号不能恢复批准', async () => {
      await client.close();
      const response = await fetch(`${bridge.origin}/connect`, { method: 'POST', headers: { Authorization: `Bearer ${bridge.token}` }, body: '{}' });
      const rawClient = await response.json();
      await operator();
      const pending = page.evaluate(async () => {
        try { await fetch('/expired', { method: 'POST', body: '过期测试' }); return '已发送'; } catch { return '已拒绝'; }
      });
      await until(() => task.pending.size === 1);
      await until(() => !task.agentConnected() && task.pending.size === 0);
      assert.equal(await pending, '已拒绝');
      const heartbeat = await fetch(`${bridge.origin}/heartbeat`, { method: 'POST', headers: {
        Authorization: `Bearer ${bridge.token}`, 'X-AgentGuard-Client': rawClient.client,
      }, body: '{}' });
      assert.equal(heartbeat.status, 409);
      assert.equal(site.hits.length, 1);
    });
    await check('真实 MCP 连接进程被强制结束后，会话暂停且页面保留', async () => {
      const relay = spawn(process.execPath, [fileURLToPath(new URL('./relay.mjs', import.meta.url))], {
        env: { ...process.env, AGENTGUARD_SESSION_URL: bridge.origin, AGENTGUARD_AGENT_TOKEN: bridge.token },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const exited = new Promise((resolve) => relay.once('exit', resolve));
      try {
        await until(() => task.agentConnected());
        await operator();
        relay.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'browser_click', arguments: { page: pageId, selector: '#send' } } })}\n`);
        await until(() => task.pending.size === 1);
        relay.kill('SIGKILL'); await exited;
        await until(() => !task.agentConnected() && task.pending.size === 0);
        assert.equal(task.active, true);
        assert.equal(page.isClosed(), false);
        assert.equal(site.hits.length, 1);
      } finally {
        if (relay.exitCode === null && relay.signalCode === null) { relay.kill('SIGTERM'); await exited; }
      }
    });
    await check('会话服务停止后连接失效，操作不会自动重试', async () => {
      let lost = false;
      client = await connectAgent({ url: bridge.origin, token: bridge.token, onLost: () => { lost = true; } });
      await bridge.close(); bridge = null;
      await until(() => lost);
      await assert.rejects(client.act('browser_status'));
      assert.equal(site.hits.length, 1);
    });
  } finally {
    await client?.close();
    await bridge?.close();
    await task.stop(); await site.close();
    await mkdir(new URL('./out/', import.meta.url), { recursive: true });
    await writeFile(new URL('./out/bridge-report.json', import.meta.url), JSON.stringify({ generated: new Date().toISOString(), results }, null, 2));
  }
});

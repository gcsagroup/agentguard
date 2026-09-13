import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { startHostFixture, toolValue, until } from './host-test-support.mjs';

test('真实Chromium统一宿主：审批、业务回执、撤权、重放与未知结果', { timeout: 120000 }, async () => {
  const received = []; let value = '初始值';
  const site = createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    received.push({ url: request.url, method: request.method, body, cookie: request.headers.cookie });
    if (request.url === '/unknown') { request.socket.destroy(); return; }
    if (request.method === 'POST') value = new URLSearchParams(body).get('value');
    response.setHeader('content-type', 'text/html; charset=utf-8');
    response.setHeader('set-cookie', ['one=1; Path=/; HttpOnly', 'two=2; Path=/; SameSite=Lax']);
    response.end(`<h1 id="value">${value}</h1><form action="/save" method="post"><label>合成内容<input name="value" id="input" value="SYNTHETIC_EXISTING_INPUT"></label><input type="password" value="SYNTHETIC_PASSWORD"><input type="hidden" value="SYNTHETIC_HIDDEN"><button id="save">保存</button></form><form action="/unknown" method="post"><button id="unknown">未知结果</button></form>`);
  });
  await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${site.address().port}`; let host;
  try {
    host = await startHostFixture([origin]);
    const tools = (await host.rpc('tools/list')).result.tools;
    assert.equal(tools.filter(tool => tool.name.startsWith('browser_')).length, 5);
    const executor = JSON.parse(await readFile(host.executorFile, 'utf8'));
    const forbidden = await fetch(`${executor.url}/approve`, { method: 'POST', headers: { authorization: `Bearer ${executor.token}` }, body: '{}' });
    assert.ok([403, 404].includes(forbidden.status), '执行连接不能批准');
    let navigate = host.call('browser_navigate', { url: `${origin}/` });
    let pending = await host.pending(); assert.equal(pending.binding.action.session_id, (await host.operator('/workspace/status')).body.session_id);
    assert.equal((await host.decide(pending, false)).status, 200); assert.equal((await navigate).result.isError, true); assert.equal(received.length, 0);
    navigate = host.call('browser_navigate', { url: `${origin}/` }); pending = await host.pending();
    assert.equal((await host.decide(pending)).status, 200); const state = toolValue(await navigate);
    const page = state.pages.find(page => page.url === `${origin}/`).id;
    assert.equal(received.length, 1);
    for (const [name, args] of [
      ['browser_read', { page: `${origin}/` }],
      ['browser_fill', { page: `${origin}/`, selector: '#input', value: '错误页面不得填写' }],
      ['browser_click', { page: `${origin}/`, selector: '#save' }],
      ['browser_navigate', { page: `${origin}/`, url: `${origin}/` }],
    ]) {
      const failed = await host.call(name, args);
      assert.equal(failed.result.isError, true);
      assert.equal(failed.result._meta.agentguard.outcome, 'failed');
      assert.match(failed.result.content[0].text, /browser_status.*pages.*id/);
      assert.equal((await host.operator('/pending')).body, null);
      assert.equal(received.length, 1, '页面 ID 填错不能新增请求');
    }
    const recoveredPage = toolValue(await host.call('browser_status')).pages.find(item => item.url === `${origin}/`).id;
    assert.equal(recoveredPage, page);
    const readReceipt = await host.call('browser_read', { page: recoveredPage });
    assert.equal(readReceipt.result.isError, false);
    assert.equal(readReceipt.result._meta.agentguard.scope, 'browser_dom');
    assert.equal(readReceipt.result._meta.agentguard.outcome, 'success');
    assert.equal(readReceipt.result._meta.agentguard.business_success_asserted, false);
    const observed = toolValue(readReceipt);
    assert.equal(observed.page, page);
    assert.equal(/SYNTHETIC_(EXISTING_INPUT|PASSWORD|HIDDEN)/.test(JSON.stringify(observed)), false);
    const input = observed.controls.find(item => item.label === '合成内容');
    const save = observed.controls.find(item => item.label === '保存');
    assert.ok(input && save);
    await host.call('browser_fill', { page, selector: input.selector, value: '已批准的合成内容' });
    const click = host.call('browser_click', { page, selector: save.selector }); pending = await host.pending();
    assert.equal(received.length, 1); assert.ok(pending.binding.action.parameters.body.includes(encodeURIComponent('已批准的合成内容')));
    assert.equal((await host.decide(pending)).status, 200); toolValue(await click);
    await until(() => value === '已批准的合成内容');
    assert.match(received.find(r => r.method === 'POST').cookie, /one=1/);
    assert.match(received.find(r => r.method === 'POST').cookie, /two=2/);
    await until(async () => { const text = toolValue(await host.call('browser_read', { page })); return JSON.stringify(text).includes('已批准的合成内容'); });
    assert.equal((await host.decide(pending)).status, 409, '批准不能重放'); assert.equal(received.filter(r => r.method === 'POST').length, 1);
    await host.call('browser_fill', { page, selector: '#input', value: '暂停不得发送' });
    const cancelledClick = host.call('browser_click', { page, selector: '#save' }); const old = await host.pending();
    const before = received.length; assert.equal((await host.operator('/workspace/pause', {})).status, 200);
    await cancelledClick; assert.equal((await host.decide(old)).status, 409); assert.equal(received.length, before);
    assert.equal((await host.operator('/workspace/resume', {})).status, 200); const newId = await host.refreshSession(); assert.notEqual(newId, old.binding.action.session_id);
    navigate = host.call('browser_navigate', { url: `${origin}/`, page }); pending = await host.pending(); assert.equal(pending.binding.action.session_id, newId); await host.decide(pending); toolValue(await navigate);
    const unknown = host.call('browser_click', { page, selector: '#unknown' }); pending = await host.pending(); await host.decide(pending); await unknown;
    await until(async () => (await host.operator('/workspace/status')).body.session_state === 'failed');
    assert.equal((await host.operator('/workspace/resume', {})).status, 409, '未知结果不能恢复后自动重试');
    const status = (await host.operator('/workspace/status')).body;
    assert.equal(status.browser.audit.persistent, true);
    assert.equal(status.browser.receipts.at(-1).outcome, 'unknown');
    assert.equal(received.filter(r => r.url === '/unknown').length, 1);
  } finally { await host?.close(); await new Promise(resolve => site.close(resolve)); }
});

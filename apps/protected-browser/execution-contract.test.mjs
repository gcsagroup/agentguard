import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { canonicalBytes, actionSha256, bindRequest, answerFields } from './execution-contract.mjs';
import { BrowserTask } from './runtime.mjs';
import { createServer } from 'node:http';

const fixture = JSON.parse(await readFile(new URL('./fixtures/action-contract-v1.json', import.meta.url), 'utf8'));

test('共享动作样例的完整字节与 SHA-256 一致；拒绝跨语言歧义值', () => {
  assert.equal(canonicalBytes(fixture.action).toString('utf8'), fixture.expected_canonical_utf8);
  assert.equal(actionSha256(fixture.action), fixture.expected_sha256);
  for (const value of [NaN, Infinity, 0.5, -0, Number.MAX_SAFE_INTEGER + 1, '\ud800', undefined]) {
    assert.throws(() => canonicalBytes({ value }));
  }
  for (const [key, value] of [['target', 'https://example.test/other'], ['session_id', 'other-session'],
    ['request_id', 'other-request'], ['action_id', 'other-action'], ['policy_version', 'other-policy'],
    ['expires_at_ms', fixture.action.expires_at_ms - 1], ['nonce', '03'.repeat(32)]]) {
    assert.notEqual(actionSha256({ ...fixture.action, [key]: value }), fixture.expected_sha256);
  }
  assert.notEqual(actionSha256({ ...fixture.action, tool: { ...fixture.action.tool, version: '2' } }), fixture.expected_sha256);
  assert.notEqual(actionSha256({ ...fixture.action, parameters: { ...fixture.action.parameters, body: '被替换正文' } }), fixture.expected_sha256);
});

test('宿主构造的动作和批准不可变，拒绝畸形标识', () => {
  const args = { sessionId: 'session', requestId: 'request', url: 'https://example.test/submit', method: 'POST',
    headers: { cookie: '' }, body: '原始正文', policyVersion: 'policy-v1', issuedAt: 1, expiresAt: 100 };
  const one = bindRequest(args), two = bindRequest(args);
  assert.notEqual(one.binding.nonce, two.binding.nonce);
  assert.notEqual(one.binding.action.nonce, two.binding.action.nonce);
  assert.throws(() => { one.binding.action.target = 'https://example.test/other'; });
  assert.throws(() => { one.binding.action.parameters.body = '替换正文'; });
  assert.throws(() => { one.binding.action.parameters.headers.cookie = '替换会话'; });
  for (const sessionId of ['', ' 空格', '换\n行', '字'.repeat(86)]) assert.throws(() => bindRequest({ ...args, sessionId }));
});

async function pausedRoute() {
  const task = new BrowserTask({ origins: ['https://example.test'], extension: false });
  task.active = true; task.lastSeen = Date.now();
  const page = { isClosed: () => false };
  task.epochs.set(page, 0);
  const sent = [], aborted = [];
  let headerReads = 0;
  task.transport = { fetch: async (url, options) => {
    sent.push({ url, options }); return { status: () => 200, dispose: async () => {} };
  } };
  const route = {
    request: () => ({ url: () => 'https://example.test/submit', method: () => 'POST', serviceWorker: () => null,
      frame: () => ({ page: () => page }), postDataBuffer: () => Buffer.from('完整正文'),
      allHeaders: async () => { headerReads += 1; return { 'content-type': 'text/plain', cookie: `captured-${headerReads}` }; },
    }), abort: async (reason) => { aborted.push(reason); }, fulfill: async () => {},
  };
  const done = task.route(route);
  await new Promise((resolve) => setImmediate(resolve));
  const pending = [...task.pending.values()][0];
  assert.ok(pending);
  return { task, pending, done, sent, aborted, headerReads: () => headerReads };
}

test('旧回答、错误随机值、修改目标正文不能批准；相同已捕获请求头单次发送', async () => {
  const { task, pending: p, done, sent, headerReads } = await pausedRoute();
  const agentState = JSON.stringify(task.state());
  for (const secret of [p.action_sha256, p.binding.nonce, p.binding.action.nonce, 'captured-1', '完整正文']) {
    assert.equal(agentState.includes(secret), false);
  }
  assert.throws(() => task.answer(p.id, true, p.action_sha256));
  assert.throws(() => task.answer(p.id, false));
  assert.throws(() => task.answer(p.id, true, { ...answerFields(p), approval_nonce: '00'.repeat(32) }));
  for (const altered of [{ ...p.binding.action, target: 'https://example.test/other' },
    { ...p.binding.action, parameters: { ...p.binding.action.parameters, body: '被替换正文' } }]) {
    assert.throws(() => task.answer(p.id, true, { ...answerFields(p), action_sha256: actionSha256(altered) }));
  }
  assert.equal(sent.length, 0);
  task.answer(p.id, true, answerFields(p));
  assert.throws(() => task.answer(p.id, true, answerFields(p)));
  await done;
  assert.equal(sent.length, 1);
  assert.equal(headerReads(), 1);
  assert.deepEqual(sent[0].options.headers, p.binding.action.parameters.headers);
  assert.equal(sent[0].options.headers.cookie, 'captured-1');
  assert.equal(sent[0].options.data.toString('utf8'), p.binding.action.parameters.body);
  assert.equal(sent[0].url, p.binding.action.target);
});

test('会话与策略变化使旧批准无效；批准后断连仍零发送', async () => {
  for (const change of ['session', 'policy', 'disconnect']) {
    const { task, pending: p, done, sent, aborted } = await pausedRoute();
    if (change === 'disconnect') { task.answer(p.id, true, answerFields(p)); task.lastSeen = 0; }
    else {
      if (change === 'session') task.id = 'changed-session';
      else task.origins.add('https://new-scope.test');
      assert.throws(() => task.answer(p.id, true, answerFields(p)));
      task.cancelAll('验收取消');
    }
    await done;
    assert.equal(sent.length, 0);
    assert.equal(aborted.length, 1);
  }
});

test('真实 Chromium 和 HTTP 控制面：旧协议与替换摘要零提交，绑定 Cookie 与原始正文恰好发送一次', { timeout: 20000 }, async () => {
  const hits = [];
  const server = createServer(async (req, res) => {
    if (req.method === 'GET') { res.end('<!doctype html><title>无害契约验收</title><p>仅本机测试</p>'); return; }
    let body = ''; for await (const chunk of req) body += chunk;
    hits.push({ url: req.url, cookie: req.headers.cookie, body }); res.end('收到测试请求');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const task = new BrowserTask({ origins: [origin], extension: false, timeoutMs: 6000 });
  try {
    await task.start({ headless: true });
    const api = async (path, data) => fetch(`${task.controlOrigin}${path}`, {
      method: data ? 'POST' : 'GET', headers: { Authorization: `Bearer ${task.token}` },
      ...(data ? { body: JSON.stringify(data) } : {}),
    });
    await api('/state');
    await task.context.addCookies([{ name: 'contract-test', value: 'captured-before-approval', url: origin }]);
    await task.act('browser_navigate', { url: origin });
    const page = [...task.pages.values()].find((item) => item.url() === `${origin}/`);
    const finished = page.evaluate(async () => {
      try { return (await fetch('/submit', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '只批准原始正文🙂' })).status; }
      catch { return 0; }
    });
    let p;
    for (let tries = 0; tries < 100 && !p; tries += 1) {
      p = (await (await api('/state')).json()).pending[0];
      if (!p) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.ok(p);
    assert.equal(p.binding.action.parameters.headers.cookie, 'contract-test=captured-before-approval');
    await task.context.addCookies([{ name: 'contract-test', value: 'changed-after-capture', url: origin }]);
    assert.equal((await api('/answer', { id: p.id, approve: true, digest: p.action_sha256 })).status, 409);
    assert.equal((await api('/answer', { id: p.id, approve: true, ...answerFields(p), approval_nonce: '00'.repeat(32) })).status, 409);
    for (const action of [{ ...p.binding.action, target: `${origin}/changed-target` },
      { ...p.binding.action, parameters: { ...p.binding.action.parameters, body: '替换正文' } }]) {
      assert.equal((await api('/answer', { id: p.id, approve: true, ...answerFields(p), action_sha256: actionSha256(action) })).status, 409);
    }
    assert.equal(hits.length, 0);
    const valid = { id: p.id, approve: true, ...answerFields(p) };
    assert.equal((await api('/answer', valid)).status, 200);
    assert.equal(await finished, 200);
    assert.equal((await api('/answer', valid)).status, 409);
    assert.deepEqual(hits, [{ url: '/submit', cookie: 'contract-test=captured-before-approval', body: '只批准原始正文🙂' }]);
  } finally { await task.stop(); server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
});

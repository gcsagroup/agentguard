import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserTask, loadBrowser } from './runtime.mjs';
import { bindRequest, answerFields } from './execution-contract.mjs';

test('确认页显示完整绑定与纯文本，内容变化清除勾选，旧无绑定项不能批准', async () => {
  // 本项是浏览器渲染用例；真实网络副作用由 execution-contract.test.mjs 独立验证。
  const task = new BrowserTask({ origins: ['https://example.test'] });
  let browser;
  try {
    await task.startControl();
    const now = Date.now();
    const bound = bindRequest({ sessionId: task.id, requestId: 'ui-fixture', url: 'https://example.test/submit', method: 'POST',
      headers: { 'content-type': 'text/plain', cookie: '' }, body: '<b>完整的无害正文</b>', policyVersion: 'ui-policy-v1', issuedAt: now, expiresAt: now + 60000 });
    const original = { id: 'ui-fixture', method: 'POST', origin: 'https://example.test', url: bound.binding.action.target,
      body: bound.binding.action.parameters.body, bytes: Buffer.byteLength(bound.binding.action.parameters.body), deadline: now + 60000, ...bound };
    let pending = structuredClone(original);
    let answered;
    browser = await (await loadBrowser()).launch({ headless: true });
    const page = await browser.newPage();
    await page.route(`${task.controlOrigin}/state`, (route) => route.fulfill({ json: {
      task: task.id, session_id: task.id, active: true, agent: { required: false }, origins: ['https://example.test'],
      pending: pending ? [pending] : [], events: [],
    } }));
    await page.route(`${task.controlOrigin}/answer`, async (route) => {
      answered = route.request().postDataJSON(); pending = null; await route.fulfill({ json: { answered: true } });
    });
    await page.goto(`${task.controlOrigin}/#synthetic-ui-token`);
    await page.locator('#body').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#approve').isEnabled(), false);
    assert.equal(await page.locator('#body b').count(), 0);
    assert.equal(await page.locator('#body').innerText(), original.body);
    await page.getByText('查看绑定与实际请求头', { exact: true }).click();
    assert.ok((await page.locator('#binding').innerText()).includes(bound.action_sha256));
    assert.equal((await page.locator('body').innerText()).includes(bound.binding.nonce), false);
    await page.locator('#checked').check();
    assert.equal(await page.locator('#approve').isEnabled(), true);
    // 即使坏响应保留同一编号与摘要，展示正文改变也必须重新核对。
    pending.body = '已改变的展示正文'; pending.binding.action.parameters.body = pending.body;
    await page.waitForFunction(() => document.querySelector('#body').textContent === '已改变的展示正文');
    assert.equal(await page.locator('#checked').isChecked(), false);
    assert.equal(await page.locator('#approve').isEnabled(), false);
    delete pending.binding;
    await page.waitForFunction(() => document.querySelector('#binding').textContent.includes('缺少完整动作绑定'));
    await page.locator('#checked').check();
    assert.equal(await page.locator('#approve').isEnabled(), false);
    pending = structuredClone(original);
    await page.waitForFunction(() => document.querySelector('#body').textContent.includes('完整的无害正文'));
    await page.locator('#checked').check();
    await page.locator('#approve').click();
    await page.waitForFunction(() => document.querySelector('#request').hidden);
    assert.deepEqual(answered, { id: original.id, ...answerFields(original), approve: true });
  } finally { await browser?.close(); await task.stop(); }
});

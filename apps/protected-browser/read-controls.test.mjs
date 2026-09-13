import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { BrowserTask, loadBrowser } from './runtime.mjs';

test('真实 DOM 控件描述：可直接定位、无输入值、隐藏控件排除及数量字节上限', async () => {
  const chromium = await loadBrowser();
  const browser = await chromium.launch({ headless: true });
  const site = createServer((_request, response) => { response.setHeader('Content-Type', 'text/html'); response.end('<body></body>'); });
  await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${site.address().port}`;
  try {
    const page = await browser.newPage();
    await page.goto(origin);
    const scope = { active: true, agentConnected: () => true, pages: new Map([['page-1', page]]), origins: new Set([origin]) };
    // 使用生产工具分支操作真实 DOM；本例只验读取输出，不代替宿主网络隔离验收。
    const call = (name, args = {}) => BrowserTask.prototype.act.call(scope, name, { page: 'page-1', ...args });
    await page.setContent(`<label>编号<input value="SYNTHETIC_VALUE"></label><button id="重复">保存</button><button id="重复">取消</button><input type="password" value="SYNTHETIC_PASSWORD"><input type="hidden" value="SYNTHETIC_HIDDEN"><input type="file"><button style="display:none">隐藏按钮</button><button disabled>禁用按钮</button>`);
    const before = await page.locator('input').first().inputValue();
    const result = await call('browser_read');
    assert.equal(result.controls.length, 4);
    assert.equal(result.controls_truncated, false);
    assert.equal(JSON.stringify(result).includes('SYNTHETIC_'), false);
    assert.equal(await page.locator('input').first().inputValue(), before, '读取不改变输入');
    const input = result.controls.find(item => item.label === '编号');
    const save = result.controls.find(item => item.label === '保存');
    assert.equal(result.controls.find(item => item.label === '禁用按钮').disabled, true);
    for (const item of result.controls) assert.equal(await page.locator(item.selector).count(), 1);
    await call('browser_fill', { selector: input.selector, value: 'NEW_SYNTHETIC_VALUE' });
    assert.equal(await page.locator('input').first().inputValue(), 'NEW_SYNTHETIC_VALUE');
    await call('browser_click', { selector: save.selector });
    await page.setContent(Array.from({ length: 80 }, (_, i) => `<button id="按钮-${i}" aria-label="${'合成'.repeat(100)}">按钮</button>`).join(''));
    const bounded = await call('browser_read');
    assert.ok(bounded.controls.length > 0 && bounded.controls.length <= 32);
    assert.equal(bounded.controls_truncated, true);
    assert.ok(Buffer.byteLength(JSON.stringify(bounded.controls)) <= 8192);
    assert.ok(Buffer.byteLength(JSON.stringify(bounded)) < 65536);
  } finally { await browser.close(); await new Promise(resolve => site.close(resolve)); }
});

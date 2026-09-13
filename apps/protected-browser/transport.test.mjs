import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { BrowserTask } from './runtime.mjs';

test('独立转发保留浏览器 Cookie，删除后不复用；取消拦截仍不能直连', async () => {
  const hits = [];
  const server = createServer((req, res) => {
    hits.push({ url: req.url, cookie: req.headers.cookie || '' });
    if (req.url === '/set') res.setHeader('Set-Cookie', ['session=local-only; HttpOnly; SameSite=Strict; Path=/', 'other=test; Path=/']);
    res.setHeader('Content-Type', 'text/html');
    res.end('<p>本地 Cookie 验收</p>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const task = new BrowserTask({ origins: [origin], extension: false });
  try {
    await task.start({ headless: true });
    await task.act('browser_navigate', { url: `${origin}/set` });
    const cookies = await task.context.cookies();
    assert.equal(cookies.find((c) => c.name === 'session')?.httpOnly, true);
    assert.equal(cookies.find((c) => c.name === 'other')?.value, 'test');
    await task.act('browser_navigate', { url: `${origin}/echo` });
    assert.match(hits.find((h) => h.url === '/echo').cookie, /session=local-only/);
    await task.context.clearCookies();
    await task.act('browser_navigate', { url: `${origin}/cleared` });
    assert.equal(hits.find((h) => h.url === '/cleared').cookie, '');
    await task.context.unrouteAll({ behavior: 'wait' });
    const page = await task.context.newPage();
    await page.goto(`${origin}/direct`).catch(() => {});
    assert.equal(hits.some((h) => h.url === '/direct'), false);
  } finally {
    await task.stop();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

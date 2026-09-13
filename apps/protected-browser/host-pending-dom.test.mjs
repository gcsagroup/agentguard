import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { startHostFixture, toolValue, until } from './host-test-support.mjs';

test('异步提交待批准时拒绝再次点击和导航，允许编辑草稿且不替换冻结正文', { timeout: 60000 }, async () => {
  const requests = [];
  const site = createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({ method: request.method, url: request.url, body });
    if (request.method === 'POST') {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ count: requests.filter(r => r.method === 'POST').length }));
      return;
    }
    response.setHeader('content-type', 'text/html; charset=utf-8');
    response.end('<!doctype html><html><link rel="icon" href="data:,"><body><input id="note" value="合成备注"><button id="send">提交</button><output id="result">等待</output><script>document.getElementById("send").onclick=async()=>{const r=await fetch("/notes",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({note:document.getElementById("note").value})});document.getElementById("result").textContent="提交次数："+(await r.json()).count}</script></body></html>');
  });
  await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${site.address().port}`;
  let host;
  try {
    host = await startHostFixture([origin]);
    const navigation = host.call('browser_navigate', { url: `${origin}/` });
    await host.decide(await host.pending());
    const page = toolValue(await navigation).pages.find(p => p.url === `${origin}/`).id;
    toolValue(await host.call('browser_click', { page, selector: '#send' }));
    const pending = await host.pending();
    for (const [name, args] of [
      ['browser_click', { page, selector: '#send' }],
      ['browser_navigate', { page, url: `${origin}/other` }],
    ]) {
      const result = (await host.call(name, args)).result;
      assert.equal(result.isError, true);
      assert.equal(result._meta.agentguard.outcome, 'refused');
      assert.equal(result._meta.agentguard.dispatched, false);
      assert.equal((await host.operator('/pending')).body.id, pending.id, '原批准不得被后续动作替换');
      assert.equal(requests.length, 1, '待批准的POST和后续动作均未到达站点');
    }
    toolValue(await host.call('browser_fill', { page, selector: '#note', value: '编辑后的新草稿' }));
    const frozen = (await host.operator('/pending')).body;
    assert.equal(frozen.id, pending.id);
    assert.equal(frozen.action_sha256, pending.action_sha256);
    assert.equal(frozen.binding.action.parameters.body, '{"note":"合成备注"}', '草稿编辑不能修改已经冻结的待批准正文');
    assert.equal(requests.length, 1);
    assert.equal((await host.operator('/workspace/status')).body.browser.pending_http_requests, 1);
    toolValue(await host.call('browser_read', { page }));
    assert.equal((await host.decide(pending)).status, 200);
    await until(async () => toolValue(await host.call('browser_read', { page })).text.includes('提交次数：1'));
    const state = (await host.operator('/workspace/status')).body.browser;
    assert.equal(state.pending_http_requests, 0);
    assert.equal(state.receipts.at(-1).outcome, 'success');
    assert.deepEqual(requests.filter(r => r.method === 'POST'), [{ method: 'POST', url: '/notes', body: '{"note":"合成备注"}' }]);
    assert.equal((await host.decide(pending)).status, 409);
  } finally {
    await host?.close();
    await new Promise(resolve => site.close(resolve));
  }
});

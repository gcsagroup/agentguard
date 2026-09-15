// 真实 Chromium 的 DOM 与 HTTP 策略切换；仅合成本机站点，脚本批准。
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';
import { startHostFixture, toolValue, until } from '../../apps/protected-browser/host-test-support.mjs';
import { createWorkspaceFixture } from './agd-workspace-session.mjs';
import { ruleFixture, rule, sha } from './agd-rule-package-fixture.mjs';
const option = name => { assert.ok(process.argv.includes(name)); return process.argv[process.argv.indexOf(name) + 1]; };
const out = option('--out'), binary = option('--binary'), cli = option('--cli');
assert.ok([out, binary, cli].every(isAbsolute)); await mkdir(out, { mode: 0o700 });
const report = { scope: '真实Chromium DOM与本机HTTP；脚本批准，不计原生人工或公网浏览器验收', binarySha256: sha(await readFile(binary)), checks: [], requests: [], receipts: [] };
const check = (name, value) => { report.checks.push({ name, passed: !!value }); assert.ok(value, name); console.error(`通过：${name}`); };
const site = createServer(async (request, response) => {
  let body = ''; for await (const part of request) body += part;
  report.requests.push({ url: request.url, method: request.method, body });
  response.setHeader('content-type', 'text/html; charset=utf-8');
  if (request.method === 'POST') { response.end('saved:' + body); return; }
  response.end('<!doctype html><html><link rel="icon" href="data:,"><body><input id="note" value="INITIAL"><button id="send">提交</button><output id="draft">INITIAL</output><output id="result">等待</output><script>document.getElementById("note").oninput=()=>document.getElementById("draft").textContent=document.getElementById("note").value;document.getElementById("send").onclick=async()=>{try{const r=await fetch("/save",{method:"POST",body:document.getElementById("note").value});document.getElementById("result").textContent=await r.text()}catch(e){document.getElementById("result").textContent="请求未完成"}}</script></body></html>');
});
await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${site.address().port}`;
report.origin = origin;
let host, packages;
try {
  const fixture = await createWorkspaceFixture({ name: 'browser-rule-policy' }); report.fixture = fixture.temporaryRoot;
  packages = await ruleFixture(fixture.control, cli); await packages.apply(packages.release(1));
  host = await startHostFixture([origin], { fixture, binary, timeout: 35, rpcTimeout: 60000, rulePackageConfig: packages.config });
  const navigation = host.call('browser_navigate', { url: origin + '/' }); const first = await host.pending();
  report.receipts.push(first); assert.equal((await host.decide(first)).status, 200);
  const page = toolValue(await navigation).pages.find(p => p.url === origin + '/').id;
  check('DOM派生的另一线程HTTP在同一策略事务中完成且无死锁', report.requests.length === 1 && first.binding.action.parameters.rule_package.status.last_sequence === 1);
  const rules = [rule('BLOCK_DOM', false, ['ui_tree_delta']), { ...rule('HTTP_DENY', false, ['network_flow']), id: 'PKG-HTTP' }, rule('ASK_DOM', true, ['ui_tree_delta'])];
  await packages.apply(packages.release(2, rules));
  const blocked = await host.call('browser_fill', { page, selector: '#note', value: 'BLOCK_DOM' }); report.receipts.push(blocked);
  const fieldValue = async () => toolValue(await host.call('browser_read', { page }));
  check('签名DOM规则拒绝实际填写且输入保持原值', blocked.result._meta.agentguard.dispatched === false && JSON.stringify(await fieldValue()).includes('INITIAL'));
  toolValue(await host.call('browser_fill', { page, selector: '#note', value: 'HTTP_DENY' }));
  toolValue(await host.call('browser_click', { page, selector: '#send' }));
  await until(async () => JSON.stringify(await fieldValue()).includes('请求未完成'));
  check('签名HTTP规则在零POST时拒绝且没有可批准请求', report.requests.filter(r => r.method === 'POST').length === 0 && (await host.operator('/pending')).body === null);
  toolValue(await host.call('browser_fill', { page, selector: '#note', value: 'OLD_HTTP' }));
  toolValue(await host.call('browser_click', { page, selector: '#send' })); const oldHttp = await host.pending(); report.receipts.push(oldHttp);
  await packages.apply(packages.release(3, rules)); assert.equal((await host.decide(oldHttp)).status, 200);
  const oldReceipt = await until(async () => (await host.operator('/workspace/status')).body.browser.receipts.find(r => r.action_id === oldHttp.binding.action.action_id));
  check('HTTP等待批准期间可更新且迟到批准零发送', oldReceipt.dispatched === false && oldReceipt.outcome === 'refused' && report.requests.filter(r => r.method === 'POST').length === 0);
  const domCall = host.call('browser_fill', { page, selector: '#note', value: 'ASK_DOM' }); const domPending = await host.pending(); report.receipts.push(domPending);
  await packages.apply(packages.release(4, rules)); assert.equal((await host.decide(domPending)).status, 200);
  const domResult = await domCall; report.receipts.push(domResult);
  check('DOM独立批准遇新发布失效且字段没有被改写', domResult.result._meta.agentguard.dispatched === false && JSON.stringify(await fieldValue()).includes('OLD_HTTP'));
  toolValue(await host.call('browser_fill', { page, selector: '#note', value: 'CURRENT_HTTP' }));
  toolValue(await host.call('browser_click', { page, selector: '#send' })); const current = await host.pending(); assert.equal((await host.decide(current)).status, 200);
  await until(async () => JSON.stringify(await fieldValue()).includes('saved:CURRENT_HTTP'));
  check('当前策略下DOM填写点击HTTP提交并从页面读回业务结果', report.requests.filter(r => r.method === 'POST').length === 1 && report.requests.at(-1).body === 'CURRENT_HTTP');
  const status = await packages.status(); await packages.apply({ ...packages.release(5), operation: { action: 'revoke', digests: [status.active_sha256], reason: '合成撤销' } });
  const refused = await host.call('browser_read', { page });
  check('撤销包后浏览器新DOM动作拒绝派发', refused.result._meta.agentguard.dispatched === false);
  await packages.apply(packages.release(6, rules)); check('新包生效后原页面可读且业务副作用仍只有一次', JSON.stringify(await fieldValue()).includes('saved:CURRENT_HTTP') && report.requests.filter(r => r.method === 'POST').length === 1);
  report.browserStatus = (await host.operator('/workspace/status')).body.browser; report.passed = true;
} catch (error) { report.error = error.stack; throw error; }
finally {
  if (packages) { report.packageCommands = packages.commands; report.packages = packages.packages; }
  if (host) await host.close({ preserve: true });
  site.closeAllConnections(); await new Promise(resolve => site.close(resolve));
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
}

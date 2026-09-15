// AGD-020 独立浏览器验收：资料读取、真实点击和实际 HTTP 副作用分别核对。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { access, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWorkspaceFixture, ROOT, DEFAULT_IMAGE } from './agd-workspace-session.mjs';
import { startHostFixture, toolValue, until } from '../../apps/protected-browser/host-test-support.mjs';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const option = name => { const i = process.argv.indexOf(name); assert.ok(i > 1, `缺少 ${name}`); return process.argv[i + 1]; };
const out = option('--out'), binary = option('--binary'), expectedBinary = option('--sha256'), runtime = option('--runtime'), python = option('--python');
assert.ok([out, binary, runtime, python].every(isAbsolute)); assert.match(expectedBinary, /^[a-f0-9]{64}$/);
assert.equal(sha(await readFile(binary)), expectedBinary); await mkdir(out, { mode: 0o700 });
const manifestBytes = await readFile(join(ROOT, 'eval/m2/dom-cases.json')), manifest = JSON.parse(manifestBytes);
const inputBytes = await readFile(join(ROOT, 'eval/m2/independent-inputs.json')), inputs = JSON.parse(inputBytes);
assert.equal(sha(inputBytes), manifest.input_manifest_sha256);
const cases = manifest.matrix.inputs.flatMap(id => manifest.matrix.modes.map(mode => ({ id: `${id}-${mode}`, input: id, mode, group: inputs.inputs.find(x => x.id === id).group, status: 'not_run' })));
cases.push(...manifest.additional_cases.map(c => ({ ...c, status: 'not_run' })));
assert.equal(cases.length, 21); assert.equal(new Set(cases.map(c => c.id)).size, 21);
await writeFile(join(out, 'declared-cases.json'), JSON.stringify({ frozenAt: new Date().toISOString(), manifestSha256: sha(manifestBytes), cases }, null, 2));
await writeFile(join(out, 'dom-cases.json'), manifestBytes); await writeFile(join(out, 'inputs.json'), inputBytes);
await copyFile(fileURLToPath(import.meta.url), join(out, 'harness-source.mjs'));
const report = { startedAt: new Date().toISOString(), scope: manifest.scope, binary, binarySha256: expectedBinary,
  runtime, runtimeSha256: sha(await readFile(runtime)), image: DEFAULT_IMAGE, manifestSha256: sha(manifestBytes), cases, requests: [], receipts: [], approvals: [] };
const escape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const formScript = 'window.addEventListener("DOMContentLoaded",()=>{document.getElementById("send").onclick=async()=>{const output=document.getElementById("result");try{const response=await fetch("/save",{method:"POST",body:document.getElementById("draft").value});output.textContent=await response.text()}catch{output.textContent="提交未完成"}}});';
const pages = new Map();
for (const row of cases) {
  const input = inputs.inputs.find(x => x.id === row.input).text;
  const visible = row.mode === 'visible' ? input : manifest.normal_visible_text;
  const hidden = row.mode === 'visible' ? '' : row.mode === 'oversized_hidden' ? 'x'.repeat(manifest.limits.oversized_hidden_characters) : input;
  const attribute = row.mode === 'low_contrast' ? 'style="color:white;background:white;font-size:1px"' : row.mode === 'opacity_zero' ? 'style="opacity:0"' : 'hidden';
  const html = `<!doctype html><html><head><meta charset="utf-8"><link rel="icon" href="data:,"><script>${formScript}</script></head><body><p id="article">${escape(visible)}</p>${hidden ? `<div ${attribute}>${escape(hidden)}</div>` : ''}<input id="draft" value="INITIAL"><input type="password" value="M2_PRIVATE_PASSWORD"><input type="hidden" value="M2_PRIVATE_HIDDEN"><textarea>M2_PRIVATE_TEXTAREA</textarea><button id="send">提交</button><output id="result">等待</output></body></html>`;
  pages.set(`/${row.id}`, { html, visible, hidden, rawNodes: [visible, ...(hidden ? [hidden] : []), '提交', '等待'] });
  await writeFile(join(out, `${row.id}.html`), html);
}
const site = createServer(async (request, response) => {
  let body = ''; for await (const part of request) { body += part; assert.ok(body.length <= 2048); }
  report.requests.push({ method: request.method, path: request.url, body });
  response.setHeader('content-type', 'text/html; charset=utf-8');
  if (request.method === 'POST' && request.url === '/save') { response.end(`已保存:${body}`); return; }
  const page = pages.get(request.url);
  if (!page || request.method !== 'GET') { response.writeHead(404); response.end('未声明页面'); return; }
  response.end(page.html);
});
await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${site.address().port}`; report.origin = origin;
let host, fixture;
const record = response => { report.receipts.push(response); return response; };
const exists = async path => { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
try {
  fixture = await createWorkspaceFixture({ name: 'm2-dom' }); report.fixture = fixture.temporaryRoot;
  host = await startHostFixture([origin], { fixture, binary, runtime, timeout: 45, rpcTimeout: 60000 });
  const decide = async (pending, method, target, body, approved) => {
    assert.equal(pending.binding.action.target, target); assert.equal(pending.binding.action.parameters.method, method);
    assert.equal(actionSha256(pending.binding.action), pending.action_sha256);
    if (body !== undefined) assert.equal(pending.binding.action.parameters.body, body);
    assert.equal((await host.decide(pending, approved)).status, 200);
    report.approvals.push({ id: pending.id, action_sha256: pending.action_sha256, method, target, body, approved });
  };
  let page;
  for (const row of cases) {
    row.startedAt = new Date().toISOString();
    try {
      const content = pages.get(`/${row.id}`), url = `${origin}/${row.id}`;
      const navigation = host.call('browser_navigate', { url, ...(page ? { page } : {}) });
      await decide(await host.pending(), 'GET', url, undefined, true);
      page = toolValue(record(await navigation)).pages.find(p => p.url === url).id;
      const receipt = record(await host.call('browser_read', { page })), value = toolValue(receipt), guard = receipt.result._meta.agentguard, views = guard.source.content_views;
      assert.equal(guard.instruction_authority, 'none'); assert.equal(guard.source.observation.entry, 'browser_read');
      assert.ok(value.text.includes(content.visible));
      assert.ok(!/M2_PRIVATE_(PASSWORD|HIDDEN|TEXTAREA)|raw_base64|_agentguard_capture/.test(JSON.stringify(receipt)));
      assert.equal(views.visible.sha256, sha(JSON.stringify(receipt.result.content)));
      assert.equal(views.raw[0].origin, 'dom_text_nodes');
      if (row.mode === 'oversized_hidden') {
        assert.equal(views.state, 'truncated'); assert.equal(views.raw[0].digest.complete, false); assert.ok(views.raw[0].digest.bytes <= manifest.limits.raw_dom_bytes);
      } else {
        assert.equal(views.state, 'complete'); assert.equal(views.raw[0].digest.sha256, sha(JSON.stringify(content.rawNodes)));
        if (row.mode === 'hidden') assert.ok(!value.text.includes(content.hidden));
        if (['low_contrast', 'opacity_zero'].includes(row.mode)) assert.ok(value.text.includes(content.hidden), 'innerText 纳入低对比节点，不冒充视觉识别');
      }
      const outside = join(fixture.control, `${row.id}-outside.txt`);
      const deniedFile = record(await host.call('write_file', { path: outside, contents: 'MUST_NOT_WRITE' }));
      assert.equal(deniedFile.result._meta.agentguard.dispatched, false); assert.equal(await exists(outside), false);
      const readPage = async () => toolValue(await host.call('browser_read', { page }));
      const send = async text => {
        toolValue(record(await host.call('browser_fill', { page, selector: '#draft', value: text })));
        toolValue(record(await host.call('browser_click', { page, selector: '#send' })));
        return host.pending();
      };
      const countBefore = report.requests.filter(r => r.method === 'POST').length;
      const deniedText = `DENIED-${row.id}`, waiting = await send(deniedText);
      assert.equal(report.requests.filter(r => r.method === 'POST').length, countBefore);
      await decide(waiting, 'POST', `${origin}/save`, deniedText, false);
      await until(async () => (await readPage()).text.includes('提交未完成'));
      assert.equal(report.requests.filter(r => r.method === 'POST').length, countBefore);
      const acceptedText = `ACCEPTED-${row.id}`, next = await send(acceptedText);
      assert.equal(report.requests.filter(r => r.method === 'POST').length, countBefore);
      await decide(next, 'POST', `${origin}/save`, acceptedText, true);
      await until(async () => (await readPage()).text.includes(`已保存:${acceptedText}`));
      assert.equal(report.requests.filter(r => r.method === 'POST').length, countBefore + 1);
      assert.deepEqual(report.requests.at(-1), { method: 'POST', path: '/save', body: acceptedText });
      assert.equal(await exists(outside), false);
      row.evidence = { source_id: guard.source.source_id, html_sha256: sha(content.html), raw_dom_sha256: views.raw[0].digest.sha256,
        raw_complete: views.raw[0].digest.complete, visible_sha256: views.visible.sha256, source_state: views.state,
        denied_action_sha256: waiting.action_sha256, approved_action_sha256: next.action_sha256, outside_file_absent: true, post_count: 1, business_result: `已保存:${acceptedText}` };
      row.status = 'passed';
    } catch (error) { row.status = 'failed'; row.error = String(error.stack); throw error; }
    finally { row.finishedAt = new Date().toISOString(); await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2)); }
  }
  assert.equal(report.requests.filter(r => r.method === 'GET').length, cases.length);
  assert.equal(report.requests.filter(r => r.method === 'POST').length, cases.length);
  report.browserStatus = (await host.operator('/workspace/status')).body.browser;
  report.passed = true;
} catch (error) { report.error = String(error.stack); report.passed = false; process.exitCode = 1; }
finally {
  if (host) { report.stderr = host.stderr(); try { await host.close({ preserve: true }); } catch (error) { report.closeError = String(error); report.passed = false; process.exitCode = 1; } }
  site.closeAllConnections(); await new Promise(resolve => site.close(resolve));
  if (fixture) for (const name of ['audit.db', 'audit.db.sources.db', 'audit.db.tools.db', 'browser.db']) {
    try { execFileSync(python, ['-c', 'import sqlite3,sys;a=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True);b=sqlite3.connect(sys.argv[2]);a.backup(b);b.close();a.close()', join(fixture.control, name), join(out, name)]); }
    catch (error) { (report.evidenceErrors ??= []).push(String(error)); report.passed = false; process.exitCode = 1; }
  }
  report.binaryUnchanged = sha(await readFile(binary)) === expectedBinary; if (!report.binaryUnchanged) { report.passed = false; process.exitCode = 1; }
  report.counts = Object.fromEntries(['normal', 'known_attack', 'unseen_variant', 'truncation'].map(group => [group, Object.fromEntries(['passed', 'failed', 'not_run'].map(status => [status, cases.filter(c => c.group === group && c.status === status).length]))]));
  report.finishedAt = new Date().toISOString(); await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ passed: report.passed, counts: report.counts, error: report.error, out }));
}

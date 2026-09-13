import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { startHostFixture, toolValue, until } from './host-test-support.mjs';

const execute = promisify(execFile);
async function processList() {
  const { stdout } = await execute('/bin/ps', ['-axo', 'pid=,ppid=,command='], { cwd: '/', maxBuffer: 4 * 1024 * 1024 });
  return stdout.split('\n').flatMap(line => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    return match ? [{ pid: Number(match[1]), parent: Number(match[2]), command: match[3] }] : [];
  });
}
async function ownedBrowser(host) {
  const processes = await processList(); const children = new Set([host.child.pid]);
  for (let pass = 0; pass < 12; pass++) for (const item of processes) if (children.has(item.parent)) children.add(item.pid);
  const browsers = processes.filter(item => children.has(item.pid) && item.command.includes('--remote-debugging-pipe') && item.command.includes('--user-data-dir=') && !item.command.includes('--type='));
  assert.equal(browsers.length, 1, '只允许识别一个属于本次gateway父进程的Chromium主进程');
  const browser = browsers[0]; const matched = browser.command.match(/--user-data-dir=(\S+)/);
  assert.ok(matched); const profile = await realpath(matched[1]); const control = await realpath(host.fixture.control);
  assert.ok(profile.startsWith(`${control}/browser-home-`) && profile.includes('/agentguard-operator-') && profile.endsWith('/profile'));
  assert.ok((await lstat(profile)).isDirectory());
  return { browserPid: browser.pid, gatewayPid: host.child.pid, profile, control,
    owned: processes.filter(item => children.has(item.pid)).map(item => ({ pid: item.pid, command: item.command })) };
}
async function verifyClosed(identity) {
  await until(async () => {
    const current = await processList();
    return identity.owned.every(previous => !current.some(item => item.pid === previous.pid && item.command === previous.command));
  }, 12000);
  await until(async () => { try { await access(identity.profile); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; } }, 5000);
}

test('F08 真实统一浏览器崩溃撤销待提交，新会话重新批准且只产生一次业务写入', { timeout: 120000 }, async () => {
  const report = { recorded_at: new Date().toISOString(), scope: 'F08 合成本机服务、实际网关和受宿主管理的Chromium', phases: [], pass: false };
  const received = []; let business = '未提交';
  const site = createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    received.push({ method: request.method, path: request.url, body });
    if (request.method === 'POST' && request.url === '/save') business = new URLSearchParams(body).get('value');
    response.setHeader('content-type', 'text/html; charset=utf-8');
    response.end(`<h1 id="business">${business}</h1><form method="POST" action="/save"><input id="value" name="value"><button id="save">提交</button></form>`);
  });
  await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${site.address().port}`;
  let first, second, firstIdentity, secondIdentity;
  try {
    first = await startHostFixture([origin], { timeout: 12 });
    report.gateway_sha256 = createHash('sha256').update(await readFile(first.binary)).digest('hex');
    let navigation = first.call('browser_navigate', { url: `${origin}/` }); let confirmation = await first.pending(); await first.decide(confirmation);
    const page = toolValue(await navigation).pages.find(page => page.url === `${origin}/`).id;
    const firstSession = (await first.rpc('gateway/stats')).result.host_session_id;
    firstIdentity = await ownedBrowser(first);
    toolValue(await first.call('browser_fill', { page, selector: '#value', value: '旧会话不得发送' }));
    const click = first.call('browser_click', { page, selector: '#save' }); const abandoned = await first.pending();
    assert.equal(abandoned.binding.action.target, `${origin}/save`);
    assert.equal(abandoned.binding.action.parameters.method, 'POST');
    assert.equal(received.filter(item => item.method === 'POST').length, 0);
    // PID、祖先与本次唯一私有profile都已同时核对，只终止本测试拥有的Chromium主进程。
    process.kill(firstIdentity.browserPid, 'SIGKILL');
    await click;
    await until(async () => (await first.operator('/pending')).body === null);
    assert.equal((await first.decide(abandoned)).status, 409, 'Chromium死亡后旧批准必须失效');
    await until(async () => (await first.operator('/workspace/status')).body.browser.receipts.some(receipt => receipt.action_id === abandoned.binding.action.action_id));
    const oldStatus = (await first.operator('/workspace/status')).body;
    const oldReceipt = oldStatus.browser.receipts.find(receipt => receipt.action_id === abandoned.binding.action.action_id);
    assert.equal(oldReceipt.dispatched, false); assert.ok(['refused', 'cancelled'].includes(oldReceipt.outcome));
    const read = await first.call('browser_read', { page });
    assert.equal(read.result.isError, true); assert.ok(['failed', 'unknown', 'refused'].includes(read.result._meta.agentguard.outcome));
    assert.equal(received.filter(item => item.method === 'POST').length, 0); assert.equal(business, '未提交');
    report.phases.push({ name: 'kill_owned_chromium_pending_post', gateway_pid: firstIdentity.gatewayPid, chromium_pid: firstIdentity.browserPid,
      private_profile: firstIdentity.profile, session_id: firstSession, post_count: 0, old_approval_status: 409,
      http_outcome: oldReceipt.outcome, dispatched: oldReceipt.dispatched, dom_outcome: read.result._meta.agentguard.outcome });
    await first.close(); first = undefined; await verifyClosed(firstIdentity);
    report.phases.push({ name: 'old_session_cleanup', processes: 'all_recorded_owned_processes_exited', profile_removed: true });

    second = await startHostFixture([origin], { timeout: 12 });
    const secondSession = (await second.rpc('gateway/stats')).result.host_session_id;
    assert.notEqual(secondSession, firstSession);
    assert.equal((await second.decide(abandoned)).status, 409, '另一宿主不能接纳旧会话批准');
    navigation = second.call('browser_navigate', { url: `${origin}/` }); confirmation = await second.pending(); await second.decide(confirmation);
    const freshPage = toolValue(await navigation).pages.find(page => page.url === `${origin}/`).id;
    secondIdentity = await ownedBrowser(second);
    toolValue(await second.call('browser_fill', { page: freshPage, selector: '#value', value: '新会话明确批准一次' }));
    const freshClick = second.call('browser_click', { page: freshPage, selector: '#save' }); const fresh = await second.pending();
    assert.notEqual(fresh.id, abandoned.id); assert.equal(fresh.binding.action.session_id, secondSession);
    assert.equal(received.filter(item => item.method === 'POST').length, 0);
    assert.equal((await second.decide(fresh)).status, 200); toolValue(await freshClick);
    await until(() => business === '新会话明确批准一次');
    await until(async () => JSON.stringify(toolValue(await second.call('browser_read', { page: freshPage }))).includes('新会话明确批准一次'));
    assert.equal((await second.decide(fresh)).status, 409);
    assert.equal(received.filter(item => item.method === 'POST').length, 1);
    assert.ok(received.filter(item => item.method === 'POST').every(item => new URLSearchParams(item.body).get('value') === '新会话明确批准一次'));
    report.phases.push({ name: 'new_session_single_approved_write', session_id: secondSession, new_action_id: fresh.binding.action.action_id,
      post_count: 1, business_verified_in_receiver_and_page: true, duplicate_approval_status: 409 });
    await second.close(); second = undefined; await verifyClosed(secondIdentity);
    report.phases.push({ name: 'new_session_cleanup', processes: 'all_recorded_owned_processes_exited', profile_removed: true });
    report.pass = true;
  } catch (error) { report.error = error.message; throw error; }
  finally {
    await first?.close(); await second?.close();
    await new Promise(resolve => site.close(resolve));
    if (process.env.AGD_BROWSER_LIFECYCLE_REPORT) { await mkdir(dirname(process.env.AGD_BROWSER_LIFECYCLE_REPORT), { recursive: true }); await writeFile(process.env.AGD_BROWSER_LIFECYCLE_REPORT, JSON.stringify(report, null, 2)); }
  }
});

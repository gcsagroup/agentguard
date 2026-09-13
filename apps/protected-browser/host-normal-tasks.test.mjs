// 原 B01～B10 的固定分母。当前是合成源码候选流程，不冒充模型自主操作或原生桌面验收。
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, writeFile, mkdir, copyFile, chmod, lstat, access, rm, realpath } from 'node:fs/promises';
import { join, resolve, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { request as httpRequest } from 'node:http';
import { promisify } from 'node:util';
import { actionSha256 } from './execution-contract.mjs';
import { startHostFixture, toolValue, until } from './host-test-support.mjs';
import { startNormalSite, FACTS } from './host-normal-site.mjs';
import { ROOT, fileTree } from '../../scripts/acceptance/agd-workspace-session.mjs';

const exec = promisify(execFile), sha = data => createHash('sha256').update(data).digest('hex');
const out = resolve(process.env.AGD_BROWSER_NORMAL_OUT || join(ROOT, '.artifacts/full-plan-2026-09-10', `browser-normal-${Date.now()}`));
const originalBinary = resolve(process.env.AGD_BROWSER_GATEWAY || join(ROOT, 'target/debug/agentguard-mcp'));
const binary = join(out, 'agentguard-mcp');
const sourceFiles = ['docs/agd-full-plan-acceptance-2026-09-10.zh.md', 'apps/protected-browser/host-normal-site.mjs', 'apps/protected-browser/host-normal-tasks.test.mjs', 'apps/protected-browser/host-test-support.mjs', 'apps/protected-browser/runtime.mjs', 'apps/protected-browser/host-connection.mjs', 'apps/protected-browser/cli.mjs', 'apps/protected-browser/mcp.mjs', 'apps/protected-browser/guardian.mjs', 'apps/protected-browser/execution-contract.mjs', 'crates/guard-gateway/src/browser_bridge.rs', 'crates/guard-gateway/src/server.rs', 'crates/guard-gateway/src/bin/agentguard_mcp.rs'];
sourceFiles.push('scripts/acceptance/agd-workspace-session.mjs', 'crates/guard-schema/rules/p0_rules.yaml', 'crates/guard-shell/policies/default.yaml', 'apps/protected-browser/agent-bridge.mjs', 'apps/protected-browser/demo.mjs');
const hashes = async () => Object.fromEntries(await Promise.all(sourceFiles.map(async path => [path, sha(await readFile(join(ROOT, path)))])));
const reports = []; let sourceBefore, matrix, binaryHash;

before(async () => {
  await mkdir(out); // 拒绝覆盖任何既有失败或通过记录。
  sourceBefore = await hashes();
  const document = await readFile(join(ROOT, sourceFiles[0]), 'utf8');
  matrix = document.split('\n').filter(line => /^\| B\d{2} \|/.test(line));
  assert.deepEqual(matrix.map(line => line.split(' | ')[0].slice(2)), Array.from({ length: 10 }, (_, i) => `B${String(i + 1).padStart(2, '0')}`));
  await writeFile(join(out, 'declared-matrix.json'), JSON.stringify({ rows: matrix, documentSha256: sourceBefore[sourceFiles[0]], denominator: 10 }, null, 2));
  binaryHash = sha(await readFile(originalBinary)); await copyFile(originalBinary, binary); await chmod(binary, 0o755);
  assert.equal(sha(await readFile(binary)), binaryHash); assert.equal(sha(await readFile(originalBinary)), binaryHash);
});

after(async () => {
  const sourceAfter = await hashes(), sourceUnchanged = JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter);
  const summary = { mode: 'source_candidate_scripted_browser_workflows', nativeDesktopVerified: false, modelAutonomousTasks: 0, denominator: 10,
    sourceBefore, sourceAfter, sourceUnchanged, binary: originalBinary, testedBinary: binary, binarySha256: binaryHash,
    passedTasks: reports.filter(item => item.passed).length, tasks: reports.map(item => ({ id: item.id, passed: item.passed, error: item.error })),
    allTenCompleted: reports.length === 10 && reports.every(item => item.passed), finalFrozenJointAcceptance: false };
  await writeFile(join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(`B01-B10证据：${out}`);
  assert.equal(sourceUnchanged, true, '源码依赖运行期间变化，本轮只能作开发诊断');
});

function runCase(id, operation) {
  test(`${id} ${['阅读两页并回答固定事实','只读查询固定订单','提交一次合成备注','拒绝初稿后提交终稿','正文变化后重新确认','目标变化后回到授权路径','暂停后完成未提交草稿','断开客户端后重新完成备注','未知结果后新会话只读查账','控制连接刷新后提交同一草稿'][Number(id.slice(1))-1]}`, { timeout: 120000 }, async () => {
    const report = { id, startedAt: new Date().toISOString(), passed: false, hosts: [], approvals: [], observations: [], boundary: ['人工操作由已声明脚本替代；不是模型自主任务。','站点范围由宿主夹具明确登记；本轮未验证原生桌面范围选择界面。'] };
    const site = await startNormalSite(), hosts = []; await mkdir(join(out, id));
    const context = { id, report, site, async start() {
      const host = await startHostFixture([site.origin], { timeout: 20, binary }); hosts.push(host);
      const stats = (await host.rpc('gateway/stats')).result;
      host.testInfo = { pid: host.child.pid, sessionId: stats.host_session_id, snapshotRoot: stats.execution_backend.snapshot_root, work: host.fixture.work, fixtureRoot: host.fixture.temporaryRoot, closed: false };
      report.hosts.push(host.testInfo); return host;
    } };
    try { await operation(context); report.passed = true; }
    catch (error) { report.error = String(error.stack || error); throw error; }
    finally {
      report.requests = site.requests; report.submissions = site.submissions;
      for (let index = 0; index < hosts.length; index++) {
        const host = hosts[index];
        try {
          if (!host.testInfo.closed) { host.testInfo.finalStatus = (await host.operator('/workspace/status')).body; await closeHost(host); }
          assert.deepEqual(await fileTree(host.fixture.work), host.fixture.initialTree);
          const journal = await saveJournal(join(host.fixture.control, 'browser.db'), join(out, id, `browser-${index + 1}.db`));
          host.testInfo.journal = journal;
          for (const approval of report.approvals.filter(item => item.hostPid === host.child.pid && item.terminalRequired)) {
            const finished = journal.rows.filter(row => row.event_type === 'GatewayExecutionFinished' && JSON.parse(row.event_json).action_sha256 === approval.actionSha256);
            assert.equal(finished.length, 1, '每个声明动作必须有唯一持久终态');
            assert.equal(JSON.parse(finished[0].event_json).outcome, approval.outcome);
          }
          for (const cancelled of (report.cancelledRequests || []).filter(item => item.hostPid === host.child.pid)) {
            assert.equal(journal.rows.filter(row => row.event_type === 'GatewayExecutionStarted' && JSON.parse(row.event_json).action_sha256 === cancelled.actionSha256).length, 0, '未批准的旧请求不能有实际派发记录');
          }
          for (const observation of report.observations.filter(item => item.hostPid === host.child.pid)) {
            const finished = journal.rows.filter(row => row.event_type === 'GatewayExecutionFinished' && JSON.parse(row.event_json).action_sha256 === observation.receipt.action_sha256);
            assert.equal(finished.length, 1, '每个实际 DOM 动作必须有相同摘要的唯一持久终态');
            assert.equal(JSON.parse(finished[0].event_json).outcome, observation.receipt.outcome);
          }
          await host.fixture.cleanup();
          const snapshot = host.testInfo.snapshotRoot;
          if (await exists(snapshot)) { assert.equal(dirname(await realpath(snapshot)), await realpath(tmpdir())); assert.ok(basename(snapshot).startsWith('agentguard-snapshot-')); await rm(snapshot, { recursive: true }); }
        } catch (error) { report.passed = false; report.cleanupError = String(error.stack || error); }
      }
      await site.close(); report.finishedAt = new Date().toISOString();
      await writeFile(join(out, id, 'report.json'), JSON.stringify(report, null, 2) + '\n'); reports.push(report);
      assert.equal(report.passed, true, report.cleanupError || report.error);
    }
  });
}

const exists = async path => { try { await access(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };

async function closeHost(host) {
  await host.close({ preserve: true });
  await until(() => host.child.exitCode !== null || host.child.signalCode !== null, 5000);
  assert.equal(await exists(host.controlFile), false, '退出后控制连接文件须撤销');
  const ids = (await exec('/usr/local/bin/docker', ['ps', '-a', '--format', '{{.ID}}'], { timeout: 10000 })).stdout.trim().split('\n').filter(Boolean), remaining = [];
  for (const id of ids) {
    let item;
    try { item = JSON.parse((await exec('/usr/local/bin/docker', ['inspect', id], { timeout: 10000 })).stdout)[0]; }
    catch (error) { if (/No such (container|object)/i.test(error.stderr || '')) continue; throw error; }
    if (item.Mounts.some(mount => mount.Source.startsWith(host.testInfo.snapshotRoot + '/'))) remaining.push(id);
  }
  assert.deepEqual(remaining, []); host.testInfo.remainingContainers = remaining; host.testInfo.closed = true;
}

async function saveJournal(database, destination) {
  // 归属进程退出后复制稳定主文件及可能的 WAL，查询只针对证据副本，不让 SQLite 在原目录建侧文件。
  const copiedFiles = [];
  for (const suffix of ['', '-wal']) {
    if (!(await exists(database + suffix))) continue;
    const bytes = await readFile(database + suffix); await writeFile(destination + suffix, bytes, { flag: 'wx', mode: 0o600 });
    assert.equal(sha(await readFile(database + suffix)), sha(bytes), '审计文件复制期间变化'); copiedFiles.push({ path: destination + suffix, sha256: sha(bytes) });
  }
  const hasWal = copiedFiles.some(file => file.path.endsWith('-wal') && file.sha256 !== sha(''));
  // 无 WAL 的已关闭副本可按 immutable 读取，避免只读 SQLite 为旧 WAL 模式创建锁侧文件。
  const code = 'import sqlite3,json,sys\nd=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro"+("&immutable=1" if sys.argv[2]=="closed-main" else ""),uri=True);d.row_factory=sqlite3.Row\nprint(json.dumps([dict(r) for r in d.execute("SELECT * FROM audit_events ORDER BY rowid")],ensure_ascii=False))\nd.close()';
  const rows = JSON.parse((await exec('/usr/bin/python3', ['-c', code, destination, hasWal ? 'with-wal' : 'closed-main'], { timeout: 10000, maxBuffer: 4 * 1024 * 1024 })).stdout);
  let previous = 'AGENTGUARD-AUDIT-GENESIS-v1';
  for (const [index, row] of rows.entries()) {
    const keys = ['id','timestamp_ms','platform','event_type','source_app','agent_session_id','rule_id','severity','action','human_message','evidence_ref','event_json'];
    let canonical = keys.map(key => row[key] ?? '').join('\u001f'); if (row.attributed_agent !== null) canonical += `\u001fagent=${row.attributed_agent}`;
    assert.equal(row.prev_hash, previous); assert.equal(row.seq, index + 1); assert.equal(row.record_hash, sha(`${previous}\n${canonical}`)); previous = row.record_hash;
  }
  assert.ok(rows.length); return { copiedDatabase: destination, copiedFiles, sha256: sha(await readFile(destination)), chainVerified: true, rows };
}

async function observe(context, host, name, arguments_) {
  const response = await host.call(name, arguments_); const value = toolValue(response);
  validateDomReceipt(response);
  context.report.observations.push({ hostPid: host.child.pid, name, arguments: arguments_, value, rawSha256: sha(JSON.stringify(response)), receipt: response.result?._meta?.agentguard });
  return value;
}
function validateDomReceipt(response) {
  const receipt = response.result?._meta?.agentguard;
  assert.equal(receipt?.scope, 'browser_dom'); assert.equal(receipt.outcome, 'success'); assert.equal(receipt.dispatched, true);
  assert.equal(receipt.automatic_retry, false); assert.equal(receipt.business_success_asserted, false);
  assert.match(receipt.action_sha256, /^[a-f0-9]{64}$/); assert.ok(receipt.action_id && receipt.session_id);
}
async function pendingFor(context, host, method, path, body = null) {
  const pending = await host.pending(), action = pending.binding.action;
  assert.equal(actionSha256(action), pending.action_sha256); assert.equal(action.tool.service, 'agentguard-protected-browser'); assert.equal(action.tool.name, 'http_request');
  assert.equal(action.session_id, (await host.operator('/workspace/status')).body.session_id);
  assert.equal(action.target, context.site.origin + path); assert.equal(action.parameters.method, method); assert.equal(action.parameters.body, body);
  return pending;
}
async function decide(context, host, pending, approve, operator = host.operator) {
  const answered = await operator(approve ? '/approve' : '/deny', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce }); assert.equal(answered.status, 200);
  const receipt = await until(async () => (await host.operator('/workspace/status')).body.browser.receipts.find(item => item.action_sha256 === pending.action_sha256));
  assert.equal(receipt.automatic_retry, false); assert.equal(receipt.session_id, pending.binding.action.session_id);
  context.report.approvals.push({ hostPid: host.child.pid, approve, actionSha256: pending.action_sha256, actionId: pending.binding.action.action_id, sessionId: receipt.session_id, target: pending.binding.action.target,
    method: pending.binding.action.parameters.method, body: pending.binding.action.parameters.body, bodySha256: sha(pending.binding.action.parameters.body || ''), outcome: receipt.outcome, receipt, terminalRequired: true });
  assert.equal(receipt.dispatched, approve); if (!approve) assert.equal(receipt.outcome, 'refused');
  return receipt;
}
async function navigate(context, host, path, page) {
  const promise = host.call('browser_navigate', { url: context.site.origin + path, ...(page ? { page } : {}) }); promise.catch(() => {});
  const pending = await pendingFor(context, host, 'GET', path); assert.equal((await decide(context, host, pending, true)).outcome, 'success');
  const response = await promise, value = toolValue(response);
  validateDomReceipt(response);
  const found = value.pages.find(item => item.url === context.site.origin + path); assert.ok(found);
  context.report.observations.push({ hostPid: host.child.pid, name: 'browser_navigate', value, rawSha256: sha(JSON.stringify(response)), receipt: response.result?._meta?.agentguard }); return found.id;
}
const read = (context, host, page) => observe(context, host, 'browser_read', { page });
const fill = (context, host, page, selector, value) => observe(context, host, 'browser_fill', { page, selector, value });
async function post(context, host, page, id, note, target = '/notes') {
  await fill(context, host, page, '#business-id', id); await fill(context, host, page, '#note', note); await fill(context, host, page, '#target', target);
  await observe(context, host, 'browser_click', { page, selector: '#send' });
  return pendingFor(context, host, 'POST', target, JSON.stringify({ id, note }));
}
async function resultContains(context, host, page, expected) {
  return until(async () => { const result = await read(context, host, page); return result.text.includes(expected) ? result : false; });
}
function oneSubmission(context, id, note, path = '/notes') {
  assert.deepEqual(context.site.submissions.map(row => ({ id: row.id, note: row.note, path: row.path })), [{ id, note, path }]);
}

runCase('B01', async context => {
  const host = await context.start(), page = await navigate(context, host, '/docs/storage');
  const storage = await read(context, host, page); await navigate(context, host, '/docs/export', page); const exported = await read(context, host, page);
  const answer = { retentionDays: Number(storage.text.match(/保留 (\d+) 天/)?.[1]), exportFormat: exported.text.match(/格式为 (\w+)/)?.[1] };
  assert.deepEqual(answer, { retentionDays: FACTS.retentionDays, exportFormat: FACTS.exportFormat }); context.report.answer = answer;
  assert.deepEqual(context.site.requests.map(row => [row.method, row.path]), [['GET','/docs/storage'], ['GET','/docs/export']]);
  context.report.answerSources = [{ url: context.site.origin + '/docs/storage', sha256: sha(storage.text) }, { url: context.site.origin + '/docs/export', sha256: sha(exported.text) }];
  assert.equal((await host.operator('/workspace/stop', {})).status, 200);
});
runCase('B02', async context => {
  const host = await context.start(), page = await navigate(context, host, '/order-query'); await fill(context, host, page, '#query', FACTS.order);
  await observe(context, host, 'browser_click', { page, selector: '#query-send' }); const pending = await pendingFor(context, host, 'GET', `/orders?id=${FACTS.order}`); await decide(context, host, pending, true);
  const result = await resultContains(context, host, page, `订单 ${FACTS.order}；状态：${FACTS.orderStatus}`); context.report.answer = result.text;
  assert.deepEqual(context.site.requests.map(row => [row.method, row.path, row.query]), [['GET','/order-query',''],['GET','/orders',`?id=${FACTS.order}`]]); assert.equal(context.site.submissions.length, 0);
});
runCase('B03', async context => {
  const host = await context.start(), page = await navigate(context, host, '/form'); await read(context, host, page);
  const id = 'B03-note', note = '第三项：逐字核对后提交的合成备注'; const pending = await post(context, host, page, id, note);
  assert.equal(context.site.submissions.length, 0); await decide(context, host, pending, true); await resultContains(context, host, page, `服务器回执：${id}；备注：${note}；提交次数：1`); oneSubmission(context, id, note);
});
runCase('B04', async context => {
  const host = await context.start(), page = await navigate(context, host, '/form'), id = 'B04-note';
  const first = await post(context, host, page, id, '错误初稿 v1'); await decide(context, host, first, false); await resultContains(context, host, page, '结果未确认'); assert.equal(context.site.submissions.length, 0);
  const final = '正确终稿 v2', next = await post(context, host, page, id, final); await decide(context, host, next, true); await resultContains(context, host, page, `备注：${final}`); oneSubmission(context, id, final);
});
runCase('B05', async context => {
  const host = await context.start(), page = await navigate(context, host, '/form'), id = 'B05-note';
  const old = await post(context, host, page, id, '展示中的正文 v1'); await fill(context, host, page, '#note', '重新确认正文 v2'); await read(context, host, page);
  await decide(context, host, old, false); const next = await post(context, host, page, id, '重新确认正文 v2');
  assert.notEqual(next.action_sha256, old.action_sha256); assert.equal((await host.decide(old)).status, 409); assert.equal(context.site.submissions.length, 0);
  await decide(context, host, next, true); await resultContains(context, host, page, '备注：重新确认正文 v2'); oneSubmission(context, id, '重新确认正文 v2');
  context.report.boundary.push('本项明确拒绝旧冻结请求后创建新请求；不声称仅修改 DOM 就自动撤销旧批准。');
});
runCase('B06', async context => {
  const host = await context.start(), page = await navigate(context, host, '/form'), id = 'B06-note';
  const old = await post(context, host, page, id, '目标 A 初稿'); await decide(context, host, old, false);
  const changed = await post(context, host, page, id, '目标变化候选', '/alternate'); assert.equal((await host.decide(old)).status, 409); await decide(context, host, changed, false);
  assert.equal(context.site.submissions.length, 0); const next = await post(context, host, page, id, '最终回到授权路径 A'); assert.equal((await host.decide(changed)).status, 409);
  await decide(context, host, next, true); await resultContains(context, host, page, '备注：最终回到授权路径 A'); oneSubmission(context, id, '最终回到授权路径 A'); assert.equal(context.site.requests.filter(row => row.path === '/alternate').length, 0);
  context.report.boundary.push('目标 A/B 均为预声明本机站点内路径；明确拒绝冻结旧请求，不声称只改 DOM 即自动撤销。');
});
runCase('B07', async context => {
  const host = await context.start(), page = await navigate(context, host, '/form'), id = 'B07-note', note = '暂停后明确继续的草稿';
  const old = await post(context, host, page, id, note); assert.equal((await host.operator('/workspace/pause', {})).status, 200);
  assert.equal((await host.decide(old)).status, 409); assert.equal(context.site.submissions.length, 0);
  assert.equal((await host.operator('/workspace/resume', {})).status, 200); const newSession = await host.refreshSession(); assert.notEqual(newSession, old.binding.action.session_id);
  const next = await post(context, host, page, id, note); assert.equal(next.binding.action.session_id, newSession); await decide(context, host, next, true); await resultContains(context, host, page, `备注：${note}`); oneSubmission(context, id, note);
  context.report.cancelledAction = { actionSha256: old.action_sha256, oldSession: old.binding.action.session_id, resumedSession: newSession };
  context.report.cancelledRequests = [{ hostPid: host.child.pid, actionSha256: old.action_sha256 }];
});
runCase('B08', async context => {
  const firstHost = await context.start(), firstPage = await navigate(context, firstHost, '/form'), id = 'B08-note';
  const old = await post(context, firstHost, firstPage, id, '断连前未批准草稿'); context.report.savedDraftObservation = await read(context, firstHost, firstPage);
  const oldCredentials = JSON.parse(await readFile(firstHost.controlFile, 'utf8'));
  await closeHost(firstHost); assert.equal(context.site.submissions.length, 0);
  const host = await context.start(), page = await navigate(context, host, '/form'); assert.notEqual(host.testInfo.sessionId, firstHost.testInfo.sessionId);
  const nextCredentials = JSON.parse(await readFile(host.controlFile, 'utf8'));
  assert.equal((await fetch(nextCredentials.url + '/status', { headers: { Authorization: `Bearer ${oldCredentials.token}` }, redirect: 'error', signal: AbortSignal.timeout(3000) })).status, 403);
  assert.equal((await host.decide(old)).status, 409); const note = '新实例明确重新完成备注', next = await post(context, host, page, id, note);
  await decide(context, host, next, true); await resultContains(context, host, page, `备注：${note}`); oneSubmission(context, id, note);
  context.report.boundary.push('选择原矩阵的取消后重建路径：stdio 断连销毁旧浏览器及 profile；活页面没有保留，保存的正文仅为观察证据。');
  context.report.cancelledRequests = [{ hostPid: firstHost.child.pid, actionSha256: old.action_sha256 }];
  context.report.oldControlCredentialRejected = true;
});
runCase('B09', async context => {
  const failedHost = await context.start(), failedPage = await navigate(context, failedHost, '/form'), id = 'B09-note', note = '服务已收件但返回链路中断';
  const pending = await post(context, failedHost, failedPage, id, note, '/unknown'); const receipt = await decide(context, failedHost, pending, true); assert.equal(receipt.outcome, 'unknown');
  const failed = await until(async () => { const status = (await failedHost.operator('/workspace/status')).body; return status.session_state === 'failed' ? status : false; }); context.report.unknownControlState = failed;
  assert.equal((await failedHost.operator('/workspace/resume', {})).status, 409); oneSubmission(context, id, note, '/unknown');
  await closeHost(failedHost);
  const host = await context.start(), page = await navigate(context, host, `/ledger?id=${id}`); assert.notEqual(host.testInfo.sessionId, failedHost.testInfo.sessionId);
  const result = await read(context, host, page); assert.ok(result.text.includes(`业务编号：${id}`) && result.text.includes('提交次数：1') && result.text.includes(`备注：${note}`));
  context.report.answer = '旧请求终态未知；新会话只读账本核实该业务编号已提交一次。'; oneSubmission(context, id, note, '/unknown');
  context.report.boundary.push('未知状态来自统一宿主控制状态与持久回执；新会话仅发出只读查账 GET，本轮没有原生窗口截图。');
});
runCase('B10', async context => {
  const host = await context.start(), page = await navigate(context, host, '/form'), id = 'B10-note', note = '控制连接重新载入后提交同一草稿';
  const pending = await post(context, host, page, id, note); const oldView = (await host.operator('/workspace/status')).body;
  const info = await lstat(host.controlFile); assert.equal(info.mode & 0o777, 0o600); assert.equal(info.isSymbolicLink(), false);
  const credentials = JSON.parse(await readFile(host.controlFile, 'utf8'));
  const reconnected = (path, body) => new Promise((resolveResult, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const request = httpRequest(credentials.url + path, { method: body ? 'POST' : 'GET', agent: false, headers: { Authorization: `Bearer ${credentials.token}`, ...(body ? { 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(data) } : {}) } }, response => {
      let text = ''; response.on('data', chunk => text += chunk); response.on('end', () => { try { resolveResult({ status: response.statusCode, body: JSON.parse(text) }); } catch (error) { reject(error); } });
    }); request.setTimeout(10000, () => request.destroy(new Error('重新连接控制面超时'))); request.on('error', reject); request.end(data);
  });
  const fresh = (await reconnected('/workspace/status')).body, refreshedPending = (await reconnected('/pending')).body;
  assert.equal(fresh.session_id, oldView.session_id); assert.deepEqual(fresh.browser.origins, [context.site.origin]); assert.equal(refreshedPending.action_sha256, pending.action_sha256);
  const preserved = await read(context, host, page); assert.ok(preserved.text.includes(`当前草稿：${note}`));
  const browserState = await observe(context, host, 'browser_status', {}); assert.ok(browserState.pages.some(item => item.id === page && item.url === context.site.origin + '/form'));
  assert.equal(context.site.requests.filter(row => row.method === 'GET' && row.path === '/form').length, 1);
  context.report.activePagePreserved = { page, sessionId: fresh.session_id, draftSha256: sha(note) };
  await decide(context, host, refreshedPending, true, reconnected); await resultContains(context, host, page, `备注：${note}`); assert.equal((await host.decide(pending)).status, 409); oneSubmission(context, id, note);
  assert.equal((await reconnected('/workspace/stop', {})).status, 200); const before = context.site.requests.length; await closeHost(host); assert.equal(context.site.requests.length, before);
  context.report.boundary.push('本项使用真实新 HTTP 连接重新载入受认证控制面，未伪装成原生控制页视觉刷新。');
});

// 统一宿主的固定100次循环专项；批准由测试脚本代行，不是100个完整用户任务。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { readFile, writeFile, mkdir, copyFile, chmod, access, readdir, realpath, rm } from 'node:fs/promises';
import { join, resolve, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { actionSha256 } from './execution-contract.mjs';
import { startHostFixture, toolValue, until } from './host-test-support.mjs';
import { ROOT, fileTree } from '../../scripts/acceptance/agd-workspace-session.mjs';

const exec = promisify(execFile), sha = value => createHash('sha256').update(value).digest('hex');
const BODY = JSON.stringify({ note: 'AGD_CYCLE_FIXED_SYNTHETIC_POST_20260910' });
const blocks = Number(process.env.AGD_BROWSER_CYCLE_BLOCKS || '10');
assert.ok(Number.isInteger(blocks) && blocks >= 1 && blocks <= 10, '样本区块数只支持1至10，正式分母始终100');
const out = resolve(process.env.AGD_BROWSER_CYCLE_OUT || join(ROOT, '.artifacts/full-plan-2026-09-10', `browser-cycles-${Date.now()}`));
const originalBinary = resolve(process.env.AGD_BROWSER_GATEWAY || join(ROOT, 'target/debug/agentguard-mcp'));
const files = ['Cargo.lock', 'crates/guard-gateway/Cargo.toml', 'docs/agd-full-plan-acceptance-2026-09-10.zh.md',
  'crates/guard-gateway/src/browser_bridge.rs', 'crates/guard-gateway/src/control_http.rs', 'crates/guard-gateway/src/journal.rs',
  'crates/guard-gateway/src/confirm.rs', 'crates/guard-gateway/src/server.rs', 'crates/guard-gateway/src/bin/agentguard_mcp.rs',
  'crates/guard-gateway/src/egress.rs', 'crates/guard-gateway/src/egress_journal.rs',
  'crates/guard-schema/rules/p0_rules.yaml', 'crates/guard-shell/policies/default.yaml', 'scripts/acceptance/agd-workspace-session.mjs',
  ...['host-cycles.test.mjs', 'host-test-support.mjs', 'runtime.mjs', 'host-connection.mjs', 'cli.mjs', 'mcp.mjs',
    'guardian.mjs', 'execution-contract.mjs', 'agent-bridge.mjs', 'demo.mjs'].map(name => `apps/protected-browser/${name}`)];
const hashes = async () => Object.fromEntries(await Promise.all(files.map(async path => [path, sha(await readFile(join(ROOT, path)))])));
const exists = async path => { try { await access(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };
const save = (path, value) => writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });

async function processTree(rootPid) {
  const rows = (await exec('/bin/ps', ['-axo', 'pid=,ppid=,command='], { maxBuffer: 4 * 1024 * 1024 })).stdout.split('\n').flatMap(line => {
    const row = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    return row ? [{ pid: Number(row[1]), parent: Number(row[2]), commandSha256: sha(row[3]), profile: row[3].match(/--user-data-dir=([^\s]+)/)?.[1] }] : [];
  });
  if (rootPid === undefined) return rows;
  const ids = new Set([rootPid]);
  for (let previous = -1; previous !== ids.size;) {
    previous = ids.size;
    for (const row of rows) if (ids.has(row.parent)) ids.add(row.pid);
  }
  return rows.filter(row => ids.has(row.pid));
}

async function journal(database, destination) {
  // 进程退出后复制审计与WAL，只读证据副本；原始库不创建查询侧文件。
  const copied = [];
  for (const suffix of ['', '-wal']) {
    if (!(await exists(database + suffix))) continue;
    const bytes = await readFile(database + suffix);
    await writeFile(destination + suffix, bytes, { flag: 'wx', mode: 0o600 });
    assert.equal(sha(await readFile(database + suffix)), sha(bytes));
    copied.push({ path: destination + suffix, sha256: sha(bytes) });
  }
  const withWal = copied.some(item => item.path.endsWith('-wal') && item.sha256 !== sha(''));
  const code = 'import sqlite3,json,sys\nd=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro"+("" if sys.argv[2]=="wal" else "&immutable=1"),uri=True);d.row_factory=sqlite3.Row\nprint(json.dumps([dict(r) for r in d.execute("SELECT * FROM audit_events ORDER BY rowid")],ensure_ascii=False));d.close()';
  const rows = JSON.parse((await exec('/usr/bin/python3', ['-c', code, destination, withWal ? 'wal' : 'main'], { timeout: 10000, maxBuffer: 8 * 1024 * 1024 })).stdout);
  let previous = 'AGENTGUARD-AUDIT-GENESIS-v1';
  for (const [index, row] of rows.entries()) {
    let canonical = ['id', 'timestamp_ms', 'platform', 'event_type', 'source_app', 'agent_session_id', 'rule_id', 'severity', 'action', 'human_message', 'evidence_ref', 'event_json'].map(key => row[key] ?? '').join('\u001f');
    if (row.attributed_agent !== null) canonical += `\u001fagent=${row.attributed_agent}`;
    assert.equal(row.seq, index + 1); assert.equal(row.prev_hash, previous);
    assert.equal(row.record_hash, sha(`${previous}\n${canonical}`)); previous = row.record_hash;
  }
  assert.ok(rows.length); await save(`${destination}.rows.json`, rows);
  return { copied, chainVerified: true, rows };
}

function dom(response) {
  toolValue(response);
  const receipt = response.result._meta?.agentguard;
  assert.equal(receipt.scope, 'browser_dom'); assert.equal(receipt.outcome, 'success');
  assert.equal(receipt.dispatched, true); assert.equal(receipt.automatic_retry, false);
  assert.equal(receipt.business_success_asserted, false); assert.match(receipt.action_sha256, /^[a-f0-9]{64}$/);
  return receipt;
}

async function pending(host, origin, method) {
  const request = await host.pending(), action = request.binding.action;
  assert.equal(actionSha256(action), request.action_sha256);
  assert.equal(action.tool.service, 'agentguard-protected-browser'); assert.equal(action.tool.name, 'http_request');
  assert.equal(action.target, origin + (method === 'GET' ? '/' : '/submit'));
  assert.equal(action.parameters.method, method); assert.equal(action.parameters.body, method === 'GET' ? null : BODY);
  assert.equal(action.session_id, (await host.operator('/workspace/status')).body.session_id);
  return request;
}

async function decided(host, request, approved) {
  assert.equal((await host.decide(request, approved)).status, 200);
  const receipt = await until(async () => (await host.operator('/workspace/status')).body.browser.receipts.find(item => item.action_sha256 === request.action_sha256));
  assert.equal(receipt.outcome, approved ? 'success' : 'refused'); assert.equal(receipt.dispatched, approved);
  assert.equal(receipt.automatic_retry, false); assert.equal(receipt.session_id, request.binding.action.session_id);
  assert.equal((await host.decide(request, approved)).status, 409, '已处理的批准与拒绝均不能重放');
  return receipt;
}

async function closeAndVerify(host, block, path) {
  const owned = await processTree(host.child.pid);
  const homes = (await readdir(host.fixture.control)).filter(name => name.startsWith('browser-home-')).map(name => join(host.fixture.control, name));
  const profiles = [...new Set(owned.flatMap(row => row.profile ? [row.profile] : []))];
  assert.ok(profiles.length >= 1, '必须记录真实Chromium专用profile');
  await host.close({ preserve: true });
  await until(() => host.child.exitCode !== null || host.child.signalCode !== null, 5000);
  assert.equal(host.child.exitCode, 0); assert.equal(host.child.signalCode, null);
  await until(async () => {
    const current = await processTree();
    return !owned.some(old => current.some(row => row.pid === old.pid && row.commandSha256 === old.commandSha256));
  }, 10000);
  for (const location of [host.controlFile, host.executorFile, ...homes, ...profiles]) {
    await until(async () => !(await exists(location)), 10000);
  }
  assert.deepEqual(await fileTree(host.fixture.work), host.fixture.initialTree);
  const stored = await journal(join(host.fixture.control, 'browser.db'), join(path, 'browser.db'));
  const records = stored.rows.map(row => ({ type: row.event_type, data: JSON.parse(row.event_json), hash: row.record_hash }));
  for (const item of [...block.setup, ...block.cycles]) {
    const final = records.filter(row => row.type === 'GatewayExecutionFinished' && row.data.action_sha256 === item.actionSha256);
    const started = records.filter(row => row.type === 'GatewayExecutionStarted' && row.data.action_sha256 === item.actionSha256);
    assert.equal(final.length, 1, '每个HTTP请求须有唯一持久终态');
    assert.equal(started.length, item.mode === 'approve' ? 1 : 0);
    assert.equal(final[0].data.dispatched, item.mode === 'approve');
    if (item.mode === 'disconnect') assert.ok(['refused', 'cancelled'].includes(final[0].data.outcome));
    else assert.equal(final[0].data.outcome, item.mode === 'approve' ? 'success' : 'refused');
    item.persistedHttpReceipt = { ...final[0].data, record_hash: final[0].hash };
  }
  for (const receipt of block.domReceipts) {
    const final = records.filter(row => row.type === 'GatewayExecutionFinished' && row.data.action_sha256 === receipt.action_sha256);
    assert.equal(final.length, 1, 'DOM回执须与独立持久终态一致');
    assert.equal(final[0].data.outcome, receipt.outcome); assert.equal(final[0].data.dispatched, true);
  }
  block.cleanup = { processIds: owned.map(row => row.pid), profiles, privateHomes: homes, childExitCode: host.child.exitCode,
    allOwnedProcessesExited: true, credentialsRemoved: true, profilesRemoved: true, workspaceUnchanged: true, auditChainVerified: stored.chainVerified };
  await host.fixture.cleanup();
  // 隔离快照是此夹具独占的临时目录；证据库已另存，清理不覆盖既有工作区。
  if (await exists(block.snapshotRoot)) {
    assert.equal(dirname(await realpath(block.snapshotRoot)), await realpath(tmpdir()));
    assert.ok(basename(block.snapshotRoot).startsWith('agentguard-snapshot-'));
    await rm(block.snapshotRoot, { recursive: true });
  }
}

test('统一宿主100循环：50批准、40拒绝、10真实stdio断连取消', { timeout: 600000 }, async () => {
  await mkdir(dirname(out), { recursive: true }); await mkdir(out);
  const sourceBefore = await hashes(), binary = join(out, 'agentguard-mcp');
  const binarySha256 = sha(await readFile(originalBinary)); await copyFile(originalBinary, binary); await chmod(binary, 0o755);
  assert.equal(sha(await readFile(binary)), binarySha256); assert.equal(sha(await readFile(originalBinary)), binarySha256);
  const matrix = Array.from({ length: 100 }, (_, index) => ({ id: `C${String(index + 1).padStart(3, '0')}`, block: Math.floor(index / 10) + 1,
    mode: index % 10 < 5 ? 'approve' : index % 10 < 9 ? 'deny' : 'disconnect', method: 'POST', path: '/submit', bodySha256: sha(BODY) }));
  const document = await readFile(join(ROOT, 'docs/agd-full-plan-acceptance-2026-09-10.zh.md'), 'utf8');
  const declaration = document.split('\n').find(line => line.startsWith('| 统一浏览器循环 |'));
  assert.ok(declaration?.includes('50 次批准、40 次拒绝、10 次断连取消'));
  // 完整分母必须在第一个服务或浏览器启动前写入，样本运行不缩小正式分母。
  await save(join(out, 'declared-matrix.json'), { denominator: 100, declaration, documentSha256: sha(document), matrix, fixedBody: BODY,
    expectedPosts: 50, setupNavigationExcludedFromDenominator: true, scriptedApprovals: true, completeUserTasks: 0 });
  const ledger = [], requests = [], results = [], blockReports = [];
  const server = createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({ method: request.method, path: request.url, body });
    if (request.method === 'POST' && request.url === '/submit') {
      ledger.push({ sequence: ledger.length + 1, method: request.method, path: request.url, body });
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ submitted: ledger.length })); return;
    }
    if (request.method !== 'GET' || request.url !== '/') { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><link rel="icon" href="data:,"><title>合成循环</title><h1>固定正文提交</h1><button id="send">提交</button><output id="result">尚未提交</output><script>
      document.getElementById('send').onclick=async function(){this.disabled=true;const result=document.getElementById('result');result.textContent='等待批准';try{const response=await fetch('/submit',{method:'POST',headers:{'content-type':'application/json'},body:${JSON.stringify(BODY)}});const value=await response.json();result.textContent='提交成功 '+value.submitted;}catch{result.textContent='请求未提交';}finally{this.disabled=false;}};
    </script></html>`);
  });
  await new Promise(resolveReady => server.listen(0, '127.0.0.1', resolveReady));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let failure, host, currentBlock;
  try {
    for (let number = 1; number <= blocks; number++) {
      const path = join(out, `block-${String(number).padStart(2, '0')}`); await mkdir(path);
      currentBlock = { number, setup: [], cycles: [], domReceipts: [], passed: false }; blockReports.push(currentBlock);
      host = await startHostFixture([origin], { timeout: 20, binary });
      const stats = (await host.rpc('gateway/stats')).result;
      currentBlock.hostPid = host.child.pid; currentBlock.sessionId = stats.host_session_id; currentBlock.snapshotRoot = stats.execution_backend.snapshot_root;
      const navigating = host.call('browser_navigate', { url: origin + '/' }); navigating.catch(() => {});
      const setup = await pending(host, origin, 'GET'), setupReceipt = await decided(host, setup, true);
      const navigation = await navigating, state = toolValue(navigation); currentBlock.domReceipts.push(dom(navigation));
      currentBlock.browser = { version: state.browserVersion, extension: state.extension, enforcement: state.enforcement };
      const page = state.pages.find(item => item.url === origin + '/').id;
      currentBlock.setup.push({ mode: 'approve', actionSha256: setup.action_sha256, receipt: setupReceipt });
      for (const declared of matrix.filter(row => row.block === number)) {
        const begin = performance.now(), beforePosts = ledger.length;
        const clicked = await host.call('browser_click', { page, selector: '#send' }), clickReceipt = dom(clicked);
        currentBlock.domReceipts.push(clickReceipt);
        const request = await pending(host, origin, 'POST');
        assert.equal(ledger.length, beforePosts, '批准前不得有POST收件');
        const result = { ...declared, actionSha256: request.action_sha256, sessionId: request.binding.action.session_id, domReceipt: clickReceipt, beforePosts, passed: false };
        currentBlock.cycles.push(result); results.push(result);
        if (declared.mode === 'disconnect') {
          await closeAndVerify(host, currentBlock, path); host = undefined;
          assert.equal(ledger.length, beforePosts, 'stdio断连不得提交待批准POST');
        } else {
          result.httpReceipt = await decided(host, request, declared.mode === 'approve');
          const expected = declared.mode === 'approve' ? beforePosts + 1 : beforePosts;
          await until(() => ledger.length === expected);
          await until(async () => {
            const read = await host.call('browser_read', { page }); currentBlock.domReceipts.push(dom(read));
            return toolValue(read).text.includes(declared.mode === 'approve' ? `提交成功 ${expected}` : '请求未提交');
          });
          assert.equal(ledger.length, expected);
        }
        result.afterPosts = ledger.length; result.elapsedMs = Math.round(performance.now() - begin); result.passed = true;
        await save(join(out, 'progress.json'), { denominator: 100, completed: results.length, ledgerPosts: ledger.length, results });
      }
      currentBlock.passed = true; await save(join(path, 'report.json'), currentBlock);
      console.log(`浏览器循环 ${results.length}/100；批准收件 ${ledger.length}/50；本区块进程、profile及审计核对通过`);
    }
    assert.equal(results.length, blocks * 10); assert.equal(ledger.length, blocks * 5);
    assert.equal(new Set(results.map(row => row.actionSha256)).size, results.length);
    assert.equal(new Set(blockReports.map(row => row.sessionId)).size, blocks, '每次真实断连后建立新会话');
    assert.deepEqual(requests.filter(row => row.method !== 'POST').map(row => [row.method, row.path]), Array.from({ length: blocks }, () => ['GET', '/']));
    assert.ok(ledger.every(row => row.body === BODY && row.path === '/submit' && row.method === 'POST'));
  } catch (error) { failure = String(error.stack || error); }
  finally {
    if (host) {
      try { await closeAndVerify(host, currentBlock, join(out, `block-${String(currentBlock.number).padStart(2, '0')}`)); }
      catch (error) { failure = `${failure || ''}\n清理或审计核对失败：${error.stack || error}`; }
    }
    server.closeAllConnections(); await new Promise(resolveClosed => server.close(resolveClosed));
    const sourceAfter = await hashes(), sourceUnchanged = JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter);
    const complete = results.length === 100 && results.every(row => row.passed) && ledger.length === 50;
    const report = { mode: blocks === 10 ? '固定100循环专项' : '开发样本；正式分母仍为100', denominator: 100, executed: results.length,
      expectedPosts: 50, ledgerPosts: ledger.length, completeUserTasks: 0, nativeDesktopVerified: false, scriptedApprovals: true,
      originalBinary, testedBinary: binary, binarySha256, sourceBefore, sourceAfter, sourceUnchanged,
      samplePassed: blocks < 10 && !failure && results.length === blocks * 10 && results.every(row => row.passed),
      all100Passed: !failure && complete && sourceUnchanged, failure, blocks: blockReports, results, requests, ledger };
    await save(join(out, 'report.json'), report); console.log(`统一浏览器循环证据：${out}`);
    assert.equal(failure, undefined, failure); assert.equal(sourceUnchanged, true, '源码运行期间变化，只保留开发诊断');
  }
});

// AGD-017 两类服务通过生产 CLI 联合验收；批准只覆盖本脚本的合成文件和请求。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join, resolve, isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { WorkspaceSession, createWorkspaceFixture, ROOT, DEFAULT_IMAGE } from './agd-workspace-session.mjs';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { remoteFixture } from './agd-mcp-remote-fixture.mjs';
const option = name => process.argv[process.argv.indexOf(name) + 1];
assert.ok(process.argv.includes('--out') && process.argv.includes('--package') && process.argv.includes('--binary'));
const out = option('--out'), source = option('--package'), binary = option('--binary');
assert.ok([out, source, binary].every(isAbsolute)); await mkdir(out, { mode: 0o700 });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const report = { scope: '生产CLI、本地官方服务和自有远程HTTPS联合；脚本批准，非原生人工或公网验收', binarySha256: sha(await readFile(binary)), image: DEFAULT_IMAGE, checks: [], receipts: [] };
const check = (name, passed) => { report.checks.push({ name, passed: !!passed }); assert.ok(passed, name); console.error(`检查通过：${name}`); };
const record = value => { report.receipts.push(value); return value; };
const exists = async path => { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
let session, oldSession, remote;
try {
  const fixture = await createWorkspaceFixture({ name: 'mcp-remote-product', seed: { 'source.txt': 'SYNTHETIC_JOINT_DATA' } });
  report.fixture = fixture.temporaryRoot; report.auditDb = fixture.auditDb;
  const plans = JSON.parse(await readFile(fixture.plans, 'utf8')); plans.plans[0].allow.push('network_egress'); plans.plans[0].scope.hosts = ['mcp.localhost'];
  await writeFile(fixture.plans, JSON.stringify(plans)); report.plansSha256 = sha(await readFile(fixture.plans));
  remote = await remoteFixture(fixture.control);
  const configPath = join(fixture.control, 'mcp-services.json');
  const config = { version: 1, services: [{ service_id: 'official-filesystem', namespace: 'filesystem', package_path: source, package_id: 'official-filesystem', package_version: '2026.8.31', entrypoint: 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js', arguments: [fixture.work] }], remote_services: [remote.config] };
  await writeFile(configPath, JSON.stringify(config)); report.config = config;
  const start = () => WorkspaceSession.start({ binary, fixture, mcpServiceConfig: configPath, startupTimeoutMs: 60000, confirmSeconds: 45 });
  // 坏令牌不触发任何 HTTPS 发现，也不允许借模型参数修复授权。
  const goodCredentials = JSON.stringify(remote.credentials);
  for (const [label, changes, scope] of [
    ['错误受众', { aud: 'https://wrong.example/mcp' }, 'mcp:discover mcp:call'],
    ['错误签发者', { iss: 'https://wrong-issuer.example' }, 'mcp:discover mcp:call'],
    ['过期令牌', { exp: Math.floor(Date.now() / 1000) - 1 }, 'mcp:discover mcp:call'],
    ['缺少调用范围', {}, 'mcp:discover'],
    ['额外范围', {}, 'mcp:discover mcp:call admin'],
  ]) {
    await writeFile(remote.config.credentials_path, JSON.stringify({ ...remote.credentials, call_token: remote.issue(scope, changes) }));
    let rejected = false; try { const invalid = await start(); await invalid.close(); } catch (e) { rejected = String(e).includes('MCP_REMOTE_TOKEN'); }
    check(`${label}配置在零远程请求时拒绝`, rejected && remote.requests.length === 0);
  }
  await writeFile(remote.config.credentials_path, goodCredentials);
  session = await start();
  const call = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
  const pendingFor = promise => Promise.race([session.waitForPending(), promise.then(v => { throw new Error('未等待批准：' + JSON.stringify(v)); })]);
  const approveService = async id => {
    const response = await session.operatorRequest('/registry/review', { service_id: id }); assert.equal(response.status, 200);
    const v = record(response.value); assert.equal(v.dispatch_supported, true);
    assert.equal((await session.operatorRequest('/registry/decide', { service_id: id, review_id: v.review_id, review_nonce: v.review_nonce, manifest_sha256: v.manifest_sha256, approve: true })).status, 200); return v;
  };
  const answer = (pending, decision = 'approve') => {
    assert.equal(actionSha256(pending.binding.action), pending.action_sha256);
    assert.equal(pending.binding.action.session_id, session.sessionId);
    return session.operatorRequest('/' + decision, { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce });
  };
  const invoke = async (name, args) => { const promise = call(name, args), p = await pendingFor(promise); assert.deepEqual(p.binding.action.parameters.arguments, args); assert.equal((await answer(p)).status, 200); return record(await promise); };
  const stats = async () => record((await session.rpc('gateway/stats')).result);
  const resume = async () => assert.equal((await session.transition('resume')).status, 200);
  check('实际发现只发送发现令牌且没有工具调用', remote.requests.length === 3 && remote.requests.every(r => r.scope === 'mcp:discover' && r.method !== 'tools/call'));
  let listing = await session.rpc('tools/list'); check('未认可本地及远程工具均不公开', !listing.result.tools.some(t => t.name.startsWith('mcp__')));
  const unregistered = record(await call('mcp__remote__write_note', { text: 'MUST_NOT_SEND' }));
  check('未认可远程调用没有新增连接请求', unregistered.result._meta.agentguard.dispatched === false && remote.requests.length === 3);
  const localReview = await approveService('official-filesystem'), remoteReview = await approveService('remote-fixture');
  report.localManifest = localReview.manifest; report.remoteManifest = remoteReview.manifest;
  check('复核显示与实际观测绑定的端点和非代码证明', remoteReview.remote_connection.url === remote.url && remoteReview.remote_connection.remote_code_attested === false && remoteReview.manifest.package.package_id === 'agentguard-remote-connection-config');
  listing = record(await session.rpc('tools/list'));
  check('两类服务同会话公开14个官方和3个远程工具', listing.result.tools.filter(t => t.name.startsWith('mcp__')).length === 17);
  const beforeInvalid = remote.requests.length;
  const invalid = record(await call('mcp__remote__write_note', { text: 'x', url: 'http://169.254.169.254/' }));
  check('参数不能新增网络目标且Schema错误零请求', invalid.result._meta.agentguard.dispatched === false && remote.requests.length === beforeInvalid);
  const waiting = call('mcp__remote__write_note', { text: 'DENIED_NOTE' }), pending = await pendingFor(waiting);
  check('批准展示端点完整参数及凭据摘要但不含令牌', pending.binding.action.parameters.remote.connection.url === remote.url && pending.binding.action.parameters.remote.credential_sha256 === sha(remote.credentials.call_token) && !JSON.stringify(pending).includes(remote.credentials.call_token) && remote.requests.length === beforeInvalid);
  assert.equal((await answer(pending, 'deny')).status, 200); const denied = record(await waiting);
  check('独立拒绝留下未派发回执及零远端副作用', denied.result._meta.agentguard.dispatched === false && await readFile(remote.note, 'utf8') === 'REMOTE_INITIAL' && remote.effects.length === 0);
  const localRead = await invoke('mcp__filesystem__read_text_file', { path: join(fixture.work, 'source.txt') });
  check('本地实际读取带来源', JSON.stringify(localRead.result.content).includes('SYNTHETIC_JOINT_DATA') && localRead.result._meta.agentguard.source);
  const locallyRead = localRead.result.structuredContent.content; assert.equal(typeof locallyRead, 'string');
  const remoteWrite = await invoke('mcp__remote__write_note', { text: locallyRead });
  check('经过批准的本地资料在远端实际写入并由服务端读回', remoteWrite.result._meta.agentguard.outcome === 'success' && await readFile(remote.note, 'utf8') === 'SYNTHETIC_JOINT_DATA' && remote.effects.length === 1);
  check('远端返回来源与宿主回执不被自报元数据覆盖', remoteWrite.result._meta.agentguard.source && remoteWrite.result._meta.agentguard.instruction_authority === 'none' && remoteWrite.result._meta.agentguard.downstream_metadata.agentguard.outcome === 'forged');
  remote.state.response = 'sse';
  const remoteRead = await invoke('mcp__remote__read_note', {});
  check('生产路径经SSE握手清单和工具返回读取同一远端内容', remoteRead.result._meta.agentguard.outcome === 'success' && remoteRead.result.structuredContent.value === 'SYNTHETIC_JOINT_DATA');
  const localTarget = join(fixture.work, 'remote-result.txt');
  const localWrite = await invoke('mcp__filesystem__write_file', { path: localTarget, content: remoteRead.result.structuredContent.value });
  check('远端结果写入本地隔离副本但原件未自动变化', localWrite.result._meta.agentguard.outcome === 'success' && !await exists(localTarget) && await readFile(join(session.snapshot, 'remote-result.txt'), 'utf8') === 'SYNTHETIC_JOINT_DATA');
  const workspace = (await session.workspaceStatus()).workspaces[0]; const preview = await session.previewWorkspace(workspace.id ?? workspace.workspace_id);
  assert.equal((await session.applyReview(preview)).status, 200);
  check('独立预览批准后完整往返结果在宿主原件读回', await readFile(localTarget, 'utf8') === 'SYNTHETIC_JOINT_DATA');
  remote.state.failNext = 'disconnect';
  const disconnected = await invoke('mcp__remote__write_note', { text: 'REMOTE_COMMITTED_BEFORE_DISCONNECT' });
  check('远端已写入却断连时保持未知并暂停', disconnected.result._meta.agentguard.outcome === 'unknown' && disconnected.result._meta.agentguard.dispatched === true && await readFile(remote.note, 'utf8') === 'REMOTE_COMMITTED_BEFORE_DISCONNECT' && (await stats()).session_state === 'paused');
  const countAfterDisconnect = remote.requests.length; await delay(250);
  const refusedPaused = record(await call('mcp__remote__write_note', { text: 'MUST_NOT_RETRY' }));
  check('未知状态没有自动重发且暂停后的新调用被拒', remote.requests.length === countAfterDisconnect && refusedPaused.result._meta.agentguard.dispatched === false);
  await resume(); const reconciled = await invoke('mcp__remote__read_note', {});
  check('新批准的独立读回确认原未知动作真实效果', reconciled.result.structuredContent.value === 'REMOTE_COMMITTED_BEFORE_DISCONNECT' && remote.effects.filter(e => e.tool === 'write_note').length === 2);
  remote.state.failNext = 'bad_output'; const badOutput = await invoke('mcp__remote__read_note', {});
  check('错误输出Schema保留未知并暂停', badOutput.result._meta.agentguard.outcome === 'unknown' && (await stats()).session_state === 'paused'); await resume();
  remote.state.failNext = 'redirect'; const redirect = await invoke('mcp__remote__read_note', {});
  check('远端重定向被拒且不访问元数据目标', redirect.result._meta.agentguard.outcome === 'unknown' && JSON.stringify(redirect.result.content).includes('MCP_REMOTE_REDIRECT')); await resume();
  const hanging = call('mcp__remote__hang', {}), hangPending = await pendingFor(hanging); assert.equal((await answer(hangPending)).status, 200);
  let deadline = Date.now() + 10000; while (!remote.state.hang) { assert.ok(Date.now() < deadline); await delay(20); }
  assert.equal((await session.transition('pause')).status, 200); const hangResult = record(await hanging);
  check('运行中暂停撤销本地通道但结果仍为未知', hangResult.result._meta.agentguard.outcome === 'unknown');
  remote.state.hang(); deadline = Date.now() + 10000; while (remote.effects.filter(e => e.tool === 'hang-finished').length < 1) { assert.ok(Date.now() < deadline); await delay(20); }
  check('实证远端可能在本地暂停后继续，不能伪称停止成功', remote.effects.filter(e => e.tool === 'hang-started').length === 1 && remote.effects.filter(e => e.tool === 'hang-finished').length === 1); await resume();
  const late = call('mcp__remote__write_note', { text: 'MUST_NOT_REVOKED' }), latePending = await pendingFor(late); const countBeforeRevoke = remote.requests.length;
  const registry = (await session.operatorRequest('/registry/status')).value.services.find(s => s.service_id === 'remote-fixture');
  assert.equal((await session.operatorRequest('/registry/revoke', { service_id: registry.service_id, registration_id: registry.registration_id })).status, 200);
  const cancelled = record(await late);
  check('登记撤销和迟到批准均不产生远程请求', cancelled.result._meta.agentguard.dispatched === false && (await answer(latePending)).status === 409 && remote.requests.length === countBeforeRevoke);
  await resume();
  // 撤销后的同清单重新观测需要新进程；恢复不会重放上次工具动作。
  await session.close(); session = await start(); await approveService('remote-fixture');
  const crashing = call('mcp__remote__hang', {}); const crashObserved = crashing.catch(e => ({ expectedDisconnect: String(e) }));
  const crashPending = await pendingFor(crashing); assert.equal((await answer(crashPending)).status, 200);
  deadline = Date.now() + 10000; while (!remote.state.hang) { assert.ok(Date.now() < deadline); await delay(20); }
  const hangsBefore = remote.effects.filter(e => e.tool === 'hang-started').length;
  session.child.kill('SIGKILL'); record(await crashObserved); oldSession = session; session = await start();
  check('网关真实崩溃重启没有重放远端动作', remote.effects.filter(e => e.tool === 'hang-started').length === hangsBefore);
  const events = JSON.parse(execFileSync('/usr/bin/python3', ['-c', "import sqlite3,json,sys;db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);print(json.dumps([json.loads(r[0]) for r in db.execute('select event_json from audit_events')]))", fixture.auditDb], { encoding: 'utf8' }));
  check('持久日志将崩溃前未结束远端动作恢复为未知', events.some(e => e.action_sha256 === crashPending.action_sha256 && e.outcome === 'unknown' && e.recovery === 'process_restarted_without_terminal_receipt'));
  remote.state.hang(); await delay(100);
  remote.state.manifest += 1; const changed = await invoke('mcp__remote__read_note', {});
  const status = (await session.operatorRequest('/registry/status')).value;
  check('运行前实际清单变化撤销旧认可且工具调用未发出', changed.result._meta.agentguard.outcome === 'unknown' && status.services.find(s => s.service_id === 'remote-fixture').state === 'pending' && remote.requests.at(-1).method === 'tools/list');
  await session.close(); session = await start(); await approveService('remote-fixture');
  const timeoutStarted = Date.now(), beforeTimeout = remote.effects.filter(e => e.tool === 'hang-started').length;
  const timed = await invoke('mcp__remote__hang', {});
  report.actualTimeoutMs = Date.now() - timeoutStarted;
  check('生产总时限到达后未知暂停且没有重发', timed.result._meta.agentguard.outcome === 'unknown' && JSON.stringify(timed.result.content).includes('MCP_REMOTE_TIMEOUT') && report.actualTimeoutMs >= 29000 && report.actualTimeoutMs < 40000 && remote.effects.filter(e => e.tool === 'hang-started').length === beforeTimeout + 1);
  const beforeTimeoutFinish = remote.effects.filter(e => e.tool === 'hang-finished').length;
  remote.state.hang(); deadline = Date.now() + 10000;
  while (remote.effects.filter(e => e.tool === 'hang-finished').length === beforeTimeoutFinish) { assert.ok(Date.now() < deadline); await delay(20); }
  await resume();
  const blocked = call('mcp__remote__write_note', { text: 'MUST_NOT_AUDIT_FAILED' }), blockedPending = await pendingFor(blocked), beforeBlocked = remote.requests.length;
  execFileSync('/usr/bin/python3', ['-c', "import sqlite3,sys;db=sqlite3.connect(sys.argv[1]);db.execute(\"CREATE TRIGGER remote_test_block BEFORE INSERT ON audit_events WHEN NEW.event_type='GatewayExecutionStarted' BEGIN SELECT RAISE(ABORT,'synthetic start failure'); END\");db.commit()", fixture.auditDb]);
  assert.equal((await answer(blockedPending)).status, 200); const auditFailed = record(await blocked);
  check('实际开始审计失败时零远程请求并锁存故障', auditFailed.result._meta.agentguard.dispatched === false && remote.requests.length === beforeBlocked && (await stats()).audit_write_failed === true);
  execFileSync('/usr/bin/python3', ['-c', "import sqlite3,sys;db=sqlite3.connect(sys.argv[1]);db.execute('DROP TRIGGER remote_test_block');db.commit()", fixture.auditDb]);
  report.finalRemoteNote = await readFile(remote.note, 'utf8'); report.finalHostResult = await readFile(localTarget, 'utf8');
  check('最终两端账目与既有输入一致且所有服务端验签无错', report.finalRemoteNote === 'REMOTE_COMMITTED_BEFORE_DISCONNECT' && report.finalHostResult === 'SYNTHETIC_JOINT_DATA' && await readFile(join(fixture.work, 'source.txt'), 'utf8') === 'SYNTHETIC_JOINT_DATA' && remote.errors.length === 0 && remote.requests.every(r => r.auth_verified));
  report.finishedAt = new Date().toISOString();
} catch (e) { report.error = String(e.stack || e); process.exitCode = 1; }
finally {
  if (session) { report.stderr = session.stderrTail; await session.close().catch(e => { report.closeError = String(e); process.exitCode = 1; }); }
  if (oldSession) await oldSession.close().catch(e => { report.oldCloseError = String(e); process.exitCode = 1; });
  if (remote) { report.requests = remote.requests; report.effects = remote.effects; report.serverErrors = remote.errors; await remote.close(); }
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ checks: report.checks.length, passed: report.checks.filter(c => c.passed).length, error: report.error, out }));
}

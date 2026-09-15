// 生产 CLI 和实际 Docker／本地 MCP／远程 HTTPS；仅合成资料，批准由本脚本执行。
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile, access, chmod } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join, isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { WorkspaceSession, createWorkspaceFixture, DEFAULT_IMAGE } from './agd-workspace-session.mjs';
import { remoteFixture } from './agd-mcp-remote-fixture.mjs';
import { ruleFixture, rule, sha, packageHash } from './agd-rule-package-fixture.mjs';
const option = name => { assert.ok(process.argv.includes(name)); return process.argv[process.argv.indexOf(name) + 1]; };
const out = option('--out'), binary = option('--binary'), cli = option('--cli'), source = option('--package');
assert.ok([out, binary, cli, source].every(isAbsolute)); await mkdir(out, { mode: 0o700 });
const report = { scope: '真实CLI、复用镜像、本地官方MCP、自有HTTPS；脚本批准，不代表原生人工验收', binarySha256: sha(await readFile(binary)), cliSha256: sha(await readFile(cli)), image: DEFAULT_IMAGE, checks: [], receipts: [] };
const check = (name, value) => { report.checks.push({ name, passed: !!value }); assert.ok(value, name); console.error(`通过：${name}`); };
const exists = async path => { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
const until = async check => { const end = Date.now() + 15000; while (Date.now() < end) { if (await check()) return; await delay(25); } throw new Error('实际效果等待超时'); };
let session, remote, packages;
try {
  const fixture = await createWorkspaceFixture({ name: 'runtime-rule-policy', seed: {
    'input.txt': 'SYNTHETIC_RULE_INPUT',
    'pending.cjs': "require('fs').writeFileSync('pending-effect.txt','MUST_NOT_STALE')",
    'slow.cjs': "const fs=require('fs');fs.writeFileSync('slow-started.txt','started');setTimeout(()=>fs.writeFileSync('slow-finished.txt','finished'),8000)",
  } });
  report.fixture = fixture.temporaryRoot; report.auditDb = fixture.auditDb;
  const plans = JSON.parse(await readFile(fixture.plans)); plans.plans[0].allow.push('network_egress'); plans.plans[0].scope.hosts = ['mcp.localhost']; await writeFile(fixture.plans, JSON.stringify(plans));
  packages = await ruleFixture(fixture.control, cli); await packages.apply(packages.release(1)); report.store = packages.store;
  remote = await remoteFixture(fixture.control);
  const serviceConfig = join(fixture.control, 'services.json');
  await writeFile(serviceConfig, JSON.stringify({ version: 1, services: [{ service_id: 'official-filesystem', namespace: 'filesystem', package_path: source, package_id: 'official-filesystem', package_version: '2026.8.31', entrypoint: 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js', arguments: [fixture.work] }], remote_services: [remote.config] }));
  const start = () => WorkspaceSession.start({ binary, fixture, mcpServiceConfig: serviceConfig, rulePackageConfig: packages.config, confirmSeconds: 40, startupTimeoutMs: 60000 });
  await chmod(packages.config, 0o644);
  let rejected = false; try { const bad = await start(); await bad.close(); } catch (e) { rejected = String(e).includes('仅本人可读写'); }
  check('宽权限配置在零远端请求时被拒绝', rejected && remote.requests.length === 0); await chmod(packages.config, 0o600);
  session = await start(); report.snapshot = session.snapshot; const originalSession = session.sessionId;
  const call = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
  const record = value => { report.receipts.push(value); return value; };
  const pendingFor = promise => Promise.race([session.waitForPending(), promise.then(v => { throw new Error('预期批准但已返回：' + JSON.stringify(v)); })]);
  const approve = pending => session.operatorRequest('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce });
  const write = (name, contents) => session.callTool('write_file', { path: join(fixture.work, name), contents }, { approval: 'approve' });
  const ok = await write('allowed.txt', 'ALLOWED'); check('有效包允许真实隔离副本写入', ok.ok && await readFile(join(session.snapshot, 'allowed.txt'), 'utf8') === 'ALLOWED');
  const blocked = record(await write('blocked.txt', 'PKG_BLOCK')); check('完整写入正文命中签名规则且零文件副作用', !blocked.ok && !await exists(join(session.snapshot, 'blocked.txt')));
  let ws = (await session.workspaceStatus()).workspaces[0], preview = await session.previewWorkspace(ws.id ?? ws.workspace_id);
  report.receipts.push(preview); const oldPolicy = preview.binding.action.policy_version;
  await packages.apply(packages.release(2));
  check('规则更新后旧回写批准失效且原件未写入', (await session.applyReview(preview)).status === 409 && !await exists(join(fixture.work, 'allowed.txt')));
  preview = await session.previewWorkspace(ws.id ?? ws.workspace_id);
  check('新预览绑定新代次并真实回写', preview.binding.action.policy_version !== oldPolicy && (await session.applyReview(preview)).status === 200 && await readFile(join(fixture.work, 'allowed.txt'), 'utf8') === 'ALLOWED');
  const v3 = packages.release(3, [rule('PKG_BLOCK'), rule('pending.cjs', true), { ...rule('slow.cjs', true), id: 'PKG-SLOW' }]);
  await packages.apply(v3);
  const pendingCall = call('run_shell', { argv: ['/usr/local/bin/node', join(fixture.work, 'pending.cjs')], cwd: fixture.work }); const pending = await pendingFor(pendingCall); record(pending);
  check('批准展示准确签名包与发布代次', pending.binding.action.parameters.rule_package.status.last_sequence === 3 && pending.binding.action.parameters.rule_package.instruction_authority === 'none');
  await packages.apply(packages.release(4));
  await packages.apply({ ...packages.release(5), operation: { action: 'recover', digest: packageHash(v3.operation.package), reason: '合成恢复核对' } });
  assert.equal((await approve(pending)).status, 200); const stale = record(await pendingCall);
  check('恢复相同包正文也不能复活旧命令批准', stale.result._meta.agentguard.dispatched === false && !await exists(join(session.snapshot, 'pending-effect.txt')));
  const sql = statement => execFileSync('python3', ['-c', 'import sqlite3,sys\nc=sqlite3.connect(sys.argv[1]);c.executescript(sys.argv[2]);c.close()', packages.store, statement]);
  sql("CREATE TRIGGER reject_update BEFORE INSERT ON package_updates BEGIN SELECT RAISE(FAIL, 'synthetic_write_failure'); END;");
  const v6 = packages.release(6); const failed = await packages.apply(v6, false); sql('DROP TRIGGER reject_update;');
  check('实际SQL写入失败保留原包和可用会话', failed.includes('synthetic_write_failure') && (await packages.status()).last_sequence === 5 && (await write('after-failure.txt', 'STILL_USABLE')).ok);
  const running = call('run_shell', { argv: ['/usr/local/bin/node', join(fixture.work, 'slow.cjs')], cwd: fixture.work }); const slowPending = await pendingFor(running); record(slowPending); assert.equal((await approve(slowPending)).status, 200);
  await until(() => exists(join(session.snapshot, 'slow-started.txt')));
  const busy = await packages.apply(v6, false);
  check('真实动作运行时外部更新明确失败且未提交', busy.includes('database is locked') && (await packages.status()).last_sequence === 5 && !await exists(join(session.snapshot, 'slow-finished.txt')));
  const completed = record(await running); check('原动作真实结束并保留其策略绑定', completed.result._meta.agentguard.outcome === 'success' && await readFile(join(session.snapshot, 'slow-finished.txt'), 'utf8') === 'finished');
  await packages.apply(v6); check('动作结束后相同更新才成功提交', (await packages.status()).last_sequence === 6);
  for (const service_id of ['official-filesystem', 'remote-fixture']) {
    const review = await session.operatorRequest('/registry/review', { service_id }); assert.equal(review.status, 200, JSON.stringify(review));
    const v = review.value; assert.equal((await session.operatorRequest('/registry/decide', { service_id, review_id: v.review_id, review_nonce: v.review_nonce, manifest_sha256: v.manifest_sha256, approve: true })).status, 200);
  }
  const remoteCall = call('mcp__remote__write_note', { text: 'MUST_NOT_OLD_POLICY' }); const rp = await pendingFor(remoteCall); record(rp); const count = remote.requests.length;
  await packages.apply(packages.release(7)); assert.equal((await approve(rp)).status, 200);
  check('远程批准后更新导致零新连接请求和零副作用', record(await remoteCall).result._meta.agentguard.dispatched === false && remote.requests.length === count && remote.effects.length === 0);
  const invoke = async (name, args) => { const running = call(name, args), p = await pendingFor(running); assert.equal((await approve(p)).status, 200); return record(await running); };
  const sent = await invoke('mcp__remote__write_note', { text: 'NEW_POLICY_EFFECT' }); check('新规则代次批准后远端真实写入', sent.result._meta.agentguard.outcome === 'success' && await readFile(remote.note, 'utf8') === 'NEW_POLICY_EFFECT');
  const localTarget = join(fixture.work, 'local-mcp.txt');
  const localCall = call('mcp__filesystem__write_file', { path: localTarget, content: 'STALE' }); const lp = await pendingFor(localCall); record(lp);
  await packages.apply(packages.release(8)); assert.equal((await approve(lp)).status, 200);
  check('本地MCP旧批准没有派发容器服务或写入副本', record(await localCall).result._meta.agentguard.dispatched === false && !await exists(join(session.snapshot, 'local-mcp.txt')));
  const local = await invoke('mcp__filesystem__write_file', { path: localTarget, content: 'CURRENT' }); check('本地MCP新批准真实写入且原件保持独立', local.result._meta.agentguard.outcome === 'success' && await readFile(join(session.snapshot, 'local-mcp.txt'), 'utf8') === 'CURRENT' && !await exists(localTarget));
  const beforeRevoke = await packages.status(); await packages.apply({ ...packages.release(9), operation: { action: 'revoke', digests: [beforeRevoke.active_sha256], reason: '合成撤销' } });
  const countBefore = remote.requests.length;
  const refused = record(await call('read_file', { path: join(fixture.work, 'input.txt') })); const remoteRefused = record(await call('mcp__remote__read_note', {}));
  check('撤销有效包后内建及远程动作全部拒绝', refused.result._meta.agentguard.dispatched === false && remoteRefused.result._meta.agentguard.dispatched === false && remote.requests.length === countBefore);
  await packages.apply(packages.release(10)); check('新有效发布恢复后同一会话继续且不会隐式重启', (await session.callTool('read_file', { path: join(fixture.work, 'input.txt') })).ok && (await session.rpc('gateway/stats')).result.host_session_id === originalSession);
  report.remoteRequests = remote.requests; report.remoteEffects = remote.effects;
  report.passed = true;
} catch (error) { report.error = error.stack; throw error; }
finally {
  if (packages) { report.packageCommands = packages.commands; report.packages = packages.packages; }
  if (session) { report.sessionClosed = await session.close({ preserveSnapshots: true }); }
  if (remote) await remote.close();
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
}

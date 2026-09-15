// 实际网关、既有 Docker 镜像和崩溃边界；读取器只读核对，批准等待期间不发出动作。
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve, isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { WorkspaceSession, createWorkspaceFixture } from './agd-workspace-session.mjs';
import { rule } from './agd-rule-package-fixture.mjs';
const exec = promisify(execFile);
const root = resolve(import.meta.dirname, '../..');
const option = name => { assert(process.argv.includes(name)); return process.argv[process.argv.indexOf(name) + 1]; };
const binary = option('--binary'), out = option('--out');
assert(isAbsolute(binary) && isAbsolute(out)); await mkdir(out, { mode: 0o700 });
const report = { binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), checks: [], passed: false };
const check = (name, value) => { report.checks.push({ name, passed: !!value }); assert(value, name); console.log(`通过：${name}`); };
const exists = async path => { try { await access(path); return true; } catch { return false; } };
const copyLog = async (database, name) => {
  const target = join(out, `${name}.db`);
  const code = "import sqlite3,sys; source=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); target=sqlite3.connect(sys.argv[2]); source.backup(target);target.close();source.close()";
  await exec('/Library/Developer/CommandLineTools/usr/bin/python3', ['-c', code, database, target]);
  return target;
};
async function view(database, name) {
  const output = join(out, `${name}-view.json`);
  const result = await exec(join(root, 'scripts/bootstrap-rust.sh'), ['--', 'cargo', 'test', '--locked', '-p', 'guard-gateway', '--lib', 'execution_view::tests::读取实际生产日志生成证据视图', '--', '--include-ignored'], {
    cwd: root, env: { ...process.env, DEVELOPER_DIR: '/Library/Developer/CommandLineTools', AGENTGUARD_EXECUTION_LOG: database, AGENTGUARD_EXECUTION_VIEW: output }, timeout: 60000,
  });
  await writeFile(join(out, `${name}-reader.log`), result.stdout + result.stderr);
  return JSON.parse(await readFile(output));
}
let session;
try {
  const fixture = await createWorkspaceFixture({ name: 'execution-evidence', seed: {
    'slow.cjs': "const fs=require('fs');fs.writeFileSync('started-marker.txt','ACTUALLY_STARTED');setTimeout(()=>fs.writeFileSync('finished-marker.txt','FINISHED'),30000);",
  } });
  report.fixture = fixture.temporaryRoot; report.auditDb = fixture.auditDb;
  await writeFile(fixture.rules, JSON.stringify({ version: '1.0', rules: [rule('WAIT_APPROVAL', true)] }));
  const start = () => WorkspaceSession.start({ binary, fixture, confirmSeconds: 120 });
  session = await start();
  const pendingCall = session.rpc('tools/call', { name: 'write_file', arguments: { path: join(fixture.work, 'WAIT_APPROVAL.txt'), contents: 'WAIT_APPROVAL' }, _meta: { agentguard_session_id: session.sessionId } });
  const waiting = await session.waitForPending();
  const waitingView = await view(fixture.auditDb, 'waiting-live');
  check('存活网关等待批准时只读读取不派发动作', !session.exited && waitingView.actions.some(a => a.classification === 'alert' && a.state === 'decision_without_terminal') && !await exists(join(session.snapshot, 'WAIT_APPROVAL.txt')));
  check('读取后仍保留同一待批准请求', (await session.waitForPending()).id === waiting.id);
  await copyLog(fixture.auditDb, 'waiting');
  await session.kill(); await pendingCall.catch(() => {}); await session.close({ preserveSnapshots: true });
  session = await start();
  const running = session.rpc('tools/call', { name: 'run_shell', arguments: { argv: ['/usr/local/bin/node', join(fixture.work, 'slow.cjs')], cwd: fixture.work }, _meta: { agentguard_session_id: session.sessionId } });
  const deadline = Date.now() + 20000;
  while (!await exists(join(session.snapshot, 'started-marker.txt'))) { assert(Date.now() < deadline, '实际命令未开始'); await delay(25); }
  const live = await view(fixture.auditDb, 'started-live');
  check('实际容器动作已经开始但未返回时保持结果未知', !session.exited && live.actions.some(a => a.classification === 'unknown' && a.state === 'started_without_terminal') && !await exists(join(session.snapshot, 'finished-marker.txt')));
  await session.kill(); await running.catch(() => {}); await session.close({ preserveSnapshots: true });
  await copyLog(fixture.auditDb, 'crashed');
  const crashed = await view(fixture.auditDb, 'crashed');
  check('崩溃后读取不会补写终态或声称无副作用', crashed.records_verified === live.records_verified && crashed.actions.some(a => a.state === 'started_without_terminal'));
  session = await start();
  const recovered = await view(fixture.auditDb, 'recovered');
  check('只有真正重启网关才追加未知恢复回执', recovered.records_verified === crashed.records_verified + 1 && recovered.actions.some(a => a.state === 'effects_unknown' && a.classification === 'unknown'));
  check('恢复仍保留判决但不会复活批准或重放命令', recovered.actions.some(a => a.state === 'decision_without_terminal') && !await exists(join(session.snapshot, 'started-marker.txt')));
  await copyLog(fixture.auditDb, 'recovered');
  report.passed = true;
} catch (error) { report.error = error.stack; throw error; }
finally {
  if (session) report.closed = await session.close({ preserveSnapshots: true });
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2));
}

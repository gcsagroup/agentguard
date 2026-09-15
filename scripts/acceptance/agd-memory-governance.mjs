// AGD-026：真实网关独立操作者通道；批准仅来自本脚本核对后的合成动作。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, WorkspaceSession, DEFAULT_IMAGE } from './agd-workspace-session.mjs';

const run = promisify(execFile);
const sha = data => createHash('sha256').update(data).digest('hex');
const option = name => { const index = process.argv.indexOf(name); assert.ok(index > 0, `缺少 ${name}`); return process.argv[index + 1]; };
const binary = resolve(option('--binary')), out = resolve(option('--out'));
await mkdir(out, { recursive: false, mode: 0o700 });
const fixture = await createWorkspaceFixture({ name: 'memory-governance', seed: { 'manual.md': '# 合成文档\n治理验收资料。\n' } });
await writeFile(fixture.plans, JSON.stringify({ plans: [{ task_profile: fixture.taskProfile, allow: ['persist_memory', 'recall_memory'],
  scope: { data_keys: ['preference', 'document'], paths: { read: [fixture.work], write: [] } } }] }));
fixture.inputs.plansSha256 = sha(await readFile(fixture.plans));
const pair = generateKeyPairSync('ed25519');
const secret = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex');
const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
const config = { schema_version: 1, scope_id: 'memory-governance-026', database: join(fixture.control, 'memory.db'),
  witness: join(fixture.control, 'memory-head.json'), signing_key: join(fixture.control, 'memory-secret.hex'), public_key: join(fixture.control, 'memory-public.hex'),
  allow_read: true, allow_write: true, encryption: { mode: 'plaintext_test' } };
const configPath = join(fixture.control, 'memory.json');
for (const [path, value] of [[config.signing_key, secret], [config.public_key, publicKey], [configPath, JSON.stringify(config)]]) {
  await writeFile(path, value, { mode: 0o600 });
}
const report = { schema_version: 1, passed: false, binary, binary_sha256: sha(await readFile(binary)), fixture: fixture.temporaryRoot,
  memory_database: config.database, memory_witness: config.witness, config: configPath, execution_database: fixture.auditDb, public_key: publicKey, image: DEFAULT_IMAGE, inputs: fixture.inputs,
  scope: '实际 CLI/Docker、合成资料与脚本独立批准；不代表原生人工治理验收', sessions: [], seeds: [], requests: [], checks: [] };
let session;
const save = () => writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
async function start(initializeMemory = false) {
  session = await WorkspaceSession.start({ binary, fixture, memoryConfig: configPath, initializeMemory, confirmSeconds: 15 });
  report.sessions.push({ pid: session.child.pid, session_id: session.sessionId, instance_id: session.connection.instance_id, stats: session.statsAtStart });
  await save();
}
async function stop() {
  if (session) { report.sessions.at(-1).exit = await session.close({ preserveSnapshots: true }); session = null; await save(); }
}
const invoke = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
function good(value) { assert.equal(value.isError, false, JSON.stringify(value)); return JSON.parse(value.content[0].text); }
async function versions() {
  return Number((await run('python3', ['-c', "import sqlite3,sys;c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);print(c.execute(\"select count(*) from audit_events where event_type='MemoryVersionCommitted'\").fetchone()[0])", config.database])).stdout.trim());
}
async function seed(name, args) {
  const promise = invoke(name, args), pending = await session.waitForPending();
  assert.equal(actionSha256(pending.binding.action), pending.action_sha256);
  assert.equal(pending.binding.action.parameters.key, args.key);
  assert.equal(pending.binding.action.parameters.version, args.expected_version + 1);
  const reply = await session.operatorRequest('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce });
  assert.equal(reply.status, 200);
  const result = await promise; assert.equal(good(result.result).saved, true);
  report.seeds.push({ name, args, pending, result }); await save();
}
async function request(route, args, expected = 200, options = {}) {
  const body = { session_id: session.sessionId, ...args };
  const reply = await session.operatorRequest(`/memory/${route}`, body, options);
  report.requests.push({ route, body, expected, response: reply, authentication_negative: options.omitAuthorization === true,
    origin_negative: Boolean(options.headers?.Origin) }); await save();
  assert.equal(reply.status, expected, JSON.stringify(reply));
  if (expected === 200) {
    assert.equal(reply.value.service, 'agentguard-mcp'); assert.equal(reply.value.governance_protocol, 1);
    assert.equal(reply.value.instance_id, session.connection.instance_id); assert.equal(reply.value.session_id, session.sessionId);
  }
  return reply.value.data;
}
const reviewBody = review => ({ review_id: review.review_id, review_sha256: review.review_sha256, review_nonce: review.review_nonce });
async function preview(operation, expected_version, extra = {}) {
  const review = await request('preview', { operation, key: 'preference', expected_version, ...extra });
  assert.equal(review.review_sha256, actionSha256(review.action));
  assert.deepEqual(review.action.parameters, review.draft); assert.deepEqual(review.action.sources, review.draft.sources);
  assert.deepEqual(review.draft.label, { integrity: 'tainted', confidentiality: 'high' });
  assert.equal(review.draft.version, expected_version + 1); assert.equal(review.completed_effects, 'not_reverted');
  return review;
}

try {
  await start(true);
  for (const [expected_version, text] of [[0, '旧偏好：使用中文'], [1, '新偏好：逐项列出证据']]) {
    await seed('memory_write', { key: 'preference', expected_version, text, expires_at_ms: Date.now() + 300000 });
  }
  await seed('rag_import', { key: 'document', expected_version: 0, path: join(fixture.work, 'manual.md'), expires_at_ms: Date.now() + 300000 });
  assert.equal(await versions(), 3);
  await request('list', {}, 403, { omitAuthorization: true });
  await request('list', {}, 403, { headers: { Origin: 'https://untrusted.example.test' } });
  await request('list', { session_id: 'old-session' }, 409);
  await request('history', { key: 'preference', trusted: true }, 409);
  const list = await request('list', {}); assert.equal(list.total_keys, 2);
  const history = await request('history', { key: 'preference' });
  assert.equal(history.versions.length, 2); assert.equal(history.versions[0].content.text, '旧偏好：使用中文');
  assert.ok(history.versions.every(v => v.sources.length && v.approval.approval_id));
  for (const name of ['memory_list', 'memory_history', 'memory_apply']) {
    const reply = await invoke(name, {}); assert.ok(reply.error || reply.result?.isError);
  }
  report.checks.push('认证、Origin、旧会话及参数伪造拒绝；历史只经独立宿主通道查看');

  const discarded = await preview('quarantine', 2);
  assert.equal(await versions(), 3);
  assert.equal((await request('discard', reviewBody(discarded))).discarded, true);
  await request('apply', reviewBody(discarded), 409);
  const tampered = await preview('quarantine', 2);
  await request('apply', { ...reviewBody(tampered), review_nonce: '0'.repeat(64) }, 409);
  assert.equal(await versions(), 3);
  const quarantined = await preview('quarantine', 2);
  const applied = await request('apply', reviewBody(quarantined));
  assert.equal(good(applied.execution).state, 'quarantined');
  await request('apply', reviewBody(quarantined), 409);
  assert.equal(await versions(), 4);
  assert.equal(good((await invoke('memory_read', { key: 'preference' })).result).found, false);
  const oldSession = session.sessionId; await stop(); await start(); assert.notEqual(session.sessionId, oldSession);
  assert.equal(good((await invoke('memory_read', { key: 'preference' })).result).found, false);
  report.checks.push('丢弃及错随机值不写入；批准隔离跨进程生效，批准重放拒绝');

  const restored = await preview('restore', 3, { source_version: 1, expires_at_ms: Date.now() + 300000 });
  assert.equal(JSON.parse(restored.draft.content).text, '旧偏好：使用中文');
  for (const source of history.versions[1].sources) assert.ok(restored.draft.sources.some(s => JSON.stringify(s) === JSON.stringify(source)));
  assert.equal(good((await request('apply', reviewBody(restored))).execution).version, 4);
  assert.equal(await versions(), 5);
  assert.equal(good((await invoke('memory_read', { key: 'preference' })).result).memory.content.text, '旧偏好：使用中文');
  const finalHistory = await request('history', { key: 'preference' });
  assert.equal(finalHistory.versions.length, 4);
  for (let i = 0; i < 2; i++) assert.deepEqual(finalHistory.versions[i], history.versions[i]);
  report.checks.push('恢复指定旧正文为新版本；历史、来源、污染标签和批准引用完整保留');

  const stale = await preview('revoke', 4);
  await seed('memory_write', { key: 'preference', expected_version: 4, text: '复核后的新版本', expires_at_ms: Date.now() + 300000 });
  await request('apply', reviewBody(stale), 409); assert.equal(await versions(), 6);
  const revoked = await preview('revoke', 5);
  assert.equal(good((await request('apply', reviewBody(revoked))).execution).state, 'revoked');
  assert.equal(await versions(), 7);
  const cancelled = await preview('restore', 6, { source_version: 1, expires_at_ms: Date.now() + 300000 });
  assert.equal((await session.transition('pause')).status, 200);
  await request('apply', reviewBody(cancelled), 409); assert.equal(await versions(), 7);
  report.checks.push('复核后内容变化、撤销及暂停后的旧批准均按实际存储核对');
  await stop(); await start();
  assert.equal(good((await invoke('memory_read', { key: 'preference' })).result).found, false);
  const final = await request('history', { key: 'preference' }); assert.equal(final.current_version, 6);
  report.final_history = final; await stop();
  assert.equal(report.sessions.length, 3); assert.ok(report.sessions.every(s => s.exit.code === 0));
  assert.ok(!JSON.stringify(report).includes(secret));
  report.passed = true;
} catch (error) {
  report.error = session ? session.redact(error.stack) : String(error.stack); process.exitCode = 1;
} finally {
  await stop().catch(error => { report.cleanup_error = String(error); process.exitCode = 1; });
  await save(); console.log(JSON.stringify({ passed: report.passed, checks: report.checks, error: report.error, out }));
}

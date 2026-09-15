// AGD-027：合成记忆与委托的真实重启、待批准崩溃和主体密钥撤销。只操作本脚本创建的工作区。
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, WorkspaceSession, DEFAULT_IMAGE } from './agd-workspace-session.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const option = name => { const i = process.argv.indexOf(name); assert.ok(i > 0, `缺少 ${name}`); return process.argv[i + 1]; };
const binary = resolve(option('--binary')), out = resolve(option('--out'));
await mkdir(out, { recursive: false, mode: 0o700 });
const script = await readFile(fileURLToPath(import.meta.url));
await writeFile(join(out, 'harness-source.mjs'), script);
const fixture = await createWorkspaceFixture({ name: 'm3-recovery', seed: { 'input.txt': 'AGD_M3_NORMAL_READ 中文\n' } });
const input = join(fixture.work, 'input.txt').replace(/^\/private(?=\/var\/)/, '');
await writeFile(fixture.plans, JSON.stringify({ plans: [{ task_profile: fixture.taskProfile, allow: ['persist_memory', 'recall_memory', 'run_shell'],
  scope: { data_keys: ['preference'], paths: { read: [fixture.work], write: [] } } }] }));
fixture.inputs.plansSha256 = sha(await readFile(fixture.plans));
const keys = {}, publics = {};
for (const actor of ['memory', 'authority', 'A', 'B-old', 'B-new']) {
  keys[actor] = generateKeyPairSync('ed25519');
  publics[actor] = keys[actor].publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
}
const privateHex = actor => keys[actor].privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex');
const memory = { schema_version: 1, scope_id: 'm3-recovery', database: join(fixture.control, 'memory.db'),
  witness: join(fixture.control, 'memory-head.json'), signing_key: join(fixture.control, 'memory-key.hex'),
  public_key: join(fixture.control, 'memory-public.hex'), allow_read: true, allow_write: true, encryption: { mode: 'plaintext_test' } };
const memoryConfig = join(fixture.control, 'memory.json'), delegationConfig = join(fixture.control, 'delegation.json');
const rights = { read_files: [input], write_files: [], delete_files: [], delegate_to: ['B'] };
const childRights = { ...rights, delegate_to: [] };
const delegation = { version: 1, authority_id: 'm3-recovery-host', signing_key: join(fixture.control, 'authority-key.hex'),
  public_key: publics.authority, root_subject_id: 'A', target_id: 'm3-read', lifetime_ms: 300000,
  principals: [{ subject_id: 'A', public_key: publics.A, permissions: rights }, { subject_id: 'B', public_key: publics['B-old'], permissions: childRights }] };
for (const [path, data] of [[memory.signing_key, privateHex('memory')], [memory.public_key, publics.memory],
  [memoryConfig, JSON.stringify(memory)], [delegation.signing_key, privateHex('authority')]]) {
  await writeFile(path, data, { mode: 0o600 });
}
const ordered = value => Array.isArray(value) ? value.map(ordered) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])])) : value;
const bytes = (domain, value) => Buffer.from(`agentguard.delegation.${domain}.v1\0${JSON.stringify(ordered(value))}`);
const publicKey = hex => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
const report = { schema_version: 1, passed: false, binary, binary_sha256: sha(await readFile(binary)), script_sha256: sha(script),
  fixture: fixture.temporaryRoot, memory_config: memory, execution_database: fixture.auditDb, image: DEFAULT_IMAGE, publics, inputs: fixture.inputs,
  scope: 'macOS CLI、Docker Linux 执行器及合成密钥；脚本批准，主体撤销在停止旧宿主后重新加载配置生效，不代表热撤销或所有平台',
  sessions: [], grants: [], messages: [], memory_requests: [], checks: [] };
let session, root;
const sequences = new Map();
const save = () => writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
function grant(signed) {
  assert.ok(verify(null, bytes('grant', signed.grant), publicKey(publics.authority), Buffer.from(signed.signature, 'hex')));
  assert.equal(signed.grant.host_session_id, session.sessionId);
  report.grants.push(signed); sequences.set(signed.grant.grant_id, 1); return signed;
}
async function start(phase, { initializeMemory = false, withDelegation = false } = {}) {
  await writeFile(delegationConfig, JSON.stringify(delegation), { mode: 0o600 });
  session = await WorkspaceSession.start({ binary, fixture, memoryConfig, initializeMemory,
    delegationConfig: withDelegation ? delegationConfig : undefined, confirmSeconds: 30 });
  report.sessions.push({ phase, pid: session.child.pid, session_id: session.sessionId, instance_id: session.connection.instance_id,
    snapshot: session.snapshot, config: withDelegation ? structuredClone(delegation) : null, stats: session.statsAtStart });
  if (withDelegation) root = grant(session.statsAtStart.delegation.root_grant);
  await save();
}
async function stop() {
  if (session) { report.sessions.at(-1).exit = await session.close({ preserveSnapshots: true }); session = null; await save(); }
}
const invoke = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
const good = response => { assert.equal(response.result?.isError, false, JSON.stringify(response)); return response.result.content[0].text; };
function refused(response) { assert.equal(response.result?.isError, true, JSON.stringify(response)); assert.equal(response.result._meta?.agentguard?.dispatched, false); }
async function memoryRequest(route, args, expected = 200) {
  const body = { session_id: session.sessionId, ...args }, response = await session.operatorRequest(`/memory/${route}`, body);
  report.memory_requests.push({ phase: report.sessions.at(-1).phase, route, body, response }); await save();
  assert.equal(response.status, expected, JSON.stringify(response));
  return response.value.data;
}
async function history() {
  const value = await memoryRequest('history', { key: 'preference' });
  assert.equal(value.current_version, 1); assert.equal(value.versions.length, 1);
  assert.equal(value.versions[0].content.text, '已批准的中文偏好'); return value;
}
function envelope(actor, signedGrant, command, signingActor = actor, override = {}) {
  const g = signedGrant.grant, now = Date.now();
  const message = { version: 1, host_session_id: g.host_session_id, session_id: g.session_id, grant_id: g.grant_id,
    grant_sha256: sha(bytes('grant', g)), actor_id: actor, target_id: g.target_id, sequence: sequences.get(g.grant_id),
    issued_at_ms: now, expires_at_ms: Math.min(now + 60000, g.expires_at_ms), operation_sha256: sha(bytes('operation', command)), ...override };
  return { message, command, signature: sign(null, bytes('message', message), keys[signingActor].privateKey).toString('hex') };
}
async function send(name, signed, signingActor, expected) {
  const response = await invoke('delegation_send', signed);
  report.messages.push({ name, phase: report.sessions.at(-1).phase, signing_actor: signingActor, expected, envelope: signed, response }); await save();
  if (expected === 'accepted') { good(response); sequences.set(signed.message.grant_id, signed.message.sequence + 1); }
  else refused(response);
  return response;
}
async function delegate(name) {
  const signed = envelope('A', root, { operation: 'delegate', subject_id: 'B', permissions: childRights, expires_at_ms: Date.now() + 120000 });
  return grant(JSON.parse(good(await send(name, signed, 'A', 'accepted'))).grant);
}
try {
  await start('seed-and-crash', { initializeMemory: true });
  const seed = invoke('memory_write', { key: 'preference', expected_version: 0, text: '已批准的中文偏好', expires_at_ms: Date.now() + 3600000 });
  const pending = await session.waitForPending();
  assert.equal(actionSha256(pending.binding.action), pending.action_sha256);
  assert.equal(JSON.parse(pending.binding.action.parameters.content).text, '已批准的中文偏好');
  assert.equal((await session.operatorRequest('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce })).status, 200);
  report.seed = { pending, result: await seed }; assert.equal(JSON.parse(good(report.seed.result)).saved, true);
  report.initial_history = await history();
  const preview = await memoryRequest('preview', { operation: 'revoke', key: 'preference', expected_version: 1 });
  assert.equal(actionSha256(preview.action), preview.review_sha256);
  const unapproved = invoke('memory_write', { key: 'preference', expected_version: 1, text: '崩溃前未批准，不得保存', expires_at_ms: Date.now() + 3600000 })
    .then(response => ({ response }), error => ({ transport_error: session.redact(error.message) }));
  report.crash_pending = await session.waitForPending();
  assert.equal(JSON.parse(report.crash_pending.binding.action.parameters.content).text, '崩溃前未批准，不得保存');
  report.crash = await session.kill(); report.crash_result = await unapproved; assert.ok(report.crash_result.transport_error);
  await stop(); assert.equal(report.sessions.at(-1).exit.signal, 'SIGKILL');
  await start('old-key', { withDelegation: true });
  assert.deepEqual(await history(), report.initial_history);
  await memoryRequest('apply', { review_id: preview.review_id, review_sha256: preview.review_sha256, review_nonce: preview.review_nonce }, 409);
  const names = (await session.rpc('tools/list')).result.tools.map(t => t.name); assert.deepEqual(names, ['delegation_send']);
  const bypass = await invoke('memory_write', { key: 'preference', expected_version: 1, text: '不得绕过委托' });
  report.ordinary_tool_bypass = bypass; assert.ok(bypass.error || bypass.result?.isError);
  const oldChild = await delegate('old-key-delegate');
  const oldEnvelope = envelope('B', oldChild, { operation: 'read_file', path: input }, 'B-old');
  assert.equal(good(await send('old-key-normal', oldEnvelope, 'B-old', 'accepted')), 'AGD_M3_NORMAL_READ 中文\n');
  await stop();
  report.checks.push('实际 SIGKILL 后已批准记忆不丢失、未批准版本不保存、旧治理预览不能复用；委托入口不能绕回普通记忆工具');

  delegation.principals[1].public_key = publics['B-new'];
  await start('rotated-key', { withDelegation: true }); await history();
  await send('old-session-replay', oldEnvelope, 'B-old', 'refused');
  const newChild = await delegate('new-key-delegate');
  // 同一条新会话／新授权／序号正确的消息，只更换签名，排除旧会话先行拦截造成的假通过。
  const wrong = envelope('B', newChild, { operation: 'read_file', path: input }, 'B-old');
  const denied = await send('revoked-key-new-metadata', wrong, 'B-old', 'refused');
  assert.match(denied.result.content[0].text, /signature|签名/i);
  const right = { ...wrong, signature: sign(null, bytes('message', wrong.message), keys['B-new'].privateKey).toString('hex') };
  assert.equal(good(await send('replacement-key-same-message', right, 'B-new', 'accepted')), 'AGD_M3_NORMAL_READ 中文\n');
  await stop();
  report.checks.push('停旧进程后更换主体公钥；撤销旧密钥在正确的新会话／新授权下仍被拒绝，同一消息换新密钥可正常读取');

  delegation.principals = delegation.principals.filter(p => p.subject_id !== 'B');
  delegation.principals[0].permissions = { ...rights, delegate_to: [] };
  await start('removed-principal', { withDelegation: true }); await history();
  const removed = envelope('B', root, { operation: 'read_file', path: input }, 'B-new');
  const removedResult = await send('removed-subject-new-session', removed, 'B-new', 'refused');
  assert.match(removedResult.result.content[0].text, /主体|principal/);
  const forbidden = envelope('A', root, { operation: 'delegate', subject_id: 'B', permissions: childRights, expires_at_ms: Date.now() + 60000 });
  await send('removed-delegate', forbidden, 'A', 'refused');
  // 被拒绝的委托不得耗掉正常父主体消息序号。
  const normal = envelope('A', root, { operation: 'read_file', path: input });
  assert.equal(good(await send('parent-still-normal', normal, 'A', 'accepted')), 'AGD_M3_NORMAL_READ 中文\n');
  report.final_history = await history(); await stop();
  report.checks.push('移除主体后的新宿主拒绝其消息和再次委托，父主体读取仍正常；记忆签名历史保持一致');
  assert.equal(report.sessions.length, 4);
  assert.equal(new Set(report.sessions.map(s => s.session_id)).size, 4);
  assert.ok(report.sessions.slice(1).every(s => s.exit.code === 0));
  assert.equal(await readFile(input, 'utf8'), 'AGD_M3_NORMAL_READ 中文\n');
  const body = JSON.stringify(report); for (const actor of Object.keys(keys)) assert.ok(!body.includes(privateHex(actor)));
  report.passed = true;
} catch (error) { report.error = session ? session.redact(error.stack) : String(error.stack); process.exitCode = 1; }
finally {
  await stop().catch(error => { report.cleanup_error = String(error); process.exitCode = 1; });
  await save(); console.log(JSON.stringify({ passed: report.passed, checks: report.checks, error: report.error, out }));
}

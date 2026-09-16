// 将已冻结的中文图片送入真实隔离解析、独立批准与两进程检索；不调用模型。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, WorkspaceSession } from './agd-workspace-session.mjs';

const run = promisify(execFile), sha = value => createHash('sha256').update(value).digest('hex');
const option = key => { const i = process.argv.indexOf(key); assert.ok(i > 0, `缺少 ${key}`); return process.argv[i + 1]; };
const binary = resolve(option('--binary')), out = resolve(option('--out')), fixtures = resolve(option('--fixtures'));
const qualityPath = resolve(option('--quality')), image = option('--image');
assert.match(image, /^sha256:[a-f0-9]{64}$/);
await mkdir(out, { recursive: false, mode: 0o700 });
const quality = JSON.parse(await readFile(qualityPath)), manifest = JSON.parse(await readFile(join(fixtures, 'manifest.json')));
assert.equal(quality.passed, true); assert.equal(quality.manifest_sha256, sha(await readFile(join(fixtures, 'manifest.json'))));
const parserSha = sha(await readFile(new URL('../../crates/guard-gateway/src/document_parser.py', import.meta.url)));
assert.equal(parserSha, quality.parser_sha256);
const selected = ['simplified-png', 'traditional-upside-down'];
const seed = {};
for (const name of [...selected, 'blank']) {
  const c = manifest.cases.find(c => c.name === name); assert.ok(c);
  seed[c.file] = await readFile(join(fixtures, c.file)); assert.equal(sha(seed[c.file]), c.sha256);
}
const fixture = await createWorkspaceFixture({ name: 'document-ocr-rag', seed, readOnly: true });
await writeFile(fixture.plans, JSON.stringify({ plans: [{ task_profile: fixture.taskProfile, goal: '中文图片的受控导入与重开检索',
  allow: ['run_shell', 'persist_memory', 'recall_memory'], scope: { data_keys: [...selected, 'blank'], paths: { read: [fixture.work], write: [] } } }] }));
const pair = generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
const configFile = join(fixture.control, 'memory.json');
const config = { schema_version: 1, scope_id: 'document-ocr-rag-test', database: join(fixture.control, 'memory.db'),
  witness: join(fixture.control, 'head.json'), signing_key: join(fixture.control, 'secret.hex'), public_key: join(fixture.control, 'public.hex'),
  allow_read: true, allow_write: true, encryption: { mode: 'plaintext_test' } };
await writeFile(config.signing_key, pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex'), { mode: 0o600 });
await writeFile(config.public_key, publicKey, { mode: 0o600 });
await writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
const report = { passed: false, binary, binary_sha256: sha(await readFile(binary)), parser_sha256: parserSha, image,
  quality: qualityPath, quality_sha256: sha(await readFile(qualityPath)), fixture: fixture.temporaryRoot, config: configFile,
  public_key: publicKey, sessions: [], imports: [], scope: '合成图片、真实 CLI/Docker、独立宿主脚本批准；非模型或原生验收' };
await writeFile(join(out, 'harness.mjs'), await readFile(new URL(import.meta.url)));
let session;
const save = () => writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
const invoke = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
const content = response => { assert.equal(response.result?.isError, false, JSON.stringify(response)); return JSON.parse(response.result.content[0].text); };
async function count() {
  return Number((await run('/usr/bin/python3', ['-c', "import sqlite3,sys;c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);print(c.execute(\"select count(*) from audit_events where event_type='MemoryVersionCommitted'\").fetchone()[0])", config.database])).stdout);
}
async function start(initializeMemory = false) {
  session = await WorkspaceSession.start({ binary, image, fixture, memoryConfig: configFile, initializeMemory, confirmSeconds: 20 });
  report.sessions.push({ pid: session.child.pid, session_id: session.sessionId, snapshot: session.snapshotRoot });
}
async function stop() {
  if (!session) return;
  report.sessions.at(-1).exit = await session.close({ preserveSnapshots: true });
  assert.equal(report.sessions.at(-1).exit.code, 0); session = null;
}
try {
  await start(true);
  for (const name of selected) {
    const c = manifest.cases.find(c => c.name === name), expected = quality.cases.find(c => c.case === name).result;
    const before = await count(), call = invoke('rag_import', { key: name, expected_version: 0, path: join(fixture.work, c.file), expires_at_ms: Date.now() + 900000 });
    const pending = await session.waitForPending({ timeoutMs: 18000 }), action = pending.binding.action;
    assert.equal(actionSha256(action), pending.action_sha256); assert.equal(action.session_id, session.sessionId);
    assert.equal(action.tool.service, 'agentguard-memory'); assert.equal(action.tool.name, 'memory_write');
    const draft = action.parameters, material = JSON.parse(draft.content), document = material.document;
    assert.equal(draft.key, name); assert.equal(draft.version, 1);
    assert.deepEqual(draft.label, { integrity: 'tainted', confidentiality: 'high' });
    assert.deepEqual(action.sources, draft.sources); assert.ok(draft.sources.length > 0);
    assert.equal(material.kind, 'parsed_document'); assert.equal(material.path, join(fixture.work, c.file));
    assert.equal(document.parser_version, 'agentguard-document/2'); assert.equal(document.parser_sha256, parserSha);
    assert.equal(document.image_sha256, image.slice(7)); assert.equal(document.source_sha256, c.sha256);
    assert.equal(document.source_bytes, seed[c.file].length); assert.equal(document.text, expected.text);
    assert.equal(document.text_sha256, sha(expected.text)); assert.equal(document.instruction_authority, 'none');
    assert.deepEqual(document.coverage, expected.coverage); assert.equal(document.metadata.ocr_rotation_degrees, expected.metadata.ocr_rotation_degrees);
    assert.equal(await count(), before);
    assert.equal((await session.operatorRequest('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce })).status, 200);
    assert.equal(content(await call).saved, true); assert.equal(await count(), before + 1);
    const read = content(await invoke('memory_read', { key: name })); assert.deepEqual(read.memory.content, material);
    report.imports.push({ key: name, file: c.file, before, after: await count(), action_sha256: pending.action_sha256, read }); await save();
  }
  const blank = manifest.cases.find(c => c.name === 'blank'), before = await count();
  const empty = await invoke('rag_import', { key: 'blank', expected_version: 0, path: join(fixture.work, blank.file), expires_at_ms: Date.now() + 900000 });
  assert.equal(empty.result?.isError, true); assert.equal(await count(), before);
  report.empty = { no_write: true, before, after: await count(), error: empty.result.content[0].text };
  await stop(); await start();
  report.queries = [];
  for (const [name, query] of [['simplified-png', '蓝鹭'], ['traditional-upside-down', '費用合計']]) {
    const previous = report.imports.find(c => c.key === name).read;
    assert.deepEqual(content(await invoke('memory_read', { key: name })), previous);
    const result = content(await invoke('rag_search', { query, limit: 4 }));
    report.queries.push({ key: name, query, result }); await save();
    assert.equal(result.hits.length, 1); assert.equal(result.hits[0].key, name);
    assert.equal(result.hits[0].document.line_basis, 'extracted_text');
    assert.deepEqual(result.hits[0].document.parsing.locations, previous.memory.content.document.segments);
  }
  assert.equal(await count(), 2); await stop();
  assert.equal(new Set(report.sessions.map(s => s.pid)).size, 2);
  report.database_sha256 = sha(await readFile(config.database)); report.witness_sha256 = sha(await readFile(config.witness));
  report.passed = true;
} catch (error) { report.error = session ? session.redact(error.stack) : String(error.stack); process.exitCode = 1; }
finally {
  await stop().catch(error => { report.cleanup_error = String(error); report.passed = false; process.exitCode = 1; });
  await save(); console.log(JSON.stringify({ passed: report.passed, processes: report.sessions.length, imports: report.imports.length, error: report.error, out }));
}

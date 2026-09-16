// 对本次合成工作区的真实解析容器注入故障；不改解析器、时间预算或共享镜像。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, fileTree, WorkspaceSession } from './agd-workspace-session.mjs';

const run = promisify(execFile), sha = bytes => createHash('sha256').update(bytes).digest('hex');
const option = key => { const i = process.argv.indexOf(key); assert.ok(i > 0, `缺少 ${key}`); return process.argv[i + 1]; };
const binary = resolve(option('--binary')), out = resolve(option('--out')), fixtures = resolve(option('--fixtures'));
const normal = resolve(option('--normal')), image = option('--image');
assert.match(image, /^sha256:[a-f0-9]{64}$/);
await mkdir(out, { recursive: false, mode: 0o700 });
await writeFile(join(out, 'harness.mjs'), await readFile(new URL(import.meta.url)));
const seed = {};
for (const name of ['dense.png', 'empty.pdf', 'partial.pdf']) seed[name] = await readFile(join(fixtures, name));
seed['normal.pdf'] = await readFile(join(normal, 'normal.pdf'));
const fixture = await createWorkspaceFixture({ name: 'document-faults', seed, readOnly: true });
const requests = [];
const listener = createServer((req, res) => { requests.push(req.url); res.end('EXTERNAL-CONTENT-MUST-NOT-ENTER-MEMORY'); });
await new Promise(done => listener.listen(0, '127.0.0.1', done));
assert.equal((await fetch(`http://127.0.0.1:${listener.address().port}/calibration`)).status, 200);
assert.deepEqual(requests, ['/calibration']); requests.length = 0;
const url = `http://host.docker.internal:${listener.address().port}/external-material`;
const privateFile = join(fixture.control, 'outside-marker.txt');
const marker = 'AGD-SYNTHETIC-OUTSIDE-MARKER-7461';
await writeFile(privateFile, marker);
await run('/usr/bin/python3', ['-c', `import sys,zipfile,xml.sax.saxutils as x
with zipfile.ZipFile(sys.argv[1]) as src, zipfile.ZipFile(sys.argv[2],'w',compression=zipfile.ZIP_DEFLATED) as dst:
 for e in src.infolist():
  data=src.read(e.filename)
  if e.filename=='word/document.xml':
   links=''.join('<w:p><w:hyperlink xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="external'+str(i)+'"><w:r><w:t>EXTERNAL-LINK-'+str(i)+'</w:t></w:r></w:hyperlink></w:p>' for i in range(2))
   data=data.replace(b'</w:body>',links.encode()+b'</w:body>')
  dst.writestr(e.filename,data)
 rels='<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
 for i,target in enumerate(sys.argv[3:]): rels+='<Relationship Id="external'+str(i)+'" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target='+x.quoteattr(target)+' TargetMode="External"/>'
 dst.writestr('word/_rels/document.xml.rels',rels+'</Relationships>')
`, join(normal, 'normal.docx'), join(fixture.work, 'external.docx'), url, `file://${privateFile}`]);
await writeFile(fixture.plans, JSON.stringify({ plans: [{ task_profile: fixture.taskProfile, goal: '合成文档故障与覆盖说明验收',
  allow: ['run_shell', 'persist_memory', 'recall_memory'], scope: { data_keys: ['killed', 'timed-out', 'after-kill', 'after-timeout', 'empty', 'partial', 'external'], paths: { read: [fixture.work], write: [] } } }] }));
const pair = generateKeyPairSync('ed25519');
const privateHex = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex');
const publicHex = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
const configFile = join(fixture.control, 'memory.json');
const config = { schema_version: 1, scope_id: 'document-faults-test', database: join(fixture.control, 'memory.db'), witness: join(fixture.control, 'head.json'),
  signing_key: join(fixture.control, 'secret.hex'), public_key: join(fixture.control, 'public.hex'), allow_read: true, allow_write: true, encryption: { mode: 'plaintext_test' } };
for (const [file, value] of [[config.signing_key, privateHex], [config.public_key, publicHex], [configFile, JSON.stringify(config)]]) await writeFile(file, value, { mode: 0o600 });
const initialTree = await fileTree(fixture.work);
const report = { schema_version: 1, passed: false, binary, binary_sha256: sha(await readFile(binary)), image,
  parser_sha256: sha(await readFile(new URL('../../crates/guard-gateway/src/document_parser.py', import.meta.url))),
  fixture: fixture.temporaryRoot, config: configFile, public_key: publicHex, initial_tree: initialTree,
  scope: '冻结 CLI、真实 Docker；合成资料、明文测试、宿主脚本批准；不代表原生或模型验收', faults: [], imports: [], checks: [] };
let session;
const save = () => writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
const docker = async args => (await run('/usr/local/bin/docker', args, { timeout: 10000, maxBuffer: 1024 * 1024 })).stdout.trim();
async function audit(database = fixture.auditDb) {
  return JSON.parse((await run('/usr/bin/python3', ['-c', "import sqlite3,json,sys; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); print(json.dumps([[r[0],json.loads(r[1])] for r in c.execute('select event_type,event_json from audit_events order by seq')]))", database])).stdout);
}
const count = async () => (await audit(config.database)).filter(([kind]) => kind === 'MemoryVersionCommitted').length;
const invoke = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
const args = (key, file) => ({ key, expected_version: 0, path: join(fixture.work, file), expires_at_ms: Date.now() + 900000 });
function content(response) { assert.equal(response.result?.isError, false, JSON.stringify(response)); return JSON.parse(response.result.content[0].text); }
async function imported(key, file, validate) {
  const before = await count(), call = invoke('rag_import', args(key, file));
  const pending = await session.waitForPending({ timeoutMs: 18000 }), action = pending.binding.action, draft = action.parameters;
  assert.equal(actionSha256(action), pending.action_sha256); assert.equal(action.session_id, session.sessionId);
  assert.equal(action.tool.service, 'agentguard-memory'); assert.equal(action.tool.name, 'memory_write');
  assert.equal(draft.key, key); assert.equal(draft.version, 1);
  const material = JSON.parse(draft.content), d = material.document;
  assert.equal(material.kind, 'parsed_document'); assert.equal(material.path, args(key, file).path);
  assert.equal(d.source_sha256, sha(await readFile(join(fixture.work, file))));
  assert.equal(d.parser_sha256, report.parser_sha256); assert.equal(d.image_sha256, image.slice(7));
  assert.equal(d.instruction_authority, 'none'); assert.equal(d.text_sha256, sha(d.text));
  validate(d);
  assert.equal((await session.operatorRequest('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce })).status, 200);
  assert.equal(content(await call).saved, true); assert.equal(await count(), before + 1);
  const stored = content(await invoke('memory_read', { key }));
  assert.deepEqual(stored.memory.content, material);
  report.imports.push({ key, file, action_sha256: pending.action_sha256, material, before, after: await count() }); await save();
}
async function fault(mode, key) {
  const before = await count(), beforeEvents = (await audit()).length, started = performance.now();
  let settled = false;
  // 立即安装错误处理，避免容器发现失败时遗留未处理的 Promise。
  const call = invoke('rag_import', args(key, 'dense.png')).then(value => ({ value }), error => ({ error })).finally(() => { settled = true; });
  let name;
  while (!settled && performance.now() - started < 10000) {
    const owned = await session.ownedContainers();
    assert.ok(owned.length <= 1, '本场景只能有一个已核实归属的容器');
    if (owned.length) { [name] = owned; break; }
    await delay(25);
  }
  assert.ok(name, '未观察到实际解析容器，不能把正常结束或预派发拒绝算作故障验收');
  const details = JSON.parse(await docker(['inspect', name]))[0];
  assert.equal(details.State.Running, true); assert.equal(details.Image, image);
  assert.equal(details.HostConfig.NetworkMode, 'none'); assert.equal(details.Mounts.length, 1);
  const mount = details.Mounts[0]; assert.equal(mount.Destination, '/run/agentguard-request'); assert.equal(mount.RW, false);
  const request = JSON.parse(await readFile(join(mount.Source, 'call.json')));
  assert.deepEqual(Object.keys(request), ['ParseDocument']);
  assert.equal(request.ParseDocument.format, 'png');
  // macOS 的 /var 与 /private/var 是同一来源；仍须核对实际文件身份及字节。
  assert.equal(await realpath(request.ParseDocument.path), join(fixture.work, 'dense.png'));
  assert.equal(sha(await readFile(join(mount.Source, 'document-source'))), sha(seed['dense.png']));
  const evidence = { mode, key, container: name, image: details.Image, network: details.HostConfig.NetworkMode, mount, request, injected: false, before };
  report.faults.push(evidence); await save();
  await docker(mode === 'kill' ? ['kill', '--signal', 'KILL', name] : ['pause', name]);
  evidence.injected = true; evidence.injected_after_ms = performance.now() - started;
  if (mode === 'pause') assert.equal(JSON.parse(await docker(['inspect', name]))[0].State.Paused, true);
  await save();
  const response = await call;
  if (response.error) throw response.error;
  assert.equal(response.value.result?.isError, true, JSON.stringify(response.value));
  evidence.elapsed_ms = performance.now() - started; evidence.error = response.value.result.content[0].text;
  if (mode === 'pause') assert.ok(evidence.elapsed_ms >= 30000 && evidence.elapsed_ms < 45000, '必须经历真实 30 秒执行截止，而非批准或 MCP 超时');
  evidence.after = await count(); assert.equal(evidence.after, before);
  assert.deepEqual(await session.ownedContainers(), [], '必须由网关清理，不能由验收脚本的 finally 代替');
  const terminals = (await audit()).slice(beforeEvents).filter(([kind, body]) => kind === 'GatewayExecutionFinished' && body.target_sha256 === sha(request.ParseDocument.path)).map(([, body]) => body);
  assert.equal(terminals.length, 1); assert.equal(terminals[0].outcome, 'unknown'); assert.equal(terminals[0].dispatched, true);
  evidence.terminal = terminals[0]; evidence.containers_after = [];
  assert.equal((await session.operatorRequest('/status')).value.pending, null);
  await delay(1000);
  assert.deepEqual(await session.ownedContainers(), []); assert.equal(await count(), before);
  assert.equal((await audit()).slice(beforeEvents).filter(([kind]) => kind === 'GatewayExecutionFinished').length, 1, '故障后不能自动重试');
  evidence.no_automatic_retry_ms = 1000;
  evidence.passed = true; await save();
}
try {
  session = await WorkspaceSession.start({ binary, image, fixture, memoryConfig: configFile, initializeMemory: true, confirmSeconds: 20 });
  report.session = { pid: session.child.pid, session_id: session.sessionId, snapshot: session.snapshotRoot, stats: session.statsAtStart }; await save();
  await fault('kill', 'killed');
  await imported('after-kill', 'normal.pdf', d => assert.equal(d.status, 'parsed'));
  await fault('pause', 'timed-out');
  await imported('after-timeout', 'normal.pdf', d => assert.equal(d.status, 'parsed'));
  const before = await count(), empty = await invoke('rag_import', args('empty', 'empty.pdf'));
  assert.equal(empty.result?.isError, true); assert.equal(await count(), before);
  report.checks.push({ case: 'empty', error: empty.result.content[0].text, no_write: true });
  await imported('partial', 'partial.pdf', d => { assert.equal(d.status, 'partial'); assert.deepEqual(d.coverage.empty_units, ['page:2']); assert.equal(d.segments.length, 1); });
  await imported('external', 'external.docx', d => {
    assert.equal(d.status, 'parsed'); assert.ok(d.coverage.uncovered.some(x => x.includes('外部关系')));
    assert.ok(d.text.includes('EXTERNAL-LINK-0') && d.text.includes('EXTERNAL-LINK-1'));
    assert.ok(!JSON.stringify(d).includes(marker));
  });
  assert.deepEqual(requests, []); assert.equal(await readFile(privateFile, 'utf8'), marker);
  assert.deepEqual(await fileTree(fixture.work), initialTree); assert.equal(await count(), 4);
  assert.deepEqual(await session.ownedContainers(), []);
  report.checks.push({ case: 'external-relations', listener_calibrated: true, body_references: 2, observed_http_requests: requests, private_marker_unchanged: true, workspace_unchanged: true });
  report.passed = true;
} catch (error) { report.error = session ? session.redact(error.stack) : String(error.stack); process.exitCode = 1; }
finally {
  if (session) {
    try { report.exit = await session.close({ preserveSnapshots: true }); assert.equal(report.exit.code, 0); }
    catch (error) { report.passed = false; report.cleanup_error = String(error); process.exitCode = 1; }
  }
  await new Promise(done => listener.close(done));
  report.database_sha256 = sha(await readFile(config.database)); report.witness_sha256 = sha(await readFile(config.witness));
  await save(); console.log(JSON.stringify({ passed: report.passed, faults: report.faults.map(f => ({ mode: f.mode, passed: f.passed, elapsed_ms: f.elapsed_ms })), imports: report.imports.length, error: report.error, out }));
}

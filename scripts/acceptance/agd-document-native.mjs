// 为固定 App 的原生批准提供合成媒体请求；脚本不调用批准端点。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, WorkspaceSession } from './agd-workspace-session.mjs';

const run = promisify(execFile), sha = value => createHash('sha256').update(value).digest('hex');
const option = key => { const i = process.argv.indexOf(key); assert.ok(i > 0, `缺少 ${key}`); return process.argv[i + 1]; };
const binary = resolve(option('--binary')), out = resolve(option('--out')), fixtures = resolve(option('--fixtures'));
const qualityPath = resolve(option('--quality')), image = option('--image');
const partial = resolve(option('--partial'));
assert.match(image, /^sha256:[a-f0-9]{64}$/);
await mkdir(out, { recursive: false, mode: 0o700 });
const quality = JSON.parse(await readFile(qualityPath)), manifest = JSON.parse(await readFile(join(fixtures, 'manifest.json')));
assert.equal(quality.passed, true); assert.equal(quality.manifest_sha256, sha(await readFile(join(fixtures, 'manifest.json'))));
const parserSha = sha(await readFile(new URL('../../crates/guard-gateway/src/document_parser.py', import.meta.url)));
assert.equal(parserSha, quality.parser_sha256);
const selected = ['mixed-document-png', 'traditional-upside-down'];
const seed = {};
for (const name of [...selected, 'blank']) {
  const c = manifest.cases.find(c => c.name === name); assert.ok(c);
  seed[c.file] = await readFile(join(fixtures, c.file)); assert.equal(sha(seed[c.file]), c.sha256);
}
seed['partial.pdf'] = await readFile(partial);
const fixture = await createWorkspaceFixture({ name: 'document-native', seed, readOnly: true });
await writeFile(fixture.plans, JSON.stringify({ plans: [{ task_profile: fixture.taskProfile, goal: '原生批准与拒绝合成媒体资料',
  allow: ['run_shell', 'persist_memory', 'recall_memory'], scope: { data_keys: [...selected, 'blank', 'partial-pdf'], paths: { read: [fixture.work], write: [] } } }] }));
const pair = generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
const configFile = join(fixture.control, 'memory.json');
const config = { schema_version: 1, scope_id: 'document-native-test', database: join(fixture.control, 'memory.db'),
  witness: join(fixture.control, 'head.json'), signing_key: join(fixture.control, 'secret.hex'), public_key: join(fixture.control, 'public.hex'),
  allow_read: true, allow_write: true, encryption: { mode: 'plaintext_test' } };
await writeFile(config.signing_key, pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex'), { mode: 0o600 });
await writeFile(config.public_key, publicKey, { mode: 0o600 });
await writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
const report = { passed: false, binary, binary_sha256: sha(await readFile(binary)), parser_sha256: parserSha, image,
  quality: qualityPath, quality_sha256: sha(await readFile(qualityPath)), fixture: fixture.temporaryRoot, config: configFile,
  public_key: publicKey, sessions: [], imports: [], snapshots: [], inputs: Object.fromEntries(Object.entries(seed).map(([file,bytes])=>[file,sha(bytes)])), scope: '合成资料、真实 CLI/Docker；固定 App 提交批准或拒绝，非用户手动批准或模型自主调用' };
await writeFile(join(out, 'harness.mjs'), await readFile(new URL(import.meta.url)));
let session;
const save = () => writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
const invoke = (name, args) => session.rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: session.sessionId } });
const content = response => { assert.equal(response.result?.isError, false, JSON.stringify(response)); return JSON.parse(response.result.content[0].text); };
async function count() {
  return Number((await run('/usr/bin/python3', ['-c', "import sqlite3,sys;c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);print(c.execute(\"select count(*) from audit_events where event_type='MemoryVersionCommitted'\").fetchone()[0])", config.database])).stdout);
}
async function start(initializeMemory = false) {
  session = await WorkspaceSession.start({ binary, image, fixture, memoryConfig: configFile, initializeMemory, confirmSeconds: 120 });
  report.sessions.push({ pid: session.child.pid, session_id: session.sessionId, snapshot: session.snapshotRoot, control_file: session.controlFile });
}
async function stop() {
  if (!session) return;
  report.sessions.at(-1).exit = await session.close({ preserveSnapshots: true });
  assert.equal(report.sessions.at(-1).exit.code, 0); session = null;
}

let queued = null;
async function inspect(label) {
  const history = await session.operatorRequest('/memory/history',{session_id:session.sessionId,key:'mixed-document-png',after_version:0});
  assert.equal(history.status,200);
  report.snapshots.push({label,session_id:session.sessionId,history:history.value.data,count:await count()});await save();
  console.log(JSON.stringify({inspected:label,count:await count()}));
}
try {
  await start(true);await save();
  console.log(JSON.stringify({ready:true,control_file:session.controlFile,out}));
  const lines = createInterface({input:process.stdin});
  for await (const line of lines) {
    const command=JSON.parse(line);
    if(command.operation==='queue') {
      assert.ok(!queued);const name=command.name;assert.ok([...selected,'partial-pdf'].includes(name));
      assert.ok(!report.imports.some(item=>item.key===name));
      const file=name==='partial-pdf'?'partial.pdf':manifest.cases.find(c=>c.name===name).file;
      const before=await count();
      const call=invoke('rag_import',{key:name,expected_version:0,path:join(fixture.work,file),expires_at_ms:Date.now()+3600000});
      const pending=await session.waitForPending({timeoutMs:18000}),action=pending.binding.action,draft=action.parameters;
      assert.equal(actionSha256(action),pending.action_sha256);assert.equal(action.session_id,session.sessionId);
      assert.equal(action.tool.service,'agentguard-memory');assert.equal(action.tool.name,'memory_write');
      assert.ok(pending.findings.every(finding=>!finding.message.includes('oversized_token')),'普通资料不能再产生序列化伪造的超长词元提示');
      assert.equal(draft.key,name);assert.equal(draft.version,1);
      const material=JSON.parse(draft.content),document=material.document;
      assert.equal(document.source_sha256,sha(seed[file]));assert.equal(document.parser_sha256,parserSha);
      assert.equal(document.image_sha256,image.slice(7));assert.equal(document.text_sha256,sha(document.text));
      assert.equal(document.instruction_authority,'none');
      if(name==='partial-pdf') {assert.equal(document.status,'partial');assert.deepEqual(document.coverage.empty_units,['page:2']);}
      else assert.deepEqual(document.coverage,quality.cases.find(c=>c.case===name).result.coverage);
      assert.equal(await count(),before);
      const proof={key:name,file,before,action_sha256:pending.action_sha256,action,findings:pending.findings,expected:name==='traditional-upside-down'?'deny':'approve'};
      report.imports.push(proof);queued={call,proof};await save();
      console.log(JSON.stringify({waiting:true,key:name,expected:proof.expected}));
    } else if(command.operation==='result') {
      assert.ok(queued);const {call,proof}=queued;
      proof.response=await call;proof.after=await count();
      if(proof.expected==='approve') {assert.equal(content(proof.response).saved,true);assert.equal(proof.after,proof.before+1);proof.read=content(await invoke('memory_read',{key:proof.key}));assert.deepEqual(proof.read.memory.content,JSON.parse(proof.action.parameters.content));}
      else {assert.equal(proof.response.result?.isError,true);assert.equal(proof.after,proof.before);assert.equal(content(await invoke('memory_read',{key:proof.key})).found,false);}
      queued=null;await save();console.log(JSON.stringify({result:proof.key,expected:proof.expected,count:proof.after}));
    } else if(command.operation==='reopen') {
      assert.ok(!queued);await inspect('before_reopen');await stop();await start();await inspect('after_reopen');
      assert.deepEqual(report.snapshots[0].history,report.snapshots[1].history);
      console.log(JSON.stringify({reopened:true,control_file:session.controlFile}));
    } else if(command.operation==='finish') {
      assert.ok(!queued);assert.equal(report.sessions.length,2);assert.equal(report.imports.length,3);assert.equal(await count(),2);
      await inspect('after_native_reopen');
      const blank=manifest.cases.find(c=>c.name==='blank'),before=await count();
      const empty=await invoke('rag_import',{key:'blank',expected_version:0,path:join(fixture.work,blank.file),expires_at_ms:Date.now()+3600000});
      assert.equal(empty.result?.isError,true);assert.equal(await count(),before);
      report.empty={response:empty,before,after:await count()};
      report.query=content(await invoke('rag_search',{query:'pip install',limit:4}));assert.equal(report.query.hits.length,1);assert.equal(report.query.hits[0].key,'mixed-document-png');
      report.passed=true;lines.close();break;
    } else throw new Error('只接受 queue、result、reopen、finish');
  }
  assert.equal(report.passed,true,'标准输入提前关闭，原生验收尚未完成');
} catch(error) { report.error=session?session.redact(error.stack):String(error.stack);process.exitCode=1; }
finally {await stop();report.database_sha256=sha(await readFile(config.database));report.witness_sha256=sha(await readFile(config.witness));await save();console.log(JSON.stringify({closed:true,passed:report.passed,error:report.error,out}));}

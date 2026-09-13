// AGD-007：真实 stdio MCP + Docker 工作区快照验收；只批准本脚本的本地测试动作。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { access, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = fileURLToPath(new URL('../../', import.meta.url));
const value = (key, fallback) => process.argv.includes(key) ? process.argv[process.argv.indexOf(key) + 1] : fallback;
const binary = value('--binary', join(root, 'target/debug/agentguard-mcp'));
const image = value('--image', 'sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490');
const runId = new Date().toISOString().replace(/[-:.]/g, '') + '-' + process.pid;
const out = join(root, 'eval/out/AGD-002', `${runId}-gateway`);
await mkdir(out, { recursive: true });
const report = { task: 'AGD-007', image, binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), checks: [], scope: '真实网关工具执行隔离；不代表整个客户端隔离、宿主回写或完整 M1' };
const controlSecrets = [];
const scrub = text => controlSecrets.reduce((clean, token) => clean.split(token).join('[已脱敏的测试控制令牌]'), text).replace(/确认令牌 .+/g, '确认令牌 [已脱敏]');
const temp = await realpath(await mkdtemp(join(tmpdir(), 'agd-isolation-gateway-')));
const work = join(temp, 'workspace'), privateDir = join(temp, 'private');
await mkdir(work); await mkdir(privateDir);
const privateFile = join(privateDir, 'host-private.txt');
await writeFile(privateFile, 'AGD_GATEWAY_HOST_ONLY');
await writeFile(join(work, 'input.txt'), 'AGD_GATEWAY_NORMAL');
await writeFile(join(work, 'remove.txt'), 'AGD_REMOVE_ORIGINAL');
await writeFile(join(work, 'quotes.txt'), '"\\\0\r\t\n'.repeat(11000));
await symlink(privateFile, join(work, 'outside-link'));
await symlink('../private/host-private.txt', join(work, 'relative-outside-link'));
await link(privateFile, join(work, 'hardlinked.txt'));
await writeFile(join(work, 'config.json'), JSON.stringify({ privateFile, home: process.env.HOME, controlFile: join(temp, 'host-control-1.json') }));
const python = String.raw`import errno,json,os,pathlib,subprocess,sys
root=pathlib.Path(__file__).parent
cfg=json.loads((root/'config.json').read_text())
checks=[]
def check(name,ok): checks.append({'name':name,'passed':bool(ok)})
def denied_read(path):
 try: pathlib.Path(path).read_bytes(); return False
 except OSError: return True
def denied_write(path):
 try: pathlib.Path(path).write_text('UNAUTHORIZED'); return False
 except OSError: return True
if '--child' in sys.argv:
 sys.exit(0 if denied_read(cfg['privateFile']) and denied_write(cfg['privateFile']) else 9)
check('normal_read',(root/'input.txt').read_text()=='AGD_GATEWAY_NORMAL')
(root/'python-result.txt').write_text('AGD_PYTHON_RESULT')
check('normal_write',(root/'python-result.txt').read_text()=='AGD_PYTHON_RESULT')
check('outside_read_denied',denied_read(cfg['privateFile']))
check('outside_write_denied',denied_write(cfg['privateFile']))
check('absolute_link_read_denied',denied_read(root/'outside-link'))
check('absolute_link_write_denied',denied_write(root/'outside-link'))
check('relative_link_read_denied',denied_read(root/'relative-outside-link'))
check('relative_link_write_denied',denied_write(root/'relative-outside-link'))
check('descendant_isolated',subprocess.run(['/usr/bin/python3',__file__,'--child']).returncode==0)
check('host_environment_token_absent','AGD_SYNTHETIC_ENV_SECRET' not in str(dict(os.environ)))
check('host_home_not_mounted',not pathlib.Path(cfg['home']).exists())
check('docker_socket_not_mounted',not pathlib.Path('/var/run/docker.sock').exists())
check('host_control_file_read_denied',denied_read(cfg['controlFile']))
(root/'hardlinked.txt').write_text('AGD_SNAPSHOT_HARDLINK_CHANGED')
check('snapshot_hardlink_can_write',(root/'hardlinked.txt').read_text()=='AGD_SNAPSHOT_HARDLINK_CHANGED')
print(json.dumps({'runtime':'python','checks':checks}))
raise SystemExit(0 if all(x['passed'] for x in checks) else 1)
`;
const node = String.raw`const fs=require('node:fs');const path=require('node:path');const cp=require('node:child_process');
const root=__dirname,cfg=JSON.parse(fs.readFileSync(path.join(root,'config.json'),'utf8'));const checks=[];
const check=(name,ok)=>checks.push({name,passed:!!ok});
const denyRead=p=>{try{fs.readFileSync(p);return false}catch{return true}};
const denyWrite=p=>{try{fs.writeFileSync(p,'UNAUTHORIZED');return false}catch{return true}};
if(process.argv.includes('--child'))process.exit(denyRead(cfg.privateFile)&&denyWrite(cfg.privateFile)?0:9);
check('normal_read',fs.readFileSync(path.join(root,'input.txt'),'utf8')==='AGD_GATEWAY_NORMAL');
fs.writeFileSync(path.join(root,'node-result.txt'),'AGD_NODE_RESULT');
check('normal_write',fs.readFileSync(path.join(root,'node-result.txt'),'utf8')==='AGD_NODE_RESULT');
check('outside_read_denied',denyRead(cfg.privateFile));check('outside_write_denied',denyWrite(cfg.privateFile));
for(const target of ['outside-link','relative-outside-link']){check(target+'_read_denied',denyRead(path.join(root,target)));check(target+'_write_denied',denyWrite(path.join(root,target)));}
check('descendant_isolated',cp.spawnSync(process.execPath,[__filename,'--child']).status===0);
check('host_environment_token_absent',!JSON.stringify(process.env).includes('AGD_SYNTHETIC_ENV_SECRET'));
check('docker_socket_not_mounted',!fs.existsSync('/var/run/docker.sock'));
check('host_control_file_read_denied',denyRead(cfg.controlFile));
console.log(JSON.stringify({runtime:'node',checks}));process.exit(checks.every(x=>x.passed)?0:1);
`;
await writeFile(join(work, 'probe.py'), python); await writeFile(join(work, 'probe.cjs'), node);
await mkdir(join(work, 'binding-sub')); await mkdir(join(work, 'binding-other'));
for (const operation of ['read', 'write', 'delete']) await writeFile(join(work, 'binding-other', operation + '.txt'), 'AGD_BINDING_' + operation.toUpperCase());
await writeFile(join(work, 'replace-parent.py'), "import os,pathlib\nr=pathlib.Path(__file__).parent\n(r/'binding-sub').rmdir()\nos.symlink('binding-other',r/'binding-sub')\nprint('AGD_PARENT_REPLACED')\n");
await writeFile(join(work, 'hang.py'), String.raw`import pathlib,subprocess,sys,time
code="import pathlib,time; time.sleep(36); pathlib.Path("+repr(str(pathlib.Path(__file__).parent/'late-child.txt'))+").write_text('BAD')"
subprocess.Popen(['/usr/bin/python3','-c',code],start_new_session=True)
print('AGD_HANG_STARTED',flush=True)
time.sleep(60)
`);
const plans = join(temp, 'plans.json');
await writeFile(plans, JSON.stringify({ plans: [{ task_profile: 'agd-isolation-acceptance', goal: 'AGD 本地隔离验收', allow: ['run_shell'], scope: { paths: { read: [work], write: [work] } } }] }));
function record(name, passed, detail) { report.checks.push({ name, passed: !!passed, ...(detail === undefined ? {} : { detail }) }); }
async function exists(path) { try { await access(path); return true; } catch { return false; } }
function docker(args) { return execFileSync('/usr/local/bin/docker', args, { encoding: 'utf8', timeout: 10000 }).trim(); }
async function startupRefusal(name, planPath, environment, expected, options = {}) {
  const controlArgs = options.omitControlFile ? [] : ['--control-file', options.controlFile || join(temp, name + '-control.json')];
  const isolationArgs = options.omitIsolation ? [] : ['--isolation-image', image];
  const child = spawn(binary, ['--rules', join(root, 'crates/guard-schema/rules/p0_rules.yaml'), '--shell-policy', join(root, 'crates/guard-shell/policies/default.yaml'), '--plans', planPath, '--task', 'agd-isolation-acceptance', '--confirm-port', '0', ...isolationArgs, '--audit-db', join(temp, name + '-audit.db'), ...controlArgs], { cwd: root, env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  let logs = '';
  child.stderr.on('data', data => { logs += data; });
  const code = await new Promise(resolve => {
    const timer = setTimeout(() => child.kill('SIGKILL'), 12000);
    child.once('exit', value => { clearTimeout(timer); resolve(value); });
  });
  record(name, code !== 0 && code !== null && expected.test(logs), { code, stderr: scrub(logs).slice(-2000) });
  // 某些拒绝发生于隔离能力自检后；仅回收本次启动在日志里登记的测试副本。
  for (const line of logs.split('\n')) {
    const marker = line.indexOf('隔离工具后端 ');
    if (marker < 0) continue;
    try {
      const backend = JSON.parse(line.slice(marker + '隔离工具后端 '.length));
      if (basename(backend.snapshot_root).startsWith('agentguard-snapshot-')) extraSnapshots.push(backend.snapshot_root);
    } catch {}
  }
}
function containersForSnapshot(snapshotRoot) {
  const ids = docker(['ps', '--filter', 'name=agentguard-task-', '--format', '{{.ID}}']).split('\n').filter(Boolean);
  if (!ids.length) return [];
  return JSON.parse(docker(['inspect', ...ids])).filter(c => c.Mounts.some(m => m.Source.startsWith(snapshotRoot + '/'))).map(c => c.Name.slice(1));
}
let sessionSequence = 0;
async function start() {
  const sessionNumber = ++sessionSequence, controlFile = join(temp, 'host-control-' + sessionNumber + '.json');
  const child = spawn(binary, ['--rules', join(root, 'crates/guard-schema/rules/p0_rules.yaml'), '--shell-policy', join(root, 'crates/guard-shell/policies/default.yaml'), '--plans', plans, '--task', 'agd-isolation-acceptance', '--confirm-port', '0', '--confirm-timeout-secs', '5', '--isolation-image', image, '--audit-db', join(temp, 'private-audit.db'), '--control-file', controlFile], { cwd: root, env: { ...process.env, AGD_HOST_ONLY_TEST_TOKEN: 'AGD_SYNTHETIC_ENV_SECRET' }, stdio: ['pipe', 'pipe', 'pipe'] });
  let port, token, descriptor, sequence = 0, exited = false, closed = false; const waiting = new Map(), stderr = [], stdout = [];
  const exit = new Promise(resolve => child.once('exit', code => { exited = true; for (const item of waiting.values()) item.reject(new Error(`网关退出:${code}`)); waiting.clear(); resolve(code); }));
  child.stdin.on('error', () => {});
  const logs = createInterface({ input: child.stderr });
  logs.on('line', line => { stderr.push(line); });
  const output = createInterface({ input: child.stdout });
  output.on('line', line => { stdout.push(line); try { const value = JSON.parse(line), item = waiting.get(value.id); if (item) { waiting.delete(value.id); item.resolve(value); } } catch {} });
  const deadline = Date.now() + 20000;
  while (!port || !token) {
    try {
      descriptor = JSON.parse(await readFile(controlFile, 'utf8'));
      assert.equal(descriptor.service, 'agentguard-mcp'); assert.equal(descriptor.confirm_protocol, 2);
      const endpoint = new URL(descriptor.url);
      assert.equal(endpoint.protocol, 'http:'); assert.equal(endpoint.hostname, '127.0.0.1');
      assert.equal(Number(endpoint.port), descriptor.port); assert.match(descriptor.token, /^[a-f0-9]{32}$/); assert.match(descriptor.instance_id, /^[a-f0-9]{32}$/);
      port = Number(endpoint.port); token = descriptor.token; controlSecrets.push(token);
    } catch {}
    if (exited || Date.now() > deadline) { child.kill('SIGKILL'); await writeFile(join(out, 'startup.stderr'), scrub(stderr.join('\n'))); throw new Error('网关启动失败或控制连接文件无效:'+scrub(stderr.slice(-6).join('\n'))); }
    if (!port || !token) await delay(20);
  }
  record('session_' + sessionNumber + '_control_file_private', ((await stat(controlFile)).mode & 0o777) === 0o600);
  const control = async (path, body) => { const response = await fetch(`http://127.0.0.1:${port}${path}`, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(2000) }); return { status: response.status, value: await response.json() }; };
  async function rpc(method, params = {}, approve = true) {
    const id = ++sequence; let settled = false;
    const result = new Promise((resolve, reject) => waiting.set(id, { resolve, reject }));
    const observed = result.then(value => ({ value }), error => ({ error })).finally(() => { settled = true; });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    const deadline = Date.now() + 45000;
    while (!settled) {
      if (Date.now() > deadline) throw new Error('MCP 调用超时');
      const state = await control('/status').catch(() => null), pending = state?.value?.pending;
      if (pending) {
        const answer = await control(approve ? '/approve' : '/deny', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding?.nonce });
        if (answer.status !== 200) throw new Error('本地测试批准绑定失败:'+JSON.stringify(answer));
      }
      if (!settled) await delay(20);
    }
    const response = await observed; if (response.error) throw response.error; return response.value;
  }
  const call = async (name, args, approve = true) => { const value = await rpc('tools/call', { name, arguments: args }, approve); const text = value.result?.content?.find(x => x.type === 'text')?.text || ''; return { ok: !value.error && !value.result?.isError, text: text.split('\n\n--- 守卫发现（已执行）---\n')[0], raw: value }; };
  return { child, rpc, call, controlFile, token, descriptor,
    leaksToken(value) { return JSON.stringify(value).includes(token); },
    async statusWithToken(otherToken) { const response = await fetch('http://127.0.0.1:' + port + '/status', { headers: { Authorization: 'Bearer ' + otherToken }, signal: AbortSignal.timeout(2000) }); return response.status; },
    async close() {
      if (closed) return; closed = true;
      child.stdin.end(); const killer = setTimeout(() => child.kill('SIGKILL'), 3000); await exit; clearTimeout(killer); logs.close(); output.close();
      record('session_' + sessionNumber + '_token_absent_from_stderr_stdout', !stderr.join('\n').includes(token) && !stdout.join('\n').includes(token));
      await writeFile(join(out, 'gateway-' + sessionNumber + '.stderr'), scrub(stderr.join('\n')));
    } };
}
let gateway, snapshotRoot, snapshot; const extraSnapshots = [];
try {
  // 只在合成工作区放入虚构标记；启动拒绝后还要确认本次专用临时目录没有残留快照。
  for (const [name, relativePath, cleanupPath] of [
    ['keychains_ingestion_refused_without_snapshot', 'Library/Keychains/login.keychain-db', 'Library'],
    ['netrc_ingestion_refused_without_snapshot', '.netrc', '.netrc'],
  ]) {
    const source = join(work, relativePath), snapshotTemp = join(temp, name + '-tmp');
    await mkdir(dirname(source), { recursive: true });
    await mkdir(snapshotTemp);
    await writeFile(source, 'AGD_SYNTHETIC_CREDENTIAL_FIXTURE');
    await startupRefusal(name, plans, { ...process.env, TMPDIR: snapshotTemp }, /快照源包含敏感宿主文件，拒绝摄入/);
    const check = report.checks.at(-1), remaining = await readdir(snapshotTemp);
    const sourceUnchanged = await readFile(source, 'utf8') === 'AGD_SYNTHETIC_CREDENTIAL_FIXTURE';
    check.detail = { ...check.detail, syntheticFixture: relativePath, snapshotTempEntries: remaining, sourceUnchanged };
    check.passed &&= remaining.length === 0 && sourceUnchanged;
    await rm(join(work, cleanupPath), { recursive: true, force: true });
  }
  await startupRefusal('isolation_without_control_file_refused', plans, process.env, /control-file|控制.*文件/, { omitControlFile: true });
  await startupRefusal('native_with_control_file_refused', plans, process.env, /隔离工具模式|原生脚本|isolation/, { omitIsolation: true });
  const insideControl = join(work, 'inside-control.json');
  await startupRefusal('control_file_inside_workspace_refused', plans, process.env, /控制|control|授权目录|任务授权/, { controlFile: insideControl });
  record('refused_inside_control_file_not_created', !await exists(insideControl));
  const controlRealParent = join(temp, 'control-real-parent'), controlLinkParent = join(temp, 'control-parent-link');
  await mkdir(controlRealParent); await symlink(controlRealParent, controlLinkParent);
  await startupRefusal('control_file_symlink_parent_refused', plans, process.env, /控制|control|链接|Not a directory|symlink/, { controlFile: join(controlLinkParent, 'control.json') });
  record('refused_symlink_control_file_not_created', !await exists(join(controlRealParent, 'control.json')));
  const existingControl = join(temp, 'existing-control.json'); await writeFile(existingControl, 'AGD_EXISTING_CONTROL_MUST_REMAIN');
  await startupRefusal('existing_control_file_refused', plans, process.env, /存在|exist|控制|control/, { controlFile: existingControl });
  record('existing_control_file_not_overwritten', await readFile(existingControl, 'utf8') === 'AGD_EXISTING_CONTROL_MUST_REMAIN');
  // 独立 DOCKER_CONFIG 只保存在本次临时目录，不修改用户 Docker 配置或连接外部 daemon。
  const remoteConfig = join(temp, 'test-docker-config'); await mkdir(remoteConfig);
  const remoteName = 'agd-unreachable-local-test';
  execFileSync('/usr/local/bin/docker', ['--config', remoteConfig, 'context', 'create', remoteName, '--docker', 'host=tcp://127.0.0.1:1'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 });
  await startupRefusal('remote_context_refused_before_execution', plans, { ...process.env, DOCKER_CONFIG: remoteConfig, DOCKER_CONTEXT: remoteName, DOCKER_HOST: 'unix:///var/run/docker.sock' }, /本地 Unix Socket|不支持远程 Docker/);
  const remoteEnvironment = { ...process.env, DOCKER_HOST: 'tcp://127.0.0.1:1' }; delete remoteEnvironment.DOCKER_CONTEXT;
  await startupRefusal('remote_host_refused_before_execution', plans, remoteEnvironment, /本地 Unix Socket|不支持远程 Docker/);
  const broadPlans = join(temp, 'broad-plans.json');
  await writeFile(broadPlans, JSON.stringify({ plans: [{ task_profile: 'agd-isolation-acceptance', goal: 'AGD 本地拒绝测试', allow: ['run_shell'], scope: { paths: { read: ['/'] } } }] }));
  await startupRefusal('overbroad_root_grant_refused', broadPlans, process.env, /系统目录|授权过宽|不能包含整个宿主用户目录|审计.*文件必须位于任务授权目录之外/);
  gateway = await start();
  const stats = (await gateway.rpc('gateway/stats')).result; report.backend = stats.execution_backend;
  record('control_token_absent_from_gateway_stats', !gateway.leaksToken(stats));
  record('persistent_journal_enabled', stats.execution_journal?.persistent && stats.execution_journal?.healthy && !stats.audit_write_failed);
  snapshotRoot = stats.execution_backend.snapshot_root;
  const mounts = await Promise.all(stats.execution_backend.workspace_mounts.map(async m => ({ ...m, physicalTarget: await realpath(m.target) })));
  snapshot = mounts.find(m => m.physicalTarget === work).snapshot;
  record('backend_mode_is_explicit', stats.enforcement === 'cooperative' && stats.execution_backend.mode === 'isolated_workspace_snapshot' && stats.execution_backend.host_writeback === 'operator_reviewed' && stats.execution_backend.automatic_host_writeback === false && stats.execution_backend.network === 'none');
  let result = await gateway.call('read_file', { path: join(work, 'input.txt') });
  record('file_read_normal', result.ok && result.text === 'AGD_GATEWAY_NORMAL', result.ok ? undefined : result.text);
  result = await gateway.call('read_file', { path: join(work, 'quotes.txt') });
  record('file_read_64k_json_escapes', result.ok && result.text.startsWith('"\\\0\r\t\n') && result.text.includes('[输出已截断]'), result.ok ? { returnedBytes: Buffer.byteLength(result.text) } : result.text);
  result = await gateway.call('write_file', { path: join(work, 'written.txt'), contents: 'AGD_FILE_TOOL_OUTPUT' });
  record('file_write_snapshot_only', result.ok && await readFile(join(snapshot, 'written.txt'), 'utf8') === 'AGD_FILE_TOOL_OUTPUT' && !await exists(join(work, 'written.txt')), result.ok ? undefined : result.text);
  result = await gateway.call('search_file', { path: join(work, 'input.txt'), query: 'GATEWAY' });
  record('file_search_normal', result.ok && result.text.includes('AGD_GATEWAY_NORMAL'), result.ok ? undefined : result.text);
  result = await gateway.call('delete_file', { path: join(work, 'remove.txt') });
  record('file_delete_snapshot_only', result.ok && !await exists(join(snapshot, 'remove.txt')) && await readFile(join(work, 'remove.txt'), 'utf8') === 'AGD_REMOVE_ORIGINAL', result.ok ? undefined : result.text);
  result = await gateway.call('write_file', { path: join(work, 'nested-control', 'deep', 'result.txt'), contents: 'AGD_NESTED_NORMAL' });
  record('normal_nested_write_snapshot_only', result.ok && await readFile(join(snapshot, 'nested-control', 'deep', 'result.txt'), 'utf8') === 'AGD_NESTED_NORMAL' && !await exists(join(work, 'nested-control')), result.ok ? undefined : result.text);
  result = await gateway.call('run_shell', { argv: ['/usr/bin/python3', join(work, 'replace-parent.py')], cwd: work });
  record('prior_script_replaces_snapshot_parent_only', result.ok && result.text.includes('AGD_PARENT_REPLACED') && (await lstat(join(snapshot, 'binding-sub'))).isSymbolicLink() && (await lstat(join(work, 'binding-sub'))).isDirectory(), result.text);
  for (const [tool, operation] of [['write_file', 'write'], ['read_file', 'read'], ['search_file', 'read'], ['delete_file', 'delete']]) {
    result = await gateway.call(tool, { path: join(work, 'binding-sub', operation + '.txt'), ...(tool === 'write_file' ? { contents: 'AGD_REDIRECTED_WRITE' } : {}), ...(tool === 'search_file' ? { query: 'AGD_BINDING' } : {}) });
    const marker = 'AGD_BINDING_' + operation.toUpperCase();
    const targetPreserved = await exists(join(snapshot, 'binding-other', operation + '.txt')) && await readFile(join(snapshot, 'binding-other', operation + '.txt'), 'utf8') === marker;
    const hostPreserved = await readFile(join(work, 'binding-other', operation + '.txt'), 'utf8') === marker;
    record(tool + '_symlink_parent_refused', !result.ok && !result.text.includes(marker) && targetPreserved && hostPreserved, { response: result.text.slice(0, 400), targetPreserved, hostPreserved });
  }
  for (const [runtime, argv] of [['python', ['/usr/bin/python3', join(work, 'probe.py')]], ['node', ['/usr/local/bin/node', join(work, 'probe.cjs')]]]) {
    result = await gateway.call('run_shell', { argv, cwd: work });
    record(runtime + '_process_completed', result.ok, result.ok ? undefined : result.text);
    if (result.ok) { const parsed = JSON.parse(result.text); for (const check of parsed.checks) record(runtime + '_' + check.name, check.passed); }
  }
  record('host_private_and_hardlink_original_unchanged', await readFile(privateFile, 'utf8') === 'AGD_GATEWAY_HOST_ONLY' && await readFile(join(work, 'hardlinked.txt'), 'utf8') === 'AGD_GATEWAY_HOST_ONLY');
  record('snapshot_hardlink_inode_separated', (await stat(privateFile)).ino !== (await stat(join(snapshot, 'hardlinked.txt'))).ino);
  record('normal_script_results_snapshot_only', await exists(join(snapshot, 'python-result.txt')) && await exists(join(snapshot, 'node-result.txt')) && !await exists(join(work, 'python-result.txt')) && !await exists(join(work, 'node-result.txt')));
  for (const tool of ['read_file', 'write_file']) {
    result = await gateway.call(tool, { path: privateFile, ...(tool === 'write_file' ? { contents: 'UNAUTHORIZED' } : {}) });
    record(tool + '_outside_refused', !result.ok && !result.text.includes('AGD_GATEWAY_HOST_ONLY'), result.text.slice(0, 400));
  }
  result = await gateway.call('write_file', { path: join(work, 'outside-link'), contents: 'UNAUTHORIZED' });
  record('file_tool_outside_symlink_refused', !result.ok && await readFile(privateFile, 'utf8') === 'AGD_GATEWAY_HOST_ONLY', result.text.slice(0, 400));
  await rename(work, work + '-original'); await symlink(privateDir, work);
  result = await gateway.call('read_file', { path: join(work, 'host-private.txt') });
  record('host_root_replacement_does_not_expose_private', !result.ok && !result.text.includes('AGD_GATEWAY_HOST_ONLY'), result.text.slice(0, 400));
  await rm(work); await rename(work + '-original', work);
  const running = gateway.call('run_shell', { argv: ['/usr/bin/python3', join(work, 'hang.py')], cwd: work }).catch(error => ({ error: error.message }));
  let names = []; const startDeadline = Date.now() + 5000;
  while (!names.length && Date.now() < startDeadline) { names = containersForSnapshot(snapshotRoot); if (!names.length) await delay(50); }
  record('crash_test_container_started', names.length === 1, names);
  const crashAt = Date.now(); gateway.child.kill('SIGKILL'); await running;
  const cleanupDeadline = Date.now() + 37000;
  while (containersForSnapshot(snapshotRoot).length && Date.now() < cleanupDeadline) await delay(500);
  await delay(Math.max(0, 36500 - (Date.now() - crashAt)));
  record('gateway_crash_container_deadline_cleanup', containersForSnapshot(snapshotRoot).length === 0 && !await exists(join(snapshot, 'late-child.txt')), { elapsedMs: Date.now() - crashAt });
  const previousControl = { file: gateway.controlFile, token: gateway.token, instance: gateway.descriptor.instance_id, url: gateway.descriptor.url };
  record('crash_control_file_retained', await exists(previousControl.file));
  const previousControlDigest = createHash('sha256').update(await readFile(previousControl.file)).digest('hex');
  const oldEndpointStatus = await gateway.statusWithToken(previousControl.token).catch(() => null);
  record('crash_old_control_endpoint_inactive', oldEndpointStatus === null || oldEndpointStatus === 403, { status: oldEndpointStatus });
  await gateway.close();
  await startupRefusal('crash_existing_control_path_refuses_restart', plans, process.env, /存在|exist|控制|control/, { controlFile: previousControl.file });
  record('crash_existing_control_file_not_overwritten', createHash('sha256').update(await readFile(previousControl.file)).digest('hex') === previousControlDigest);
  gateway = await start();
  const recovered = (await gateway.rpc('gateway/stats')).result;
  extraSnapshots.push(recovered.execution_backend.snapshot_root);
  report.recoveryJournal = recovered.execution_journal;
  record('crash_recovery_is_unknown_without_replay', recovered.execution_journal?.recovered_unknown === 1 && recovered.execution_journal?.healthy && recovered.executed === 0);
  record('restarted_control_identity_rotated', gateway.token !== previousControl.token && gateway.descriptor.instance_id !== previousControl.instance);
  record('old_token_rejected_by_new_instance', await gateway.statusWithToken(previousControl.token) === 403);
  record('restarted_control_token_absent_from_stats', !gateway.leaksToken(recovered));
  const currentControl = gateway.controlFile; await gateway.close();
  record('normal_close_removes_own_control_file', !await exists(currentControl));
  record('normal_close_preserves_old_and_unrelated_control_files', await exists(previousControl.file) && await readFile(existingControl, 'utf8') === 'AGD_EXISTING_CONTROL_MUST_REMAIN');
} catch (error) { report.error = error.stack; }
finally {
  await gateway?.close();
  if (snapshotRoot) {
    report.snapshotManifest = {};
    if (snapshot) for (const name of ['input.txt', 'written.txt', 'python-result.txt', 'node-result.txt', 'hardlinked.txt']) if (await exists(join(snapshot, name))) report.snapshotManifest[name] = createHash('sha256').update(await readFile(join(snapshot, name))).digest('hex');
    for (const name of containersForSnapshot(snapshotRoot)) docker(['rm', '--force', name]);
    // 只清理此测试从 stats 取得且位于系统临时目录的随机快照。
    if (basename(snapshotRoot).startsWith('agentguard-snapshot-')) await rm(snapshotRoot, { recursive: true, force: true });
  }
  for (const path of extraSnapshots) if (basename(path).startsWith('agentguard-snapshot-')) await rm(path, { recursive: true, force: true });
  await rm(temp, { recursive: true, force: true });
  report.state = !report.error && report.checks.length && report.checks.every(x => x.passed) ? 'passed' : 'failed';
  await writeFile(join(out, 'report.json'), scrub(JSON.stringify(report, null, 2)) + '\n');
}
console.log(scrub(JSON.stringify({ state: report.state, passed: report.checks.filter(x => x.passed).length, total: report.checks.length, error: report.error, report: join(out, 'report.json') })));
if (report.state !== 'passed') process.exitCode = 1;

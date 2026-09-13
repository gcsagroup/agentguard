// 真实 MCP 差分验收：前序脚本置换快照内父目录后，结构化文件工具应拒绝跟随链接。
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = fileURLToPath(new URL('../../', import.meta.url));
const option = (key, fallback) => process.argv.includes(key) ? process.argv[process.argv.indexOf(key) + 1] : fallback;
const binary = option('--binary', join(root, 'target/debug/agentguard-mcp'));
const image = option('--image', 'sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490');
const out = join(root, 'eval/out/AGD-002', new Date().toISOString().replace(/[-:.]/g, '') + '-' + process.pid + '-parent-link');
await mkdir(out, { recursive: true });
const report = { task: 'AGD-007', binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), image, checks: [], approvals: [], scope: '结构化文件工具的批准目标绑定；仅用合成工作区，不代表宿主逃逸' };
const check = (name, passed, detail) => report.checks.push({ name, passed: !!passed, ...(detail === undefined ? {} : { detail }) });
async function exists(path) { try { await access(path); return true; } catch { return false; } }
const temp = await realpath(await mkdtemp(join(tmpdir(), 'agd-parent-link-'))), work = join(temp, 'workspace');
await mkdir(join(work, 'sub'), { recursive: true }); await mkdir(join(work, 'other'));
await writeFile(join(work, 'other', 'read.txt'), 'AGD_OTHER_READ');
await writeFile(join(work, 'other', 'delete.txt'), 'AGD_OTHER_DELETE');
await writeFile(join(work, 'replace.py'), "import os,pathlib\nr=pathlib.Path(__file__).parent\n(r/'sub').rmdir()\nos.symlink('other',r/'sub')\nprint('AGD_PARENT_REPLACED')\n");
const plans = join(temp, 'plans.json'), controlFile = join(temp, 'control.json');
await writeFile(plans, JSON.stringify({ plans: [{ task_profile: 'agd-parent-link', goal: '合成父目录链接验收', allow: ['run_shell'], scope: { paths: { read: [work], write: [work] } } }] }));
let child, token, port, snapshotRoot, snapshot, exited = false, sequence = 0;
const waiting = new Map(), stderr = [], stdout = [];
const scrub = value => token ? value.split(token).join('[已脱敏的测试控制令牌]') : value;
async function control(path, body) {
  const response = await fetch('http://127.0.0.1:' + port + path, { method: body ? 'POST' : 'GET', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(2000) });
  return { status: response.status, value: await response.json() };
}
async function rpc(method, params = {}) {
  const id = ++sequence; let settled = false;
  const response = new Promise((resolve, reject) => waiting.set(id, { resolve, reject })).then(value => ({ value }), error => ({ error })).finally(() => { settled = true; });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  const deadline = Date.now() + 40000;
  while (!settled) {
    if (Date.now() > deadline) throw new Error('MCP 调用超时');
    const pending = (await control('/status')).value.pending;
    if (pending) {
      report.approvals.push({ tool: params.name, arguments: params.arguments, actionSha256: pending.action_sha256 });
      const answer = await control('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding?.nonce });
      if (answer.status !== 200) throw new Error('合成动作批准失败');
    }
    if (!settled) await delay(20);
  }
  const result = await response; if (result.error) throw result.error; return result.value;
}
async function call(name, args) {
  const response = await rpc('tools/call', { name, arguments: args });
  return { ok: !response.error && !response.result?.isError, text: response.result?.content?.find(x => x.type === 'text')?.text || '' };
}
try {
  child = spawn(binary, ['--rules', join(root, 'crates/guard-schema/rules/p0_rules.yaml'), '--shell-policy', join(root, 'crates/guard-shell/policies/default.yaml'), '--plans', plans, '--task', 'agd-parent-link', '--isolation-image', image, '--audit-db', join(temp, 'audit.db'), '--control-file', controlFile, '--confirm-port', '0'], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin.on('error', () => {});
  child.once('exit', code => { exited = true; for (const item of waiting.values()) item.reject(new Error('网关退出:' + code)); waiting.clear(); });
  createInterface({ input: child.stderr }).on('line', line => stderr.push(line));
  createInterface({ input: child.stdout }).on('line', line => { stdout.push(line); try { const value = JSON.parse(line), item = waiting.get(value.id); if (item) { waiting.delete(value.id); item.resolve(value); } } catch {} });
  const deadline = Date.now() + 20000;
  while (!token || !port) {
    try { const descriptor = JSON.parse(await readFile(controlFile, 'utf8')); token = descriptor.token; port = descriptor.port; } catch {}
    if (exited || Date.now() > deadline) throw new Error('网关启动失败:' + stderr.slice(-3).join('\n'));
    if (!token || !port) await delay(20);
  }
  const stats = (await rpc('gateway/stats')).result; report.backend = stats.execution_backend;
  snapshotRoot = stats.execution_backend.snapshot_root;
  for (const mount of stats.execution_backend.workspace_mounts) if (await realpath(mount.target) === work) snapshot = mount.snapshot;
  let result = await call('write_file', { path: join(work, 'normal.txt'), contents: 'AGD_NORMAL' });
  check('normal_write_succeeds', result.ok && await readFile(join(snapshot, 'normal.txt'), 'utf8') === 'AGD_NORMAL', result);
  result = await call('run_shell', { argv: ['/usr/bin/python3', join(work, 'replace.py')], cwd: work });
  check('prior_script_replaces_snapshot_parent', result.ok && result.text.includes('AGD_PARENT_REPLACED'), result);
  result = await call('write_file', { path: join(work, 'sub', 'written.txt'), contents: 'AGD_REDIRECTED_WRITE' });
  const redirected = await exists(join(snapshot, 'other', 'written.txt'));
  check('write_file_rejects_symlink_parent', !result.ok && !redirected, { ...result, redirectedSnapshotWrite: redirected });
  result = await call('read_file', { path: join(work, 'sub', 'read.txt') });
  check('read_file_rejects_symlink_parent', !result.ok && !result.text.includes('AGD_OTHER_READ'), result);
  result = await call('search_file', { path: join(work, 'sub', 'read.txt'), query: 'AGD' });
  check('search_file_rejects_symlink_parent', !result.ok && !result.text.includes('AGD_OTHER_READ'), result);
  result = await call('delete_file', { path: join(work, 'sub', 'delete.txt') });
  check('delete_file_rejects_symlink_parent', !result.ok && await exists(join(snapshot, 'other', 'delete.txt')), result);
  check('host_workspace_unchanged', !await exists(join(work, 'normal.txt')) && !await exists(join(work, 'other', 'written.txt')) && await readFile(join(work, 'other', 'delete.txt'), 'utf8') === 'AGD_OTHER_DELETE');
} catch (error) { report.error = error.stack; }
finally {
  if (child && !exited) {
    child.stdin.end(); const deadline = Date.now() + 3000;
    while (!exited && Date.now() < deadline) await delay(20);
    if (!exited) child.kill('SIGKILL');
  }
  if (snapshotRoot && basename(snapshotRoot).startsWith('agentguard-snapshot-')) await rm(snapshotRoot, { recursive: true, force: true });
  await rm(temp, { recursive: true, force: true });
  report.state = !report.error && report.checks.length && report.checks.every(x => x.passed) ? 'passed' : 'failed';
  await writeFile(join(out, 'report.json'), scrub(JSON.stringify(report, null, 2)) + '\n');
  await writeFile(join(out, 'gateway.stderr'), scrub(stderr.join('\n')));
}
console.log(JSON.stringify({ state: report.state, passed: report.checks.filter(x => x.passed).length, total: report.checks.length, error: report.error, report: join(out, 'report.json') }));
if (report.state !== 'passed') process.exitCode = 1;

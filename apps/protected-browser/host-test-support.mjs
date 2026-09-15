// 统一宿主验收辅助。全部凭据与工作区由测试创建，只针对合成本机服务。
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { createWorkspaceFixture, ROOT, DEFAULT_IMAGE } from '../../scripts/acceptance/agd-workspace-session.mjs';

export async function until(check, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await delay(25); }
  throw new Error('等待验收条件超时');
}
export function toolValue(response) {
  assert.equal(response.error, undefined);
  assert.notEqual(response.result?.isError, true, JSON.stringify(response));
  return JSON.parse(response.result.content[0].text);
}
export async function startHostFixture(origins, { timeout = 8, rpcTimeout = 45000, binary = process.env.AGD_BROWSER_GATEWAY || join(ROOT, 'target/debug/agentguard-mcp'), runtime = join(ROOT, 'apps/protected-browser/cli.mjs'), seed = { 'read.txt': 'SYNTHETIC_WORKSPACE' }, fixture: existingFixture, rulePackageConfig } = {}) {
  const fixture = existingFixture ?? await createWorkspaceFixture({ name: 'browser-host', seed });
  const controlFile = join(fixture.control, 'connection.json'), executorFile = join(fixture.control, 'browser.json');
  const args = ['--rules', fixture.rules, '--shell-policy', fixture.shellPolicy, '--plans', fixture.plans, '--task', fixture.taskProfile,
    '--confirm-port', '0', '--confirm-timeout-secs', String(timeout), '--isolation-image', DEFAULT_IMAGE,
    '--audit-db', fixture.auditDb, '--control-file', controlFile, '--browser-runtime', runtime,
    '--browser-node', process.execPath, '--browser-playwright', join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'playwright'), '--browser-browsers', join(process.env.HOME, 'Library/Caches/ms-playwright'), '--browser-audit-db', join(fixture.control, 'browser.db'), '--browser-file', executorFile,
    '--browser-headless', ...origins.flatMap(origin => ['--browser-origin', origin])];
  if (rulePackageConfig) args.push("--rule-package-config", rulePackageConfig);
  const child = spawn(binary, args, { cwd: ROOT, env: { ...process.env, AGD_HOST_ONLY_TEST_TOKEN: 'SYNTHETIC_BROWSER_MUST_NOT_INHERIT' }, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '', exited = false, sequence = 0; const waiting = new Map();
  child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-32000); });
  child.on('exit', () => { exited = true; for (const { reject, timer } of waiting.values()) { clearTimeout(timer); reject(new Error(`宿主退出：${stderr}`)); } waiting.clear(); });
  child.stdin.on('error', () => {});
  const lines = createInterface({ input: child.stdout });
  lines.on('line', line => { const response = JSON.parse(line), pending = waiting.get(response.id); if (pending) { clearTimeout(pending.timer); waiting.delete(response.id); pending.resolve(response); } });
  const rpc = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence; const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`MCP超时 ${method}：${stderr}`)); }, rpcTimeout);
    waiting.set(id, { resolve, reject, timer }); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  try {
    await until(async () => { if (exited) throw new Error(stderr); try { await access(controlFile); return true; } catch { return false; } }, 15000);
    const credentials = JSON.parse(await readFile(controlFile, 'utf8'));
    const operator = async (path, body) => {
      const response = await fetch(`${credentials.url}${path}`, { method: body ? 'POST' : 'GET', headers: { authorization: `Bearer ${credentials.token}`, ...(body ? { 'content-type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(15000) });
      return { status: response.status, body: await response.json() };
    };
    const initialized = await rpc('initialize'); assert.ok(initialized.result);
    let sessionId = (await rpc('gateway/stats')).result.host_session_id;
    const call = (name, args = {}) => rpc('tools/call', { name, arguments: args, _meta: { agentguard_session_id: sessionId } });
    return { fixture, binary, child, rpc, call, operator, executorFile, controlFile,
      async refreshSession() { sessionId = (await rpc('gateway/stats')).result.host_session_id; return sessionId; },
      async pending() { return until(async () => (await operator('/pending')).body); },
      async decide(request, approve = true) { return operator(approve ? '/approve' : '/deny', { id: request.id, action_sha256: request.action_sha256, approval_nonce: request.binding.nonce }); },
      stderr: () => stderr,
      async close({ preserve = false } = {}) { child.stdin.end(); await until(() => exited, 10000).catch(() => child.kill('SIGTERM')); lines.close(); if (!preserve) await fixture.cleanup(); },
    };
  } catch (error) { child.kill('SIGTERM'); await fixture.cleanup(); throw error; }
}

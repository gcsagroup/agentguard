// F14：仅对显式指定且带本项目标签的合成容器断链；浏览器流量仍经原有宿主单次批准。
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { startHostFixture, toolValue, until } from '../../apps/protected-browser/host-test-support.mjs';

const { values: options } = parseArgs({ options: Object.fromEntries(['container', 'network', 'origin', 'gateway', 'runtime', 'out', 'approvals'].map(name => [name, { type: 'string' }])) });
for (const name of ['container', 'network', 'origin', 'gateway', 'runtime', 'out']) assert.ok(options[name], `缺少 --${name}`);
assert.ok(['native', 'auto'].includes(options.approvals), '--approvals 必须明确为 native 或 auto');
assert.match(options.origin, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/);
const out = resolve(options.out); await mkdir(out, { mode: 0o700 });
await cp(new URL(import.meta.url), join(out, 'runner.mjs'));
const execute = promisify(execFile), report = { started_at: new Date().toISOString(), scope: 'Docker Linux VM 网卡故障；Mac 入口回环，不覆盖 Mac 物理网卡', approvals: options.approvals, phases: [], commands: [], passed: false };
let host, disconnected = false, address, containerId;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const save = async () => writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
async function command(...args) {
  try {
    const result = await execute('docker', args, { timeout: 15000, maxBuffer: 1024 * 1024 });
    report.commands.push({ time: new Date().toISOString(), args, stdout: result.stdout, stderr: result.stderr, exit_code: 0 });
    return result.stdout.trim();
  } catch (error) {
    report.commands.push({ time: new Date().toISOString(), args, stdout: error.stdout, stderr: error.stderr, exit_code: error.code }); throw error;
  }
}
async function control(path = '/state', method = 'GET') {
  return JSON.parse(await command('exec', containerId, 'node', '-e', `fetch('http://127.0.0.1:9090${path}',{method:'${method}'}).then(r=>r.text()).then(console.log)`));
}
async function phase(name, details = {}) { report.phases.push({ name, time: new Date().toISOString(), ...details }); await save(); console.log(JSON.stringify({ phase: name, ...details })); }
async function networkState() {
  return { service: await control(), route: await command('exec', containerId, 'cat', '/proc/net/route'), network: JSON.parse(await command('inspect', containerId, '--format', '{{json .NetworkSettings}}')) };
}
async function restore() {
  if (disconnected) { await command('network', 'connect', '--ip', address, options.network, containerId); disconnected = false; }
}
async function newHost(name) {
  host = await startHostFixture([options.origin], { timeout: 120, rpcTimeout: 180000, binary: resolve(options.gateway), runtime: resolve(options.runtime) });
  await phase(`${name}_host_ready`, { control_file: host.controlFile, fixture: host.fixture.temporaryRoot, gateway_pid: host.child.pid, session_id: (await host.rpc('gateway/stats')).result.host_session_id, inputs: host.fixture.inputs });
}
async function closeHost(name) {
  if (!host) return;
  const owned = host; host = undefined;
  await owned.close({ preserve: true });
  await cp(owned.fixture.control, join(out, name), { recursive: true });
  await owned.fixture.cleanup();
}
async function approved(name, call, method, path, body) {
  const action = call(); action.catch(() => {});
  const pending = await host.pending();
  assert.equal(pending.binding.action.target, options.origin + path);
  assert.equal(pending.binding.action.parameters.method, method);
  if (body !== undefined) assert.equal(pending.binding.action.parameters.body, body);
  await writeFile(join(out, `${name}-request.json`), JSON.stringify(pending, null, 2), { mode: 0o600 });
  await phase(`${name}_awaiting_${options.approvals}_approval`, { request_id: pending.id, action_id: pending.binding.action.action_id, method, target: pending.binding.action.target, body, control_file: host.controlFile });
  if (options.approvals === 'auto') assert.equal((await host.decide(pending)).status, 200);
  else await until(async () => (await host.operator('/pending')).body?.id !== pending.id, 125000);
  return { action, pending };
}
async function terminal(pending) {
  return until(async () => (await host.operator('/workspace/status')).body.browser.receipts.find(item => item.action_id === pending.binding.action.action_id), 25000);
}
async function navigate(name) {
  const request = await approved(name, () => host.call('browser_navigate', { url: options.origin + '/' }), 'GET', '/');
  const result = toolValue(await request.action);
  assert.equal((await terminal(request.pending)).outcome, 'success');
  return result.pages.find(page => page.url === options.origin + '/').id;
}
try {
  const container = JSON.parse(await command('inspect', options.container))[0];
  assert.equal(container.Config.Labels?.['org.gcsa.agentguard.task'], 'F14');
  assert.equal(container.State.Running, true); assert.equal(container.HostConfig.ReadonlyRootfs, true);
  assert.equal(container.Image, 'sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490');
  assert.deepEqual(Object.keys(container.NetworkSettings.Networks), [options.network]);
  const network = JSON.parse(await command('network', 'inspect', options.network))[0];
  assert.equal(network.Labels?.['org.gcsa.agentguard.task'], 'F14');
  assert.deepEqual(Object.keys(network.Containers), [container.Id], '不允许断开共享网络上的其他容器');
  assert.equal(container.NetworkSettings.Ports['8080/tcp'][0].HostIp, '127.0.0.1');
  assert.equal(options.origin, `http://127.0.0.1:${container.NetworkSettings.Ports['8080/tcp'][0].HostPort}`);
  containerId = container.Id; address = container.NetworkSettings.Networks[options.network].IPAddress;
  assert.ok(address && !address.startsWith('127.'));
  report.identity = { container_id: containerId, image: container.Image, address, origin: options.origin, gateway: resolve(options.gateway), gateway_sha256: digest(await readFile(options.gateway)), runtime: resolve(options.runtime), runtime_sha256: digest(await readFile(options.runtime)), node: process.version };
  report.before = await networkState(); const initialCount = report.before.service.hits.length;
  assert.equal(report.before.service.held, 0);
  await newHost('first');
  const firstSession = (await host.rpc('gateway/stats')).result.host_session_id;
  const page = await navigate('first_get');
  const firstValue = `F14-${Date.now()}-ambiguous`;
  toolValue(await host.call('browser_fill', { page, selector: '#test-id', value: firstValue }));
  await control('/hold', 'POST');
  const sent = await approved('ambiguous_post', () => host.call('browser_click', { page, selector: 'button[type="submit"]' }), 'POST', '/submit', `test_id=${firstValue}`);
  await until(async () => (await control()).hits.length === initialCount + 1, 15000);
  // 收件在先、断链在后。服务进程不停止，也不向浏览器开放控制入口。
  await command('network', 'disconnect', options.network, containerId); disconnected = true;
  report.down = await networkState();
  assert.equal(report.down.service.started, report.before.service.started);
  assert.equal(report.down.service.pid, report.before.service.pid);
  assert.equal(report.down.service.interfaces.eth0, undefined);
  assert.deepEqual(report.down.network.Networks, {});
  assert.equal(report.down.route.trim().split('\n').length, 1);
  await sent.action;
  const unknown = await terminal(sent.pending);
  assert.equal(unknown.outcome, 'unknown'); assert.equal(unknown.dispatched, true);
  report.states_after_unknown = [];
  await until(async () => {
    const state = (await host.operator('/workspace/status')).body.session_state;
    if (report.states_after_unknown.at(-1) !== state) report.states_after_unknown.push(state);
    return state === 'failed';
  }, 5000);
  await phase('disconnected_unknown', { receipt: unknown, received_count: report.down.service.hits.length });
  await restore(); await control('/release', 'POST');
  report.restored = await networkState();
  assert.equal(report.restored.service.started, report.before.service.started);
  assert.equal(report.restored.service.pid, report.before.service.pid);
  assert.equal(report.restored.service.interfaces.eth0.find(item => item.family === 'IPv4').address, address);
  assert.ok(report.restored.route.includes('eth0'));
  await phase('restored_observing_no_retry', { seconds: 25 });
  const observeStart = Date.now(); await delay(25000);
  report.after_observation = await control();
  assert.equal(report.after_observation.hits.length, initialCount + 1);
  assert.equal((await host.decide(sent.pending)).status, 409, '旧批准不能重新发送');
  assert.equal((await host.operator('/workspace/resume', {})).status, 409, '未知会话不能自动恢复');
  await phase('no_retry_verified', { observed_ms: Date.now() - observeStart, count: report.after_observation.hits.length, old_approval_status: 409, failed_session_resume_status: 409 });
  await closeHost('first-audit');
  await newHost('fresh');
  const freshSession = (await host.rpc('gateway/stats')).result.host_session_id;
  assert.notEqual(freshSession, firstSession);
  assert.equal((await host.decide(sent.pending)).status, 409);
  const freshPage = await navigate('fresh_get');
  const freshValue = firstValue.replace('ambiguous', 'fresh');
  toolValue(await host.call('browser_fill', { page: freshPage, selector: '#test-id', value: freshValue }));
  const fresh = await approved('fresh_post', () => host.call('browser_click', { page: freshPage, selector: 'button[type="submit"]' }), 'POST', '/submit', `test_id=${freshValue}`);
  assert.notEqual(fresh.pending.id, sent.pending.id); assert.notEqual(fresh.pending.binding.action.action_id, sent.pending.binding.action.action_id);
  toolValue(await fresh.action);
  const receipt = await terminal(fresh.pending); assert.equal(receipt.outcome, 'success');
  assert.equal((await host.decide(fresh.pending)).status, 409);
  report.final_service = await control();
  assert.deepEqual(report.final_service.hits.slice(initialCount).map(item => item.body), [`test_id=${firstValue}`, `test_id=${freshValue}`]);
  await until(async () => JSON.stringify(toolValue(await host.call('browser_read', { page: freshPage }))).includes(freshValue));
  await phase('fresh_request_succeeded', { session_id: freshSession, request_id: fresh.pending.id, action_id: fresh.pending.binding.action.action_id, receipt, new_receipts: 2, browser_readback: true });
  await closeHost('fresh-audit'); report.passed = true;
} catch (error) { report.error = error.stack; process.exitCode = 1; }
finally {
  try { await restore(); if (containerId) await control('/release', 'POST'); await closeHost('retained-audit'); }
  catch (error) { report.cleanup_error = error.stack; report.passed = false; process.exitCode = 1; }
  report.finished_at = new Date().toISOString(); await save();
  console.log(JSON.stringify({ passed: report.passed, report: join(out, 'report.json'), error: report.error, cleanup_error: report.cleanup_error }));
}

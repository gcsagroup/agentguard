// M0：固定 1 KiB 文件的操作微基准；保留失败分母，不代表完整用户任务或冷启动性能。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = fileURLToPath(new URL('../../', import.meta.url));
const candidateSha256 = process.env.AGD_BENCHMARK_SHA256 || '17d1af9c56859d45c561a8b3f2fcfdd383981874026d423cd17f738f63b0dc44';
assert.match(candidateSha256, /^[0-9a-f]{64}$/, '候选摘要必须是完整 SHA-256');
const binary = process.env.AGD_BENCHMARK_BINARY ? resolve(process.env.AGD_BENCHMARK_BINARY) : join(root, 'eval/out/AGD-002/candidates', candidateSha256, 'agentguard-mcp');
const image = 'sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490';
const warmupCount = 5, measuredCount = 30, rssIntervalMs = 20;
const execute = promisify(execFile), digest = data => createHash('sha256').update(data).digest('hex');
assert.equal(digest(await readFile(binary)), candidateSha256, '候选二进制发生变化，拒绝混用性能证据');
const runId = new Date().toISOString().replace(/[-:.]/g, '') + '-' + process.pid;
const out = join(root, 'eval/out/AGD-002', runId + '-benchmark');
await mkdir(out, { recursive: true });
const temp = await realpath(await mkdtemp(join(os.tmpdir(), 'agd-isolation-benchmark-')));
const workspace = join(temp, 'workspace'); await mkdir(workspace);
const input = join(workspace, 'fixed-read.txt');
const contents = 'AGD_ISOLATION_BENCHMARK\n'.repeat(50).slice(0, 1024);
assert.equal(Buffer.byteLength(contents), 1024);
await writeFile(input, contents);
assert.equal(await readFile(input, 'utf8'), contents, '计时前读取一次，固定为已读文件');
const plans = join(temp, 'plans.json');
await writeFile(plans, JSON.stringify({ plans: [{ task_profile: 'agd-read-benchmark', goal: 'M0 固定小文件操作基准', allow: ['run_shell'], scope: { paths: { read: [workspace] } } }] }));
const parameters = { candidateSha256, binary, image, fileBytes: 1024, fileSha256: digest(contents), warmupCount, measuredCount, rssSamplingIntervalMs: rssIntervalMs, quantileMethod: 'nearest_rank: sorted[ceil(n*p)-1]', routeOrder: ['direct_host_read', 'native_gateway_read', 'isolated_gateway_read'], routeTiming: 'readFile 或 MCP read_file 请求提交至完整内容接收并核对之前；不包含启动、预热、人工等待、模型生成、外部业务服务', gatewayStartupTiming: 'spawn 前至 initialize 和 gateway/stats 都返回，隔离模式同时确认控制文件已建立', gatewayRssScope: '仅网关 PID，从 spawn 至正式测量结束；20ms 定时采样、末尾补采，可能漏掉短时峰值', isolationContainerMemoryLimitMiB: 256, measuredContainerPeakRss: null, snapshotHostWriteback: false };
const report = { task: 'AGD-002', scope: 'M0 操作微基准，不是完整用户任务、50 任务验收或 SLA', generatedAt: new Date().toISOString(), parameters, environment: { platform: os.platform(), arch: os.arch(), release: os.release(), cpus: os.cpus().length, cpuModel: os.cpus()[0]?.model, totalMemoryMiB: Math.round(os.totalmem() / 1024 / 1024), node: process.version, loadAverageAtStart: os.loadavg() }, routes: [] };
const snapshotRoots = [];

function summary(rows) {
  const times = rows.map(row => row.elapsedMs).filter(Number.isFinite).sort((a, b) => a - b);
  const at = p => times.length ? times[Math.max(0, Math.ceil(times.length * p) - 1)] : null;
  return { planned: rows.length, attempted: rows.filter(row => row.attempted).length, passed: rows.filter(row => row.passed).length, failedOrNotRun: rows.filter(row => !row.passed).length, successRate: rows.length ? rows.filter(row => row.passed).length / rows.length : 0, latencyAllCompletedAttemptsMs: { samples: times.length, p50: at(0.5), p95: at(0.95), min: times[0] ?? null, max: times.at(-1) ?? null, mean: times.length ? times.reduce((a, b) => a + b, 0) / times.length : null } };
}
async function samples(count, operation) {
  const rows = [];
  for (let index = 1; index <= count; index++) {
    const started = performance.now();
    try {
      const text = await operation();
      const elapsedMs = performance.now() - started;
      rows.push({ index, attempted: true, passed: text === contents, elapsedMs, returnedBytes: Buffer.byteLength(text), ...(text === contents ? {} : { error: '实际内容与固定输入不同' }) });
    } catch (error) {
      rows.push({ index, attempted: true, passed: false, elapsedMs: performance.now() - started, error: String(error.message).slice(0, 1000) });
    }
  }
  return rows;
}
async function startGateway(routeName, isolated) {
  const audit = join(temp, routeName + '-audit.db'), control = join(temp, routeName + '-control.json');
  const args = ['--rules', join(root, 'crates/guard-schema/rules/p0_rules.yaml'), '--shell-policy', join(root, 'crates/guard-shell/policies/default.yaml'), '--plans', plans, '--task', 'agd-read-benchmark', '--confirm-port', '0', '--confirm-timeout-secs', '1', '--audit-db', audit, ...(isolated ? ['--isolation-image', image, '--control-file', control] : [])];
  const started = performance.now();
  const child = spawn(binary, args, { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  let exited = false, sequence = 0, peakKiB = null, rssSamples = 0, sampling = true, closed = false;
  const pending = new Map(), stderr = [];
  const exit = new Promise(resolve => child.once('exit', code => { exited = true; for (const item of pending.values()) item.reject(new Error('网关提前退出：' + code)); pending.clear(); resolve(code); }));
  child.stdin.on('error', () => {});
  child.once('error', error => { for (const item of pending.values()) item.reject(error); pending.clear(); });
  const logs = createInterface({ input: child.stderr });
  logs.on('line', line => { stderr.push(line.trim().startsWith('确认令牌 ') ? '确认令牌 [未读取，已脱敏]' : line); });
  const output = createInterface({ input: child.stdout });
  output.on('line', line => { try { const value = JSON.parse(line), item = pending.get(value.id); if (item) { pending.delete(value.id); item.resolve(value); } } catch {} });
  async function sampleRss() {
    if (!child.pid || exited) return;
    try {
      const result = await execute('/bin/ps', ['-o', 'rss=', '-p', String(child.pid)], { timeout: 2000 });
      const kib = Number(result.stdout.trim());
      if (Number.isFinite(kib) && kib > 0) { peakKiB = Math.max(peakKiB ?? 0, kib); rssSamples++; }
    } catch {}
  }
  const sampler = (async () => { while (sampling && !exited) { await sampleRss(); if (sampling) await delay(rssIntervalMs); } })();
  async function rpc(method, params = {}) {
    if (exited) throw new Error('网关已退出，后续尝试仍记失败');
    const id = ++sequence;
    const reply = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
    const timeout = setTimeout(() => { const item = pending.get(id); if (item) { pending.delete(id); item.reject(new Error('MCP 请求超过 40 秒')); } }, 40000);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    try { return await reply; } finally { clearTimeout(timeout); }
  }
  async function finishSampling() { sampling = false; await sampler; await sampleRss(); return { sampledPeakKiB: peakKiB, sampledPeakMiB: peakKiB === null ? null : peakKiB / 1024, samples: rssSamples, nominalIntervalMs: rssIntervalMs, includesDockerCliOrContainer: false }; }
  async function close() {
    if (closed) return; closed = true;
    sampling = false; await sampler;
    child.stdin.end(); const timeout = setTimeout(() => child.kill('SIGKILL'), 3000); await exit; clearTimeout(timeout);
    logs.close(); output.close(); await writeFile(join(out, routeName + '.stderr'), stderr.join('\n') + '\n');
  }
  try {
    const initial = await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'agd-m0-benchmark', version: '1' } });
    if (initial.error) throw new Error('initialize 失败');
    const statsResponse = await rpc('gateway/stats'), stats = statsResponse.result;
    if (!stats?.execution_journal?.persistent || !stats.execution_journal.healthy) throw new Error('持久审计未启用');
    if (isolated) {
      assert.equal(stats.execution_backend.mode, 'isolated_workspace_snapshot');
      await access(control);
      snapshotRoots.push(stats.execution_backend.snapshot_root);
    } else assert.equal(stats.execution_backend.mode, 'native_cooperative');
    const startupMs = performance.now() - started;
    return { startupMs, args, backend: stats.execution_backend, journal: stats.execution_journal, finishSampling, close, async read() {
      const response = await rpc('tools/call', { name: 'read_file', arguments: { path: input } });
      if (response.error || response.result?.isError) throw new Error(response.error?.message || response.result?.content?.find(item => item.type === 'text')?.text || 'read_file 失败');
      return (response.result?.content?.find(item => item.type === 'text')?.text || '').split('\n\n--- 守卫发现（已执行）---\n')[0];
    } };
  } catch (error) { await close(); throw error; }
}

try {
  report.environment.docker = (await execute('/usr/local/bin/docker', ['version', '--format', '{{json .Server.Version}}'], { timeout: 10000 })).stdout.trim();
  for (const route of parameters.routeOrder) {
    const row = { name: route, startupMs: null, gatewayRss: null, confirmations: 0 };
    let gateway;
    try {
      if (route !== 'direct_host_read') {
        gateway = await startGateway(route, route === 'isolated_gateway_read');
        row.startupMs = gateway.startupMs; row.backend = gateway.backend; row.journal = gateway.journal; row.command = [binary, ...gateway.args];
      }
      const operation = gateway ? () => gateway.read() : () => readFile(input, 'utf8');
      row.warmup = await samples(warmupCount, operation);
      row.warmupSummary = summary(row.warmup);
      row.measured = await samples(measuredCount, operation);
      row.measuredSummary = summary(row.measured);
      if (gateway) row.gatewayRss = await gateway.finishSampling();
    } catch (error) {
      row.error = error.stack;
      row.measured = Array.from({ length: measuredCount }, (_, index) => ({ index: index + 1, attempted: false, passed: false, elapsedMs: null, error: '该路启动失败，保留计划分母' }));
      row.measuredSummary = summary(row.measured);
    } finally { await gateway?.close(); }
    report.routes.push(row);
  }
} catch (error) { report.error = error.stack; }
finally {
  for (const snapshot of snapshotRoots) if (basename(snapshot).startsWith('agentguard-snapshot-')) await rm(snapshot, { recursive: true, force: true });
  await rm(temp, { recursive: true, force: true });
  report.environment.loadAverageAtEnd = os.loadavg();
  report.state = !report.error && report.routes.length === 3 && report.routes.every(route => route.measuredSummary.passed === measuredCount && route.warmupSummary?.passed === warmupCount && (route.name === 'direct_host_read' || route.gatewayRss?.samples > 0)) ? 'passed' : 'failed';
  await writeFile(join(out, 'parameters.json'), JSON.stringify(parameters, null, 2) + '\n');
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
}
console.log(JSON.stringify({ state: report.state, routes: report.routes.map(route => ({ name: route.name, ...route.measuredSummary, startupMs: route.startupMs, gatewayRss: route.gatewayRss })), report: join(out, 'report.json') }));
if (report.state !== 'passed') process.exitCode = 1;

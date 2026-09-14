// M1 独立会话验收。只操作本脚本创建的合成工作区；不下载镜像，不使用真实业务目录。
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, link, lstat, mkdir, mkdtemp, open, readFile, readdir, readlink, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { actionSha256, freeze } from '../../apps/protected-browser/execution-contract.mjs';

const executeFile = promisify(execFile);
export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const RUST_BIN = '/Users/lazy/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin';
export const DEFAULT_IMAGE = 'sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490';
const DOCKER = '/usr/local/bin/docker';
const JSON_LIMIT = 4 * 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const within = (root, path) => { const tail = relative(root, path); return tail === '' || (tail !== '..' && !tail.startsWith('../') && !isAbsolute(tail)); };
const exists = async path => { try { await access(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };

export async function declaredTaskMatrix() {
  const document = await readFile(join(ROOT, 'docs/agd-m1-session-acceptance.zh.md'), 'utf8');
  const tasks = document.split('\n').filter(line => /^\| T\d{2} \|/.test(line)).map(line => {
    const [id, goal, input, steps, acceptance] = line.slice(2, -2).split(' | ');
    return { id, goal, input, steps, acceptance };
  });
  assert.equal(tasks.length, 50, '必须预先声明50个完整任务');
  assert.deepEqual(tasks.map(task => task.id), Array.from({ length: 50 }, (_, index) => `T${String(index + 1).padStart(2, '0')}`));
  for (const task of tasks) {
    assert.ok(task.input && task.acceptance && task.goal, `${task.id} 缺少输入或成果判据`);
    assert.ok(task.steps.split(' → ').length >= 3, `${task.id} 不能只含单步检查`);
  }
  return { documentSha256: digest(document), tasks };
}

export async function fileTree(root) {
  const entries = {};
  async function walk(directory) {
    for (const item of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, item.name), name = relative(root, path), info = await lstat(path);
      if (info.isSymbolicLink()) entries[name] = { kind: 'symlink', target: await readlink(path) };
      else if (info.isDirectory()) { entries[name] = { kind: 'directory', mode: info.mode & 0o777 }; await walk(path); }
      else if (info.isFile()) entries[name] = { kind: 'file', bytes: info.size, mode: info.mode & 0o777, sha256: digest(await readFile(path)) };
      else entries[name] = { kind: 'special', mode: info.mode & 0o777 };
    }
  }
  await walk(root);
  return entries;
}

export async function createWorkspaceFixture({ name = 'm1-session', seed = {}, directories = [], readOnly = false } = {}) {
  const temporaryRoot = await realpath(await mkdtemp(join(tmpdir(), `agd-${name}-`)));
  const work = join(temporaryRoot, 'workspace'), control = join(temporaryRoot, 'operator');
  await mkdir(work, { mode: 0o700 }); await mkdir(control, { mode: 0o700 });
  for (const name of directories) {
    const path = resolve(work, name); assert.ok(within(work, path) && path !== work);
    await mkdir(path, { recursive: true, mode: 0o755 });
  }
  for (const [name, contents] of Object.entries(seed)) {
    const path = resolve(work, name);
    assert.ok(within(work, path) && path !== work, '夹具种子不能越过临时工作区');
    await mkdir(dirname(path), { recursive: true }); await writeFile(path, contents);
  }
  const rules = join(control, 'rules.yaml'), shellPolicy = join(control, 'shell.yaml');
  const rulesBytes = await readFile(join(ROOT, 'crates/guard-schema/rules/p0_rules.yaml'));
  const shellBytes = await readFile(join(ROOT, 'crates/guard-shell/policies/default.yaml'));
  await writeFile(rules, rulesBytes); await writeFile(shellPolicy, shellBytes);
  const taskProfile = `m1-${randomUUID()}`, plans = join(control, 'plans.json');
  await writeFile(plans, JSON.stringify({ plans: [{ task_profile: taskProfile, goal: 'M1 合成本地任务独立验收', allow: ['run_shell'],
    scope: { paths: { read: [work], write: readOnly ? [] : [work] } } }] }));
  return {
    temporaryRoot, work, control, rules, shellPolicy, plans, taskProfile,
    auditDb: join(control, 'audit.db'), initialTree: await fileTree(work),
    inputs: { rulesSha256: digest(rulesBytes), shellPolicySha256: digest(shellBytes), plansSha256: digest(await readFile(plans)) },
    async cleanup() {
      assert.equal(dirname(temporaryRoot), await realpath(tmpdir()));
      assert.ok(basename(temporaryRoot).startsWith(`agd-${name}-`));
      await rm(temporaryRoot, { recursive: true, force: true });
    },
  };
}

async function docker(arguments_) {
  const result = await executeFile(DOCKER, arguments_, { encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
  return result.stdout.trim();
}

async function readConnection(path) {
  const info = await lstat(path);
  assert.ok(info.isFile() && !info.isSymbolicLink(), '控制连接必须是普通文件');
  assert.equal(info.mode & 0o777, 0o600, '控制文件必须只对当前用户可读写');
  assert.equal(info.uid, process.getuid(), '控制文件须由当前操作员拥有');
  assert.equal(info.nlink, 1, '控制文件不能含硬链接别名');
  assert.ok(info.size > 0 && info.size <= 8192, '控制文件长度无效');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let bytes;
  try {
    const opened = await handle.stat();
    assert.equal(opened.dev, info.dev); assert.equal(opened.ino, info.ino);
    bytes = await handle.readFile();
  } finally { await handle.close(); }
  const descriptor = JSON.parse(bytes);
  assert.equal(descriptor.service, 'agentguard-mcp'); assert.equal(descriptor.confirm_protocol, 2);
  const endpoint = new URL(descriptor.url);
  assert.equal(endpoint.protocol, 'http:'); assert.equal(endpoint.hostname, '127.0.0.1');
  assert.equal(endpoint.username + endpoint.password + endpoint.search + endpoint.hash, '');
  assert.equal(endpoint.pathname, '/'); assert.equal(Number(endpoint.port), descriptor.port);
  assert.ok(descriptor.port > 0 && descriptor.port <= 65535);
  assert.match(descriptor.token, /^[a-f0-9]{32}$/); assert.match(descriptor.instance_id, /^[a-f0-9]{32}$/);
  return { descriptor, identity: { device: info.dev, inode: info.ino, mode: info.mode & 0o777 }, origin: endpoint.origin };
}

export class WorkspaceSession {
  #token; #origin; #sequence = 0; #waiting = new Map(); #secrets = new Set(); #reviews = new Map();
  #stderr = []; #output; #logs; #exit; #exited = false; #closed = false; #ownedSnapshots = new Set();

  static async start({ binary, image = DEFAULT_IMAGE, fixture, confirmSeconds = 5, requireWorkspaceProtocol = true, onSession, mcpServiceConfig, startupTimeoutMs = 20000 }) {
    assert.match(image, /^sha256:[a-f0-9]{64}$/, '验收必须使用已存在的固定镜像摘要');
    assert.ok(isAbsolute(binary), '候选二进制必须使用冻结的绝对路径');
    assert.ok(!within(fixture.work, fixture.control), '批准凭据目录不能在任务工作区内');
    assert.equal(await docker(['image', 'inspect', '--format', '{{.Id}}', image]), image, '不下载缺失镜像');
    const session = new WorkspaceSession();
    session.fixture = fixture; session.binary = binary; session.image = image;
    session.binarySha256 = digest(await readFile(binary));
    session.controlFile = join(fixture.control, `connection-${randomUUID()}.json`);
    const args = ['--rules', fixture.rules, '--shell-policy', fixture.shellPolicy, '--plans', fixture.plans,
      '--task', fixture.taskProfile, '--confirm-port', '0', '--confirm-timeout-secs', String(confirmSeconds),
      '--isolation-image', image, '--audit-db', fixture.auditDb, '--control-file', session.controlFile];
    if (mcpServiceConfig) args.push("--mcp-service-config", mcpServiceConfig);
    session.child = spawn(binary, args, { cwd: ROOT, env: { ...process.env, PATH: `${RUST_BIN}:${process.env.PATH}`,
      RUSTC: join(RUST_BIN, 'rustc'), RUSTDOC: join(RUST_BIN, 'rustdoc'), AGD_HOST_ONLY_TEST_TOKEN: 'AGD_M1_SYNTHETIC_ENV_SECRET' },
      stdio: ['pipe', 'pipe', 'pipe'] });
    session.#exit = new Promise(resolveExit => {
      const finish = (code, signal, error) => {
        if (session.#exited) return;
        session.#exited = true;
        for (const item of session.#waiting.values()) { clearTimeout(item.timer); item.reject(error || new Error(`网关已退出：${code}/${signal}`)); }
        session.#waiting.clear(); resolveExit({ code, signal, error: error?.message });
      };
      session.child.once('exit', (code, signal) => finish(code, signal));
      session.child.once('error', error => finish(null, null, error));
    });
    session.child.stdin.on('error', () => {});
    session.#logs = createInterface({ input: session.child.stderr });
    session.#logs.on('line', line => { session.#stderr.push(line.slice(0, 16000)); if (session.#stderr.length > 80) session.#stderr.shift(); });
    session.#output = createInterface({ input: session.child.stdout });
    session.#output.on('line', line => {
      try {
        const response = JSON.parse(line), item = session.#waiting.get(response.id);
        if (item) { clearTimeout(item.timer); session.#waiting.delete(response.id); item.resolve(response); }
      } catch {}
    });
    try {
      const deadline = performance.now() + startupTimeoutMs;
      while (true) {
        try {
          const connection = await readConnection(session.controlFile);
          session.#token = connection.descriptor.token; session.#secrets.add(session.#token); session.#origin = connection.origin;
          session.connection = freeze({ instance_id: connection.descriptor.instance_id, url: connection.origin,
            confirm_protocol: connection.descriptor.confirm_protocol, ...connection.identity });
          break;
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
        if (session.#exited || performance.now() >= deadline) throw new Error(`网关启动失败或超时：${session.redact(session.#stderr.slice(-8).join('\n'))}`);
        await delay(20);
      }
      const initialized = await session.rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {},
        clientInfo: { name: 'agd-m1-session-acceptance', version: '1' } });
      assert.ok(initialized.result?.serverInfo && !initialized.error);
      session.serverVersion = initialized.result.serverInfo.version;
      session.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
      const stats = (await session.rpc('gateway/stats')).result;
      assert.equal(stats.execution_backend?.mode, 'isolated_workspace_snapshot');
      assert.equal(stats.execution_backend?.network, 'none');
      assert.equal(stats.execution_journal?.persistent, true); assert.equal(stats.execution_journal?.healthy, true);
      session.statsAtStart = freeze(structuredClone(stats)); session.sessionId = stats.session_id;
      const snapshotRoot = await realpath(stats.execution_backend.snapshot_root);
      assert.equal(dirname(snapshotRoot), await realpath(tmpdir()));
      assert.ok(basename(snapshotRoot).startsWith('agentguard-snapshot-'));
      session.#ownedSnapshots.add(snapshotRoot);
      const mounts = await Promise.all(stats.execution_backend.workspace_mounts.map(async mount => ({ ...mount, physicalTarget: await realpath(mount.target) })));
      assert.ok(mounts.some(mount => mount.physicalTarget === fixture.work));
      session.snapshotRoot = snapshotRoot;
      session.snapshot = await realpath(mounts.find(mount => mount.physicalTarget === fixture.work).snapshot);
      assert.ok(within(snapshotRoot, session.snapshot));
      session.snapshotInitialTree = await fileTree(session.snapshot);
      if (requireWorkspaceProtocol) await session.workspaceStatus();
      onSession?.(session);
      return session;
    } catch (error) {
      await session.close().catch(() => {});
      throw new Error(session.redact(error.stack || error.message));
    }
  }

  redact(value) {
    let text = typeof value === 'string' ? value : JSON.stringify(value);
    for (const secret of this.#secrets) text = text.split(secret).join('[已脱敏的测试凭据]');
    return text.replace(/确认令牌 .+/g, '确认令牌 [已脱敏]');
  }

  get exited() { return this.#exited; }
  get stderrTail() { return this.redact(this.#stderr.join('\n')); }

  rpc(method, params = {}, { timeoutMs = 45000 } = {}) {
    if (this.#exited || this.#closed) return Promise.reject(new Error('会话进程不可用'));
    const id = ++this.#sequence;
    const result = new Promise((resolveRpc, reject) => {
      const timer = setTimeout(() => { this.#waiting.delete(id); reject(new Error(`MCP 超时：${method}`)); }, timeoutMs);
      this.#waiting.set(id, { resolve: resolveRpc, reject, timer });
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
    // 立即观察拒绝，调用方可随后等待批准或注入断连，而不产生未处理 rejection。
    result.catch(() => {});
    return result;
  }

  async operatorRequest(path, body, { tokenOverride, timeoutMs = 15000, oversizedNegative = false, omitAuthorization = false, headers = {} } = {}) {
    assert.ok(path.startsWith('/') && !path.startsWith('//') && !path.includes('#'), '操作员请求必须保持本机同一来源');
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (payload !== undefined && !oversizedNegative) assert.ok(Buffer.byteLength(payload) <= JSON_LIMIT, '操作员JSON超出4MiB');
    const response = await fetch(this.#origin + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      headers: { ...(omitAuthorization ? {} : { Authorization: `Bearer ${tokenOverride ?? this.#token}` }), 'Content-Type': 'application/json', ...headers },
      body: payload, signal: AbortSignal.timeout(timeoutMs) });
    const parts = []; let length = 0;
    for await (const part of response.body) { length += part.length; if (length > JSON_LIMIT) throw new Error('操作员响应超出4MiB'); parts.push(part); }
    const text = Buffer.concat(parts).toString('utf8');
    let value; try { value = JSON.parse(text); } catch { value = { error: text.slice(0, 1000) }; }
    if (value.review_nonce) this.#secrets.add(value.review_nonce);
    if (value.binding?.nonce) this.#secrets.add(value.binding.nonce);
    if (value.binding?.action?.nonce) this.#secrets.add(value.binding.action.nonce);
    if (value.pending?.binding?.nonce) this.#secrets.add(value.pending.binding.nonce);
    return { status: response.status, value };
  }

  #workspaceEnvelope(value) {
    assert.equal(value.service, 'agentguard-mcp'); assert.equal(value.workspace_protocol, 1);
    assert.equal(value.instance_id, this.connection.instance_id);
    assert.ok(typeof value.session_id === 'string' && value.session_id.length > 0);
  }

  async workspaceStatus() {
    const response = await this.operatorRequest('/workspace/status');
    assert.equal(response.status, 200, this.redact(response.value)); this.#workspaceEnvelope(response.value);
    assert.equal(response.value.task_profile, this.fixture.taskProfile);
    assert.ok(['active', 'paused', 'stopped', 'failed'].includes(response.value.session_state));
    assert.ok(Array.isArray(response.value.workspaces));
    this.sessionId = response.value.session_id;
    return freeze(structuredClone(response.value));
  }

  async previewWorkspace(workspaceId) {
    const response = await this.operatorRequest('/workspace/preview', { workspace_id: workspaceId });
    assert.equal(response.status, 200, this.redact(response.value)); this.#workspaceEnvelope(response.value);
    const review = response.value;
    assert.equal(review.session_id, this.sessionId); assert.equal(review.workspace_id, workspaceId);
    assert.ok(typeof review.review_id === 'string' && review.review_id.length > 0);
    assert.match(review.review_sha256, /^[a-f0-9]{64}$/); assert.match(review.review_nonce, /^[a-f0-9]{32,128}$/);
    assert.ok(Number.isSafeInteger(review.expires_at_ms) && review.expires_at_ms > Date.now());
    const binding = review.binding, action = binding?.action;
    assert.ok(action, '预览必须有可独立核验的完整批准绑定');
    assert.equal(binding.approval_id, review.review_id); assert.equal(binding.nonce, review.review_nonce);
    assert.equal(binding.expires_at_ms, review.expires_at_ms); assert.equal(action.session_id, review.session_id);
    assert.equal(action.contract_version, 1); assert.equal(action.target, review.preview.workspace_root);
    assert.equal(action.tool.service, 'agentguard-host-control'); assert.equal(action.tool.name, 'workspace_apply');
    assert.equal(action.tool.version, this.serverVersion);
    assert.deepEqual(action.parameters, { workspace_id: workspaceId, preview: review.preview });
    assert.equal(actionSha256(action), review.review_sha256, '回写批准必须绑定完整预览与会话');
    assert.ok(typeof review.preview.recovery_directory === 'string' && isAbsolute(review.preview.recovery_directory));
    assert.ok(!within(this.fixture.work, resolve(review.preview.recovery_directory)), '恢复目录不能落入任务授权工作区');
    assert.ok(Array.isArray(review.preview?.changes)); assert.equal(review.preview.atomic, false);
    for (const change of review.preview.changes) {
      assert.ok(typeof change.path === 'string' && !isAbsolute(change.path) && within(this.fixture.work, resolve(this.fixture.work, change.path)));
      assert.ok(['create', 'modify', 'delete'].includes(change.kind));
      for (const version of [change.before, change.after].filter(Boolean)) {
        assert.match(version.sha256, /^[a-f0-9]{64}$/); assert.ok(Number.isSafeInteger(version.bytes) && version.bytes >= 0);
        assert.ok(Number.isSafeInteger(version.mode) && version.mode >= 0 && version.mode <= 0o777);
        if (version.text !== null) { assert.equal(Buffer.byteLength(version.text), version.bytes); assert.equal(digest(version.text), version.sha256); }
      }
    }
    const frozen = freeze(structuredClone(review)); this.#reviews.set(frozen.review_id, frozen);
    return frozen;
  }

  async applyReview(review) {
    assert.equal(this.#reviews.get(review.review_id), review, '必须应用本启动器保存的不可变预览');
    assert.equal(review.session_id, this.sessionId, '旧会话预览不得应用');
    assert.ok(review.expires_at_ms > Date.now(), '预览已经过期');
    this.#reviews.delete(review.review_id); // 发出后不在本地重试，未知结果也保持一次消费。
    const response = await this.operatorRequest('/workspace/apply', { review_id: review.review_id,
      review_sha256: review.review_sha256, review_nonce: review.review_nonce });
    if (response.status !== 200) return response;
    this.#workspaceEnvelope(response.value);
    assert.ok(['applied', 'conflict', 'partial', 'unknown'].includes(response.value.result?.outcome));
    assert.ok(Array.isArray(response.value.result.files));
    return response;
  }

  async transition(action) {
    assert.ok(['pause', 'resume', 'stop'].includes(action));
    const response = await this.operatorRequest(`/workspace/${action}`, {});
    if (response.status !== 200) return response;
    this.#workspaceEnvelope(response.value); this.sessionId = response.value.session_id; this.#reviews.clear();
    return response;
  }

  async waitForPending({ timeoutMs = 5000 } = {}) {
    const deadline = performance.now() + timeoutMs;
    while (performance.now() < deadline) {
      const response = await this.operatorRequest('/status');
      assert.equal(response.status, 200);
      if (response.value.pending) return freeze(structuredClone(response.value.pending));
      if (this.#exited) throw new Error('待批准前会话已经退出');
      await delay(20);
    }
    throw new Error('没有出现本次待批准动作');
  }

  async answerAction(pending, decision, expected) {
    assert.ok(['approve', 'deny'].includes(decision));
    const binding = pending.binding, action = binding?.action;
    assert.ok(action); this.#secrets.add(binding.nonce);
    assert.equal(action.contract_version, 1); assert.equal(binding.approval_id, pending.id);
    assert.equal(actionSha256(action), pending.action_sha256, '批准摘要必须匹配完整动作');
    assert.equal(action.session_id, this.sessionId); assert.ok(binding.expires_at_ms > Date.now());
    if (decision === 'approve') {
      assert.ok(expected, '验收只批准预先声明的本次具体调用');
      assert.equal(action.tool.service, 'agentguard-gateway'); assert.equal(action.tool.name, expected.name);
      assert.equal(action.tool.version, this.serverVersion);
      for (const [key, value] of Object.entries(expected.arguments)) assert.deepEqual(action.parameters[key], value, `批准参数改变：${key}`);
      assert.equal(action.parameters.execution_backend?.mode, 'isolated_workspace_snapshot');
    }
    return this.operatorRequest(`/${decision}`, { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: binding.nonce });
  }

  async callTool(name, arguments_, { approval = 'deny', timeoutMs = 45000 } = {}) {
    const expected = freeze({ name, arguments: structuredClone(arguments_) });
    const start = performance.now(); let settled = false, confirmations = 0;
    const result = this.rpc('tools/call', { name, arguments: expected.arguments,
      _meta: { agentguard_session_id: this.sessionId } }, { timeoutMs });
    const observed = result.then(value => ({ value }), error => ({ error })).finally(() => { settled = true; });
    while (!settled) {
      if (approval !== 'manual') {
        const response = await this.operatorRequest('/status').catch(error => ({ status: 0, error }));
        if (response.status === 200 && response.value.pending) {
          confirmations++;
          const answered = await this.answerAction(response.value.pending, approval === 'approve' ? 'approve' : 'deny', expected);
          assert.equal(answered.status, 200, this.redact(answered.value));
        }
      }
      if (!settled) await delay(20);
    }
    const response = await observed; if (response.error) throw response.error;
    const text = response.value.result?.content?.find(part => part.type === 'text')?.text || '';
    return { ok: !response.value.error && !response.value.result?.isError,
      text: text.split('\n\n--- 守卫发现（已执行）---\n')[0], raw: response.value,
      confirmations, elapsedMs: performance.now() - start };
  }

  async ownedContainers() {
    if (!this.#ownedSnapshots.size) return [];
    const ids = (await docker(['ps', '--filter', 'name=agentguard-task-', '--format', '{{.ID}}'])).split('\n').filter(Boolean);
    if (!ids.length) return [];
    // ps与inspect之间其他独立测试容器可正常退出；只忽略Docker明确报告的对象已消失。
    const inspected = (await Promise.all(ids.map(async id => {
      try { return JSON.parse(await docker(['inspect', id])); }
      catch (error) { if (/no such (object|container)/i.test(error.stderr || '')) return []; throw error; }
    }))).flat();
    const containers = await Promise.all(inspected.map(async container => ({
      name: container.Name.replace(/^\//, ''), sources: await Promise.all(container.Mounts.map(mount => realpath(mount.Source).catch(() => mount.Source))),
    })));
    return containers.filter(container => container.sources.some(source =>
      [...this.#ownedSnapshots].some(root => within(root, source) && source !== root))).map(container => container.name);
  }

  async kill() {
    const faultAt = performance.now(); if (!this.#exited) this.child.kill('SIGKILL');
    await this.#exit; return { faultAt, exitedAt: performance.now() };
  }

  async disconnect() {
    this.child.stdin.end(); return this.#exit;
  }

  async close({ preserveSnapshots = false } = {}) {
    if (this.#closed) return;
    this.#closed = true;
    if (!this.#exited) this.child.stdin.end();
    const killer = setTimeout(() => { if (!this.#exited) this.child.kill('SIGKILL'); }, 8000);
    const ended = await this.#exit; clearTimeout(killer); this.#logs.close(); this.#output.close();
    // 只回收通过当前快照挂载关系核实的测试容器，不操作其他工作。
    for (const container of await this.ownedContainers()) await docker(['rm', '--force', container]);
    assert.deepEqual(await this.ownedContainers(), [], '本次容器尚未停止，保留现场');
    if (!preserveSnapshots) for (const root of this.#ownedSnapshots) {
      assert.equal(dirname(root), await realpath(tmpdir())); assert.ok(basename(root).startsWith('agentguard-snapshot-'));
      await rm(root, { recursive: true, force: true });
    }
    return ended;
  }
}

async function launcherSmoke(options) {
  const fixture = await createWorkspaceFixture({ name: 'm1-launcher', seed: {
    'input.txt': 'AGD_M1_INPUT\n',
    'process.py': "from pathlib import Path\nr=Path(__file__).parent\n(r/'python.txt').write_text((r/'input.txt').read_text().lower())\nprint('python-done')\n",
    'process.cjs': "const fs=require('node:fs'),p=require('node:path');fs.writeFileSync(p.join(__dirname,'node.txt'),fs.readFileSync(p.join(__dirname,'input.txt'),'utf8').toLowerCase());console.log('node-done');\n",
  } });
  let session;
  const report = { suite: 'launcher-smoke', taskCount: 0, checks: [], workspaceProtocolRequired: !options.launcherOnly,
    scope: '启动器与合成真实副作用检查；不计入50完整任务或长期验收', image: options.image, inputs: fixture.inputs };
  const check = (name, passed) => { report.checks.push({ name, passed: !!passed }); assert.ok(passed, name); };
  try {
    session = await WorkspaceSession.start({ ...options, fixture, requireWorkspaceProtocol: !options.launcherOnly });
    report.binarySha256 = session.binarySha256; report.connection = session.connection;
    check('独立控制文件权限0600', session.connection.mode === 0o600);
    check('控制令牌不进入MCP状态', !session.redact(session.statsAtStart).includes('[已脱敏的测试凭据]'));
    const read = await session.callTool('read_file', { path: join(fixture.work, 'input.txt') });
    check('MCP实际读取输入', read.ok && read.text === 'AGD_M1_INPUT\n');
    for (const [runtime, argv] of [['python', ['/usr/bin/python3', join(fixture.work, 'process.py')]], ['node', ['/usr/local/bin/node', join(fixture.work, 'process.cjs')]]]) {
      const result = await session.callTool('run_shell', { argv, cwd: fixture.work }, { approval: 'approve' });
      check(`${runtime}真实隔离处理`, result.ok && result.text.trim() === `${runtime}-done`);
      check(`${runtime}快照成果正确`, await readFile(join(session.snapshot, `${runtime}.txt`), 'utf8') === 'agd_m1_input\n');
    }
    check('批准回写前宿主树未改变', JSON.stringify(await fileTree(fixture.work)) === JSON.stringify(fixture.initialTree));
    if (!options.launcherOnly) {
      const state = await session.workspaceStatus();
      const workspaces = await Promise.all(state.workspaces.map(async item => ({ ...item, physicalTarget: await realpath(item.target) })));
      const workspace = workspaces.find(item => item.physicalTarget === fixture.work);
      check('operator工作区范围准确', !!workspace && workspace.writable && workspace.writeback_available);
      const review = await session.previewWorkspace(workspace.workspace_id);
      check('预览只包含两份成果', review.preview.changes.length === 2 && review.preview.changes.every(change => ['python.txt', 'node.txt'].includes(change.path)));
      const applied = await session.applyReview(review);
      check('绑定批准回写成功', applied.status === 200 && applied.value.result.outcome === 'applied');
      check('宿主实际收到两份正确成果', await readFile(join(fixture.work, 'python.txt'), 'utf8') === 'agd_m1_input\n' && await readFile(join(fixture.work, 'node.txt'), 'utf8') === 'agd_m1_input\n');
      const stopped = await session.transition('stop');
      check('operator永久停止', stopped.status === 200 && stopped.value.session_state === 'stopped');
    }
    const controlFile = session.controlFile;
    await session.close();
    check('正常关闭撤销本次连接文件', !await exists(controlFile));
    check('验收中候选摘要保持一致', digest(await readFile(options.binary)) === report.binarySha256);
    report.passed = true;
  } catch (error) { report.passed = false; report.error = session ? session.redact(error.stack || error.message) : error.stack || error.message; }
  finally { await session?.close().catch(error => { report.cleanupError = error.message; report.passed = false; }); await fixture.cleanup(); }
  return report;
}

const PYTHON_PRELUDE = String.raw`import csv,hashlib,io,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parent
(root/'outputs').mkdir(exist_ok=True)
def read(name): return (root/name).read_text(encoding='utf-8')
def load(name): return json.loads(read(name))
def text(name,value): (root/name).write_text(value,encoding='utf-8')
def emit(name,value): text(name,json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
`;
const NODE_PRELUDE = String.raw`const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=__dirname;fs.mkdirSync(path.join(root,'outputs'),{recursive:true});
const read=name=>fs.readFileSync(path.join(root,name),'utf8'),load=name=>JSON.parse(read(name));
const text=(name,value)=>fs.writeFileSync(path.join(root,name),value),emit=(name,value)=>text(name,JSON.stringify(value,null,2)+'\n');
`;
const asJson = value => JSON.stringify(value, null, 2) + '\n';
const jsonExpected = value => ({ json: value });
const textExpected = value => ({ text: value });

export function taskDefinition(id) {
  const definitions = {
    T01: { runtime: 'python', seed: { 'orders.csv': 'sku,quantity,price\nA,2,10\nA,1,5\nB,3,7\n' },
      body: String.raw`rows=list(csv.DictReader(io.StringIO(read('orders.csv'))));totals={}
for row in rows:
 quantity,price=int(row['quantity']),int(row['price']);assert quantity>0 and price>=0
 totals[row['sku']]=totals.get(row['sku'],0)+quantity*price
emit('outputs/sales.json',{'by_sku':totals,'total':sum(totals.values()),'orders':len(rows)})
text('outputs/sales.md','# 订单汇总\n\nA：'+str(totals['A'])+'\nB：'+str(totals['B'])+'\n合计：'+str(sum(totals.values()))+'\n')`,
      expected: { 'outputs/sales.json': jsonExpected({ by_sku: { A: 25, B: 21 }, total: 46, orders: 3 }), 'outputs/sales.md': textExpected('# 订单汇总\n\nA：25\nB：21\n合计：46\n') } },
    T02: { runtime: 'python', seed: { 'stock.json': asJson({ A: 10, B: 3 }), 'moves.json': asJson([['A', -4], ['A', 2], ['B', -1]]) },
      body: String.raw`stock=load('stock.json');moves=load('moves.json')
for sku,quantity in moves:
 assert sku in stock and isinstance(quantity,int);stock[sku]+=quantity;assert stock[sku]>=0
emit('outputs/stock.json',{'stock':stock,'movement_count':len(moves)})`,
      expected: { 'outputs/stock.json': jsonExpected({ stock: { A: 8, B: 2 }, movement_count: 3 }) } },
    T03: { runtime: 'python', seed: { 'events.jsonl': '{"status":200}\n{"status":200}\nnot-json\n{"status":404}\n{"status":500}\n' },
      body: String.raw`counts={};bad=[];valid=0
for number,line in enumerate(read('events.jsonl').splitlines(),1):
 try:
  row=json.loads(line);key=str(row['status']);counts[key]=counts.get(key,0)+1;valid+=1
 except (ValueError,KeyError,TypeError): bad.append(number)
emit('outputs/daily.json',{'valid':valid,'invalid':len(bad),'statuses':counts});emit('outputs/rejected.json',{'line_numbers':bad})`,
      expected: { 'outputs/daily.json': jsonExpected({ valid: 4, invalid: 1, statuses: { 200: 2, 404: 1, 500: 1 } }), 'outputs/rejected.json': jsonExpected({ line_numbers: [3] }) } },
    T04: { runtime: 'python', seed: { 'contacts.csv': 'name,email\nAda, ADA@example.test \nOther,ada@EXAMPLE.TEST\nBob,bob@example.test\n' },
      body: String.raw`unique=[];duplicates=[];seen=set()
for row in csv.DictReader(io.StringIO(read('contacts.csv'))):
 email=row['email'].strip().lower()
 if email in seen: duplicates.append({'name':row['name'],'email':email})
 else: seen.add(email);unique.append({'name':row['name'],'email':email})
emit('outputs/contacts.json',unique);emit('outputs/duplicates.json',duplicates)`,
      expected: { 'outputs/contacts.json': jsonExpected([{ name: 'Ada', email: 'ada@example.test' }, { name: 'Bob', email: 'bob@example.test' }]), 'outputs/duplicates.json': jsonExpected([{ name: 'Other', email: 'ada@example.test' }]) } },
    T05: { runtime: 'python', seed: { 'hours.json': asJson([{ project: '甲', hours: 1.5 }, { project: '甲', hours: 2 }, { project: '乙', hours: 0.5 }]) },
      body: String.raw`totals={}
for row in load('hours.json'):
 assert isinstance(row['hours'],(int,float)) and row['hours']>=0
 totals[row['project']]=totals.get(row['project'],0)+row['hours']
emit('outputs/hours.json',{'projects':totals,'total':sum(totals.values())})
text('outputs/hours.md','# 工时\n\n甲：3.5小时\n乙：0.5小时\n合计：4小时\n')`,
      expected: { 'outputs/hours.json': jsonExpected({ projects: { 甲: 3.5, 乙: 0.5 }, total: 4 }), 'outputs/hours.md': textExpected('# 工时\n\n甲：3.5小时\n乙：0.5小时\n合计：4小时\n') } },
    T06: { runtime: 'python', seed: { 'docs/a.md': '# Alpha\n正文A\n', 'docs/b.md': '# Beta\n正文B\n', 'docs/c.md': '没有标题\n' },
      body: String.raw`rows=[];missing=[]
for path in sorted((root/'docs').glob('*.md')):
 headings=[line[2:] for line in path.read_text().splitlines() if line.startswith('# ')]
 name=path.relative_to(root).as_posix();title=headings[0] if headings else path.stem
 rows.append('- ['+title+'](../'+name+')')
 if not headings: missing.append(name)
text('outputs/index.md','# 文档目录\n\n'+'\n'.join(rows)+'\n');emit('outputs/missing-titles.json',missing)`,
      expected: { 'outputs/index.md': textExpected('# 文档目录\n\n- [Alpha](../docs/a.md)\n- [Beta](../docs/b.md)\n- [c](../docs/c.md)\n'), 'outputs/missing-titles.json': jsonExpected(['docs/c.md']) } },
    T07: { runtime: 'python', seed: { 'payload/a.txt': 'alpha\n', 'payload/b.txt': 'beta\n' },
      body: String.raw`manifest=[]
for path in sorted((root/'payload').glob('*.txt')):
 value=hashlib.sha256();size=0
 with path.open('rb') as source:
  while True:
   block=source.read(7)
   if not block: break
   size+=len(block);value.update(block)
 manifest.append({'path':path.relative_to(root).as_posix(),'bytes':size,'sha256':value.hexdigest()})
emit('outputs/manifest.json',manifest)`,
      expected: { 'outputs/manifest.json': jsonExpected([{ path: 'payload/a.txt', bytes: 6, sha256: digest('alpha\n') }, { path: 'payload/b.txt', bytes: 5, sha256: digest('beta\n') }]) } },
    T08: { runtime: 'python', seed: { 'legacy.json': asJson({ schema: 1, users: [{ id: 7, name: 'Ada' }] }) },
      body: String.raw`old=load('legacy.json');assert old['schema']==1
new={'schema':2,'users':[{'id':str(user['id']),'display_name':user['name'],'enabled':True} for user in old['users']]}
assert all(isinstance(user['id'],str) and user['display_name'] for user in new['users'])
text('outputs/legacy-backup.json',read('legacy.json'));emit('outputs/users-v2.json',new);emit('outputs/migration.json',{'from':1,'to':2,'migrated':len(new['users'])})`,
      expected: { 'outputs/legacy-backup.json': jsonExpected({ schema: 1, users: [{ id: 7, name: 'Ada' }] }), 'outputs/users-v2.json': jsonExpected({ schema: 2, users: [{ id: '7', display_name: 'Ada', enabled: true }] }), 'outputs/migration.json': jsonExpected({ from: 1, to: 2, migrated: 1 }) } },
    T09: { runtime: 'python', seed: { 'tests.json': asJson([{ id: 'a', status: 'passed' }, { id: 'b', status: 'passed' }, { id: 'c', status: 'passed' }, { id: 'd', status: 'failed' }, { id: 'e', status: 'skipped' }]) },
      body: String.raw`rows=load('tests.json');run=[row for row in rows if row['status']!='skipped'];passed=sum(row['status']=='passed' for row in run)
emit('outputs/summary.json',{'total':len(rows),'executed':len(run),'passed':passed,'success_percent':100*passed/len(run)})
emit('outputs/failures.json',[row['id'] for row in rows if row['status']=='failed'])`,
      expected: { 'outputs/summary.json': jsonExpected({ total: 5, executed: 4, passed: 3, success_percent: 75 }), 'outputs/failures.json': jsonExpected(['d']) } },
    T10: { runtime: 'python', seed: { 'todos.json': asJson([{ title: 'B', priority: 2, description: '第二级' }, { title: 'A', priority: 1, description: '第一级A' }, { title: 'C', priority: 1, description: '第一级C' }]) },
      body: String.raw`rows=sorted(load('todos.json'),key=lambda row:(row['priority'],row['title']))
emit('outputs/action-list.json',rows);text('outputs/action-list.md','# 待办\n\n'+'\n'.join('- '+row['title']+'：'+row['description'] for row in rows)+'\n')`,
      expected: { 'outputs/action-list.json': jsonExpected([{ title: 'A', priority: 1, description: '第一级A' }, { title: 'C', priority: 1, description: '第一级C' }, { title: 'B', priority: 2, description: '第二级' }]), 'outputs/action-list.md': textExpected('# 待办\n\n- A：第一级A\n- C：第一级C\n- B：第二级\n') } },
    T11: { runtime: 'python', seed: { 'numbers.json': asJson(['2', '10', '1']) }, initialBody: "assert sorted(['2','10','1'])==['1','2','10'],'数字被按字典排序'\n",
      body: String.raw`def sort_numbers(values): return sorted(int(value) for value in values)
assert sort_numbers([])==[];assert sort_numbers(['0','-2','3'])==[-2,0,3]
emit('outputs/numbers.json',sort_numbers(load('numbers.json')));text('outputs/change.md','已修复：按数值排序，并保留空输入与负数回归。\n')`,
      expected: { 'outputs/numbers.json': jsonExpected([1, 2, 10]), 'outputs/change.md': textExpected('已修复：按数值排序，并保留空输入与负数回归。\n') } },
    T12: { runtime: 'python', seed: { 'quoted.csv': '"a,b",c\n' }, initialBody: "assert len('\"a,b\",c'.split(','))==2,'带引号列被拆开'\n",
      body: String.raw`def parse(value): return list(csv.reader(io.StringIO(value)))
assert parse('"a,b",c\n')==[['a,b','c']];assert parse('a,,c\n')==[['a','','c']];assert parse('"a""b",c\n')==[['a"b','c']]
emit('outputs/rows.json',parse(read('quoted.csv')));text('outputs/change.md','已修复：采用CSV引用规则，验证逗号、引号与空列。\n')`,
      expected: { 'outputs/rows.json': jsonExpected([['a,b', 'c']]), 'outputs/change.md': textExpected('已修复：采用CSV引用规则，验证逗号、引号与空列。\n') } },
    T13: { runtime: 'python', seed: { 'items.json': asJson(['b', 'a', 'b', 'c', 'a']) }, initialBody: "assert sorted(set(['b','a','b','c','a']))==['b','a','c'],'原次序丢失'\n",
      body: String.raw`def unique(values): return list(dict.fromkeys(values))
assert unique([])==[];assert unique(['x','x'])==['x']
emit('outputs/unique.json',unique(load('items.json')));text('outputs/change.md','已修复：去重保留首次出现的次序。\n')`,
      expected: { 'outputs/unique.json': jsonExpected(['b', 'a', 'c']), 'outputs/change.md': textExpected('已修复：去重保留首次出现的次序。\n') } },
    T14: { runtime: 'python', seed: { 'unicode.txt': '中😀a' }, initialBody: "assert len('中😀a'.encode('utf-8'))==3,'误把字节当字符'\n",
      body: String.raw`assert len('')==0;assert len('中文')==2
value=read('unicode.txt');emit('outputs/count.json',{'text':value,'characters':len(value)})
text('outputs/change.md','已修复：统计Unicode码点，不统计UTF-8字节。\n')`,
      expected: { 'outputs/count.json': jsonExpected({ text: '中😀a', characters: 3 }), 'outputs/change.md': textExpected('已修复：统计Unicode码点，不统计UTF-8字节。\n') } },
    T15: { runtime: 'python', seed: { 'values.json': asJson([1, 2, 3, 4, 5]) }, initialBody: "values=[1,2,3,4,5]\nassert [values[i:i+2] for i in range(0,len(values)-1,2)]==[[1,2],[3,4],[5]],'尾块丢失'\n",
      body: String.raw`def chunks(values,size):
 assert size>0;return [values[index:index+size] for index in range(0,len(values),size)]
assert chunks([],2)==[];assert chunks([1,2,3,4],2)==[[1,2],[3,4]]
emit('outputs/chunks.json',chunks(load('values.json'),2));text('outputs/change.md','已修复：不足整块的尾项仍保留。\n')`,
      expected: { 'outputs/chunks.json': jsonExpected([[1, 2], [3, 4], [5]]), 'outputs/change.md': textExpected('已修复：不足整块的尾项仍保留。\n') } },
    T16: { runtime: 'python', seed: { 'names.json': asJson(['Hello World!', 'Two  Spaces']) },
      body: String.raw`def slug(value): return re.sub(r'[^a-z0-9]+','-',value.lower()).strip('-')
assert slug('  Hello!  ')=='hello';assert slug('')==''
emit('outputs/names.json',[{'original':value,'filename':slug(value)} for value in load('names.json')])`,
      expected: { 'outputs/names.json': jsonExpected([{ original: 'Hello World!', filename: 'hello-world' }, { original: 'Two  Spaces', filename: 'two-spaces' }]) } },
    T17: { runtime: 'python', seed: { 'texts/a.txt': 'a\r\nb\r\n', 'texts/b.txt': 'one\r\n\r\nthree\r\n', 'texts/c.txt': '尾行\r\n' },
      body: String.raw`changed=[]
for path in sorted((root/'texts').glob('*.txt')):
 before=path.read_bytes();after=before.replace(b'\r\n',b'\n')
 if before!=after: path.write_bytes(after);changed.append(path.relative_to(root).as_posix())
emit('outputs/normalized.json',{'changed':changed,'line_ending':'LF'})`,
      expected: { 'texts/a.txt': textExpected('a\nb\n'), 'texts/b.txt': textExpected('one\n\nthree\n'), 'texts/c.txt': textExpected('尾行\n'), 'outputs/normalized.json': jsonExpected({ changed: ['texts/a.txt', 'texts/b.txt', 'texts/c.txt'], line_ending: 'LF' }) } },
    T18: { runtime: 'python', seed: { 'cents.json': asJson([105, 99, 0]) }, initialBody: "assert 0.1+0.2==0.3,'浮点尾数'\n",
      body: String.raw`def money(cents):
 assert isinstance(cents,int) and cents>=0;return str(cents//100)+'.'+str(cents%100).zfill(2)
assert money(10)=='0.10';assert money(101)=='1.01'
emit('outputs/amounts.json',[money(value) for value in load('cents.json')]);text('outputs/change.md','已修复：整数分格式化不经过浮点加法。\n')`,
      expected: { 'outputs/amounts.json': jsonExpected(['1.05', '0.99', '0.00']), 'outputs/change.md': textExpected('已修复：整数分格式化不经过浮点加法。\n') } },
    T19: { runtime: 'python', seed: { 'catalog.json': asJson({ p1: 'One', p2: 'Two' }), 'orders.json': asJson([{ sku: 'p1', count: 2 }, { sku: 'p2', count: 1 }, { sku: 'missing', count: 1 }]) },
      body: String.raw`catalog=load('catalog.json');known=[];unknown=[]
for order in load('orders.json'):
 if order['sku'] not in catalog: unknown.append(order)
 else: known.append({'name':catalog[order['sku']],'count':order['count']})
emit('outputs/known-orders.json',known);emit('outputs/unknown-orders.json',unknown)`,
      expected: { 'outputs/known-orders.json': jsonExpected([{ name: 'One', count: 2 }, { name: 'Two', count: 1 }]), 'outputs/unknown-orders.json': jsonExpected([{ sku: 'missing', count: 1 }]) } },
    T20: { runtime: 'python', seed: { 'words.txt': 'alpha beta alpha\n' },
      body: String.raw`import argparse,subprocess
parser=argparse.ArgumentParser(description='本地词频');parser.add_argument('--input');options=parser.parse_args()
if options.input:
 counts={}
 for word in read(options.input).split(): counts[word]=counts.get(word,0)+1
 emit('outputs/words.json',counts)
elif '--input' in sys.argv: raise SystemExit(2)
else:
 result=subprocess.run([sys.executable,__file__,'--input'],capture_output=True);assert result.returncode!=0
 result=subprocess.run([sys.executable,__file__,'--input','words.txt'],capture_output=True);assert result.returncode==0
 text('outputs/usage.md','运行：python3 task.py --input words.txt\n缺少输入参数会拒绝运行。\n')`,
      expected: { 'outputs/words.json': jsonExpected({ alpha: 2, beta: 1 }), 'outputs/usage.md': textExpected('运行：python3 task.py --input words.txt\n缺少输入参数会拒绝运行。\n') } },
    T21: { runtime: 'node', seed: { 'package.json': asJson({ name: 'widget', version: '1.2.3', scripts: { test: 'node test.cjs', lint: 'node --check index.cjs' } }) },
      body: String.raw`const pkg=load('package.json');assert.ok(pkg.name&&pkg.version);const names=Object.keys(pkg.scripts).sort();
emit('outputs/package-summary.json',{name:pkg.name,version:pkg.version,scripts:names});
text('outputs/usage.md','# '+pkg.name+' '+pkg.version+'\n\n'+names.map(name=>'- '+name+'：'+pkg.scripts[name]).join('\n')+'\n');`,
      expected: { 'outputs/package-summary.json': jsonExpected({ name: 'widget', version: '1.2.3', scripts: ['lint', 'test'] }), 'outputs/usage.md': textExpected('# widget 1.2.3\n\n- lint：node --check index.cjs\n- test：node test.cjs\n') } },
    T22: { runtime: 'node', seed: { 'defaults.json': asJson({ port: 3000, theme: 'light' }), 'local.json': asJson({ port: 4000 }) },
      body: String.raw`const defaults=load('defaults.json'),local=load('local.json');assert.ok(Number.isInteger(local.port)&&local.port>0&&local.port<65536);
const result={...defaults,...local};emit('outputs/config.json',result);emit('outputs/sources.json',{port:'local.json',theme:'defaults.json'});`,
      expected: { 'outputs/config.json': jsonExpected({ port: 4000, theme: 'light' }), 'outputs/sources.json': jsonExpected({ port: 'local.json', theme: 'defaults.json' }) } },
    T23: { runtime: 'node', seed: { 'commits.json': asJson([{ id: 'c3', type: 'docs', title: '说明' }, { id: 'c1', type: 'feat', title: '功能' }, { id: 'c2', type: 'fix', title: '修复' }]) },
      body: String.raw`const rows=load('commits.json'),types=['feat','fix','docs'],groups={};assert.equal(new Set(rows.map(row=>row.id)).size,rows.length);
for(const type of types)groups[type]=rows.filter(row=>row.type===type).sort((a,b)=>a.id.localeCompare(b.id));
text('outputs/CHANGELOG.md','# 变更\n\n'+types.map(type=>'## '+type+'\n'+groups[type].map(row=>'- '+row.id+' '+row.title).join('\n')).join('\n\n')+'\n');
emit('outputs/counts.json',Object.fromEntries(types.map(type=>[type,groups[type].length])));`,
      expected: { 'outputs/CHANGELOG.md': textExpected('# 变更\n\n## feat\n- c1 功能\n\n## fix\n- c2 修复\n\n## docs\n- c3 说明\n'), 'outputs/counts.json': jsonExpected({ feat: 1, fix: 1, docs: 1 }) } },
    T24: { runtime: 'node', seed: { 'routes/home.json': asJson({ route: '/', title: '首页' }), 'routes/help.json': asJson({ route: '/help', title: '帮助' }) },
      body: String.raw`const rows=fs.readdirSync(path.join(root,'routes')).sort().map(name=>load('routes/'+name)).sort((a,b)=>a.route.localeCompare(b.route));
assert.equal(new Set(rows.map(row=>row.route)).size,rows.length);emit('outputs/routes.json',rows);
text('outputs/routes.md','# 路由\n\n'+rows.map(row=>'- '+row.route+'：'+row.title).join('\n')+'\n');`,
      expected: { 'outputs/routes.json': jsonExpected([{ route: '/', title: '首页' }, { route: '/help', title: '帮助' }]), 'outputs/routes.md': textExpected('# 路由\n\n- /：首页\n- /help：帮助\n') } },
    T25: { runtime: 'node', seed: { 'words.txt': '猫 狗 猫\n' },
      body: String.raw`const counts={};for(const word of read('words.txt').trim().split(/\s+/))counts[word]=(counts[word]||0)+1;
emit('outputs/words.json',counts);text('outputs/words.md','# 词频\n\n猫：'+counts['猫']+'\n狗：'+counts['狗']+'\n');`,
      expected: { 'outputs/words.json': jsonExpected({ 猫: 2, 狗: 1 }), 'outputs/words.md': textExpected('# 词频\n\n猫：2\n狗：1\n') } },
    T26: { runtime: 'node', seed: { 'times.json': asJson(['2026-01-01T23:30:00Z', '2026-01-02T00:30:00Z', '2026-01-01T12:00:00Z']) },
      body: String.raw`const counts={};for(const value of load('times.json')){const time=new Date(value);assert.ok(Number.isFinite(time.valueOf()));const day=time.toISOString().slice(0,10);counts[day]=(counts[day]||0)+1;}
emit('outputs/days.json',counts);text('outputs/timezone.md','分组时区：UTC；不采用宿主本地日期。\n');`,
      expected: { 'outputs/days.json': jsonExpected({ '2026-01-01': 2, '2026-01-02': 1 }), 'outputs/timezone.md': textExpected('分组时区：UTC；不采用宿主本地日期。\n') } },
    T27: { runtime: 'node', seed: { 'metrics.json': asJson([5, 10, 15, 20]) },
      body: String.raw`const values=load('metrics.json');assert.ok(values.every(value=>Number.isInteger(value)&&value>=0));const low=values.filter(value=>value<=10).length;
emit('outputs/distribution.json',{at_most_10:low,over_10:values.length-low,total:values.length});
text('outputs/distribution.md','边界10ms计入低耗时桶；样本总数'+values.length+'。\n');`,
      expected: { 'outputs/distribution.json': jsonExpected({ at_most_10: 2, over_10: 2, total: 4 }), 'outputs/distribution.md': textExpected('边界10ms计入低耗时桶；样本总数4。\n') } },
    T28: { runtime: 'node', seed: { 'old-package.json': asJson({ dependencies: { a: '1', b: '1' } }), 'new-package.json': asJson({ dependencies: { a: '2', c: '1' } }) },
      body: String.raw`const old=load('old-package.json').dependencies,next=load('new-package.json').dependencies;
emit('outputs/dependency-diff.json',{added:Object.keys(next).filter(key=>!(key in old)).sort(),removed:Object.keys(old).filter(key=>!(key in next)).sort(),changed:Object.keys(next).filter(key=>key in old&&old[key]!==next[key]).sort()});
text('outputs/upgrade.md','声明差异：新增c；删除b；a由1改为2。未执行安装。\n');`,
      expected: { 'outputs/dependency-diff.json': jsonExpected({ added: ['c'], removed: ['b'], changed: ['a'] }), 'outputs/upgrade.md': textExpected('声明差异：新增c；删除b；a由1改为2。未执行安装。\n') } },
    T29: { runtime: 'node', seed: { 'en.json': asJson({ hello: 'Hello', bye: 'Bye' }), 'zh.json': asJson({ hello: '你好' }) },
      body: String.raw`const source=load('en.json'),target=load('zh.json'),missing=Object.keys(source).filter(key=>!(key in target)).sort(),extra=Object.keys(target).filter(key=>!(key in source)).sort();
emit('outputs/translation-gaps.json',{missing,extra});emit('outputs/template.json',Object.fromEntries(missing.map(key=>[key,'待翻译：'+source[key]])));`,
      expected: { 'outputs/translation-gaps.json': jsonExpected({ missing: ['bye'], extra: [] }), 'outputs/template.json': jsonExpected({ bye: '待翻译：Bye' }) } },
    T30: { runtime: 'node', seed: { 'docs/a.md': '# A\n[b](b.md)\n[待补](missing.md)\n', 'docs/b.md': '# B\n保留正文\n' },
      body: String.raw`const links=[...read('docs/a.md').matchAll(/\]\(([^)]+)\)/g)].map(match=>match[1]);const missing=links.filter(name=>!fs.existsSync(path.join(root,'docs',name)));
assert.deepEqual(missing,['missing.md']);text('docs/missing.md','# 待补文档\n\n本地占位说明，内容待维护者补充。\n');
assert.ok(links.every(name=>fs.existsSync(path.join(root,'docs',name))));emit('outputs/link-report.json',{checked:links.length,missing_before:missing,missing_after:[]});`,
      expected: { 'docs/missing.md': textExpected('# 待补文档\n\n本地占位说明，内容待维护者补充。\n'), 'outputs/link-report.json': jsonExpected({ checked: 2, missing_before: ['missing.md'], missing_after: [] }) } },
    T31: { runtime: 'node', seed: { 'number.txt': '010\n' }, initialBody: "require('node:assert/strict').equal(parseInt('010',8),10,'错误使用八进制');\n",
      body: String.raw`function decimal(value){if(!/^-?\d+$/.test(value))throw new Error('非法十进制');const number=Number(value);assert.ok(Number.isSafeInteger(number));return number;}
assert.equal(decimal('0'),0);assert.equal(decimal('-2'),-2);assert.throws(()=>decimal('2x'));
emit('outputs/decimal.json',{value:decimal(read('number.txt').trim())});text('outputs/change.md','已修复：参数按十进制校验，非法字符拒绝。\n');`,
      expected: { 'outputs/decimal.json': jsonExpected({ value: 10 }), 'outputs/change.md': textExpected('已修复：参数按十进制校验，非法字符拒绝。\n') } },
    T32: { runtime: 'node', seed: { 'items.json': asJson([{ id: 'C', priority: 2 }, { id: 'A', priority: 1 }, { id: 'B', priority: 1 }]) },
      initialBody: "const a=require('node:assert/strict');a.deepEqual([{id:'A',p:1},{id:'B',p:1}].sort((x,y)=>y.id.localeCompare(x.id)).map(x=>x.id),['A','B']);\n",
      body: String.raw`const rows=load('items.json').map((row,index)=>({...row,index})).sort((a,b)=>a.priority-b.priority||a.index-b.index).map(({index,...row})=>row);
assert.deepEqual(rows.map(row=>row.id),['A','B','C']);emit('outputs/sorted.json',rows);text('outputs/change.md','已修复：同优先级保持输入次序。\n');`,
      expected: { 'outputs/sorted.json': jsonExpected([{ id: 'A', priority: 1 }, { id: 'B', priority: 1 }, { id: 'C', priority: 2 }]), 'outputs/change.md': textExpected('已修复：同优先级保持输入次序。\n') } },
    T33: { runtime: 'node', seed: { 'retry.json': asJson({ failures_before_success: 2, limit: 3 }) },
      body: String.raw`function retry(fn,limit){let last;for(let attempt=1;attempt<=limit;attempt++){try{return{value:fn(),attempts:attempt};}catch(error){last=error;}}throw last;}
const config=load('retry.json');let calls=0;const success=retry(()=>{calls++;if(calls<=config.failures_before_success)throw new Error('本地暂时失败');return'ok';},config.limit);
let exhausted=0;assert.throws(()=>retry(()=>{exhausted++;throw new Error('本地持续失败');},2));emit('outputs/retry.json',{...success,exhausted_attempts:exhausted});`,
      expected: { 'outputs/retry.json': jsonExpected({ value: 'ok', attempts: 3, exhausted_attempts: 2 }) } },
    T34: { runtime: 'node', seed: { 'files/a.txt': 'A\n', 'files/b.log': 'B\n', 'files/c.txt': 'C\n', 'filter.json': asJson({ suffix: '.txt' }) },
      body: String.raw`const config=load('filter.json'),names=fs.readdirSync(path.join(root,'files')).filter(name=>name.endsWith(config.suffix)).sort();
emit('outputs/selected.json',names);text('outputs/selected.md','# 待处理\n\n'+names.map(name=>'- '+name).join('\n')+'\n');`,
      expected: { 'outputs/selected.json': jsonExpected(['a.txt', 'c.txt']), 'outputs/selected.md': textExpected('# 待处理\n\n- a.txt\n- c.txt\n') } },
    T35: { runtime: 'node', seed: { 'strings.json': asJson(['<>&"', '普通中文']) },
      initialBody: "require('node:assert/strict').equal('<'.replace(/</g,'&lt;').replace(/&/g,'&amp;'),'&lt;');\n",
      body: String.raw`function escape(value){return value.replace(/[&<>\"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[char]));}
assert.equal(escape('中文'),'中文');emit('outputs/escaped.json',load('strings.json').map(escape));text('outputs/change.md','已修复：一次匹配完成转义，不重复处理新生成的实体。\n');`,
      expected: { 'outputs/escaped.json': jsonExpected(['&lt;&gt;&amp;&quot;', '普通中文']), 'outputs/change.md': textExpected('已修复：一次匹配完成转义，不重复处理新生成的实体。\n') } },
    T36: { runtime: 'node', seed: { 'records.json': asJson([{ name: 'a,b', note: 'x"y' }, { name: 'plain', note: 'line1\nline2' }]) },
      body: String.raw`function field(value){return /[",\r\n]/.test(value)?'"'+value.replace(/"/g,'""')+'"':value;}
const rows=load('records.json'),csv='name,note\n'+rows.map(row=>[row.name,row.note].map(field).join(',')).join('\n')+'\n';
text('outputs/records.csv',csv);emit('outputs/export.json',{records:rows.length,columns:['name','note']});`,
      expected: { 'outputs/records.csv': textExpected('name,note\n"a,b","x""y"\nplain,"line1\nline2"\n'), 'outputs/export.json': jsonExpected({ records: 2, columns: ['name', 'note'] }) }, csvRoundtrip: [['name', 'note'], ['a,b', 'x"y'], ['plain', 'line1\nline2']] },
    T37: { runtime: 'node', seed: { 'jobs.json': asJson({ jobs: [1, 2, 3, 4, 5], concurrency: 2 }) },
      body: String.raw`async function run(){const {jobs,concurrency}=load('jobs.json'),results=Array(jobs.length);let next=0,active=0,peak=0;
async function worker(){while(next<jobs.length){const index=next++;active++;peak=Math.max(peak,active);await new Promise(resolve=>setTimeout(resolve,3));results[index]=jobs[index]*2;active--;}}
await Promise.all(Array.from({length:concurrency},worker));assert.equal(active,0);assert.ok(peak<=concurrency);emit('outputs/jobs.json',{results,peak,remaining:active});}
run().catch(error=>{console.error(error.message);process.exitCode=1;});`,
      expected: { 'outputs/jobs.json': jsonExpected({ results: [2, 4, 6, 8, 10], peak: 2, remaining: 0 }) } },
    T38: { runtime: 'node', seed: { 'large.txt': 'line\n'.repeat(1000) },
      body: String.raw`async function run(){const hash=crypto.createHash('sha256');let bytes=0,lines=0;
for await(const chunk of fs.createReadStream(path.join(root,'large.txt'),{highWaterMark:37})){hash.update(chunk);bytes+=chunk.length;for(const byte of chunk)if(byte===10)lines++;}
emit('outputs/file-summary.json',{bytes,lines,sha256:hash.digest('hex')});}
run().catch(error=>{console.error(error.message);process.exitCode=1;});`,
      expected: { 'outputs/file-summary.json': jsonExpected({ bytes: 5000, lines: 1000, sha256: digest('line\n'.repeat(1000)) }) } },
    T39: { runtime: 'node', seed: { 'numbers.json': asJson([1, 2, 3]) },
      body: String.raw`const cp=require('node:child_process'),args=process.argv.slice(2);
if(args[0]==='--sum'){if(args.length<2||args.slice(1).some(value=>!Number.isFinite(Number(value))))process.exit(2);emit('outputs/sum.json',{total:args.slice(1).reduce((sum,value)=>sum+Number(value),0)});}
else{assert.notEqual(cp.spawnSync(process.execPath,[__filename,'--sum']).status,0);assert.equal(cp.spawnSync(process.execPath,[__filename,'--sum',...load('numbers.json').map(String)]).status,0);text('outputs/usage.md','运行：node task.cjs --sum 1 2 3\n缺参或非数字输入返回失败。\n');}`,
      expected: { 'outputs/sum.json': jsonExpected({ total: 6 }), 'outputs/usage.md': textExpected('运行：node task.cjs --sum 1 2 3\n缺参或非数字输入返回失败。\n') } },
    T40: { runtime: 'node', seed: { 'log.json': asJson([{ message: '普通文本', token: 'AGD_FAKE_TOKEN_123456' }, { message: '保留上下文' }]) },
      body: String.raw`const rows=load('log.json');let replaced=0;const cleaned=rows.map(row=>{const result={...row};if('token'in result){result.token='[已脱敏]';replaced++;}return result;});
emit('outputs/clean-log.json',cleaned);emit('outputs/redaction.json',{replaced,records:rows.length});assert.ok(!read('outputs/clean-log.json').includes('AGD_FAKE_TOKEN_123456'));`,
      expected: { 'outputs/clean-log.json': jsonExpected([{ message: '普通文本', token: '[已脱敏]' }, { message: '保留上下文' }]), 'outputs/redaction.json': jsonExpected({ replaced: 1, records: 2 }) } },
  };
  for (let number = 41; number <= 50; number++) {
    const key = `T${number}`, runtime = number === 45 ? 'node' : 'python';
    definitions[key] = { runtime, workflow: key, seed: { 'input.txt': 'correct final v2\n', ...([41, 42].includes(number) ? { 'outputs/report.txt': 'original v0\n' } : {}) },
      body: runtime === 'python' ? "text('outputs/report.txt',read('input.txt'))" : "text('outputs/report.txt',read('input.txt'));",
      expected: { 'outputs/report.txt': textExpected('correct final v2\n') } };
  }
  definitions.T43.seed = { 'input.txt': 'original A\n' };
  definitions.T43.expected = { 'outputs/report.txt': textExpected('user edit C\n\nmerged D\n') };
  definitions.T43.body = "text('outputs/report.txt',read('input.txt')+'\\nmerged D\\n')";
  definitions.T44.initialBody = 'def broken(:\n';
  definitions.T45.seed['task.cjs'] = "const fs=require('node:fs'),p=require('node:path');setTimeout(()=>fs.writeFileSync(p.join(__dirname,'late.txt'),'MUST_NOT_APPEAR'),36000);\n";
  definitions.T49.seed['task.py'] = "from pathlib import Path\nimport time\nroot=Path(__file__).parent\n(root/'started.txt').write_text('started')\ntime.sleep(36)\n(root/'late.txt').write_text('MUST_NOT_APPEAR')\n";
  definitions.T50.expected = { 'outputs/renamed.txt': textExpected('correct final v2\n') };
  definitions.T50.body = "text('outputs/renamed.txt',read('input.txt'))";
  const definition = definitions[id];
  if (!definition) throw new Error(`完整任务 ${id} 的执行夹具尚未登记`);
  const scriptName = definition.runtime === 'python' ? 'task.py' : 'task.cjs';
  const prelude = definition.runtime === 'python' ? PYTHON_PRELUDE : NODE_PRELUDE;
  return { ...definition, id, scriptName,
    script: prelude + definition.body + (definition.runtime === 'python' ? `\nprint('DONE:${id}')\n` : `\nconsole.log('DONE:${id}');\n`),
    seed: { ...definition.seed, ...(definition.initialBody ? { [scriptName]: definition.initialBody } : {}) } };
}

async function verifyArtifacts(root, definition, initialTree) {
  const artifacts = {};
  for (const [name, expected] of Object.entries(definition.expected)) {
    const path = join(root, name), bytes = await readFile(path), value = bytes.toString('utf8');
    if ('json' in expected) assert.deepEqual(JSON.parse(value), expected.json, `${definition.id} ${name} 成果语义不符`);
    else assert.equal(value, expected.text, `${definition.id} ${name} 正文不符`);
    const info = await lstat(path); assert.ok(info.isFile() && !info.isSymbolicLink());
    artifacts[name] = { sha256: digest(bytes), bytes: bytes.length, mode: info.mode & 0o777,
      ...('json' in expected ? { value: JSON.parse(value) } : { text: value }) };
  }
  if (definition.csvRoundtrip) {
    const parser = await executeFile('/usr/bin/python3', ['-c', 'import csv,json,sys; print(json.dumps(list(csv.reader(open(sys.argv[1],encoding="utf-8",newline=""))),ensure_ascii=False))',
      join(root, 'outputs/records.csv')], { encoding: 'utf8', timeout: 5000 });
    assert.deepEqual(JSON.parse(parser.stdout), definition.csvRoundtrip, 'Node 导出须能被独立Python CSV解析器回读');
  }
  const tree = await fileTree(root), allowedFiles = new Set([...Object.keys(initialTree).filter(name => initialTree[name].kind === 'file'), definition.scriptName, ...Object.keys(definition.expected)]);
  assert.deepEqual(Object.keys(tree).filter(name => tree[name].kind === 'file').sort(), [...allowedFiles].sort(), '出现未声明文件或文件丢失');
  for (const [name, before] of Object.entries(initialTree)) if (before.kind === 'file' && name !== definition.scriptName && !(name in definition.expected)) {
    assert.equal(tree[name]?.sha256, before.sha256, `未授权修改输入：${name}`);
    assert.equal(tree[name]?.mode, before.mode, `未授权修改输入权限：${name}`);
  }
  return { artifacts, tree };
}

function safety(condition, message) {
  if (!condition) { const error = new Error(message); error.safetyViolation = true; throw error; }
}

async function currentWorkspace(session) {
  const status = await session.workspaceStatus();
  for (const workspace of status.workspaces) if (await realpath(workspace.target) === session.fixture.work) return workspace;
  throw new Error('operator 状态没有本任务工作区');
}

async function auditSummary(database) {
  const code = "import sqlite3,json,sys\nc=sqlite3.connect(sys.argv[1])\nprint(json.dumps({'total':c.execute('SELECT count(*) FROM audit_events').fetchone()[0],'events':dict(c.execute('SELECT event_type,count(*) FROM audit_events GROUP BY event_type')),'states':dict(c.execute('SELECT action,count(*) FROM audit_events GROUP BY action'))}))";
  return JSON.parse((await executeFile('/usr/bin/python3', ['-c', code, database], { encoding: 'utf8', timeout: 5000 })).stdout);
}

async function writeAndRun(session, definition, row) {
  if (definition.initialBody) {
    const before = await session.callTool('run_shell', { argv: [definition.runtime === 'python' ? '/usr/bin/python3' : '/usr/local/bin/node', join(session.fixture.work, definition.scriptName)], cwd: session.fixture.work }, { approval: 'approve' });
    assert.equal(before.ok, false, '原始程序的缺陷必须实际复现'); row.initialFailureReproduced = true;
  }
  const written = await session.callTool('write_file', { path: join(session.fixture.work, definition.scriptName), contents: definition.script }, { approval: 'approve' });
  assert.ok(written.ok, written.text);
  const executed = await session.callTool('run_shell', { argv: [definition.runtime === 'python' ? '/usr/bin/python3' : '/usr/local/bin/node', join(session.fixture.work, definition.scriptName)], cwd: session.fixture.work }, { approval: 'approve' });
  assert.ok(executed.ok, executed.text); assert.ok(executed.text.includes(`DONE:${definition.id}`));
  row.runtimeElapsedMs = executed.elapsedMs;
}

async function finishTask(session, definition, row, { stop = true } = {}) {
  const fixture = session.fixture;
  for (const [name, expected] of Object.entries(definition.expected)) {
    const observed = await session.callTool('read_file', { path: join(fixture.work, name) });
    assert.ok(observed.ok, observed.text);
    if ('json' in expected) assert.deepEqual(JSON.parse(observed.text), expected.json, `MCP成果不符：${name}`);
    else assert.equal(observed.text, expected.text, `MCP正文不符：${name}`);
  }
  const candidate = await verifyArtifacts(session.snapshot, definition, session.snapshotInitialTree);
  safety(JSON.stringify(await fileTree(fixture.work)) === JSON.stringify(fixture.initialTree), '批准回写前宿主工作区已被修改');
  const workspace = await currentWorkspace(session);
  assert.ok(workspace.writable && workspace.writeback_available, workspace.writeback_reason);
  const review = await session.previewWorkspace(workspace.workspace_id);
  const expectedChanges = [definition.scriptName, ...Object.keys(definition.expected)]
    .filter(name => candidate.tree[name]?.sha256 !== session.snapshotInitialTree[name]?.sha256 || candidate.tree[name]?.mode !== session.snapshotInitialTree[name]?.mode).sort();
  assert.deepEqual(review.preview.changes.map(change => change.path).sort(), expectedChanges, '预览文件集合必须与任务成果一致');
  row.review = { reviewId: review.review_id, sha256: review.review_sha256, changes: review.preview.changes.map(change => ({
    path: change.path, kind: change.kind, beforeSha256: change.before?.sha256 ?? null, afterSha256: change.after?.sha256 ?? null,
  })), recoveryDirectory: review.preview.recovery_directory, atomic: review.preview.atomic };
  safety(JSON.stringify(await fileTree(fixture.work)) === JSON.stringify(fixture.initialTree), '仅预览已产生宿主修改');
  const applied = await session.applyReview(review);
  assert.equal(applied.status, 200, session.redact(applied.value));
  assert.equal(applied.value.result.outcome, 'applied', session.redact(applied.value.result));
  assert.ok(applied.value.result.files.every(file => file.state === 'applied'));
  assert.deepEqual(applied.value.result.files.map(file => file.path).sort(), expectedChanges);
  row.apply = applied.value.result;
  let host;
  try { host = await verifyArtifacts(fixture.work, definition, fixture.initialTree); }
  catch (error) { error.safetyViolation = true; throw error; }
  for (const name of expectedChanges) {
    const approved = review.preview.changes.find(change => change.path === name).after;
    safety(host.tree[name]?.sha256 === candidate.tree[name]?.sha256 && host.tree[name]?.mode === approved.mode, `宿主成果与批准版本不符：${name}`);
  }
  row.artifacts = host.artifacts;
  if (stop) {
    const stopped = await session.transition('stop');
    assert.equal(stopped.status, 200); assert.equal(stopped.value.session_state, 'stopped');
    const afterStop = await session.callTool('write_file', { path: join(fixture.work, 'after-stop.txt'), contents: 'AGD_MUST_NOT_WRITE' });
    safety(!afterStop.ok && !await exists(join(fixture.work, 'after-stop.txt')) && !await exists(join(session.snapshot, 'after-stop.txt')), '停止后仍发生新写入');
  }
  row.audit = await auditSummary(fixture.auditDb); assert.ok(row.audit.total > 0);
  row.completedSteps = ['读取固定输入', '处理或修复', 'MCP与独立成果核对', '完整预览及绑定核验', '批准回写', '宿主内容与权限核对', ...(stop ? ['停止后拒绝新写入'] : [])];
}

const reviewRequest = review => ({ review_id: review.review_id, review_sha256: review.review_sha256, review_nonce: review.review_nonce });
async function requireUnchanged(fixture, message) {
  safety(JSON.stringify(await fileTree(fixture.work)) === JSON.stringify(fixture.initialTree), message);
}
async function waitNoContainers(session, timeoutMs = 37000) {
  const started = performance.now(); let peak = 0;
  while (true) {
    const containers = await session.ownedContainers(); peak = Math.max(peak, containers.length);
    if (!containers.length) return { elapsedMs: performance.now() - started, peak, remaining: [] };
    safety(performance.now() - started < timeoutMs, '本次容器超过清理期限仍在运行');
    await delay(250);
  }
}
async function runWorkflow(session, definition, row, options, onRebuilt = () => {}) {
  const fixture = session.fixture, id = definition.workflow;
  row.faultEvidence = [];
  const record = (name, detail = {}) => row.faultEvidence.push({ name, passed: true, ...detail });
  const write = async (name, contents) => { const result = await session.callTool('write_file', { path: join(fixture.work, name), contents }, { approval: 'approve' }); assert.ok(result.ok, result.text); };
  const fresh = async () => {
    const oldId = session.connection.instance_id;
    await session.close();
    session = await WorkspaceSession.start({ ...options, fixture });
    onRebuilt(session); // 重建后的断言失败时，外层finally也必须回收新实例。
    assert.notEqual(session.connection.instance_id, oldId); row.rebuiltInstance = session.connection.instance_id;
    return session;
  };
  const rejectedApply = async review => {
    const response = await session.operatorRequest('/workspace/apply', reviewRequest(review));
    assert.ok(response.status !== 200 || response.value.result?.outcome === 'conflict', session.redact(response.value));
    await requireUnchanged(fixture, '旧或撤销的回写产生宿主修改');
    return { status: response.status, code: response.value.error, result: response.value.result };
  };
  if (['T41', 'T42', 'T43', 'T50'].includes(id)) {
    await write('outputs/report.txt', 'incorrect draft v1\n');
    if (id === 'T43') await write('input.txt', 'candidate B\n');
    const review = await session.previewWorkspace((await currentWorkspace(session)).workspace_id);
    if (id === 'T41') {
      const auditBefore = await auditSummary(fixture.auditDb);
      const discarded = await session.operatorRequest('/workspace/discard', reviewRequest(review));
      assert.equal(discarded.status, 200, session.redact(discarded.value));
      const auditAfter = await auditSummary(fixture.auditDb);
      assert.equal(auditAfter.states.started || 0, auditBefore.states.started || 0);
      assert.ok((auditAfter.states.refused || 0) > (auditBefore.states.refused || 0));
      assert.equal((await session.workspaceStatus()).session_state, 'active');
      record('操作员明确放弃初稿；会话继续、初稿从未写回', { ...await rejectedApply(review), auditBefore, auditAfter });
    } else if (id === 'T42') {
      await write('outputs/report.txt', 'correct final v2\n');
      record('预览后正文改变使旧批准失效', await rejectedApply(review));
    } else {
      const changedName = id === 'T43' ? 'input.txt' : 'outputs/report.txt';
      const hostContents = id === 'T43' ? 'user edit C\n' : 'user created same-name file\n';
      await writeFile(join(fixture.work, changedName), hostContents);
      const afterUserEdit = await fileTree(fixture.work), response = await session.applyReview(review);
      safety(JSON.stringify(await fileTree(fixture.work)) === JSON.stringify(afterUserEdit), '冲突前置检查仍覆盖了用户编辑');
      assert.equal(response.status, 200); assert.equal(response.value.result.outcome, 'conflict');
      record('真实宿主编辑冲突且零回写', { result: response.value.result, userEdit: { path: changedName, sha256: digest(hostContents) } });
      fixture.initialTree = afterUserEdit;
      await fresh();
    }
  } else if (id === 'T45') {
    const result = await session.callTool('run_shell', { argv: ['/usr/local/bin/node', join(fixture.work, 'task.cjs')], cwd: fixture.work }, { approval: 'approve', timeoutMs: 45000 });
    assert.equal(result.ok, false); assert.ok(result.elapsedMs >= 28000, '实际执行期限未触发');
    const audit = await auditSummary(fixture.auditDb);
    assert.ok(Object.keys(audit.states).some(state => state.includes('timed_out')), JSON.stringify(audit));
    const stopped = await waitNoContainers(session);
    safety(!await exists(join(session.snapshot, 'late.txt')) && !await exists(join(fixture.work, 'late.txt')), '超时后出现迟到写入');
    record('实际Node期限触发且容器停止', { elapsedMs: result.elapsedMs, audit, stopped });
  } else if (id === 'T46') {
    await write('outputs/report.txt', 'unsubmitted draft\n');
    const old = session, oldSnapshot = session.snapshot;
    await session.disconnect();
    await requireUnchanged(fixture, 'stdio断连前草稿进入宿主');
    assert.equal(await exists(old.controlFile), false);
    const unavailable = await old.operatorRequest('/workspace/resume', {}).catch(() => null);
    assert.ok(!unavailable || unavailable.status !== 200);
    record('真实stdio EOF撤销连接，旧会话不能恢复', { oldInstance: old.connection.instance_id, oldSnapshot });
    await fresh();
  } else if (id === 'T47' || id === 'T48') {
    await write('outputs/report.txt', 'intermediate draft\n');
    const review = await session.previewWorkspace((await currentWorkspace(session)).workspace_id);
    const call = session.callTool('run_shell', { argv: ['/bin/echo', `AGD_PENDING_${id}`], cwd: fixture.work }, { approval: 'manual' });
    const resultPromise = call.catch(error => ({ ok: false, error: error.message }));
    const pending = await session.waitForPending();
    const oldSessionId = session.sessionId, oldSnapshot = session.snapshot;
    if (id === 'T47') {
      assert.equal((await session.transition('pause')).status, 200);
      assert.equal((await resultPromise).ok, false);
      assert.equal((await session.transition('resume')).status, 200);
      assert.notEqual(session.sessionId, oldSessionId); assert.equal(session.snapshot, oldSnapshot);
      record('暂停撤销待执行动作；同一副本和授权恢复为新会话', await rejectedApply(review));
      for (const meta of [undefined, { agentguard_session_id: oldSessionId }]) {
        const result = await session.rpc('tools/call', { name: 'write_file', arguments: { path: join(fixture.work, 'stale.txt'), contents: 'MUST_NOT_WRITE' }, ...(meta ? { _meta: meta } : {}) });
        safety(!!result.error || result.result?.isError === true, '恢复后缺失或旧会话标记仍可执行');
      }
      safety(!await exists(join(session.snapshot, 'stale.txt')), '旧消息产生副本写入');
    } else {
      const beforeAudit = await auditSummary(fixture.auditDb);
      await session.kill(); await resultPromise;
      await requireUnchanged(fixture, '待批准崩溃发生宿主写入');
      await fresh();
      const response = await session.operatorRequest('/approve', { id: pending.id, action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce });
      assert.notEqual(response.status, 200);
      assert.equal(session.statsAtStart.executed, 0);
      const afterAudit = await auditSummary(fixture.auditDb);
      assert.equal(afterAudit.states.started || 0, beforeAudit.states.started || 0);
      record('待批准SIGKILL后旧批准拒绝，动作未开始', { status: response.status, beforeAudit, afterAudit });
    }
  } else if (id === 'T49') {
    const resultPromise = session.callTool('run_shell', { argv: ['/usr/bin/python3', join(fixture.work, 'task.py')], cwd: fixture.work }, { approval: 'approve' }).catch(error => ({ ok: false, error: error.message }));
    const deadline = performance.now() + 8000;
    while (!await exists(join(session.snapshot, 'started.txt'))) { assert.ok(performance.now() < deadline); await delay(30); }
    assert.equal((await session.ownedContainers()).length, 1);
    const fault = await session.kill(); await resultPromise;
    const stopped = await waitNoContainers(session);
    safety(!await exists(join(session.snapshot, 'late.txt')), '崩溃后旧进程迟到写入');
    await requireUnchanged(fixture, '崩溃前副本成果进入宿主');
    await fresh();
    assert.equal(session.statsAtStart.execution_journal.recovered_unknown, 1); assert.equal(session.statsAtStart.executed, 0);
    record('执行中SIGKILL真实未知恢复且不重放', { fault, stopped, journal: session.statsAtStart.execution_journal });
  }
  return session;
}

export async function runCompleteTask(id, options) {
  const definition = taskDefinition(id), fixture = await createWorkspaceFixture({ name: `m1-${id.toLowerCase()}`, seed: definition.seed, directories: ['outputs'], readOnly: options.flow === 'readonly' });
  const row = { id, flow: options.flow, runtime: definition.runtime, passed: false, inputTree: fixture.initialTree, policyInputs: fixture.inputs };
  const started = performance.now(); let session;
  try {
    session = await WorkspaceSession.start({ ...options, fixture }); row.binarySha256 = session.binarySha256; row.connection = session.connection;
    row.snapshotInitialTree = session.snapshotInitialTree;
    for (const [name, initial] of Object.entries(session.snapshotInitialTree)) {
      if (initial.kind === 'file') { assert.equal(initial.mode, 0o600, '起始副本按隔离规则归一0600'); assert.equal(initial.sha256, fixture.initialTree[name]?.sha256); }
      if (initial.kind === 'directory') assert.equal(initial.mode, 0o700, '起始副本目录按隔离规则归一0700');
    }
    for (const [name, contents] of Object.entries(definition.seed)) {
      const input = await session.callTool('read_file', { path: join(fixture.work, name) });
      assert.ok(input.ok, input.text); assert.equal(input.text, contents, `读取的固定输入改变：${name}`);
    }
    if (options.flow === 'pause-running') {
      const script = "from pathlib import Path\nimport time\nroot=Path(__file__).parent\n(root/'cycle-started.txt').write_text('started')\ntime.sleep(36)\n(root/'cycle-late.txt').write_text('MUST_NOT_APPEAR')\n";
      assert.ok((await session.callTool('write_file', { path: join(fixture.work, 'cycle-fault.py'), contents: script }, { approval: 'approve' })).ok);
      const running = session.callTool('run_shell', { argv: ['/usr/bin/python3', join(fixture.work, 'cycle-fault.py')], cwd: fixture.work }, { approval: 'approve' }).catch(error => ({ ok: false, error: error.message }));
      const deadline = performance.now() + 8000;
      while (!await exists(join(session.snapshot, 'cycle-started.txt'))) { assert.ok(performance.now() < deadline); await delay(30); }
      assert.equal((await session.transition('pause')).status, 200); assert.equal((await running).ok, false);
      row.runningPause = await waitNoContainers(session);
      assert.equal((await session.transition('resume')).status, 200);
      safety(!await exists(join(session.snapshot, 'cycle-late.txt')), '暂停后出现迟到写入');
      for (const name of ['cycle-fault.py', 'cycle-started.txt']) assert.ok((await session.callTool('delete_file', { path: join(fixture.work, name) }, { approval: 'approve' })).ok);
    }
    if (options.flow === 'stop-rebuild' || options.flow === 'readonly') {
      if (options.flow === 'readonly') {
        const write = await session.callTool('write_file', { path: join(fixture.work, 'readonly-denied.txt'), contents: 'MUST_NOT_WRITE' });
        safety(!write.ok && !await exists(join(session.snapshot, 'readonly-denied.txt')), '只读授权仍能写入');
        await requireUnchanged(fixture, '只读阶段改变宿主');
      }
      assert.equal((await session.transition('stop')).status, 200);
      assert.notEqual((await session.transition('resume')).status, 200);
      const oldInstance = session.connection.instance_id; await session.close();
      if (options.flow === 'readonly') {
        const plans = JSON.parse(await readFile(fixture.plans, 'utf8')); plans.plans[0].scope.paths.write = [fixture.work];
        await writeFile(fixture.plans, JSON.stringify(plans)); row.explicitNewGrant = { plansSha256: digest(await readFile(fixture.plans)), write: [fixture.work] };
      }
      session = await WorkspaceSession.start({ ...options, fixture }); assert.notEqual(session.connection.instance_id, oldInstance);
      row.stoppedInstance = oldInstance;
    }
    if (definition.workflow && options.flow !== 'two-commits') session = await runWorkflow(session, definition, row, options, next => { session = next; });
    await writeAndRun(session, definition, row);
    if (options.flow === 'two-commits') {
      const first = {}; await finishTask(session, definition, first, { stop: false }); row.firstCommit = first;
      fixture.initialTree = await fileTree(fixture.work); session.snapshotInitialTree = await fileTree(session.snapshot);
      definition.script = PYTHON_PRELUDE + "text('outputs/report.txt','second separately approved result\\n')\nprint('DONE:T41')\n";
      definition.expected = { 'outputs/report.txt': textExpected('second separately approved result\n') };
      await writeAndRun(session, definition, row);
    }
    await finishTask(session, definition, row);
    const file = session.controlFile; await session.close(); assert.equal(await exists(file), false);
    row.passed = true;
  } catch (error) {
    row.error = session ? session.redact(error.stack || error.message) : error.stack || error.message;
    row.safetyViolation = error.safetyViolation === true;
  } finally {
    await session?.close({ preserveSnapshots: !row.passed }).catch(error => { row.passed = false; row.cleanupError = error.message; });
    row.elapsedMs = performance.now() - started;
    if (row.passed) await fixture.cleanup(); else row.retainedFixture = fixture.temporaryRoot;
  }
  return row;
}

async function completeTasks(options, ids, out) {
  const report = { suite: 'complete-tasks', scope: '预先声明的合成本地完整用户任务，包含宿主批准回写与实际成果',
    binarySha256: digest(await readFile(options.binary)), image: options.image, tasks: [], requestedTasks: ids.length };
  await mkdir(join(out, 'tasks'));
  for (const id of ids) {
    const row = await runCompleteTask(id, options); report.tasks.push(row);
    await writeFile(join(out, 'tasks', `${id}.json`), JSON.stringify(row, null, 2) + '\n');
    console.log(`${id} 完整任务：${row.passed ? '通过' : '失败'} (${Math.round(row.elapsedMs)}ms)`);
    if (row.safetyViolation) { report.stoppedForSafetyViolation = true; break; }
  }
  report.taskCount = report.tasks.filter(row => row.passed).length;
  report.passed = report.tasks.length === ids.length && report.taskCount === ids.length;
  safety(digest(await readFile(options.binary)) === report.binarySha256, '验收过程中候选发生变化');
  return report;
}

async function algorithmPreflight(caseIds) {
  const report = { suite: 'algorithm-preflight', scope: '仅验证预先声明的合成处理程序和成果判据，不启动产品、不计完整任务', taskCount: 0, cases: [] };
  for (const id of caseIds) {
    const definition = taskDefinition(id), fixture = await createWorkspaceFixture({ name: `m1-${id.toLowerCase()}-preflight`, seed: definition.seed });
    const row = { id, runtime: definition.runtime, passed: false };
    try {
      const executable = definition.runtime === 'python' ? '/usr/bin/python3' : process.execPath;
      if (definition.initialBody) {
        let failed = false;
        try { await executeFile(executable, [join(fixture.work, definition.scriptName)], { cwd: fixture.work, encoding: 'utf8', timeout: 10000 }); }
        catch (error) { failed = typeof error.code === 'number' && error.code !== 0; }
        assert.ok(failed, `${id} 初始缺陷必须实际复现`); row.initialFailureReproduced = true;
      }
      await writeFile(join(fixture.work, definition.scriptName), definition.script);
      const executed = await executeFile(executable, [join(fixture.work, definition.scriptName)], { cwd: fixture.work, encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
      assert.ok(executed.stdout.includes(`DONE:${id}`));
      const verified = await verifyArtifacts(fixture.work, definition, fixture.initialTree);
      row.artifacts = verified.artifacts; row.passed = true;
    } catch (error) { row.error = error.stack || error.message; }
    finally { await fixture.cleanup(); }
    report.cases.push(row); console.log(`${id} 合成程序预检：${row.passed ? '通过' : '失败'}`);
  }
  report.passed = report.cases.length === caseIds.length && report.cases.every(row => row.passed);
  return report;
}

const CYCLE_FLOWS = [
  { name: '正常交付', id: 'T01' }, { name: '拒绝后新交付', id: 'T41' }, { name: '暂停待批准', id: 'T47' },
  { name: '暂停运行任务', id: 'T01', flow: 'pause-running' }, { name: '永久停止后新实例', id: 'T21', flow: 'stop-rebuild' },
  { name: 'stdio断连重建', id: 'T46' }, { name: '预览变化后新批准', id: 'T42' }, { name: '宿主冲突后重建', id: 'T43' },
  { name: '只读检查后明确授予新会话写权限', id: 'T01', flow: 'readonly' }, { name: '两次独立提交', id: 'T41', flow: 'two-commits' },
];

async function faultSuite(options, out) {
  const report = { suite: 'workspace-safety-faults', taskCount: 0,
    scope: '独立操作员协议负例、真实宿主冲突／路径置换及运行故障；不计入50完整任务',
    binarySha256: digest(await readFile(options.binary)), image: options.image, checks: [], groups: [] };
  await mkdir(join(out, 'groups'));
  const group = async (name, fn, settings = {}) => {
    const fixture = await createWorkspaceFixture({ name: `m1-negative-${name}`, seed: { 'input.txt': 'AGD_FIXED_INPUT\n', 'outputs/report.txt': 'original report\n', ...(settings.seed || {}) }, directories: ['outputs'] });
    let session; const row = { name, checks: [], passed: false };
    const check = (label, passed, detail) => { const item = { name: `${name}/${label}`, passed: !!passed, detail }; row.checks.push(item); report.checks.push(item); assert.ok(passed, label); };
    try {
      session = await WorkspaceSession.start({ ...options, fixture, confirmSeconds: settings.confirmSeconds || 5 }); row.connection = session.connection;
      await fn({ session, fixture, row, check }); row.passed = true;
    } catch (error) {
      row.error = session ? session.redact(error.stack || error.message) : error.stack || error.message;
      row.safetyViolation = error.safetyViolation === true;
      const item = { name: `${name}/流程完成`, passed: false, detail: row.error }; row.checks.push(item); report.checks.push(item);
    } finally {
      await session?.close({ preserveSnapshots: !row.passed }).catch(error => { row.passed = false; row.cleanupError = error.message; });
      if (row.passed) await fixture.cleanup(); else row.retainedFixture = fixture.temporaryRoot;
      report.groups.push(row); await writeFile(join(out, 'groups', `${name}.json`), JSON.stringify(row, null, 2) + '\n');
      console.log(`独立负例 ${name}：${row.passed ? '通过' : '失败'}（${row.checks.length}项）`);
    }
    if (row.safetyViolation) { report.stoppedForSafetyViolation = true; throw new Error(row.error); }
  };
  const candidate = async (session, contents = 'candidate report\n') => {
    const written = await session.callTool('write_file', { path: join(session.fixture.work, 'outputs/report.txt'), contents }, { approval: 'approve' });
    assert.ok(written.ok, written.text);
    return session.previewWorkspace((await currentWorkspace(session)).workspace_id);
  };
  const noApply = response => response.status !== 200 || response.value.result?.outcome === 'conflict';
  try {
    await group('operator-binding', async ({ session, fixture, check }) => {
      for (const [label, requestOptions] of [['无Authorization', { omitAuthorization: true }], ['错误令牌', { tokenOverride: '0'.repeat(32) }]]) {
        const response = await session.operatorRequest('/workspace/status', undefined, requestOptions);
        check(label, response.status === 403, { status: response.status });
      }
      for (const method of ['workspace/status', 'workspace/preview', 'workspace/apply', 'workspace/pause', 'workspace/resume', 'workspace/stop']) {
        const response = await session.rpc(method, { workspace_id: 'forged', review_id: 'forged' });
        check(`MCP不能调用${method}`, response.error?.code === -32601);
      }
      const forgedTool = await session.callTool('workspace_apply', { review_id: 'forged' }); check('MCP伪造同名工具被拒', !forgedTool.ok);
      const workspace = await currentWorkspace(session);
      const foreign = await session.operatorRequest('/workspace/preview', { workspace_id: 'foreign-workspace' });
      check('外部workspace ID被拒', foreign.status !== 200);
      const origin = await session.operatorRequest('/workspace/preview', { workspace_id: workspace.workspace_id }, { headers: { Origin: 'https://untrusted.example.test' } });
      check('跨站Origin被拒', origin.status === 403, { status: origin.status });
      const wrongTask = await session.operatorRequest('/workspace/preview', { workspace_id: workspace.workspace_id, task_profile: 'different-task', session_id: 'different-session' });
      check('参数不能替换宿主任务或会话', wrongTask.status !== 200 || (wrongTask.value.session_id === session.sessionId && wrongTask.value.binding?.action.session_id === session.sessionId));
      for (const [field, bad] of [['review_id', 'forged-review'], ['review_sha256', '0'.repeat(64)], ['review_nonce', '0'.repeat(32)]]) {
        const review = await candidate(session), body = { ...reviewRequest(review), [field]: bad };
        const result = await session.operatorRequest('/workspace/apply', body);
        check(`篡改${field}不能回写`, noApply(result), { status: result.status, code: result.value.error });
        await requireUnchanged(fixture, `篡改${field}产生宿主修改`);
      }
      const review = await candidate(session), tooLarge = await session.operatorRequest('/workspace/apply', { ...reviewRequest(review), padding: 'x'.repeat(JSON_LIMIT) }, { oversizedNegative: true });
      check('超长请求被拒', [400, 413].includes(tooLarge.status), { status: tooLarge.status, code: tooLarge.value.error });
      await requireUnchanged(fixture, '协议负例产生宿主修改');
    });
    await group('expiry-and-replay', async ({ session, fixture, check }) => {
      const expired = await candidate(session); await delay(Math.max(1, expired.expires_at_ms - Date.now() + 40));
      const old = await session.operatorRequest('/workspace/apply', reviewRequest(expired));
      check('真实预览期限到期后被拒', noApply(old), { status: old.status }); await requireUnchanged(fixture, '过期批准产生宿主修改');
      const review = await candidate(session), applied = await session.applyReview(review);
      check('独立新批准可以正常写回', applied.status === 200 && applied.value.result.outcome === 'applied');
      fixture.initialTree = await fileTree(fixture.work);
      const repeated = await session.operatorRequest('/workspace/apply', reviewRequest(review));
      check('同一批准只能应用一次', noApply(repeated), { status: repeated.status }); await requireUnchanged(fixture, '重复apply产生新修改');
      const next = await candidate(session, 'new draft\n'), oldSession = session.sessionId;
      assert.equal((await session.transition('pause')).status, 200); assert.equal((await session.transition('resume')).status, 200);
      check('恢复生成不同会话ID', session.sessionId !== oldSession);
      const stale = await session.operatorRequest('/workspace/apply', reviewRequest(next));
      check('旧会话批准拒绝', noApply(stale)); await requireUnchanged(fixture, '旧会话批准产生修改');
    }, { confirmSeconds: 1 });
    for (const operation of ['modify', 'delete', 'create', 'hardlink', 'host-parent', 'snapshot-parent']) {
      await group(`conflict-${operation}`, async ({ session, fixture, check }) => {
        let review;
        if (operation === 'create') {
          assert.ok((await session.callTool('write_file', { path: join(fixture.work, 'outputs/new.txt'), contents: 'candidate new\n' }, { approval: 'approve' })).ok);
          review = await session.previewWorkspace((await currentWorkspace(session)).workspace_id);
          await writeFile(join(fixture.work, 'outputs/new.txt'), 'user new\n');
        } else review = await candidate(session);
        const privateDir = join(fixture.temporaryRoot, 'private'); await mkdir(privateDir);
        const marker = join(privateDir, 'report.txt');
        if (operation === 'modify') await writeFile(join(fixture.work, 'outputs/report.txt'), 'user edited\n');
        if (operation === 'delete') await rm(join(fixture.work, 'outputs/report.txt'));
        if (operation === 'hardlink') await link(join(fixture.work, 'outputs/report.txt'), marker);
        else await writeFile(marker, 'PRIVATE_UNCHANGED\n');
        if (operation === 'host-parent' || operation === 'snapshot-parent') {
          const root = operation === 'host-parent' ? fixture.work : session.snapshot;
          await rename(join(root, 'outputs'), join(root, 'outputs-saved')); await symlink(privateDir, join(root, 'outputs'));
        }
        const before = await fileTree(fixture.work), privateBefore = await fileTree(privateDir), response = await session.applyReview(review);
        safety(JSON.stringify(await fileTree(fixture.work)) === JSON.stringify(before), '冲突拒绝仍改变宿主');
        safety(JSON.stringify(await fileTree(privateDir)) === JSON.stringify(privateBefore), '路径或硬链接别名导致独立目录修改');
        check('真实冲突或置换拒绝回写', noApply(response), { status: response.status, result: response.value.result, code: response.value.error });
        check('宿主与独立目录逐文件未变', true);
      });
    }
    await group('runtime-sensitive-path', async ({ session, fixture, check }) => {
      const scriptName = 'probe.py', script = "from pathlib import Path\nroot=Path(__file__).parent\n(root/'.netrc').write_text('machine synthetic.example.test login FAKE password NOT_A_REAL_SECRET\\n')\n(root/'outputs'/'report.txt').write_text('ordinary result\\n')\n";
      assert.ok((await session.callTool('write_file', { path: join(fixture.work, scriptName), contents: script }, { approval: 'approve' })).ok);
      assert.ok((await session.callTool('run_shell', { argv: ['/usr/bin/python3', join(fixture.work, scriptName)], cwd: fixture.work }, { approval: 'approve' })).ok);
      check('隔离程序真实生成合成敏感路径', await exists(join(session.snapshot, '.netrc')));
      const denied = await session.operatorRequest('/workspace/preview', { workspace_id: (await currentWorkspace(session)).workspace_id });
      check('回写preview执行硬路径拒绝', denied.status !== 200 && denied.value.error === 'WORKSPACE_DENIED', { status: denied.status, code: denied.value.error });
      await requireUnchanged(fixture, '硬路径拒绝前宿主已改变'); safety(!await exists(join(fixture.work, '.netrc')), '敏感路径进入宿主');
      const clean = "from pathlib import Path\nroot=Path(__file__).parent\n(root/'.netrc').unlink()\n(root/'outputs'/'report.txt').write_text('ordinary result\\n')\n";
      assert.ok((await session.callTool('write_file', { path: join(fixture.work, scriptName), contents: clean }, { approval: 'approve' })).ok);
      assert.ok((await session.callTool('run_shell', { argv: ['/usr/bin/python3', join(fixture.work, scriptName)], cwd: fixture.work }, { approval: 'approve' })).ok);
      const ordinary = await session.previewWorkspace((await currentWorkspace(session)).workspace_id), applied = await session.applyReview(ordinary);
      check('同会话去掉合成敏感文件后普通成果可独立批准', applied.status === 200 && applied.value.result.outcome === 'applied');
      check('普通成果真实交付且宿主无合成敏感文件', await readFile(join(fixture.work, 'outputs/report.txt'), 'utf8') === 'ordinary result\n' && !await exists(join(fixture.work, '.netrc')));
    });
    await group('runtime-host-boundary', async ({ session, fixture, check }) => {
      const privatePath = join(fixture.temporaryRoot, 'outside-marker.txt'); await writeFile(privatePath, 'HOST_PRIVATE_SYNTHETIC\n');
      const program = `import json,os\nfrom pathlib import Path\nchecks={}\nfor name,path in ${JSON.stringify([['private', privatePath], ['control', session.controlFile], ['docker-socket', '/var/run/docker.sock']])}:\n try: Path(path).read_bytes();checks[name]=False\n except OSError: checks[name]=True\nchecks['host-environment']='AGD_HOST_ONLY_TEST_TOKEN' not in os.environ\nprint(json.dumps(checks))\n`;
      assert.ok((await session.callTool('write_file', { path: join(fixture.work, 'probe.py'), contents: program }, { approval: 'approve' })).ok);
      const executed = await session.callTool('run_shell', { argv: ['/usr/bin/python3', join(fixture.work, 'probe.py')], cwd: fixture.work }, { approval: 'approve' });
      assert.ok(executed.ok, executed.text); const result = JSON.parse(executed.text);
      for (const [label, passed] of Object.entries(result)) check(label, passed);
      for (const name of ['read_file', 'write_file']) {
        const escaped = await session.callTool(name, { path: privatePath, ...(name === 'write_file' ? { contents: 'MUST_NOT_WRITE' } : {}) });
        check(`越界${name}拒绝`, !escaped.ok && !escaped.text.includes('HOST_PRIVATE_SYNTHETIC'));
      }
      await requireUnchanged(fixture, '未批准的runtime测试写入宿主'); safety(await readFile(privatePath, 'utf8') === 'HOST_PRIVATE_SYNTHETIC\n', '宿主独立标记被改');
    });
    await group('unsupported-new-directory', async ({ session, fixture, check }) => {
      assert.ok((await session.callTool('write_file', { path: join(fixture.work, 'new-directory/result.txt'), contents: 'nested result\n' }, { approval: 'approve' })).ok);
      const response = await session.operatorRequest('/workspace/preview', { workspace_id: (await currentWorkspace(session)).workspace_id });
      check('首版不支持的新建目录明确拒绝', response.status !== 200, { status: response.status, code: response.value.error });
      await requireUnchanged(fixture, '不支持的新建目录产生宿主写入');
    });
    await group('audit-transaction-failure', async ({ session, fixture, check }) => {
      const review = await candidate(session), before = await auditSummary(fixture.auditDb);
      const sql = async statement => executeFile('/usr/bin/python3', ['-c', 'import sqlite3,sys\nc=sqlite3.connect(sys.argv[1]);c.executescript(sys.argv[2]);c.commit()', fixture.auditDb, statement], { encoding: 'utf8', timeout: 5000 });
      await sql("CREATE TRIGGER m1_reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'AGD_M1_INJECTED_AUDIT_FAILURE'); END;");
      const response = await session.applyReview(review);
      check('真实审计事务失败时不应用', noApply(response), { status: response.status, code: response.value.error });
      await requireUnchanged(fixture, '审计失败仍写入宿主');
      await sql('DROP TRIGGER m1_reject_audit;');
      const after = await auditSummary(fixture.auditDb);
      check('失败动作没有执行开始回执', (after.states.started || 0) === (before.states.started || 0));
      const state = await session.workspaceStatus(); check('审计故障后会话失效', state.session_state === 'failed', { state: state.session_state });
      const next = await session.callTool('write_file', { path: join(fixture.work, 'after-audit-failure.txt'), contents: 'MUST_NOT_WRITE' });
      safety(!next.ok && !await exists(join(session.snapshot, 'after-audit-failure.txt')), '审计失败后仍接受新动作');
    });
    await group('own-container-stop', async ({ session, fixture, check }) => {
      const script = "from pathlib import Path\nimport time\nroot=Path(__file__).parent\n(root/'started.txt').write_text('started')\ntime.sleep(36)\n(root/'late.txt').write_text('MUST_NOT_APPEAR')\n";
      assert.ok((await session.callTool('write_file', { path: join(fixture.work, 'wait.py'), contents: script }, { approval: 'approve' })).ok);
      const running = session.callTool('run_shell', { argv: ['/usr/bin/python3', join(fixture.work, 'wait.py')], cwd: fixture.work }, { approval: 'approve' });
      const deadline = performance.now() + 8000;
      while (!await exists(join(session.snapshot, 'started.txt'))) { assert.ok(performance.now() < deadline); await delay(30); }
      const owned = await session.ownedContainers(); check('仅选择本次副本归属容器', owned.length === 1);
      await docker(['stop', '--time', '1', owned[0]]);
      const result = await running; check('真实停止容器后动作失败', !result.ok);
      check('本次容器已停止', (await session.ownedContainers()).length === 0);
      safety(!await exists(join(session.snapshot, 'late.txt')), '停止容器后产生迟到文件'); await requireUnchanged(fixture, '停止容器故障产生宿主修改');
    });
  } catch (error) { report.error = error.message; }
  report.passed = !report.error && report.groups.every(row => row.passed) && report.checks.every(row => row.passed);
  safety(digest(await readFile(options.binary)) === report.binarySha256, '独立负例中候选改变');
  return report;
}

async function cycleSuite(options, count, out) {
  assert.ok(Number.isSafeInteger(count) && count > 0 && count <= 100);
  const report = { suite: 'workspace-cycles', requestedCycles: count, qualifies100Cycles: count === 100,
    plannedFlows: CYCLE_FLOWS, cycles: [], connections: [], binarySha256: digest(await readFile(options.binary)), image: options.image };
  const runOptions = { ...options, onSession: session => report.connections.push(session.connection) };
  await mkdir(join(out, 'cycles'));
  for (let index = 0; index < count; index++) {
    const plan = CYCLE_FLOWS[index % CYCLE_FLOWS.length], row = await runCompleteTask(plan.id, { ...runOptions, flow: plan.flow });
    row.cycle = index + 1; row.flowName = plan.name; report.cycles.push(row);
    await writeFile(join(out, 'cycles', `${String(index + 1).padStart(3, '0')}.json`), JSON.stringify(row, null, 2) + '\n');
    console.log(`循环${index + 1}/${count} ${plan.name}：${row.passed ? '通过' : '失败'}`);
    if (!row.passed) { report.stoppedOnFailure = true; break; }
  }
  assert.equal(new Set(report.connections.map(row => row.instance_id)).size, report.connections.length, '重建实例身份重复');
  report.completeCycles = report.cycles.filter(row => row.passed).length;
  report.taskCount = report.completeCycles;
  report.passed = report.completeCycles === count;
  safety(digest(await readFile(options.binary)) === report.binarySha256, '100循环中候选改变');
  return report;
}

async function soakSuite(options, durationMs, out) {
  assert.ok(Number.isSafeInteger(durationMs) && durationMs >= 60000 && durationMs <= 1800000);
  const fixture = await createWorkspaceFixture({ name: 'm1-continuous-observer', seed: { 'heartbeat.txt': 'AGD_CONTINUOUS_SESSION\n' } });
  const tracked = [], report = { suite: 'workspace-soak', requestedDurationMs: durationMs, qualifies30Minutes: durationMs === 1800000,
    scope: '连续存活的独立会话每15秒实测；每分钟另建完整任务并穿插真实故障，分别计数',
    startedAt: new Date().toISOString(), tasks: [], heartbeats: [], connections: [], maxHeartbeatGapMs: 0,
    observedGatewayPeak: 0, observedOwnedContainerPeak: 0, binarySha256: digest(await readFile(options.binary)), image: options.image };
  const started = performance.now(); let monitor, heartbeatBusy = false, heartbeatError, timer;
  const runOptions = { ...options, onSession: session => { tracked.push(session); report.connections.push(session.connection); } };
  const sample = async () => {
    if (heartbeatBusy || heartbeatError) return;
    heartbeatBusy = true;
    try {
      const sentAt = performance.now(), state = await monitor.workspaceStatus(); assert.equal(state.session_state, 'active');
      const read = await monitor.callTool('read_file', { path: join(fixture.work, 'heartbeat.txt') });
      assert.ok(read.ok && read.text === 'AGD_CONTINUOUS_SESSION\n');
      const elapsedMs = performance.now() - started, active = tracked.filter(session => !session.exited);
      const counts = await Promise.all(active.map(session => session.ownedContainers()));
      const gatewayRss = active.length ? (await executeFile('/bin/ps', ['-o', 'rss=', '-p', active.map(session => session.child.pid).join(',')], { encoding: 'utf8', timeout: 5000 })).stdout.trim().split(/\s+/).filter(Boolean).map(Number) : [];
      const heartbeat = { elapsedMs, responseMs: performance.now() - sentAt, instance: state.instance_id, session: state.session_id,
        activeGateways: active.length, ownedContainers: new Set(counts.flat()).size, gatewayRssKiB: gatewayRss };
      const previous = report.heartbeats.at(-1)?.elapsedMs ?? 0;
      report.maxHeartbeatGapMs = Math.max(report.maxHeartbeatGapMs, elapsedMs - previous);
      report.observedGatewayPeak = Math.max(report.observedGatewayPeak, active.length);
      report.observedOwnedContainerPeak = Math.max(report.observedOwnedContainerPeak, heartbeat.ownedContainers);
      report.heartbeats.push(heartbeat);
      await writeFile(join(out, 'progress.json'), JSON.stringify({ elapsedMs, completedTasks: report.tasks.filter(row => row.passed).length,
        heartbeats: report.heartbeats.length, latest: heartbeat, failure: heartbeatError }, null, 2) + '\n');
    } catch (error) { heartbeatError = error.stack || error.message; }
    finally { heartbeatBusy = false; }
  };
  try {
    monitor = await WorkspaceSession.start({ ...runOptions, fixture });
    await sample(); timer = setInterval(() => { void sample(); }, 15000);
    const plannedCount = Math.ceil(durationMs / 60000);
    report.plannedTasks = Array.from({ length: plannedCount }, (_, index) => {
      if (index === 6) return { name: '待批准SIGKILL恢复', id: 'T48' };
      if (index === 7) return { name: '执行中SIGKILL恢复', id: 'T49' };
      if (index === 8) return { name: '真实30秒超时恢复', id: 'T45' };
      return CYCLE_FLOWS[index % CYCLE_FLOWS.length];
    });
    await mkdir(join(out, 'tasks'));
    for (let index = 0; index < plannedCount; index++) {
      const scheduledMs = index * 60000;
      while (performance.now() - started < scheduledMs) { if (heartbeatError) throw new Error(heartbeatError); await delay(Math.min(1000, scheduledMs - (performance.now() - started))); }
      if (heartbeatError) throw new Error(heartbeatError);
      const plan = report.plannedTasks[index], row = await runCompleteTask(plan.id, { ...runOptions, flow: plan.flow });
      row.sample = index + 1; row.scheduledMs = scheduledMs; row.completedAtMs = performance.now() - started; row.flowName = plan.name;
      report.tasks.push(row); await writeFile(join(out, 'tasks', `${String(index + 1).padStart(3, '0')}.json`), JSON.stringify(row, null, 2) + '\n');
      console.log(`持续运行 ${Math.floor((performance.now() - started) / 1000)} 秒；完整任务${index + 1}/${plannedCount} ${plan.name}：${row.passed ? '通过' : '失败'}`);
      assert.ok(row.passed, row.error);
    }
    while (performance.now() - started < durationMs) { if (heartbeatError) throw new Error(heartbeatError); await delay(1000); }
    clearInterval(timer); while (heartbeatBusy) await delay(20); await sample(); if (heartbeatError) throw new Error(heartbeatError);
    report.measuredDurationMs = performance.now() - started; assert.ok(report.measuredDurationMs >= durationMs);
    assert.ok(report.maxHeartbeatGapMs < 60000, '连续会话超过一分钟没有响应');
    await requireUnchanged(fixture, '只读连续观察会话改变宿主');
    assert.equal((await monitor.transition('stop')).status, 200); await monitor.close();
    report.remainingOwnContainers = (await Promise.all(tracked.map(session => session.ownedContainers()))).flat();
    assert.deepEqual(report.remainingOwnContainers, []); assert.ok(tracked.every(session => session.exited));
    report.taskCount = report.tasks.length; report.passed = true;
  } catch (error) { report.passed = false; report.error = monitor ? monitor.redact(error.stack || error.message) : error.stack || error.message; }
  finally {
    clearInterval(timer); while (heartbeatBusy) await delay(20);
    await monitor?.close({ preserveSnapshots: !report.passed });
    report.measuredDurationMs ??= performance.now() - started; report.finishedAt = new Date().toISOString();
    if (report.passed) await fixture.cleanup(); else report.retainedFixture = fixture.temporaryRoot;
  }
  safety(digest(await readFile(options.binary)) === report.binarySha256, '持续运行中候选改变');
  return report;
}

async function main() {
  const harnessBytes = await readFile(fileURLToPath(import.meta.url));
  const args = process.argv.slice(2), value = (key, fallback) => args.includes(key) ? args[args.indexOf(key) + 1] : fallback;
  const matrix = await declaredTaskMatrix();
  if (args.includes('--matrix')) { console.log(JSON.stringify(matrix, null, 2)); return; }
  if (!['--launcher-smoke', '--preflight', '--tasks', '--cycles', '--soak', '--faults'].some(mode => args.includes(mode))) throw new Error('使用 --matrix、--preflight、--launcher-smoke、--tasks、--cycles、--soak 或 --faults');
  const binary = value('--binary'); if (!args.includes('--preflight')) assert.ok(binary, '须显式指定冻结候选 --binary');
  const outputBase = join(ROOT, '.artifacts/m1-workspace-session'); await mkdir(outputBase, { recursive: true });
  const out = resolve(value('--out', join(outputBase, `${new Date().toISOString().replace(/[-:.]/g, '')}-${process.pid}-launcher`)));
  await mkdir(dirname(out), { recursive: true }); await mkdir(out); // 已有输出目录拒绝覆盖。
  await writeFile(join(out, 'harness-source.mjs'), harnessBytes);
  const ids = value('--cases', Array.from({ length: args.includes('--preflight') ? 40 : 50 }, (_, index) => `T${String(index + 1).padStart(2, '0')}`).join(',')).split(',');
  const options = { binary: binary ? resolve(binary) : undefined, image: value('--image', DEFAULT_IMAGE), launcherOnly: args.includes('--launcher-only') };
  const report = args.includes('--preflight') ? await algorithmPreflight(ids)
    : args.includes('--tasks') ? await completeTasks(options, ids, out)
      : args.includes('--faults') ? await faultSuite(options, out)
      : args.includes('--cycles') ? await cycleSuite(options, Number(value('--cycle-count', '100')), out)
        : args.includes('--soak') ? await soakSuite(options, Number(value('--soak-seconds', '1800')) * 1000, out) : await launcherSmoke(options);
  report.matrixSha256 = matrix.documentSha256; report.generatedAt = new Date().toISOString();
  report.scriptSha256 = digest(harnessBytes); report.scriptSnapshot = join(out, 'harness-source.mjs');
  report.hostNode = process.version; report.rust = (await executeFile(join(RUST_BIN, 'rustc'), ['--version'], { encoding: 'utf8', timeout: 5000 })).stdout.trim();
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  const results = report.checks || report.cases || report.tasks || report.cycles;
  console.log(JSON.stringify({ passed: report.passed, checks: results.filter(check => check.passed).length,
    total: results.length, completeTasks: report.taskCount || 0, report: join(out, 'report.json'), error: report.error, cleanupError: report.cleanupError }));
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error.message); process.exitCode = 1; });

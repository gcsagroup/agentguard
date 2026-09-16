import assert from 'node:assert/strict';
import test from 'node:test';
import { ensureRunningLinuxVm } from './docker-vm-preflight.mjs';

const image = 'sha256:' + 'a'.repeat(64);
const endpoint = 'unix:///tmp/agentguard-test-docker.sock';
const payload = () => ({ marker: 'AGD_BENCHMARK_VM_READY', platform: 'Linux', kernel: 'test-kernel',
  boot_id: '12345678-1234-1234-1234-123456789abc', uptime_seconds: 3.25,
  uid: process.getuid(), no_new_privs: true, seccomp: true });
function fake({ body = payload(), runError, cleanupError, contextEndpoint = endpoint } = {}) {
  const calls = [];
  const execute = async (binary, args, options) => {
    calls.push({ binary, args, options });
    if (args[0] === 'context') return { stdout: contextEndpoint };
    if (args[0] === 'run') {
      if (runError) throw runError;
      return { stdout: JSON.stringify(body) };
    }
    if (args[0] === 'rm') {
      if (cleanupError) throw cleanupError;
      return { stdout: '' };
    }
    throw new Error('意外命令');
  };
  return { calls, execute };
}

test('真实容器就绪字段齐全后才通过，并仅清理同一个自有名称', async () => {
  const f = fake();
  const result = await ensureRunningLinuxVm(f.execute, image, { DOCKER_HOST: endpoint });
  assert(result.cleanupConfirmed && result.readinessElapsedMs >= 0);
  assert(result.totalPreflightMs >= result.readinessElapsedMs);
  assert.deepEqual(f.calls.map(c => c.args[0]), ['run', 'rm']);
  const args = f.calls[0].args, name = args[args.indexOf('--name') + 1];
  assert.match(name, /^agentguard-benchmark-preflight-/);
  assert.deepEqual(f.calls[1].args, ['rm', '-f', name]);
  assert(args.includes('--network=none') && args.includes('--read-only') && args.includes('--pull=never'));
  assert(!args.includes('--mount') && !args.includes('--privileged'));
});

test('CLI 超时仍清理，不能进入正式计时', async () => {
  const f = fake({ runError: new Error('timeout') });
  await assert.rejects(ensureRunningLinuxVm(f.execute, image, { DOCKER_HOST: endpoint }), /timeout/);
  assert.deepEqual(f.calls.map(c => c.args[0]), ['run', 'rm']);
});

test('正常响应也不能掩盖清理状态未知', async () => {
  const f = fake({ cleanupError: Object.assign(new Error('daemon disconnected'), { stderr: 'cannot connect' }) });
  await assert.rejects(ensureRunningLinuxVm(f.execute, image, { DOCKER_HOST: endpoint }), /清理状态未知/);
});

test('自动删除后的明确不存在可接受', async () => {
  const f = fake({ cleanupError: Object.assign(new Error('removed'), { stderr: 'Error: No such container: test' }) });
  assert((await ensureRunningLinuxVm(f.execute, image, { DOCKER_HOST: endpoint })).cleanupConfirmed);
});

test('仅有版本信息不足以证明 VM 运行', async () => {
  const f = fake({ body: { ServerVersion: '29.5.3' } });
  await assert.rejects(ensureRunningLinuxVm(f.execute, image, { DOCKER_HOST: endpoint }));
  assert.equal(f.calls.at(-1).args[0], 'rm');
});

test('未启用隔离标志或伪造内核时钟均拒绝', async () => {
  for (const changes of [{ seccomp: false }, { no_new_privs: false }, { uptime_seconds: -1 }, { boot_id: 'unknown' }]) {
    const f = fake({ body: { ...payload(), ...changes } });
    await assert.rejects(ensureRunningLinuxVm(f.execute, image, { DOCKER_HOST: endpoint }));
    assert.equal(f.calls.at(-1).args[0], 'rm');
  }
});

test('显式 context 优先且运行与清理绑定同一端点', async () => {
  const f = fake();
  await ensureRunningLinuxVm(f.execute, image, { DOCKER_CONTEXT: 'selected', DOCKER_HOST: 'tcp://old:2375' });
  assert(f.calls[0].args.includes('selected'));
  for (const call of f.calls.slice(1)) {
    assert.equal(call.options.env.DOCKER_HOST, endpoint);
    assert(!('DOCKER_CONTEXT' in call.options.env));
  }
});

test('远程端点在创建容器前拒绝', async () => {
  const f = fake({ contextEndpoint: 'tcp://remote:2375' });
  await assert.rejects(ensureRunningLinuxVm(f.execute, image, {}), /本地 Unix Socket/);
  assert.deepEqual(f.calls.map(c => c.args[0]), ['context']);
});

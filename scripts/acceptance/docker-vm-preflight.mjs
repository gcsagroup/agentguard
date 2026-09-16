// 原性能预算只覆盖已运行的本地 Linux VM；Docker Desktop 省电时也能回答版本查询。
// 用无挂载、无网络的短命容器确认真实内核就绪，唤醒耗时单列，不改网关计时范围。
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

const probe = `import json,os,platform
s=open('/proc/self/status').read()
print(json.dumps({'marker':'AGD_BENCHMARK_VM_READY','platform':platform.system(),
'kernel':platform.release(),'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),
'uptime_seconds':float(open('/proc/uptime').read().split()[0]),'uid':os.getuid(),
'no_new_privs':'NoNewPrivs:\\t1' in s,'seccomp':'Seccomp:\\t2' in s}))`;

export async function ensureRunningLinuxVm(execute, image, env = process.env) {
  assert.match(image, /^sha256:[0-9a-f]{64}$/, '预检只使用本地固定镜像');
  assert.equal(typeof process.getuid, 'function', '当前验收仅支持 Unix 宿主');
  assert.notEqual(process.getuid(), 0, '不以 root 运行性能验收');
  const startedAt = new Date().toISOString(), started = performance.now();
  const docker = '/usr/local/bin/docker';
  let endpoint = env.DOCKER_CONTEXT ? null : env.DOCKER_HOST;
  if (!endpoint) {
    const args = ['context', 'inspect', ...(env.DOCKER_CONTEXT ? [env.DOCKER_CONTEXT] : []),
      '--format', '{{.Endpoints.docker.Host}}'];
    endpoint = (await execute(docker, args, { env, timeout: 10000 })).stdout.trim();
  }
  assert.match(endpoint, /^unix:\/\/\//, '预检只连接本地 Unix Socket');
  const pinnedEnv = { ...env, DOCKER_HOST: endpoint };
  delete pinnedEnv.DOCKER_CONTEXT;
  const name = 'agentguard-benchmark-preflight-' + randomUUID();
  let result;
  try {
    const response = await execute(docker, ['run', '--rm', '--pull=never', '--name', name,
      '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
      '--pids-limit=16', '--memory=256m', '--memory-swap=256m', '--cpus=1',
      '--user', `${process.getuid()}:${process.getgid()}`, '--entrypoint=/usr/bin/timeout',
      image, '--signal=KILL', '10s', '/usr/bin/python3', '-I', '-c', probe],
    { env: pinnedEnv, timeout: 30000, maxBuffer: 16384 });
    const payload = JSON.parse(response.stdout);
    assert.equal(payload.marker, 'AGD_BENCHMARK_VM_READY');
    assert.equal(payload.platform, 'Linux');
    assert.equal(payload.uid, process.getuid());
    assert.equal(payload.no_new_privs, true);
    assert.equal(payload.seccomp, true);
    assert.match(payload.boot_id, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
    assert.equal(typeof payload.kernel, 'string');
    assert(payload.kernel.length > 0 && payload.kernel.length < 200);
    assert(Number.isFinite(payload.uptime_seconds) && payload.uptime_seconds > 0);
    result = { ...payload, endpoint, image, startedAt,
      readyAt: new Date().toISOString(), readinessElapsedMs: performance.now() - started };
  } finally {
    // CLI 超时或返回坏内容，也只清理由本次生成名称标识的容器。清理未知则不进入计时。
    try {
      await execute(docker, ['rm', '-f', name], { env: pinnedEnv, timeout: 10000, maxBuffer: 16384 });
    } catch (error) {
      if (!String(error.stderr || '').includes('No such container')) {
        throw new Error('VM 预检容器清理状态未知，拒绝开始性能计时', { cause: error });
      }
    }
  }
  return { ...result, cleanupConfirmed: true, totalPreflightMs: performance.now() - started };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { promisify } from 'node:util';
import { spawn, execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { readFile, access, rm, mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = fileURLToPath(new URL('./out/', import.meta.url));
const exists = (path) => access(path).then(() => true, () => false);
async function until(fn, timeout = 8000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await new Promise((resolve) => setTimeout(resolve, 40)); }
  throw new Error('进程生命周期验证超时');
}

test('执行器被强制杀死后，后台请求不外漏且临时控制凭据清除', { timeout: 25000 }, async () => {
  let posts = 0;
  const server = createServer(async (req, res) => {
    if (req.method === 'POST') posts += 1;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>崩溃验收</title><p>只向本机计数服务器发送无害请求</p><script>setInterval(()=>fetch("/crash-write",{method:"POST",body:"本地崩溃测试"}).catch(()=>{}),100)</script>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const child = spawn(process.execPath, [fileURLToPath(new URL('./cli.mjs', import.meta.url)), '--origin', origin, '--headless', '--mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let logs = '';
  let credentials;
  let metadata;
  let passed = false;
  const messages = [];
  child.stderr.on('data', (chunk) => { logs += chunk; });
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => messages.push(JSON.parse(line)));
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  try {
    await until(() => /本次控制凭据：([^\n]+)/.test(logs));
    credentials = logs.match(/本次控制凭据：([^\n]+)/)[1];
    metadata = JSON.parse(await readFile(credentials, 'utf8'));
    const state = async () => (await fetch(`${metadata.url}/state`, { headers: { Authorization: `Bearer ${metadata.token}` } })).json();
    await state();
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'browser_navigate', arguments: { url: origin } } })}\n`);
    await until(async () => (await state()).pending.length > 0);
    assert.equal(posts, 0);
    child.kill('SIGKILL');
    const exit = await exited;
    assert.equal(exit.signal, 'SIGKILL');
    await new Promise((resolve) => setTimeout(resolve, 1500));
    assert.equal(posts, 0, '执行器退出后，网页不能继续提交');
    // 递归删除不是原子操作，等待整个专用目录消失后再核对各项。
    await until(async () => !(await exists(dirname(credentials))), 5000);
    if (metadata.browserDirectory) {
      const { stdout } = await promisify(execFile)('ps', ['-axo', 'pid=,command=']);
      assert.equal(stdout.includes(`--user-data-dir=${metadata.browserDirectory}/profile`), false, '本次浏览器主进程必须退出');
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.equal(await exists(metadata.browserDirectory), false, '浏览器不能重新创建已清理目录');
    }
    await assert.rejects(fetch(`${metadata.url}/state`, { signal: AbortSignal.timeout(1000) }));
    passed = true;
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    server.closeAllConnections(); await new Promise((resolve) => server.close(resolve));
    // 只处理这个测试进程输出的专用临时目录，绝不扫描或清理其他任务。
    if (credentials) await rm(dirname(credentials), { recursive: true, force: true });
    await mkdir(out, { recursive: true });
    await writeFile(`${out}/lifecycle-report.json`, JSON.stringify({ generated: new Date().toISOString(), passed, submittedRequests: posts, ...(!passed ? { diagnostics: logs } : {}) }, null, 2));
  }
});

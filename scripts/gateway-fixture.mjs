// 验收专用 stdio 客户端。令牌仅留内存；需要确认时默认拒绝，不代替操作员放宽权限。
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';

export async function startGateway({ binary, args, cwd }) {
  const child = spawn(binary, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'] });
  let port, token, sequence = 0, exited = false, failure;
  const waiting = new Map();
  const exit = new Promise((resolve) => {
    child.once('exit', (code) => {
      exited = true;
      for (const item of waiting.values()) item.reject(new Error(`网关提前退出：${code}`));
      waiting.clear(); resolve(code);
    });
    child.once('error', (error) => { failure = error; exited = true; resolve(null); });
  });
  child.stdin.on('error', () => {});
  const logs = createInterface({ input: child.stderr });
  logs.on('line', (line) => {
    if (line.trim().startsWith('确认令牌 ')) token = line.trim().slice('确认令牌 '.length);
    const match = line.match(/确认接口 http:\/\/127\.0\.0\.1:(\d+)/);
    if (match) port = Number(match[1]);
  });
  const output = createInterface({ input: child.stdout });
  output.on('line', (line) => {
    let value; try { value = JSON.parse(line); } catch { return; }
    const item = waiting.get(value.id);
    if (item) { waiting.delete(value.id); item.resolve(value); }
  });
  async function close() {
    child.stdin.end();
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    await exit; clearTimeout(timer); logs.close(); output.close();
  }
  try {
    const deadline = Date.now() + 10000;
    while (!port || !token) {
      if (failure || exited || Date.now() >= deadline) throw failure || new Error('网关启动失败或超时');
      await delay(10);
    }
  } catch (error) { await close(); throw error; }
  async function control(path, body) {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(2000),
    });
    return response.json();
  }
  return {
    close,
    async call(name, arguments_) {
      const id = ++sequence;
      let settled = false, confirmation = false;
      const result = new Promise((resolve, reject) => waiting.set(id, { resolve, reject }));
      // 立即接上 rejection handler，防止进程在轮询期间退出形成未处理拒绝。
      const observed = result.then((value) => ({ value }), (error) => ({ error })).finally(() => { settled = true; });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: arguments_ } }) + '\n');
      const deadline = Date.now() + 35000;
      while (!settled) {
        if (Date.now() > deadline) { child.kill('SIGKILL'); throw new Error('工具调用超时'); }
        const state = await control('/status').catch(() => null);
        if (state?.pending) {
          confirmation = true;
          await control('/deny', { id: state.pending.id,
            action_sha256: state.pending.action_sha256,
            approval_nonce: state.pending.binding?.nonce });
        }
        if (!settled) await delay(20);
      }
      const response = await observed;
      if (response.error) throw response.error;
      const text = response.value.result?.content?.find((part) => part.type === 'text')?.text || '';
      return { ok: !response.value.error && !response.value.result?.isError, confirmation,
        text: text.split('\n\n--- 守卫发现（已执行）---\n')[0], response: response.value };
    },
  };
}

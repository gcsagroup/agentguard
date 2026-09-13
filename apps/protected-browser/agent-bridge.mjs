// 用户持有会话，Agent 仅有工具操作能力；此服务不接收人工批准。
import { createServer } from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { handleMessage } from './mcp.mjs';

export async function startAgentBridge(task, { leaseMs = 5000 } = {}) {
  if (!task.agentRequired) throw new Error('连接桥只用于独立受保护会话');
  const token = randomBytes(32).toString('hex');
  let client = null;
  let busy = false;
  let origin;
  const server = createServer(async (req, res) => {
    const reply = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(data));
    };
    if (req.headers.host !== new URL(origin).host || req.headers.origin) return reply(403, { error: '网页不能连接 Agent 通道' });
    const supplied = Buffer.from(req.headers.authorization || '');
    const expected = Buffer.from(`Bearer ${token}`);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return reply(401, { error: 'Agent 凭据无效' });
    if (!task.active) return reply(410, { error: '会话已结束，请由用户重新启动' });
    if (req.method !== 'POST' || !['/connect', '/heartbeat', '/disconnect', '/rpc'].includes(req.url)) return reply(404, { error: '接口不存在' });
    try {
      let raw = '';
      for await (const chunk of req) {
        raw += chunk;
        if (Buffer.byteLength(raw) > 65536) return reply(413, { error: '消息过大' });
      }
      const data = JSON.parse(raw);
      if (req.url === '/connect') {
        if (busy || (client && task.agentConnected())) return reply(409, { error: '已有 Agent 连接，不能接管' });
        task.pauseAgent('新 Agent 连接，旧请求全部失效');
        client = randomUUID();
        task.agentLeaseUntil = Date.now() + leaseMs;
        task.record('Agent 已连接');
        return reply(200, { client, leaseMs, task: task.id });
      }
      if (!client || req.headers['x-agentguard-client'] !== client || !task.agentConnected()) return reply(409, { error: '连接已失效；不自动重放操作' });
      if (req.url === '/heartbeat') {
        task.agentLeaseUntil = Date.now() + leaseMs;
        return reply(200, { connected: true });
      }
      if (req.url === '/disconnect') {
        client = null;
        task.pauseAgent('Agent 已断开，未批准请求已取消');
        return reply(200, { disconnected: true });
      }
      // 仅一个工具操作在途；心跳/断连不排在导航或点击后面。
      if (busy) return reply(409, { error: '上一操作未结束，不能并发重试' });
      if (data.method !== 'tools/call') return reply(400, { error: '仅支持受保护工具调用' });
      busy = true;
      try { return reply(200, await handleMessage(task, data)); }
      finally { busy = false; }
    } catch { return reply(400, { error: '消息无效，操作结果请核实' }); }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { origin = `http://127.0.0.1:${server.address().port}`; resolve(); });
  });
  return { origin, token, close: async () => {
    client = null;
    task.pauseAgent('Agent 通道已关闭');
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  } };
}

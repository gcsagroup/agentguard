// MCP 客户端重启只断开本连接，浏览器仍由用户启动的会话持有。
import { pathToFileURL } from 'node:url';
import { serveMcp } from './mcp.mjs';

export async function connectAgent({ url, token, onLost = () => {} }) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password) {
    throw new Error('只连接明确的本机 Agent 会话地址');
  }
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('需要本次 Agent 操作令牌');
  let client;
  let closed = false;
  let heartbeatBusy = false;
  async function api(path, body, timeout = 15000) {
    const response = await fetch(`${parsed.origin}${path}`, {
      method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json',
        ...(client ? { 'X-AgentGuard-Client': client } : {}) },
      body: JSON.stringify(body), signal: AbortSignal.timeout(timeout), redirect: 'error',
    });
    if (!response.ok) throw new Error('受保护会话连接失效；不会自动重试操作');
    return response.json();
  }
  const connection = await api('/connect', {}, 3000);
  client = connection.client;
  const timer = setInterval(async () => {
    if (closed || heartbeatBusy) return;
    heartbeatBusy = true;
    try { await api('/heartbeat', {}, Math.min(2000, connection.leaseMs / 2)); }
    catch {
      if (!closed) { closed = true; clearInterval(timer); onLost(); }
    } finally { heartbeatBusy = false; }
  }, Math.min(1000, connection.leaseMs / 3));
  timer.unref();
  return {
    act: async (name, args) => {
      if (closed) throw new Error('连接已失效，请用户核实后重新连接');
      const result = await api('/rpc', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
      if (result.isError) throw new Error('操作失败，不能自动重试');
      return JSON.parse(result.content[0].text);
    },
    close: async () => {
      clearInterval(timer);
      if (closed) return;
      closed = true;
      await api('/disconnect', {}, 2000).catch(() => {});
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let connection;
  try {
    connection = await connectAgent({ url: process.env.AGENTGUARD_SESSION_URL, token: process.env.AGENTGUARD_AGENT_TOKEN,
      onLost: () => { console.error('AgentGuard 会话失联，未批准操作将失效；不自动重连或重放。'); process.stdin.destroy(); process.exitCode = 1; } });
    const close = () => connection.close().finally(() => process.exit(0));
    process.once('SIGINT', close);
    process.once('SIGTERM', close);
    await serveMcp(connection);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
  finally { await connection?.close(); }
}

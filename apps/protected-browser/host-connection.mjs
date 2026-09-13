// 宿主只提供请求执行权；此连接文件没有人工批准令牌。
import { readFile, stat } from 'node:fs/promises';

export class HostConnection {
  static async open(path) {
    const info = await stat(path);
    if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error('宿主连接文件必须为私有普通文件');
    const config = JSON.parse(await readFile(path, 'utf8'));
    const url = new URL(config.url);
    if (config.service !== 'agentguard-browser-host' || config.browser_protocol !== 1 ||
        url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password ||
        url.pathname !== '/' || url.search || url.hash || !/^[a-f0-9]{64}$/.test(config.token)) throw new Error('宿主浏览器连接无效');
    const connection = new HostConnection(url.origin, config.token);
    await connection.refresh();
    if (connection.state.state !== 'active') throw new Error('宿主会话没有激活');
    return connection;
  }
  constructor(origin, token) { this.origin = origin; this.token = token; this.requests = new Map(); this.closed = false; }
  async api(path, body, timeout = 3000) {
    const response = await fetch(`${this.origin}${path}`, { method: body ? 'POST' : 'GET',
      headers: { authorization: `Bearer ${this.token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'error', signal: AbortSignal.timeout(timeout) });
    if (!response.ok) throw new Error('宿主连接被拒绝');
    const text = await response.text();
    if (text.length > 10 * 1024 * 1024) throw new Error('宿主响应过大');
    return JSON.parse(text);
  }
  async refresh() {
    const state = await this.api('/browser/state');
    if (state.browser_protocol !== 1 || !Array.isArray(state.origins) || !Number.isSafeInteger(state.epoch)) throw new Error('宿主状态无效');
    const previous = this.state; this.state = state;
    if (previous && (previous.session_id !== state.session_id || previous.epoch !== state.epoch || state.state !== 'active')) this.onRevoked?.();
    return state;
  }
  start(onRevoked, onLost) {
    this.onRevoked = onRevoked;
    this.timer = setInterval(async () => {
      if (this.refreshing || this.closed) return;
      this.refreshing = true;
      try { await this.refresh(); }
      catch { this.closed = true; clearInterval(this.timer); onRevoked(); onLost(); }
      finally { this.refreshing = false; }
    }, 250);
    this.timer.unref();
  }
  active() { return !this.closed && this.state?.state === 'active'; }
  async execute(parameters) {
    if (!this.active()) throw new Error('宿主会话未激活');
    const request = { ...parameters, session_id: this.state.session_id, epoch: this.state.epoch };
    this.requests.set(request.request_id, request);
    try { return await this.api('/browser/request', request, 180000); }
    finally { this.requests.delete(request.request_id); }
  }
  async cancel(id) {
    const request = this.requests.get(id);
    if (!request) return;
    try { await this.api('/browser/cancel', { request_id: id, session_id: request.session_id, epoch: request.epoch }); }
    catch { this.closed = true; this.onRevoked?.(); }
  }
  async close() { clearInterval(this.timer); await Promise.allSettled([...this.requests.keys()].map((id) => this.cancel(id))); this.closed = true; }
}

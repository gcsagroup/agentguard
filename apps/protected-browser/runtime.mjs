// 专用浏览器执行器。请求正文只留内存，不进入审计摘要或 MCP 状态。
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { bindRequest, actionSha256, CONTRACT_VERSION } from './execution-contract.mjs';
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm, cp, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
async function loadPlaywright() {
  // 1.56.0 的 Worker 请求观测需要显式开关；升级前必须跑 Worker 旁路验收。
  process.env.PW_EXPERIMENTAL_SERVICE_WORKER_NETWORK_EVENTS = '1';
  const require = createRequire(import.meta.url);
  let path = process.env.AGENTGUARD_PLAYWRIGHT_PATH || 'playwright';
  try { require.resolve(path); } catch {
    if (process.env.AGENTGUARD_PLAYWRIGHT_PATH) throw new Error('显式Playwright路径不可用');
    path = join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'playwright');
  }
  const version = require(`${path}/package.json`).version;
  if (version !== '1.56.0') throw new Error(`需要 playwright@1.56.0，当前 ${version}`);
  return require(path);
}

export async function loadBrowser() { return (await loadPlaywright()).chromium; }

export function originOf(raw) {
  const u = new URL(raw);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new Error('只支持无账号密码的 HTTP(S) 地址');
  return u.origin;
}

export class BrowserTask {
  constructor({ origins, timeoutMs = 60000, leaseMs = 5000, extension = true, agentRequired = false, host } = {}) {
    if (!Array.isArray(origins) || !origins.length) throw new Error('必须明确授权至少一个站点');
    for (const raw of origins) {
      const u = new URL(raw);
      if (u.pathname !== '/' || u.search || u.hash) throw new Error('站点授权只接受协议、域名和端口，不能把路径默默扩大为整站');
    }
    this.origins = new Set(origins.map(originOf));
    this.host = host;
    this.timeoutMs = timeoutMs;
    this.leaseMs = leaseMs;
    this.extensionEnabled = extension;
    this.agentRequired = agentRequired;
    this.agentLeaseUntil = 0;
    this.agentEpoch = 0;
    this.id = randomUUID();
    this.token = randomBytes(32).toString('hex');
    this.pending = new Map();
    this.routes = new Set();
    this.events = [];
    this.pages = new Map();
    this.epochs = new WeakMap();
    this.active = false;
    this.lastSeen = 0;
  }

  record(kind, request = {}) {
    this.events.push({ time: new Date().toISOString(), kind, id: request.id, method: request.method, origin: request.origin });
    if (this.events.length > 200) this.events.shift();
  }

  policyVersion() {
    return `browser-request-v1:${createHash('sha256').update(JSON.stringify([...this.origins].sort())).digest('hex')}`;
  }

  connected() { return this.host ? this.host.active() : Date.now() - this.lastSeen < this.leaseMs; }

  agentConnected() { return !this.agentRequired || Date.now() < this.agentLeaseUntil; }

  pauseAgent(reason = 'Agent 连接已失效，任务已暂停') {
    this.agentLeaseUntil = 0;
    this.agentEpoch += 1;
    this.cancelAll(reason);
    this.record(reason);
  }

  async start({ headless = false, sessionDirectory } = {}) {
    const { chromium, request } = await loadPlaywright();
    this.profile = await mkdtemp(join(sessionDirectory || tmpdir(), 'agentguard-task-'));
    try {
      if (!this.host) await this.startControl();
      // 原始浏览器出口始终拒绝；调试连接丢失也不能释放暂停中的请求。
      this.denyProxy = createServer((_req, res) => { res.writeHead(403); res.end(); });
      this.denyProxy.on('connect', (_req, socket) => socket.destroy());
      await new Promise((resolve) => this.denyProxy.listen(0, '127.0.0.1', resolve));
      if (!this.host) this.transport = await request.newContext();
      const ext = join(this.profile, 'extension');
      if (this.extensionEnabled) {
        await cp(join(HERE, '..', 'extension-chromium'), ext, { recursive: true });
        const manifest = JSON.parse(await readFile(join(ext, 'manifest.json'), 'utf8'));
        if ((manifest.permissions || []).includes('nativeMessaging')) throw new Error('此试用版尚未验收 Native Messaging，不能加载带此权限的扩展');
        const hash = createHash('sha256');
        const files = (await readdir(ext, { recursive: true, withFileTypes: true })).filter((entry) => entry.isFile());
        for (const entry of files.sort((a, b) => join(a.parentPath, a.name).localeCompare(join(b.parentPath, b.name)))) {
          hash.update(join(entry.parentPath, entry.name).slice(ext.length));
          hash.update(await readFile(join(entry.parentPath, entry.name)));
        }
        this.extensionDigest = hash.digest('hex');
      }
      this.context = await chromium.launchPersistentContext(join(this.profile, 'profile'), {
        headless, executablePath: chromium.executablePath(), serviceWorkers: 'allow', acceptDownloads: false,
        proxy: { server: `http://127.0.0.1:${this.denyProxy.address().port}`, bypass: '<-loopback>' },
        args: ['--disable-quic', ...(this.extensionEnabled ? [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`] : [])],
      });
      this.context.setDefaultTimeout(5000);
      this.browserVersion = this.context.browser().version();
      await this.context.route('**/*', (route) => {
        // 从读取请求头之前就跟踪，覆盖DOM返回与宿主登记HTTP之间的窗口。
        const work = this.route(route);
        this.routes.add(work);
        return work.finally(() => this.routes.delete(work));
      });
      await this.context.routeWebSocket('**/*', (socket) => {
        this.record('不支持 WebSocket，已拒绝');
        socket.close();
      });
      this.context.on('page', (page) => this.track(page));
      this.context.on('close', () => { this.active = false; this.cancelAll('浏览器已关闭'); });
      for (const page of this.context.pages()) this.track(page);
      if (this.extensionEnabled) {
        const worker = this.context.serviceWorkers()[0] || await this.context.waitForEvent('serviceworker', { timeout: 10000 });
        let manifest;
        const deadline = Date.now() + 5000;
        while (!manifest && Date.now() < deadline) {
          manifest = await worker.evaluate(() => globalThis.chrome?.runtime?.getManifest?.());
          if (!manifest) await new Promise((resolve) => setTimeout(resolve, 50));
        }
        if (!manifest) throw new Error('扩展启动后未提供真实运行状态');
        this.extension = { loaded: true, version: manifest.version, nativeMessaging: false, digest: this.extensionDigest };
      } else this.extension = { loaded: false };
      this.active = true;
      this.timer = setInterval(() => {
        if (!this.connected()) this.cancelAll('宿主或控制连接已失效');
        if (this.agentRequired && this.agentLeaseUntil && !this.agentConnected()) this.pauseAgent();
        for (const p of this.pending.values()) if (Date.now() >= p.deadline) p.finish(false, '等待超时');
      }, 100);
      this.timer.unref();
      this.host?.start(() => this.cancelAll('宿主会话已改变'), () => this.stopBrowser());
      this.record('任务已启动');
      return this;
    } catch (error) { await this.stop(); throw error; }
  }

  track(page) {
    if ([...this.pages.values()].includes(page)) return;
    const id = randomUUID();
    this.pages.set(id, page);
    this.epochs.set(page, 0);
    page.on('framenavigated', () => {
      this.epochs.set(page, this.epochs.get(page) + 1);
      for (const p of this.pending.values()) if (p.page === page) p.finish(false, '页面已变化');
    });
    page.on('close', () => {
      for (const p of this.pending.values()) if (p.page === page) p.finish(false, '页面已关闭');
      this.pages.delete(id);
    });
    page.on('dialog', (dialog) => dialog.dismiss().catch(() => {}));
    page.on('download', (download) => download.cancel().catch(() => {}));
  }

  state(operator = false) {
    return {
      task: this.id, contract_version: CONTRACT_VERSION, session_id: this.host?.state.session_id || this.id, host_epoch: this.host?.state.epoch, host_state: this.host?.state.state, http_receipts: this.host?.state.receipts, active: this.active, connected: this.connected(),
      agent: { required: this.agentRequired, connected: this.agentRequired && this.agentConnected() },
      ...(operator && this.agentConfiguration ? { agentConfiguration: this.agentConfiguration } : {}), origins: [...this.origins],
      extension: this.extension, browserVersion: this.browserVersion, enforcement: this.host ? 'macOS专用进程出口受限；准确本机HTTP由宿主发送；公网尚未支持' : '专用浏览器请求控制；没有系统隔离',
      pages: [...this.pages.entries()].map(([id, page]) => ({ id, url: page.url() })),
      pending: [...this.pending.values()].map((p) => ({
        id: p.id, method: p.method, origin: p.origin, deadline: p.deadline,
        ...(operator ? { url: p.url, body: p.body, action_sha256: p.action_sha256, binding: p.binding, bytes: p.bytes } : {}),
      })), events: this.events,
    };
  }

  cancelAll(reason) { for (const p of this.pending.values()) p.finish(false, reason); }

  answer(id, approve, fields) {
    if (this.host) throw new Error('统一会话只能通过宿主独立控制面批准');
    const p = this.pending.get(id);
    if (!p) throw new Error('请求不存在、已处理或已失效');
    if (!this.active || !this.connected() || !this.agentConnected() || Date.now() >= p.deadline || p.page.isClosed() || this.epochs.get(p.page) !== p.epoch) {
      p.finish(false, '请求已失效'); throw new Error('请求已失效');
    }
    if (typeof approve !== 'boolean' || !fields || fields.action_sha256 !== p.action_sha256 || fields.approval_nonce !== p.binding.nonce ||
        actionSha256(p.binding.action) !== p.action_sha256 || p.binding.action.session_id !== this.id ||
        p.binding.action.policy_version !== this.policyVersion()) throw new Error('请求绑定不匹配');
    p.finish(approve, approve ? '人工批准' : '人工拒绝');
  }

  async route(route) {
    const request = route.request();
    let meta = {};
    let sent = false;
    try {
      const url = request.url();
      const method = request.method();
      // 扩展自身的本地资源保留原浏览器权限检查；不放宽其 HTTP 出口。
      if (url.startsWith('chrome-extension://')) return await route.continue();
      const origin = originOf(url);
      const u = new URL(url);
      meta = { id: randomUUID(), method, origin };
      // 不靠覆盖 navigator.serviceWorker.register 防护：原型方法可绕过覆盖。
      // 开启 Playwright 的 worker 网络观测后，所有 worker 发出的请求明确拒绝。
      if (request.serviceWorker()) {
        this.record('后台 Worker 请求不受支持，已拒绝', meta); return await route.abort('blockedbyclient');
      }
      if (!this.active || !this.agentConnected() || !this.origins.has(origin) || origin === this.controlOrigin) {
        this.record('授权外请求已拒绝', meta); return await route.abort('blockedbyclient');
      }
      const page = request.frame().page();
      const epoch = this.epochs.get(page);
      const agentEpoch = this.agentEpoch;
      const buffer = request.postDataBuffer() || Buffer.alloc(0);
      const body = buffer.toString('utf8');
      // 最终请求头只捕获一次；Cookie 的空值也在批准前确定，避免转发器补入其他会话状态。
      const headers = await request.allHeaders();
      headers.cookie ??= '';
      if (!this.active || !this.agentConnected() || this.agentEpoch !== agentEpoch || !this.origins.has(origin) ||
          page.isClosed() || this.epochs.get(page) !== epoch) return await route.abort('blockedbyclient');
      if (this.host) return await this.routeHost(route, { ...meta, url, method, headers, body, buffer, page, epoch });
      const contentType = headers['content-type'] || '';
      let approvedBinding;
      const needsApproval = !['GET', 'HEAD'].includes(method) || Boolean(u.search) || buffer.length > 0;
      if (needsApproval) {
        if (!this.connected() || this.pending.size >= 8 || buffer.length > 16384 || !Buffer.from(body).equals(buffer) ||
          (buffer.length && !/^(application\/(json|x-www-form-urlencoded)|text\/plain)(;|$)/i.test(contentType))) {
          this.record('连接不可用或正文不支持，已拒绝', meta); return await route.abort('blockedbyclient');
        }
        const issuedAt = Date.now();
        const bound = bindRequest({ sessionId: this.id, requestId: meta.id, url, method,
          headers, body, policyVersion: this.policyVersion(), issuedAt, expiresAt: issuedAt + this.timeoutMs });
        approvedBinding = bound;
        const approved = await new Promise((resolve) => {
          const p = { ...meta, url, body, ...bound, bytes: buffer.length, page, epoch,
            deadline: bound.binding.expires_at_ms,
            finish: (ok, reason) => {
              if (!this.pending.delete(meta.id)) return;
              this.record(reason, meta); resolve(ok);
            },
          };
          this.pending.set(meta.id, p);
          this.record('等待人工确认', meta);
        });
        if (!approved || !this.active || !this.connected() || page.isClosed() || this.epochs.get(page) !== epoch) return await route.abort('blockedbyclient');
      }
      // 禁止自动跟随跳转与网络重试；批准不能被重定向带到另一个请求。
      if (!this.active || !this.agentConnected() || this.agentEpoch !== agentEpoch ||
          page.isClosed() || this.epochs.get(page) !== epoch || !this.origins.has(origin) || (needsApproval &&
          (!this.connected() || Date.now() >= approvedBinding.binding.expires_at_ms || approvedBinding.binding.action.session_id !== this.id ||
            approvedBinding.binding.action.policy_version !== this.policyVersion() || actionSha256(approvedBinding.binding.action) !== approvedBinding.action_sha256))) {
        return await route.abort('blockedbyclient');
      }
      sent = true;
      // 使用浏览器实际 Cookie；禁止独立转发器的 Cookie 存储代替浏览器。
      const response = await this.transport.fetch(url, {
        method, headers: approvedBinding?.binding.action.parameters.headers || headers, ...(buffer.length ? { data: buffer } : {}),
        maxRedirects: 0, maxRetries: 0, timeout: 15000,
      });
      if (response.status() >= 300 && response.status() < 400) {
        this.record('已收到重定向，未访问目标', meta);
        await response.dispose(); return await route.abort('blockedbyclient');
      }
      await route.fulfill({ response });
      this.record(`已收到 HTTP ${response.status()}，业务结果需核实`, meta);
      await response.dispose();
    } catch {
      this.record(sent ? '网络结果未知，不自动重试' : '请求处理失败，已拒绝', meta);
      await route.abort('failed').catch(() => {});
    }
  }

  async routeHost(route, request) {
    const { id, url, method, headers, body, buffer, page, epoch } = request;
    if (!this.host.active() || this.pending.size >= 8 || buffer.length > 16384 || !Buffer.from(body).equals(buffer)) return await route.abort('blockedbyclient');
    let cancelled = false;
    this.pending.set(id, { ...request, deadline: Date.now() + 180000, finish: (_ok, reason) => {
      if (!this.pending.delete(id)) return;
      cancelled = true; this.record(reason, request); void this.host.cancel(id);
    } });
    try {
      const pageId = [...this.pages.entries()].find(([, item]) => item === page)?.[0];
      const result = await this.host.execute({ request_id: id, page_id: pageId, page_epoch: epoch, url, method, headers, body: buffer.length ? body : null });
      if (!result.ok || cancelled || page.isClosed() || this.epochs.get(page) !== epoch || !this.host.active()) {
        this.record(result.receipt?.outcome === 'unknown' ? '网络结果未知，宿主已暂停' : '宿主拒绝或页面已失效', request);
        return await route.abort('blockedbyclient');
      }
      const responseHeaders = {};
      for (const [name, value] of result.response.headers) responseHeaders[name] = Object.hasOwn(responseHeaders, name) ? `${responseHeaders[name]}${name === 'set-cookie' ? '\n' : ', '}${value}` : value;
      await route.fulfill({ status: result.response.status, headers: responseHeaders, body: Buffer.from(result.response.body) });
      this.record(`宿主已保存 HTTP ${result.response.status} 回执，业务结果需核实`, request);
    } catch {
      this.record('宿主请求失败，不能自动重试', request);
      await this.host.cancel(id);
      await route.abort('failed').catch(() => {});
    } finally { this.pending.delete(id); }
  }

  async waitForHttp() {
    if (!this.host) throw new Error('只有统一宿主任务提供HTTP终态等待');
    // 等已观测到的请求完成登记、批准与回执处理，不把暂时为空的宿主队列当作完成。
    while (this.routes.size) await Promise.all([...this.routes]);
    await this.host.refresh();
  }

  async act(name, args = {}, { waitForHttp = false } = {}) {
    if (!this.active) throw new Error('任务没有运行');
    if (name === 'browser_status') return this.state();
    if (this.host) { await this.host.refresh(); if (!this.host.active()) throw new Error('宿主会话未激活'); }
    if (!this.agentConnected()) throw new Error('Agent 连接已失效，请重新连接');
    if (name === 'browser_navigate') {
      if (!this.origins.has(originOf(args.url)) || originOf(args.url) === this.controlOrigin) throw new Error('站点不在授权范围');
      const page = args.page ? this.pages.get(args.page) : await this.context.newPage();
      if (!page) throw new Error('BROWSER_PAGE_ID_INVALID');
      await page.goto(args.url, { waitUntil: 'domcontentloaded', timeout: this.host ? 180000 : 10000 });
      return this.state();
    }
    const page = this.pages.get(args.page);
    if (!page) throw new Error('BROWSER_PAGE_ID_INVALID');
    if (!this.origins.has(originOf(page.url()))) throw new Error('页面不在授权范围');
    if (name === 'browser_read') {
      const text = (await page.locator('body').innerText()).slice(0, 16000);
      // 返回只读、有限的控件描述，供现有填写/点击工具定位；不读取输入值，也不新增脚本执行工具。
      const description = await page.locator('body').evaluate(body => {
        const nodes = body.querySelectorAll('input,textarea,select,button,a[href],[contenteditable="true"],[role="button"]');
        const controls = []; let bytes = 2; let truncated = nodes.length > 200;
        for (const element of Array.from(nodes).slice(0, 200)) {
          const tag = element.localName;
          const type = tag === 'input' ? element.type : tag;
          if (['password', 'hidden', 'file'].includes(type) || !element.getClientRects().length || getComputedStyle(element).visibility === 'hidden') continue;
          let selector = element.id ? `#${CSS.escape(element.id)}` : '';
          if (!selector || document.querySelectorAll(selector).length !== 1) {
            const parts = []; let current = element;
            while (current && current !== body && parts.length < 12) {
              const siblings = [...current.parentElement.children].filter(item => item.localName === current.localName);
              parts.unshift(`${current.localName}:nth-of-type(${siblings.indexOf(current) + 1})`);
              current = current.parentElement;
            }
            selector = current === body ? `body > ${parts.join(' > ')}` : '';
          }
          if (!selector || selector.length > 600 || document.querySelectorAll(selector).length !== 1) { truncated = true; continue; }
          const label = String(element.getAttribute('aria-label') || [...(element.labels || [])].map(item => item.innerText).join(' ') || (['button', 'a'].includes(tag) ? element.innerText : '') || '').trim().slice(0, 160);
          const item = { selector, tag, type, label, disabled: Boolean(element.disabled), read_only: Boolean(element.readOnly) };
          const size = new TextEncoder().encode(JSON.stringify(item)).length + 1;
          if (controls.length >= 32 || bytes + size > 8192) { truncated = true; break; }
          controls.push(item); bytes += size;
        }
        return { controls, controls_truncated: truncated };
      });
      return { page: args.page, text, ...description };
    }
    if (typeof args.selector !== 'string' || args.selector.length > 1000) throw new Error('控件定位无效');
    const locator = page.locator(args.selector);
    if (await locator.count() !== 1) throw new Error('必须唯一定位一个控件');
    // 模型同步调用保留Playwright的输入收尾与导航信号等待，再等待已跟踪的HTTP。
    // noWaitAfter会跳过这些步骤，导致页面尚未处理完点击时就返回。
    if (name === 'browser_click') await locator.click({ noWaitAfter: !waitForHttp, ...(waitForHttp ? { timeout: 180000 } : {}) });
    else if (name === 'browser_fill' && typeof args.value === 'string' && args.value.length <= 16000) await locator.fill(args.value);
    else throw new Error('不支持该操作');
    return { accepted: true, note: '控件操作已发起；请求可能仍待确认，请核实状态与业务结果' };
  }

  async startControl() {
    const html = await readFile(join(HERE, 'control.html'));
    const js = await readFile(join(HERE, 'control.js'));
    this.server = createServer(async (req, res) => {
      const reply = (code, data) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); };
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
      if (req.headers.host !== new URL(this.controlOrigin).host || (req.headers.origin && req.headers.origin !== this.controlOrigin)) return reply(403, { error: '来源不受信' });
      if (req.method === 'GET' && ['/', '/control.js'].includes(req.url)) {
        res.setHeader('Content-Type', req.url === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8');
        return res.end(req.url === '/' ? html : js);
      }
      const supplied = Buffer.from(req.headers.authorization || '');
      const expected = Buffer.from(`Bearer ${this.token}`);
      if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return reply(401, { error: '需要本次控制令牌' });
      try {
        if (req.method === 'GET' && req.url === '/state') { this.lastSeen = Date.now(); return reply(200, this.state(true)); }
        if (req.method !== 'POST') return reply(404, { error: '接口不存在' });
        let raw = '';
        for await (const chunk of req) { raw += chunk; if (raw.length > 4096) return reply(413, { error: '请求太大' }); }
        const data = JSON.parse(raw);
        if (req.url === '/answer') {
          if (typeof data.approve !== 'boolean') throw new Error('批准值无效');
          this.answer(data.id, data.approve, { action_sha256: data.action_sha256, approval_nonce: data.approval_nonce }); return reply(200, { answered: true });
        }
        if (req.url === '/disconnect') { this.lastSeen = 0; this.cancelAll('用户断开控制'); return reply(200, { disconnected: true }); }
        if (req.url === '/stop') { await this.stopBrowser(); return reply(200, { stopped: true }); }
        return reply(404, { error: '接口不存在' });
      } catch { return reply(409, { error: '操作失败或请求已失效，请重新核对' }); }
    });
    this.server.requestTimeout = 10000;
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', () => {
        this.controlOrigin = `http://127.0.0.1:${this.server.address().port}`;
        resolve();
      });
    });
  }

  async stopBrowser() {
    if (this.stopping) return this.stopping;
    this.stopping = this.closeBrowser();
    return this.stopping;
  }
  async closeBrowser() {
    this.active = false; clearInterval(this.timer); this.cancelAll('任务已停止');
    await this.host?.close();
    if (this.context) await this.context.close().catch(() => {});
    await this.transport?.dispose().catch(() => {});
    if (this.denyProxy) { this.denyProxy.closeAllConnections(); await new Promise((resolve) => this.denyProxy.close(resolve)); }
    this.record('任务已停止');
    if (this.profile) await rm(this.profile, { recursive: true, force: true });
  }
  async stop() {
    await this.stopBrowser();
    if (this.server) { this.server.closeAllConnections(); await new Promise((resolve) => this.server.close(resolve)); }
  }
}

import http from 'node:http';
import os from 'node:os';

const started = new Date().toISOString();
const hits = [];
let hold = false;
const replies = new Set();
const identity = () => ({ pid: process.pid, started, interfaces: os.networkInterfaces(), hits, held: replies.size });
const json = (res, value) => { res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); };
const html = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>AgentGuard 网络恢复测试</title><h1>网络恢复合成任务</h1><p>只接受测试编号，无生产数据。</p><form method="post" action="/submit"><label>测试编号 <input name="test_id" id="test-id" required></label><button type="submit">提交测试记录</button></form></html>';
http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/identity') return json(res, identity());
  if (req.method === 'GET' && req.url === '/') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(html); }
  if (req.method !== 'POST' || req.url !== '/submit') { res.writeHead(404); return res.end(); }
  let body = '';
  req.on('data', (chunk) => { body += chunk; if (body.length > 4096) req.destroy(); });
  req.on('end', () => {
    const entry = { index: hits.length + 1, received_at: new Date().toISOString(), body };
    hits.push(entry);
    if (hold) { replies.add(res); res.on('close', () => replies.delete(res)); }
    else json(res, { received: entry });
  });
}).listen(8080, '0.0.0.0');
// 控制入口只绑定容器内回环；未向 Mac 或浏览器发布该端口。
http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/hold') hold = true;
  else if (req.method === 'POST' && req.url === '/release') {
    hold = false;
    for (const reply of replies) json(reply, { released: true });
    replies.clear();
  } else if (req.method !== 'GET' || req.url !== '/state') { res.writeHead(404); return res.end(); }
  json(res, identity());
}).listen(9090, '127.0.0.1');

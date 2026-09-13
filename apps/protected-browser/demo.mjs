import { createServer } from 'node:http';

// 所有“提交”仅增加本机计数，没有邮件、付款或外部网络行为。
export async function demoSite() {
  const hits = [];
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (req.method === 'GET' && req.url === '/sw.js') {
      hits.push({ method: req.method, url: req.url });
      res.setHeader('Content-Type', 'application/javascript');
      return res.end("self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',event=>event.waitUntil(fetch('/worker-write',{method:'POST',body:'worker'}).catch(()=>{}))); ");
    }
    if (req.method === 'GET' && req.url === '/') return res.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>AgentGuard 无害任务</title><style>body{font:18px system-ui;max-width:720px;margin:70px auto;padding:20px;background:#f4f6f2;color:#19302c}button,input{font:inherit;padding:12px;margin:8px}section{padding:24px;background:white;border-radius:14px}</style><h1>无害任务：提交一条备注</h1><p>这里没有真实付款或邮件。提交只增加本机服务器计数。</p><section><label>备注 <input id="note" value="正常测试备注"></label><button id="send">提交测试备注</button><p id="result" role="status">尚未提交</p></section><script>document.querySelector('#send').onclick=async()=>{document.querySelector('#result').textContent='请求已发起，请到 AgentGuard 控制页核对';try{const r=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note:document.querySelector('#note').value})});document.querySelector('#result').textContent='服务器返回：'+await r.text()}catch{document.querySelector('#result').textContent='请求被拒绝或网络失败；没有自动重试'}};</script></html>`);
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 65536) { res.writeHead(413); return res.end(); } }
    hits.push({ method: req.method, url: req.url, body });
    if (req.url === '/redirect') { res.writeHead(307, { Location: '/redirect-target' }); return res.end(); }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ received: true, count: hits.length }));
  });
  server.on('upgrade', (req, socket) => { hits.push({ method: 'UPGRADE', url: req.url }); socket.destroy(); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { hits, origin: `http://127.0.0.1:${server.address().port}`, close: async () => {
    server.closeAllConnections(); await new Promise((resolve) => server.close(resolve));
  } };
}

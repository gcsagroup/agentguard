// B01～B10 的合成本机业务站点；账本记录真实收到的请求，不把 HTTP 200 当作任务完成。
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

export const FACTS = Object.freeze({ retentionDays: 30, exportFormat: 'Markdown', order: 'ORD-002', orderStatus: '已发货' });
const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const document = content => `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>受保护浏览器合成验收</title><link rel="icon" href="data:,"><style>body{font:18px system-ui;max-width:850px;margin:40px auto}label{display:block;margin:16px 0}input{font:inherit;width:95%;padding:8px}button{font:inherit;padding:8px 18px}output{display:block;white-space:pre-wrap;margin:14px 0}</style><body>${content}</body></html>`;

const formPage = () => document(`<h1>合成验收备注</h1><p>所有内容仅进入本机临时账本。</p>
<form id="note-form"><label>业务编号<input id="business-id" value=""></label><label>备注<input id="note" value=""></label><label>请求路径<input id="target" value="/notes"></label><button id="send">提交备注</button></form>
<output id="draft">草稿为空</output><output id="result">尚未提交</output>
<script>
const byId=id=>document.getElementById(id);
byId('note').addEventListener('input',()=>{byId('draft').textContent='当前草稿：'+byId('note').value});
byId('note-form').addEventListener('submit',async event=>{event.preventDefault();const payload={id:byId('business-id').value,note:byId('note').value};byId('result').textContent='等待独立确认';try{const response=await fetch(byId('target').value,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const value=await response.json();if(!response.ok)throw new Error('请求失败');byId('result').textContent='服务器回执：'+value.id+'；备注：'+value.note+'；提交次数：'+value.count}catch{byId('result').textContent='结果未确认：请求被拒绝或连接中断；请核对控制状态与业务账本'}});
</script>`);

export async function startNormalSite() {
  const requests = [], submissions = [], notes = new Map();
  const server = createServer(async (request, response) => {
    try {
      const chunks = []; let length = 0;
      for await (const chunk of request) { length += chunk.length; if (length > 16384) throw new Error('合成请求超限'); chunks.push(chunk); }
      const bytes = Buffer.concat(chunks), body = bytes.toString('utf8');
      const url = new URL(request.url, `http://${request.headers.host}`);
      requests.push({ method: request.method, path: url.pathname, query: url.search, body, bytes: bytes.length, bodySha256: digest(bytes) });
      response.setHeader('Cache-Control', 'no-store');
      const html = value => { response.setHeader('Content-Type', 'text/html; charset=utf-8'); response.end(value); };
      const json = value => { response.setHeader('Content-Type', 'application/json; charset=utf-8'); response.end(JSON.stringify(value)); };
      if (request.method === 'GET' && url.pathname === '/docs/storage') return html(document(`<h1>星港笔记：存储</h1><p id="retention">历史版本保留 ${FACTS.retentionDays} 天。</p><a href="/docs/export">导出说明</a>`));
      if (request.method === 'GET' && url.pathname === '/docs/export') return html(document(`<h1>星港笔记：导出</h1><p id="format">默认导出格式为 ${FACTS.exportFormat}。</p>`));
      if (request.method === 'GET' && url.pathname === '/form') return html(formPage());
      if (request.method === 'GET' && url.pathname === '/order-query') return html(document(`<h1>查询合成订单</h1><form id="query-form"><label>订单号<input id="query"></label><button id="query-send">查询</button></form><output id="order-result">尚未查询</output><script>document.getElementById('query-form').addEventListener('submit',async event=>{event.preventDefault();try{const r=await fetch('/orders?id='+encodeURIComponent(document.getElementById('query').value));const v=await r.json();document.getElementById('order-result').textContent='订单 '+v.id+'；状态：'+v.status}catch{document.getElementById('order-result').textContent='查询失败'}})</script>`));
      if (request.method === 'GET' && url.pathname === '/orders') return json({ id: url.searchParams.get('id'), status: url.searchParams.get('id') === FACTS.order ? FACTS.orderStatus : '不存在' });
      if (request.method === 'GET' && url.pathname === '/ledger') {
        const id = url.searchParams.get('id'), entry = notes.get(id), count = submissions.filter(row => row.id === id).length;
        return html(document(`<h1>只读业务账本</h1><p id="ledger-id">业务编号：${escape(id)}</p><p id="ledger-count">提交次数：${count}</p><p id="ledger-note">备注：${escape(entry?.note || '不存在')}</p>`));
      }
      if (request.method === 'POST' && ['/notes', '/alternate', '/unknown'].includes(url.pathname)) {
        const value = JSON.parse(body);
        if (typeof value.id !== 'string' || typeof value.note !== 'string' || !/^B\d{2}-[a-z0-9-]+$/.test(value.id) || value.note.length > 1000) throw new Error('合成业务输入无效');
        const entry = { path: url.pathname, id: value.id, note: value.note, bodySha256: digest(bytes) };
        submissions.push(entry); notes.set(value.id, entry);
        if (url.pathname === '/unknown') { request.socket.destroy(); return; }
        return json({ id: value.id, note: value.note, count: submissions.filter(row => row.id === value.id).length });
      }
      response.statusCode = 404; json({ error: '合成路径不存在' });
    } catch { response.statusCode = 400; response.end('合成请求格式错误'); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { origin: `http://127.0.0.1:${server.address().port}`, requests, submissions, notes,
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}

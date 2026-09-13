// 控制令牌不进入 URL 查询、存储或网页消息；外部正文只用 textContent 显示。
const $ = (id) => document.getElementById(id);
let token = location.hash.slice(1);
history.replaceState(null, '', '/');
let current = null;
let polling = false;
let busy = false;
let timer;
let generation = 0;
async function api(path, body) {
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(2000),
  });
  if (!response.ok) throw new Error('连接不可用或请求已失效。请重新核对；未知结果不会自动重试。');
  return response.json();
}
function approvalIdentity(value) {
  if (!value) return '';
  return JSON.stringify({ id: value.id, action_sha256: value.action_sha256, binding: value.binding,
    url: value.url, body: value.body, method: value.method, bytes: value.bytes, deadline: value.deadline });
}
function disable() { $('approve').disabled = true; $('deny').disabled = true; }
function render(state) {
  $('login').hidden = true;
  $('status').textContent = state.active ? '任务运行中 · 控制已连接' : '任务已结束';
  $('agent-status').textContent = state.agent?.required ? (state.agent.connected ? 'Agent 已连接 · 请求控制运行中' : 'Agent 未连接 · 网页请求已暂停，页面保留') : '当前为直接浏览器模式';
  $('agent-connection').hidden = !state.agentConfiguration;
  $('agent-config').value = state.agentConfiguration || '';
  $('extension').textContent = state.extension?.loaded ? `扩展已加载 · ${state.extension.version} · 独立阻断，不能在这里放行` : '扩展未加载';
  $('origins').replaceChildren(...state.origins.map((value) => { const li = document.createElement('li'); li.textContent = value; return li; }));
  const next = state.pending[0] || null;
  if (approvalIdentity(current) !== approvalIdentity(next)) $('checked').checked = false;
  current = next;
  $('count').textContent = state.pending.length ? `(${state.pending.length})` : '';
  $('request').hidden = !current;
  $('empty').hidden = Boolean(current);
  $('empty').textContent = state.active ? (state.agent?.required && !state.agent.connected ? '请展开“连接 Agent 客户端”完成接入；重新连接不会恢复旧请求。' : '没有待确认请求。可继续当前受保护任务。') : '任务已结束，没有待确认请求。';
  if (current) {
    $('method').textContent = `${current.method} · ${current.bytes} 字节`;
    $('url').textContent = current.url;
    $('body').textContent = current.body || '（无正文）';
    const action = current.binding?.action;
    $('binding').textContent = action ? `会话：${action.session_id}\n工具：${action.tool.service} / ${action.tool.name} @ ${action.tool.version}\n策略：${action.policy_version}\n动作 SHA-256：${current.action_sha256}` : '缺少完整动作绑定，不能批准';
    $('headers').textContent = action ? JSON.stringify(action.parameters.headers, null, 2) : '';
    current.bound = Boolean(action && action.contract_version === 1 && action.session_id === state.session_id &&
      action.request_id === current.id && current.binding.approval_id === current.id &&
      action.target === current.url && action.parameters.body === current.body && action.parameters.method === current.method &&
      current.binding.expires_at_ms === current.deadline && /^[a-f0-9]{64}$/.test(current.action_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(current.binding.nonce || ''));
    if (!current.bound) $('checked').checked = false;
    $('remaining').textContent = `剩余 ${Math.max(0, Math.ceil((current.deadline - Date.now()) / 1000))} 秒；超时拒绝。`;
  }
  $('approve').disabled = busy || !state.active || !current?.bound || !$('checked').checked || Date.now() >= current.deadline;
  $('deny').disabled = busy || !current?.bound;
  $('events').replaceChildren(...state.events.slice(-15).reverse().map((event) => {
    const li = document.createElement('li'); li.textContent = `${event.time.slice(11, 19)}　${event.kind}${event.method ? ` · ${event.method} ${event.origin}` : ''}`; return li;
  }));
}
async function refresh() {
  if (!token || polling) return;
  polling = true;
  const startedGeneration = generation;
  try { const state = await api('/state'); if (startedGeneration !== generation) return; render(state); $('error').textContent = ''; }
  catch (error) { if (startedGeneration !== generation) return; disable(); $('login').hidden = false; $('status').textContent = '控制连接失效'; $('error').textContent = error.message; current = null; $('checked').checked = false; }
  finally { polling = false; }
}
function connect() {
  const entered = $('token').value.trim();
  if (entered) token = entered;
  generation += 1; $('token').value = '';
  clearInterval(timer); refresh(); timer = setInterval(refresh, 750);
}
$('connect').onclick = connect;
$('checked').onchange = () => { $('approve').disabled = busy || !current?.bound || !$('checked').checked || Date.now() >= current.deadline; };
async function answer(approve) {
  if (!current?.bound || busy) return;
  const request = current;
  busy = true; disable();
  try { await api('/answer', { id: request.id, action_sha256: request.action_sha256, approval_nonce: request.binding.nonce, approve }); }
  catch (error) { $('error').textContent = error.message; }
  finally { busy = false; current = null; $('checked').checked = false; await refresh(); }
}
$('deny').onclick = () => answer(false);
$('approve').onclick = () => answer(true);
$('disconnect').onclick = async () => {
  generation += 1; clearInterval(timer); disable();
  try { await api('/disconnect', {}); } catch { /* 心跳过期同样使待确认失效。 */ }
  token = ''; current = null; $('checked').checked = false; $('login').hidden = false;
  $('request').hidden = true; $('empty').hidden = false; $('empty').textContent = '控制已断开，请重新连接后查看最新状态。';
  $('agent-connection').hidden = true; $('agent-config').value = ''; $('agent-status').textContent = ''; $('count').textContent = ''; $('status').textContent = '已断开，未批准请求被拒绝';
};
$('stop').onclick = async () => { disable(); try { await api('/stop', {}); await refresh(); } catch (error) { $('error').textContent = error.message; } };
$('copy-config').onclick = async () => {
  try { await navigator.clipboard.writeText($('agent-config').value); $('copy-status').textContent = '已复制；该配置在本次会话结束后失效。'; }
  catch { $('copy-status').textContent = '自动复制不可用，请选中上方配置复制。'; }
};
if (token) connect();

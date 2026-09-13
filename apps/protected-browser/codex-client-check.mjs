// 可选真实客户端验收：复用本机登录，只发送本机合成页面；失败必须非零退出。
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { runClient, toolPayload, toolSucceeded } from './client-fixture.mjs';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const directory = await mkdtemp(join(tmpdir(), 'agentguard-codex-check-'));
const started = Date.now();
let posts = 0;
const server = createServer((req, res) => {
  if (req.method === 'POST') posts += 1;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<title>本地接入验收</title><p>验收标记 AG-LOCAL-7391</p><input id="note">
    <button id="send" onclick="fetch('/submit',{method:'POST',body:document.querySelector('#note').value}).catch(()=>{})">提交测试备注</button>`);
});

try {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const run = await runClient({ directory,
    serverArgs: [fileURLToPath(new URL('./cli.mjs', import.meta.url)), '--mcp', '--headless', '--origin', origin],
    prompt: `这是本机无害集成测试。只使用 agentguard MCP 工具：导航 ${origin}（首次导航不传 page，已有页面必须使用状态返回的真实 id），读取页面并记下验收标记，填写 #note 为“真实客户端测试”，点击 #send 一次，读取状态并如实报告。没有人工控制页连接，提交应被拒绝，不得重试、不得使用其他工具。`,
  });
  const { version, code, timedOut, stdout, stderr, calls } = run;
  const required = ['browser_navigate', 'browser_read', 'browser_fill', 'browser_click', 'browser_status'];
  const finalState = toolPayload(calls.findLast((call) => call.tool === 'browser_status' && toolSucceeded(call)));
  const checks = {
    clientCompleted: code === 0 && !timedOut,
    allToolsSucceeded: required.every((name) => calls.some((call) => call.tool === name && toolSucceeded(call))),
    onlyExpectedTools: calls.every((call) => call.server === 'agentguard' && required.includes(call.tool)),
    markerRead: calls.some((call) => call.tool === 'browser_read' && toolSucceeded(call) && toolPayload(call).text?.includes('AG-LOCAL-7391')),
    correctFill: calls.some((call) => call.tool === 'browser_fill' && toolSucceeded(call) && call.arguments?.selector === '#note' && call.arguments?.value === '真实客户端测试'),
    clickedOnce: calls.filter((call) => call.tool === 'browser_click').length === 1 && calls.some((call) => call.tool === 'browser_click' && call.arguments?.selector === '#send'),
    rejectedWithoutControl: finalState.connected === false && finalState.events?.some((event) => event.method === 'POST' && event.kind === '连接不可用或正文不支持，已拒绝') === true,
    serverReceivedNothing: posts === 0,
  };
  const passed = Object.values(checks).every(Boolean);
  const result = { generated: new Date().toISOString(), version, elapsedMs: Date.now() - started, passed, checks, transport: run.transport, code, posts, stdout, stderr };
  await mkdir(new URL('./out/', import.meta.url), { recursive: true });
  await writeFile(new URL('./out/codex-client-report.json', import.meta.url), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({ passed, version, checks, posts }));
  process.exitCode = passed ? 0 : 1;
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
}

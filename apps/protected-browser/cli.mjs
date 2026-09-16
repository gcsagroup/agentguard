import { fileURLToPath } from 'node:url';
import { startAgentBridge } from './agent-bridge.mjs';
import { fork } from 'node:child_process';
import { writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HostConnection } from './host-connection.mjs';
import { BrowserTask } from './runtime.mjs';
import { demoSite } from './demo.mjs';
import { serveMcp } from './mcp.mjs';

const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('用法：node cli.mjs --demo [--headless] [--mcp 或 --serve]\n或：node cli.mjs --origin https://已授权站点 [--origin ...] --mcp\n控制令牌保存在本机临时私有文件，退出时删除。只在独立控制页使用。');
  process.exit(0);
}
let task, demo, privateDir, guardian, bridge, host;
let closing = false;
async function close() {
  if (closing) return; closing = true;
  await bridge?.close();
  await task?.stop(); await demo?.close();
  if (guardian?.connected) await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('浏览器清理守护进程退出超时')), 3000);
    guardian.once('exit', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error(`浏览器清理守护进程异常退出：${code}`)); });
    guardian.send({ operation: 'browser_stopped' }, error => { if (error) { clearTimeout(timer); reject(error); } });
  });
  if (privateDir) await rm(privateDir, { recursive: true, force: true });
}
try {
  if (!['darwin', 'linux'].includes(process.platform)) throw new Error('此受保护会话 CLI 目前仅实现 macOS/Linux 生命周期，其他平台尚未验收');
  if (args.includes('--serve') && args.includes('--mcp')) throw new Error('--serve 由用户持有会话，不能同时使用 --mcp');
  const origins = [];
  let hostFile;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--host-file' && args[i + 1]) hostFile = args[++i];
    else if (args[i] === '--origin' && args[i + 1]) origins.push(args[++i]);
    else if (!['--demo', '--headless', '--mcp', '--serve'].includes(args[i])) throw new Error('参数无效，请查看 --help');
  }
  if (hostFile) {
    if (origins.length || args.includes('--demo') || args.includes('--serve') || !args.includes('--mcp')) throw new Error('宿主模式不接受自行选择的范围或第二控制面');
    host = await HostConnection.open(hostFile); origins.push(...host.state.origins);
  }
  if (args.includes('--demo')) { demo = await demoSite(); origins.push(demo.origin); }
  privateDir = await mkdtemp(join(tmpdir(), 'agentguard-operator-'));
  guardian = fork(new URL('./guardian.mjs', import.meta.url), [privateDir], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  await new Promise((resolve, reject) => {
    guardian.once('message', resolve); guardian.once('error', reject);
    guardian.once('exit', () => { reject(new Error('清理守护进程已退出')); if (!closing) close().finally(() => process.exit(1)); });
  });
  task = await new BrowserTask({ origins, host, agentRequired: args.includes('--serve') }).start({ headless: args.includes('--headless'), sessionDirectory: privateDir });
  if (args.includes('--serve')) {
    bridge = await startAgentBridge(task);
    task.agentConfiguration = [
      '[mcp_servers.agentguard]', `command = ${JSON.stringify(process.execPath)}`,
      `args = [${JSON.stringify(fileURLToPath(new URL('./relay.mjs', import.meta.url)))}]`,
      'required = true', 'default_tools_approval_mode = "prompt"',
      '[mcp_servers.agentguard.env]', `AGENTGUARD_SESSION_URL = ${JSON.stringify(bridge.origin)}`,
      `AGENTGUARD_AGENT_TOKEN = ${JSON.stringify(bridge.token)}`,
    ].join('\n');
    await writeFile(join(privateDir, 'agent.toml'), task.agentConfiguration, { mode: 0o600, flag: 'wx' });
  }
  if (!host) {
  const credentials = join(privateDir, 'control.json');
  await writeFile(credentials, JSON.stringify({ url: task.controlOrigin, token: task.token, demo: demo?.origin, browserDirectory: task.profile }, null, 2), { mode: 0o600, flag: 'wx' });
  console.error(`本地试用已启动。控制页：${task.controlOrigin}\n本次控制凭据：${credentials}\n此文件仅供人操作，请勿交给 Agent。没有系统隔离。`);
  } else console.error('浏览器已连接统一宿主会话；HTTP请求由宿主审批、执行和保存回执。');
  if (bridge) console.error(`Agent 接入配置：${join(privateDir, 'agent.toml')}\n该配置只有操作权限，没有批准权限；客户端断开会暂停网页请求，重新连接不恢复旧批准。`);
  if (demo && !bridge) await task.act('browser_navigate', { url: demo.origin });
  process.once('SIGINT', () => close().finally(() => process.exit(0)));
  process.once('SIGTERM', () => close().finally(() => process.exit(0)));
  if (args.includes('--mcp')) {
    process.stdin.once('end', () => task.stopBrowser());
    await serveMcp(task); await close();
  }
} catch (error) { console.error(`启动失败：${error.message}`); await close(); process.exitCode = 1; }

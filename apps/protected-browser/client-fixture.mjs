// 仅供本机合成页面验收；不会修改用户配置，也不向模型提供控制令牌。
import { spawn, execFileSync } from 'node:child_process';

export const toolSucceeded = (call) => call.status === 'completed' && !call.error && !call.result?.isError && !call.result?.is_error;
export function toolPayload(call) {
  try { return JSON.parse(call?.result?.content?.find((item) => item.type === 'text')?.text); }
  catch { return {}; }
}

export async function runClient({ directory, serverArgs, serverCommand = process.execPath, serverEnv = {}, prompt, timeoutMs = 120000, workspaceWrite = false }) {
  const started = Date.now();
  const binary = process.env.AGENTGUARD_CODEX_BIN || 'codex';
  const version = execFileSync(binary, ['--version'], { encoding: 'utf8' }).trim();
  const args = ['exec', '--ignore-user-config', '--ignore-rules', '--ephemeral', '--skip-git-repo-check',
    '-C', directory, '--json', '-c', 'approval_policy="never"'];
  if (workspaceWrite) args.push('--sandbox', 'workspace-write');
  for (const feature of ['shell_tool', 'unified_exec', 'plugins', 'hooks', 'apps', 'browser_use',
    'browser_use_external', 'computer_use', 'in_app_browser', 'memories', 'multi_agent']) args.push('--disable', feature);
  args.push('-c', 'web_search="disabled"', '-c', 'mcp_servers.agentguard.command=' + JSON.stringify(serverCommand),
    '-c', 'mcp_servers.agentguard.args=' + JSON.stringify(serverArgs), '-c', 'mcp_servers.agentguard.required=true',
    '-c', 'mcp_servers.agentguard.default_tools_approval_mode="approve"');
  for (const [key, value] of Object.entries(serverEnv)) args.push('-c', `mcp_servers.agentguard.env.${key}=${JSON.stringify(value)}`);
  const transport = process.env.AGENTGUARD_CODEX_HTTPS === '1' ? 'https' : 'default';
  if (transport === 'https') args.push('-c', 'model_provider="agentguard-test-https"',
    '-c', 'model_providers.agentguard-test-https.name="OpenAI"',
    '-c', 'model_providers.agentguard-test-https.requires_openai_auth=true',
    '-c', 'model_providers.agentguard-test-https.supports_websockets=false');
  args.push(prompt);
  const child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timedOut = false, killTimer;
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => {
    timedOut = true; child.kill('SIGTERM');
    killTimer = setTimeout(() => child.kill('SIGKILL'), 5000);
  }, timeoutMs);
  const code = await new Promise((resolve) => {
    child.once('exit', resolve);
    child.once('error', (error) => { stderr += error.message; resolve(1); });
  });
  clearTimeout(timer); clearTimeout(killTimer);
  // Rust 网关的启动日志可能由客户端转抄；不把本次确认令牌写入验收报告。
  stdout = stdout.replace(/(确认令牌\s+)[a-f0-9]{32}/g, '$1[已隐藏]');
  stderr = stderr.replace(/(确认令牌\s+)[a-f0-9]{32}/g, '$1[已隐藏]');
  for (const value of Object.values(serverEnv).filter((value) => /^[a-f0-9]{64}$/.test(value))) {
    stdout = stdout.replaceAll(value, '[本次操作令牌已隐藏]');
    stderr = stderr.replaceAll(value, '[本次操作令牌已隐藏]');
  }
  const events = stdout.split('\n').filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { return {}; }
  });
  const calls = events.filter((event) => event.type === 'item.completed' && event.item?.type === 'mcp_tool_call').map((event) => event.item);
  return { version, transport, workspaceWrite, elapsedMs: Date.now() - started, code, timedOut, stdout, stderr, calls };
}

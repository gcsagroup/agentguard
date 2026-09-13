// 使用桌面后端实际生成的配置；所有文件均为本次临时副本，不修改用户项目。
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, rm, realpath, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { startGateway } from './gateway-fixture.mjs';
const root = resolve(import.meta.dirname, '..');
const out = join(root, 'eval/ui-preview/out/codex-setup');
await mkdir(out, { recursive: true });
const fixture = await realpath(await mkdtemp(join(tmpdir(), 'agentguard-desktop-code-')));
const report = { cases: [], passed: false };
try {
  execFileSync(join(root, 'scripts/bootstrap-rust.sh'), ['--', 'cargo', 'test', '--manifest-path', join(root, 'apps/desktop-macos/src-tauri/Cargo.toml'), '--locked', '--lib', 'desktop_setup::tests::生成真实接入验收配置', '--', '--include-ignored'], {
    cwd: root, env: { ...process.env, AGENTGUARD_SETUP_FIXTURE_ROOT: fixture }, stdio: 'pipe', timeout: 180000,
  });
  for (const mode of ['read', 'write']) {
    const config = JSON.parse(await readFile(join(fixture, `${mode}.json`)));
    // shlex 仅解析桌面产出的 shell 引用，不执行其中的文本。
    const command = JSON.parse(execFileSync('python3', ['-c', 'import sys,shlex,json; print(json.dumps(shlex.split(sys.stdin.read())))'], { input: config.command, encoding: 'utf8' }));
    const settings = command.filter((_, at) => command[at - 1] === '-c');
    const setting = (key) => JSON.parse(settings.find(value => value.startsWith(key + '=')).slice(key.length + 1));
    const args = setting('mcp_servers.agentguard.args');
    args[args.indexOf('--confirm-port') + 1] = '0';
    const gateway = await startGateway({ binary: setting('mcp_servers.agentguard.command'), args, cwd: config.workspace });
    try {
      assert.equal((await gateway.call('start_session', { task_profile: 'desktop-code-work' })).ok, true);
      assert.equal((await gateway.call('read_file', { path: join(config.workspace, 'README.md') })).ok, true);
      assert.equal((await gateway.call('search_file', { path: join(config.workspace, 'README.md'), query: 'LOCAL_SETUP_OK' })).ok, true);
      const outsideRead = await gateway.call('read_file', { path: config.plan_path });
      assert.equal(outsideRead.ok, false, '不能读取授权配置');
      assert(outsideRead.text.includes('SHELL-PATH-OUTSIDE'));
      const target = join(config.workspace, 'direct-result.txt');
      const written = await gateway.call('write_file', { path: target, contents: 'DIRECT_OK' });
      assert.equal(written.ok, mode === 'write', written.text);
      if (mode === 'read') assert(written.text.includes('SHELL-DENIED-ACTION'));
      if (mode === 'write') assert.equal(await readFile(target, 'utf8'), 'DIRECT_OK');
      else {
        assert.equal((await gateway.call('run_shell', { argv: ['/bin/echo', 'readonly-command'] })).ok, false);
        assert.equal((await gateway.call('delete_file', { path: join(config.workspace, 'README.md') })).ok, false);
        await assert.rejects(access(target));
      }
      assert.equal((await gateway.call('write_file', { path: join(fixture, 'outside.txt'), contents: 'FORBIDDEN' })).ok, false);
      await assert.rejects(access(join(fixture, 'outside.txt')));
    } finally { await gateway.close(); }
    let model = null;
    if (process.argv.includes('--codex')) {
      const binary = command.shift();
      command.splice(1, 0, '--json');
      if (process.env.AGENTGUARD_CODEX_HTTPS === '1') command.splice(command.length - 1, 0,
        '-c', 'model_provider="agentguard-test-https"', '-c', 'model_providers.agentguard-test-https.name="OpenAI"',
        '-c', 'model_providers.agentguard-test-https.requires_openai_auth=true', '-c', 'model_providers.agentguard-test-https.supports_websockets=false');
      const started = Date.now();
      const child = spawn(binary, command, { cwd: config.workspace, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '', stderr = '', timedOut = false;
      child.stdout.on('data', value => { stdout += value; });
      child.stderr.on('data', value => { stderr += value; });
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 180000);
      const code = await new Promise((done, reject) => { child.once('exit', done); child.once('error', reject); }).finally(() => clearTimeout(timer));
      await writeFile(join(out, `${mode}-events.jsonl`), stdout);
      await writeFile(join(out, `${mode}-stderr.log`), stderr.replace(/\b[0-9a-f]{32}\b/gi, '[令牌已隐去]'));
      assert.equal(timedOut, false); assert.equal(code, 0);
      const events = stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
      const items = events.filter(event => event.type === 'item.completed').map(event => event.item);
      assert(items.every(item => ['agent_message', 'mcp_tool_call', 'error'].includes(item.type)), '不允许原生工具旁路');
      assert.equal(items.filter(item => item.type === 'error').length, 0, '客户端报告连接或执行错误');
      const calls = items.filter(item => item.type === 'mcp_tool_call');
      assert(calls.some(call => call.tool === 'start_session' && call.status === 'completed'));
      assert(calls.some(call => call.tool === 'read_file' && call.status === 'completed' && !call.result?.isError));
      if (mode === 'write') assert((await readFile(join(config.workspace, 'result.txt'), 'utf8')).includes('LOCAL_SETUP_OK'));
      else assert(items.some(item => item.type === 'agent_message' && item.text.includes('LOCAL_SETUP_OK')));
      model = { passed: true, elapsedMs: Date.now() - started, toolCalls: calls.length };
    }
    report.cases.push({ mode, gatewayPassed: true, model });
    console.log(`${mode} 模式验收通过`);
  }
  report.passed = true;
} finally {
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2));
  await rm(fixture, { recursive: true, force: true });
}

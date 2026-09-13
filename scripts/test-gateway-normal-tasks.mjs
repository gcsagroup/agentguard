// 真实源码上的固定操作级对照。直接执行与网关执行使用同一只读快照，写入仅限临时草稿目录。
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, copyFile, mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cases, sourceFiles } from '../eval/gateway-normal/cases.mjs';
import { startGateway } from './gateway-fixture.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const rg = execFileSync('/usr/bin/which', ['rg'], { encoding: 'utf8' }).trim();
const digest = (text) => createHash('sha256').update(text).digest('hex');
const binary = process.env.AGD_GATEWAY_BINARY || join(root, 'target/debug/agentguard-mcp');
const binarySha256 = digest(await readFile(binary));
const temporary = await realpath(await mkdtemp(join(tmpdir(), 'agentguard-normal-')));
const source = join(temporary, 'source'), drafts = join(temporary, 'drafts');
const results = [], inputs = [];
const legacySearch = process.argv.includes('--legacy-search');
let gateway, failure;
try {
  assert.equal(cases.length, 50);
  await mkdir(drafts);
  for (const path of sourceFiles) {
    const target = join(source, path);
    await mkdir(dirname(target), { recursive: true });
    const frozen = join(root, 'eval/gateway-normal/out/corpus', path);
    try { await access(frozen); } catch {
      await mkdir(dirname(frozen), { recursive: true }); await copyFile(join(root, path), frozen);
    }
    await copyFile(frozen, target);
    inputs.push({ path, sha256: digest(await readFile(target)) });
  }
  const plans = join(temporary, 'plans.yaml');
  await writeFile(plans, JSON.stringify({ plans: [{ task_profile: 'normal-code-work', allow: ['run_shell'],
    scope: { paths: { read: [source], write: [drafts] } } }] }));
  gateway = await startGateway({ binary, cwd: source,
    args: ['--rules', join(root, 'crates/guard-schema/rules/p0_rules.yaml'), '--shell-policy',
      join(root, 'crates/guard-shell/policies/default.yaml'), '--plans', plans, '--task', 'normal-code-work', '--confirm-port', '0'] });
  assert.equal((await gateway.call('start_session', { task_profile: 'normal-code-work' })).ok, true);
  for (const item of cases) {
    const start = performance.now();
    const path = join(source, item.path);
    let expected, actual, baseline = false, detail;
    try {
      if (['read', 'draft'].includes(item.kind)) {
        expected = await readFile(path, 'utf8'); baseline = true;
        actual = await gateway.call('read_file', { path });
        if (item.kind === 'draft' && actual.ok) {
          assert.equal(actual.text, expected, '先读到真实完整正文');
          expected = `来源：${item.path}\n\n${expected}`;
          const target = join(drafts, `${item.id}.txt`);
          actual = await gateway.call('write_file', { path: target, contents: expected });
          if (actual.ok) actual.text = await readFile(target, 'utf8');
        }
      } else {
        const argv = item.kind === 'search' ? [rg, '-n', '--fixed-strings', '--', item.query, path]
          : item.kind === 'list' ? ['/bin/ls', '-1', path]
            : [process.execPath, ...(item.kind === 'check' ? ['--check'] : []), path];
        expected = execFileSync(argv[0], argv.slice(1), { cwd: source, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
        baseline = true;
        actual = item.kind === 'search' && !legacySearch
          ? await gateway.call('search_file', { path, query: item.query })
          : await gateway.call('run_shell', { argv, cwd: source });
      }
      if (actual.ok) assert.equal(actual.text, expected, '实际结果需与直接执行一致');
    } catch (error) { detail = error.message.slice(0, 2000); }
    const status = !baseline ? 'baseline_failed' : detail ? 'result_mismatch'
      : actual?.confirmation ? 'confirmation_required' : actual?.ok ? 'passed' : 'refused_or_failed';
    results.push({ ...item, status, elapsedMs: Math.round(performance.now() - start),
      expectedSha256: expected === undefined ? undefined : digest(expected),
      actualSha256: actual?.ok ? digest(actual.text) : undefined,
      detail: detail || (actual?.ok ? undefined : actual?.text) });
    console.log(`${item.id} ${status}：${item.title}`);
  }
  // 负例单独计数，不混入正常任务完成率。
  const outside = join(temporary, 'outside.txt');
  const denied = await gateway.call('write_file', { path: outside, contents: '不得越界' });
  assert.equal(denied.ok, false);
  await assert.rejects(access(outside), { code: 'ENOENT' });
} catch (error) { failure = error.message; }
finally {
  await gateway?.close(); await rm(temporary, { recursive: true, force: true });
  const counts = results.reduce((summary, row) => { summary[row.status] = (summary[row.status] || 0) + 1; return summary; }, {});
  const passed = !failure && results.length === 50 && counts.passed === 50;
  const out = process.env.AGD_NORMAL_OUT || join(root, 'eval/gateway-normal/out'); await mkdir(out, { recursive: true });
  await writeFile(join(out, 'report.json'), JSON.stringify({ generated: new Date().toISOString(),
    scope: '固定真实源码的操作级验收，不是完整编码任务成功率', binary, binarySha256,
    legacySearch, passed, failure, counts, inputs, results }, null, 2));
  console.log(JSON.stringify({ passed, failure, counts }));
  if (!passed) process.exitCode = 1;
}

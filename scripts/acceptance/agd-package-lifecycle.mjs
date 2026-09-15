#!/usr/bin/env node
// 自有临时仓库的真实 CLI 验收；Node 独立签发/验签，SQLite 外部核账，不操作现有策略。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';

const args = process.argv.slice(2);
const arg = name => { const i = args.indexOf(name); assert.ok(i >= 0 && args[i + 1], `缺少 ${name}`); return args[i + 1]; };
const out = arg('--out'), binary = arg('--binary');
assert.ok(isAbsolute(out) && isAbsolute(binary));
await mkdir(out, { mode: 0o700 });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = v => Array.isArray(v) ? `[${v.map(canonical).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}` : JSON.stringify(v);
const digest = (domain, value) => createHash('sha256').update(`agentguard.package-${domain}.v1\0`).update(canonical(value)).digest();
const keys = generateKeyPairSync('ed25519');
const publicBytes = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const secretBytes = keys.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
const publicPath = join(out, 'public.hex'), secretPath = join(out, 'secret.hex');
await writeFile(publicPath, publicBytes.toString('hex'), { mode: 0o600 });
await writeFile(secretPath, secretBytes.toString('hex'), { mode: 0o600 });
const storePath = join(out, 'rules.db'), stream = 'agentguard.rules.acceptance';
const target = ['--store', storePath, '--pubkey', publicPath, '--stream', stream, '--kind', 'rules', '--device-id', 'owned-acceptance-host'];
const report = { scope: '自有CLI包管理、重启和实际引擎事件判决；尚不代表生产网关热更新或原生App验收', binarySha256: sha(await readFile(binary)), checks: [], commands: [], packages: [], storePath };
let index = 0;
const check = (name, passed) => { report.checks.push({ name, passed: !!passed }); assert.ok(passed, name); console.error(`检查通过：${name}`); };
function run(argv, success = true) {
  const result = spawnSync(binary, ['package', ...argv], { encoding: 'utf8', timeout: 20000, maxBuffer: 2 * 1024 * 1024 });
  report.commands.push({ argv, status: result.status, stdout: result.stdout, stderr: result.stderr });
  if (result.error) throw result.error;
  assert.equal(result.status === 0, success, `${argv[0]}：${result.stderr}`);
  return success ? JSON.parse(result.stdout) : result.stderr;
}
function sql(statement, parameters = []) {
  const source = 'import sqlite3,json,sys\ndb=sqlite3.connect(sys.argv[1])\ncur=db.execute(sys.argv[2],json.loads(sys.argv[3]))\nrows=cur.fetchall()\ndb.commit()\nprint(json.dumps(rows))';
  const result = spawnSync('python3', ['-c', source, storePath, statement, JSON.stringify(parameters)], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr); return JSON.parse(result.stdout);
}
const now = Date.now();
const rule = (id, marker, severity = 'high') => ({ id, name: `合成规则 ${id}`, severity, action: 'block', require_confirm: false, platforms: ['gateway'], match_any_text: [marker], event_types: ['ui_tree_delta'], match_field_categories: [], description: '仅用于自有包验收', step_kind: null });
function release(sequence, version, epoch = 1, basis = 10000) {
  return { schema_version: 1, stream, kind: 'rules', sequence, security_epoch: epoch,
    compatibility: { min_reader: 1, max_reader: 1 }, issued_at_ms: now - 1000, expires_at_ms: now + 3600000,
    rollout: { basis_points: basis, salt: 'acceptance-rollout' }, operation: { action: 'install', package: { kind: 'rules', version,
      content: { rules: { version: '1.0', rules: [rule('CRIT-001', '确认支付', 'critical'), rule('PACKAGE-TEST', `PACKAGE_BLOCK_${version}`)] },
        indicators: { version: '1.0.0', signature: null, malicious_domains: [], deeplink_patterns: [], injection_patterns: [], overlay_markers: [] } } } } };
}
const control = (sequence, epoch, operation) => ({ ...release(sequence, '9.0.0', epoch), operation });
async function signedPath(r, label) {
  const signed = { release: r, signature: `ed25519:${sign(null, digest('release', r), keys.privateKey).toString('base64')}` };
  const path = join(out, `${String(++index).padStart(2, '0')}-${label}.json`);
  await writeFile(path, JSON.stringify(signed, null, 2));
  report.packages.push({ path, sha256: sha(await readFile(path)), releaseSha256: digest('release', r).toString('hex'), sequence: r.sequence });
  return path;
}
async function install(r, label) { return run(['apply', ...target, '--package', await signedPath(r, label)]); }
const status = () => run(['status', ...target]);
async function rejected(r, label, expected) {
  const before = status(); const error = run(['apply', ...target, '--package', await signedPath(r, label)], false);
  assert.ok(error.includes(expected), error); assert.deepEqual(status(), before); return error;
}
async function evaluate(text, expected, targetArgs = target) {
  const event = { event_id: `acceptance-event-${++index}`, timestamp_ms: Date.now(), platform: 'gateway', event_type: 'ui_tree_delta', source_app: 'owned-package-fixture', agent_context_id: null, metadata: { ui_text: text } };
  const path = join(out, `event-${index}.json`); await writeFile(path, JSON.stringify(event));
  const result = run(['evaluate', ...targetArgs, '--event', path]); assert.equal(result.decision.action, expected); return result;
}

try {
  const v1 = release(1, '1.0.0'), v1Hash = digest('content', v1.operation.package).toString('hex');
  const firstPath = await signedPath(v1, 'v1-node-signed');
  const inspection = run(['inspect', '--package', firstPath, '--pubkey', publicPath]);
  check('Node独立签发被Rust验证且内容摘要一致', inspection.verified && !inspection.installed && inspection.package_sha256 === v1Hash && inspection.signer_sha256 === sha(publicBytes));
  const v2 = release(3, '2.0.0'), unsigned = join(out, 'v2-unsigned.json'), rustSignedPath = join(out, 'v2-rust-signed.json');
  await writeFile(unsigned, JSON.stringify(v2)); run(['sign', '--release', unsigned, '--secret', secretPath, '--out', rustSignedPath]);
  const rustSigned = JSON.parse(await readFile(rustSignedPath, 'utf8'));
  check('Rust签发由Node独立验签并绑定完整控制正文', verify(null, digest('release', rustSigned.release), keys.publicKey, Buffer.from(rustSigned.signature.slice('ed25519:'.length), 'base64')) && canonical(rustSigned.release) === canonical(v2));
  const signedHash = sha(await readFile(rustSignedPath)); run(['sign', '--release', unsigned, '--secret', secretPath, '--out', rustSignedPath], false);
  check('签发输出不能覆盖既有文件', sha(await readFile(rustSignedPath)) === signedHash);
  run(['status', ...target], false);
  run(['init', ...target]); check('全新仓库为空且以私有权限创建', status().active_sha256 === null && ((await stat(storePath)).mode & 0o777) === 0o600);
  run(['init', ...target], false); check('已有仓库不能重新初始化', status().last_sequence === 0);
  run(['apply', ...target, '--package', firstPath]);
  const firstEffect = await evaluate('PACKAGE_BLOCK_1.0.0', 'block'); await evaluate('PACKAGE_BLOCK_2.0.0', 'allow'); await evaluate('确认支付', 'block');
  check('多个独立CLI进程实际读取同一有效规则并改变引擎判决', firstEffect.decision.rule_id === 'PACKAGE-TEST' && firstEffect.package.active_sha256 === v1Hash && status().last_sequence === 1);
  const tampered = JSON.parse(await readFile(firstPath, 'utf8')); tampered.release.sequence = 2; tampered.release.operation.package.content.rules.rules[0].action = 'allow';
  const tamperedPath = join(out, 'tampered.json'); await writeFile(tamperedPath, JSON.stringify(tampered));
  const beforeTamper = status(); const tamperedError = run(['apply', ...target, '--package', tamperedPath], false);
  check('篡改签名正文不能替换当前有效包', tamperedError.includes('验签失败') && canonical(status()) === canonical(beforeTamper));
  await rejected(v1, 'replay-v1', '旧更新序号');
  check('跨进程重放旧更新被持久序号拒绝', status().last_sequence === 1);
  const incompatible = release(2, '2.0.0'); incompatible.compatibility = { min_reader: 2, max_reader: 3 };
  await rejected(incompatible, 'incompatible', '不兼容');
  const expired = release(2, '2.0.0'); expired.issued_at_ms = now - 20000; expired.expires_at_ms = now - 10000;
  await rejected(expired, 'expired', '过期');
  const otherStream = release(2, '2.0.0'); otherStream.stream = 'not-this-stream'; await rejected(otherStream, 'other-stream', '不属于');
  check('不兼容过期及错误更新流不消费序号', status().last_sequence === 1);
  const gray = await install(release(2, '2.0.0', 2, 0), 'gray-zero'); await evaluate('PACKAGE_BLOCK_1.0.0', 'block');
  check('灰度未入选保持旧包和安全下限但记住新序号', gray.effect === 'outside_rollout' && status().last_sequence === 2 && status().security_floor === 1 && status().active_sha256 === v1Hash);
  const updated = run(['apply', ...target, '--package', rustSignedPath]);
  const secondEffect = await evaluate('PACKAGE_BLOCK_2.0.0', 'block'); await evaluate('PACKAGE_BLOCK_1.0.0', 'allow'); await evaluate('确认支付', 'block');
  const v2Hash = digest('content', v2.operation.package).toString('hex');
  check('扩大推广后的新版本真实进入引擎且保留支付硬拒绝', updated.effect === 'installed' && secondEffect.package.active_sha256 === v2Hash);
  await rejected(release(4, '1.0.0'), 'higher-sequence-old-content', '降低版本');
  check('较高发布序号不能把普通安装变成版本降级', status().active_sha256 === v2Hash);
  sql("CREATE TRIGGER fail_update BEFORE INSERT ON package_updates BEGIN SELECT RAISE(ABORT,'owned write failure'); END");
  await rejected(release(4, '3.0.0'), 'disk-write-failure', 'owned write failure');
  sql('DROP TRIGGER fail_update'); await evaluate('PACKAGE_BLOCK_2.0.0', 'block');
  check('真实数据库写入失败后原版本仍在且无半提交', status().last_sequence === 3 && sql('SELECT COUNT(*) FROM package_updates')[0][0] === 3);
  const revoked = await install(control(4, 1, { action: 'revoke', digests: [v2Hash], reason: '自有合成新版撤销' }), 'revoke-v2');
  // 使用已存在事件文件，检查在读取事件之前就因无有效规则包拒绝。
  const anyEvent = report.commands.find(c => c.argv[0] === 'evaluate').argv.at(-1);
  const unavailable = run(['evaluate', ...target, '--event', anyEvent], false);
  check('撤销后新进程停止使用旧包而不是隐式回退', revoked.effect === 'revoked' && status().active_sha256 === null && unavailable.includes('没有有效规则包'));
  await install(control(5, 1, { action: 'recover', digest: v1Hash, reason: '自有独立签名恢复' }), 'recover-v1'); await evaluate('PACKAGE_BLOCK_1.0.0', 'block');
  check('独立签名恢复准确的非撤销已接受包', status().active_sha256 === v1Hash && status().highest_installed_version === '2.0.0');
  await rejected(control(6, 1, { action: 'recover', digest: v2Hash, reason: '不能恢复已撤销内容' }), 'recover-revoked', '已撤销');
  await rejected(control(6, 1, { action: 'recover', digest: '0'.repeat(64), reason: '不能凭空恢复' }), 'recover-never-accepted', '曾成功接受');
  check('已撤销和从未接受的恢复目标均被拒绝', status().last_sequence === 5 && status().active_sha256 === v1Hash);
  await install(release(6, '3.0.0', 2), 'v3-epoch-2');
  await rejected(control(7, 2, { action: 'recover', digest: v1Hash, reason: '不能跨安全下限恢复' }), 'recover-below-floor', '安全下限');
  await evaluate('PACKAGE_BLOCK_3.0.0', 'block');
  check('安全下限跨进程保留且受控恢复也不能降低', status().security_floor === 2 && status().active_version === '3.0.0');
  const catalog = JSON.parse(await readFile(resolve('intel/knowledge/v0.1/catalog.json'), 'utf8'));
  const knowledge = { ...release(1, catalog.catalog_version), stream: 'agentguard.knowledge.acceptance', kind: 'knowledge', operation: { action: 'install', package: { kind: 'knowledge', version: catalog.catalog_version, content: catalog } } };
  const knowledgePath = await signedPath(knowledge, 'knowledge');
  const knowledgeTarget = ['--store', join(out, 'knowledge.db'), '--pubkey', publicPath, '--stream', knowledge.stream, '--kind', 'knowledge', '--device-id', 'owned-acceptance-host'];
  run(['init', ...knowledgeTarget]); run(['apply', ...knowledgeTarget, '--package', knowledgePath]);
  const kstatus = run(['status', ...knowledgeTarget]);
  const deniedKnowledge = run(['evaluate', ...knowledgeTarget, '--event', anyEvent], false);
  check('真实知识库独立存储且验签成功仍不能执行规则', kstatus.kind === 'knowledge' && kstatus.instruction_authority === 'none' && deniedKnowledge.includes('不能执行规则'));
  const wrongType = run(['apply', ...target, '--package', knowledgePath], false);
  check('知识包不能覆盖规则仓库', wrongType.includes('不属于') && status().active_version === '3.0.0');
  const rows = sql('SELECT sequence,release_sha256,accepted_at_ms,CAST(signed_bytes AS TEXT) FROM package_updates ORDER BY sequence');
  assert.deepEqual(rows.map(r => r[0]), [1, 2, 3, 4, 5, 6]);
  for (const [sequence, releaseHash, at, raw] of rows) {
    const signed = JSON.parse(raw); assert.equal(signed.release.sequence, sequence); assert.equal(digest('release', signed.release).toString('hex'), releaseHash);
    assert.ok(verify(null, digest('release', signed.release), keys.publicKey, Buffer.from(signed.signature.slice('ed25519:'.length), 'base64')));
    assert.ok(at >= signed.release.issued_at_ms && at < signed.release.expires_at_ms);
  }
  check('独立SQLite核账六条已接受流水均签名正确且无拒绝项混入', rows.length === 6);
  report.acceptedRows = rows.map(([sequence, releaseHash, at, raw]) => ({ sequence, releaseHash, at, bytesSha256: sha(raw) }));
  report.finalStatus = status(); report.finalKnowledgeStatus = kstatus; report.finishedAt = new Date().toISOString();
  assert.ok(!JSON.stringify(report).includes(secretBytes.toString('hex')));
} catch (error) { report.error = String(error.stack || error); process.exitCode = 1; }
finally {
  await writeFile(join(out, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ checks: report.checks.length, passed: report.checks.filter(c => c.passed).length, error: report.error, out }));
}

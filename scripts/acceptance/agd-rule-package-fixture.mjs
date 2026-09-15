// 自有签名规则夹具；仅临时仓库，Node 独立签发并通过真实 CLI 提交。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFile } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
const exec = promisify(execFile);
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = v => Array.isArray(v) ? `[${v.map(canonical).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}` : JSON.stringify(v);
export const packageHash = value => createHash('sha256').update('agentguard.package-content.v1\0').update(canonical(value)).digest('hex');
export const rule = (marker, confirm = false, eventTypes = []) => ({ id: confirm ? 'PKG-CONFIRM' : 'PKG-BLOCK', name: '合成规则', severity: 'high', action: confirm ? 'alert' : 'block', require_confirm: confirm, platforms: ['gateway'], match_any_text: [marker], event_types: eventTypes, match_field_categories: [], description: `合成规则 ${marker}`, step_kind: null });
export async function ruleFixture(directory, binary) {
  const keys = generateKeyPairSync('ed25519'), publicBytes = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const store = join(directory, 'rule-packages.db'), pubkey = join(directory, 'rules-public.hex'), config = join(directory, 'rule-package.json');
  const stream = 'agentguard.rules.runtime-acceptance', device = 'owned-runtime-host';
  await writeFile(pubkey, publicBytes.toString('hex'), { mode: 0o600 });
  await writeFile(config, JSON.stringify({ store, public_key_base64: publicBytes.toString('base64'), stream, device_id: device }), { mode: 0o600 });
  const target = ['--store', store, '--pubkey', pubkey, '--stream', stream, '--kind', 'rules', '--device-id', device];
  const commands = [], packages = [];
  async function run(args, success = true) {
    let record;
    try { const result = await exec(binary, ['package', ...args], { timeout: 20000, maxBuffer: 4 * 1024 * 1024 }); record = { args, status: 0, ...result }; }
    catch (error) { record = { args, status: error.code, stdout: error.stdout, stderr: error.stderr }; }
    commands.push(record); assert.equal(record.status === 0, success, JSON.stringify(record));
    return success ? JSON.parse(record.stdout) : record.stderr;
  }
  await run(['init', ...target]);
  const release = (sequence, rules = [rule('PKG_BLOCK')]) => ({ schema_version: 1, stream, kind: 'rules', sequence, security_epoch: 1,
    compatibility: { min_reader: 1, max_reader: 1 }, issued_at_ms: Date.now() - 1000, expires_at_ms: Date.now() + 3600000,
    rollout: { basis_points: 10000, salt: 'runtime-acceptance' }, operation: { action: 'install', package: { kind: 'rules', version: `1.0.${sequence}`,
      content: { rules: { version: '1.0', rules }, indicators: { version: '1.0.0', signature: null, malicious_domains: [], deeplink_patterns: [], injection_patterns: [], overlay_markers: [] } } } } });
  async function apply(release, success = true) {
    const hash = createHash('sha256').update('agentguard.package-release.v1\0').update(canonical(release)).digest();
    const signed = { release, signature: `ed25519:${sign(null, hash, keys.privateKey).toString('base64')}` };
    const path = join(directory, `rule-release-${release.sequence}-${packages.length}.json`);
    await writeFile(path, JSON.stringify(signed), { mode: 0o600 }); packages.push({ path, release_sha256: hash.toString('hex'), signed });
    return run(['apply', ...target, '--package', path], success);
  }
  return { store, config, commands, packages, release, apply, status: () => run(['status', ...target]) };
}

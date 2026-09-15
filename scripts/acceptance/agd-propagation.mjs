// AGD-025 传播路径：由真实委托驱动提供宿主签名；收件箱是 Docker 工作区内的普通文件。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, writeFile, access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile), sha = value => createHash('sha256').update(value).digest('hex');
const exists = async path => { try { await access(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };

export async function runPropagationAcceptance(ctx) {
  const { fixture, paths, config, configPath, rootRights, bRights, cRights, report, out,
    start, stop, send, delegate, good, refused, negative, save } = ctx;
  const i = process.argv.indexOf('--payload'); assert.ok(i > 0, '缺少已持久化资料');
  const payloadBytes = await readFile(resolve(process.argv[i + 1])), payload = JSON.parse(payloadBytes);
  assert.equal(payload.instruction_authority, 'none');
  assert.deepEqual(payload.note.label, { integrity: 'tainted', confidentiality: 'high' });
  assert.deepEqual(payload.document.label, payload.note.label);
  assert.ok(payload.note.content.text.includes('PERSIST-ORIOLE-025'));
  const receivers = Array.from({ length: 4 }, (_, index) => join(fixture.work, `receiver-${index + 1}.json`).replace(/^\/private(?=\/var\/)/, ''));
  await writeFile(paths.input, payloadBytes);
  report.propagation = { payload_sha256: sha(payloadBytes), note_entry_sha256: payload.note.entry_sha256,
    document_entry_sha256: payload.document.entry_sha256, receiver_paths: receivers, phases: [], deliveries: [], triggers: [] };
  const proof = report.propagation;
  const status = async () => { const value = await ctx.session.operatorRequest('/delegation/status'); assert.equal(value.status, 200); return value.value; };
  async function begin(name) {
    await writeFile(configPath, JSON.stringify(config), { mode: 0o600 }); await start();
    const phase = { name, config: structuredClone(config), session_id: ctx.session.sessionId, snapshot: ctx.session.snapshot,
      message_start: report.messages.length, before: await status() }; proof.phases.push(phase); await save(); return phase;
  }
  async function finish(phase) { phase.after = await status(); phase.message_end = report.messages.length; phase.passed = true; await stop(); await save(); }

  config.budgets = { max_depth: 2, max_calls: 20, max_output_bytes: 1024 * 1024, max_elapsed_ms: 60000 };
  const attenuation = await begin('持久投毒进入 A→B→C 后不能递权');
  const b = await delegate('A', ctx.rootGrant, 'B'), c = await delegate('B', b, 'C');
  assert.deepEqual(c.grant.permissions, cRights);
  const observed = await send('C', c, { operation: 'read_file', path: paths.input });
  assert.ok(good(observed.response).includes('PERSIST-ORIOLE-025'));
  attenuation.read_payload_message = report.messages.length - 1;
  for (const command of [
    { operation: 'read_file', path: paths.private },
    { operation: 'write_file', path: paths.output, contents: payloadBytes.toString() },
    { operation: 'delegate', subject_id: 'A', permissions: rootRights, expires_at_ms: Date.now() + 30000 },
  ]) refused((await send('C', c, command, { consume: false })).response);
  assert.equal(await exists(join(ctx.session.snapshot, 'output.txt')), false);
  assert.ok(good((await send('A', ctx.rootGrant, { operation: 'read_file', path: paths.private })).response).includes('AGD_PARENT_ONLY_DATA'));
  await finish(attenuation);

  // 两个被允许投递是正例；第三、第四次具有相同文件权限，必须由共享预算阻止。
  for (const rights of [rootRights, bRights, cRights]) {
    rights.read_files = [paths.input]; rights.write_files = [...receivers].sort(); rights.delete_files = []; rights.delegate_to = ['A', 'B', 'C'];
  }
  // 两次授权、一次深度越界尝试、一次读取与两次投递共六次；越界深度尝试也消费预算。
  config.budgets = { max_depth: 2, max_calls: 6, max_output_bytes: 1024 * 1024, max_elapsed_ms: 60000 };
  const bounded = await begin('两次真实投递后阻止后续复制和再次触发');
  const parent = await delegate('A', ctx.rootGrant, 'B'), child = await delegate('B', parent, 'C');
  refused((await send('C', child, { operation: 'delegate', subject_id: 'A', permissions: rootRights, expires_at_ms: Date.now() + 30000 }, { consume: false })).response);
  assert.ok(good((await send('C', child, { operation: 'read_file', path: paths.input })).response).includes('PERSIST-ORIOLE-025'));
  const deliveredEnvelopes = [];
  for (const [index, path] of receivers.entries()) {
    const result = await send('C', child, { operation: 'write_file', path, contents: payloadBytes.toString() }, { consume: index < 2 });
    const stored = join(ctx.session.snapshot, `receiver-${index + 1}.json`);
    if (index < 2) {
      good(result.response); assert.deepEqual(await readFile(stored), payloadBytes); deliveredEnvelopes.push(result.envelope);
      proof.deliveries.push({ receiver: index + 1, path: stored, sha256: sha(await readFile(stored)), message_index: report.messages.length - 1 });
    } else {
      refused(result.response); assert.ok(result.response.result.content[0].text.includes('调用预算耗尽'));
      assert.equal(await exists(stored), false);
    }
    assert.equal(await exists(path), false); // 未确认宿主回写，原工作区不能出现副作用。
  }
  // 独立接收进程确实读取已投递字节，随后对相同网关提交传播请求；不是仅统计脚本循环次数。
  const receiverProgram = `const fs=require('node:fs'),c=require('node:crypto');const b=fs.readFileSync(process.argv[1]);const v=JSON.parse(b);process.stdout.write(JSON.stringify({pid:process.pid,sha256:c.createHash('sha256').update(b).digest('hex'),label:v.note.label,instruction_authority:v.instruction_authority}));`;
  for (const delivery of proof.deliveries) {
    const receiver = JSON.parse((await run(process.execPath, ['-e', receiverProgram, delivery.path])).stdout);
    assert.equal(receiver.sha256, proof.payload_sha256); assert.deepEqual(receiver.label, payload.note.label); assert.equal(receiver.instruction_authority, 'none');
    const result = await send('C', child, { operation: 'write_file', path: receivers[2], contents: payloadBytes.toString() }, { consume: false });
    refused(result.response); assert.ok(result.response.result.content[0].text.includes('调用预算耗尽'));
    proof.triggers.push({ receiver, message_index: report.messages.length - 1, dispatched: result.response.result._meta.agentguard.dispatched });
  }
  bounded.delivered_count = proof.deliveries.length; assert.equal(bounded.delivered_count, 2);
  bounded.follow_up_count = proof.triggers.length; assert.equal(bounded.follow_up_count, 2);
  assert.equal((await status()).budget.nodes.find(n => n.grant_id === ctx.rootGrant.grant.grant_id).used_calls, 6);
  assert.equal(await exists(join(ctx.session.snapshot, 'receiver-3.json')), false);
  assert.equal(await exists(join(ctx.session.snapshot, 'receiver-4.json')), false);
  await finish(bounded);

  const reopened = await begin('新进程拒绝已投递内容携带的旧授权');
  for (const envelope of deliveredEnvelopes) await negative(envelope);
  assert.ok(good((await send('A', ctx.rootGrant, { operation: 'read_file', path: paths.input })).response).includes('PERSIST-ORIOLE-025'));
  for (const [index, path] of receivers.entries()) {
    assert.equal(await exists(join(ctx.session.snapshot, `receiver-${index + 1}.json`)), false);
    assert.equal(await exists(path), false);
  }
  for (const delivery of proof.deliveries) assert.equal(sha(await readFile(delivery.path)), proof.payload_sha256);
  reopened.old_deliveries_preserved = 2; reopened.old_authorization_replays_refused = deliveredEnvelopes.length;
  await finish(reopened);
  assert.equal(report.sessions.length, 3); assert.ok(report.sessions.every(s => s.exit.code === 0));
  assert.equal(new Set(proof.triggers.map(t => t.receiver.pid)).size, 2);
  report.checks.push('持久资料不赋予指令权限；真实三进程、两次文件投递、两次接收后触发和旧授权重放均核对副作用');
  report.passed = true; await save();
}

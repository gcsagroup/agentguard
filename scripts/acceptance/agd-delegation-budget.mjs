// AGD-024 真实 CLI 验收。由 agd-delegation.mjs --budget-mode 提供宿主签名与受控会话。
import assert from 'node:assert/strict';
import { writeFile, readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const exists = async path => { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
const defaults = { max_depth: 3, max_calls: 32, max_output_bytes: 1024 * 1024, max_elapsed_ms: 30000 };

export async function runBudgetAcceptance(ctx) {
  const { config, configPath, rootRights, bRights, cRights, paths, out, report,
    start, stop, send, delegate, good, refused, negative, save } = ctx;
  // 深度负例必须先具备合法递交权限，不能让权限拒绝替预算测试过关。
  for (const rights of [rootRights, bRights, cRights]) rights.delegate_to = ['A', 'B', 'C'];
  report.budget_phases = [];
  const status = async () => {
    const response = await ctx.session.operatorRequest('/delegation/status');
    assert.equal(response.status, 200);
    assert.equal(response.value.host_session_id, ctx.session.sessionId);
    return response.value;
  };
  const node = (state, grant) => state.budget.nodes.find(n => n.grant_id === grant.grant.grant_id);
  async function phase(name, budgets, action, auditFault = false) {
    config.budgets = { ...defaults, ...budgets };
    await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
    await start();
    const proof = { name, config: structuredClone(config), host_session_id: ctx.session.sessionId,
      message_start: report.messages.length, before: await status() };
    report.budget_phases.push(proof);
    await action(proof);
    proof.after = auditFault ? (await ctx.session.rpc('gateway/stats')).result.delegation.budgets : await status();
    proof.audit_fault = auditFault;
    proof.message_end = report.messages.length;
    proof.passed = true;
    await stop(); await save();
  }

  await phase('深度限制与合法后续操作', { max_depth: 2 }, async proof => {
    const root = ctx.rootGrant;
    const b = await delegate('A', root, 'B');
    const c = await delegate('B', b, 'C');
    const denied = await send('C', c, { operation: 'delegate', subject_id: 'A',
      permissions: rootRights, expires_at_ms: Date.now() + 60000 }, { consume: false });
    refused(denied.response);
    assert.ok(denied.response.result.content[0].text.includes('深度上限'));
    const state = await status();
    assert.equal(state.budget.nodes.length, 3);
    assert.equal(node(state, c).limits.max_depth, 0);
    assert.equal((await ctx.session.rpc('gateway/stats')).result.delegation.active_grants, 3);
    good((await send('C', c, { operation: 'read_file', path: paths.input })).response);
    proof.depth_denied = true;
    proof.child_grants = [b.grant.grant_id, c.grant.grant_id];
  });

  await phase('兄弟分支共用调用总量', { max_calls: 4 }, async proof => {
    const root = ctx.rootGrant;
    const left = await delegate('A', root, 'B');
    const right = await delegate('A', root, 'B');
    good((await send('B', left, { operation: 'read_file', path: paths.input })).response);
    good((await send('B', right, { operation: 'read_file', path: paths.input })).response);
    for (const grant of [left, right]) {
      const denied = await send('B', grant, { operation: 'write_file', path: paths.new,
        contents: '不应透支写入' }, { consume: false });
      refused(denied.response);
      assert.ok(denied.response.result.content[0].text.includes('调用预算耗尽'));
    }
    const state = await status();
    assert.equal(node(state, root).used_calls, 4);
    assert.equal(node(state, left).used_calls, 1);
    assert.equal(node(state, right).used_calls, 1);
    assert.equal(await exists(join(ctx.session.snapshot, 'new.txt')), false);
    assert.equal(await exists(paths.new), false);
    proof.root_used_calls = 4;
  });

  const initial = await readFile(paths.input);
  const large = Buffer.from('AGD_OUTPUT_SECRET ' + '\u0001'.repeat(12000));
  await writeFile(join(out, 'output-input.txt'), large);
  await writeFile(paths.input, large);
  await phase('完整 JSON 转义后的输出限额', { max_output_bytes: 16000 }, async proof => {
    assert.ok(large.length < 16000 && Buffer.byteLength(JSON.stringify(large.toString())) > 16000);
    const result = await send('A', ctx.rootGrant, { operation: 'read_file', path: paths.input });
    const meta = result.response.result._meta.agentguard;
    assert.equal(meta.dispatched, true);
    assert.equal(meta.outcome, 'success');
    assert.equal(meta.budget_output_hidden, true);
    assert.equal(meta.budget_reason, 'output_limit');
    assert.ok(!JSON.stringify(result.response).includes('AGD_OUTPUT_SECRET'));
    const encoded = Buffer.byteLength(JSON.stringify(result.response));
    assert.ok(encoded <= 16000);
    const state = await status();
    assert.equal(node(state, ctx.rootGrant).used_output_bytes, encoded);
    proof.source_sha256 = sha(large);
    proof.source_bytes = large.length;
    proof.encoded_source_bytes = Buffer.byteLength(JSON.stringify(large.toString()));
    proof.response_bytes = encoded;
  });
  await writeFile(paths.input, initial);

  let oldHost, oldGrant;
  await phase('等待中父撤销及兄弟继续', {}, async proof => {
    const root = ctx.rootGrant;
    const parent = await delegate('A', root, 'B');
    const child = await delegate('B', parent, 'C');
    oldHost = ctx.session.sessionId; oldGrant = parent.grant.grant_id;
    const result = await send('B', parent, { operation: 'write_file', path: paths.output,
      contents: '不应在撤销后写入' }, { approval: 'revoke', onPending: async pending => {
        const body = { host_session_id: ctx.session.sessionId, grant_id: parent.grant.grant_id };
        assert.equal((await ctx.session.operatorRequest('/delegation/revoke', body, { omitAuthorization: true })).status, 403);
        const revoked = await ctx.session.operatorRequest('/delegation/revoke', body);
        assert.equal(revoked.status, 200);
        assert.equal(revoked.value.affected, 2);
        assert.equal(revoked.value.completed_effects, 'not_reverted');
        proof.revocation = revoked.value;
        assert.notEqual((await ctx.session.operatorRequest('/approve', { id: pending.id,
          action_sha256: pending.action_sha256, approval_nonce: pending.binding.nonce })).status, 200);
      } });
    refused(result.response);
    assert.equal(result.response.result._meta.agentguard.outcome, 'cancelled');
    assert.equal(await exists(join(ctx.session.snapshot, 'output.txt')), false);
    await negative(result.envelope);
    refused((await send('C', child, { operation: 'read_file', path: paths.input }, { consume: false })).response);
    const sibling = await delegate('A', root, 'B');
    good((await send('B', sibling, { operation: 'read_file', path: paths.input })).response);
    assert.equal(node(await status(), sibling).revoked, false);
    proof.sibling_continued = true;
  });

  await phase('预算期限取消等待及旧会话撤销拒绝', { max_elapsed_ms: 500 }, async proof => {
    assert.equal((await ctx.session.operatorRequest('/delegation/revoke', {
      host_session_id: oldHost, grant_id: oldGrant })).status, 409);
    const result = await send('A', ctx.rootGrant, { operation: 'write_file', path: paths.output,
      contents: '不应超出运行期限' }, { approval: 'expire' });
    refused(result.response);
    assert.equal(result.response.result._meta.agentguard.outcome, 'timed_out');
    assert.equal(await exists(join(ctx.session.snapshot, 'output.txt')), false);
    assert.equal(await exists(paths.output), false);
    const root = node(await status(), ctx.rootGrant);
    assert.equal(root.remaining_ms, 0);
    assert.equal(root.used_calls, 1);
    proof.expired_without_write = true;
  });

  await phase('输出审计写入失败后隐藏正文并消费完整预留', {}, async proof => {
    const db = ctx.fixture.auditDb;
    await run('python3', ['-c', `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("CREATE TRIGGER agd_budget_finish_fault BEFORE INSERT ON audit_events WHEN NEW.event_type='GatewayDelegationBudget' AND NEW.action='finished' BEGIN SELECT RAISE(FAIL, 'AGD_BUDGET_AUDIT_FAULT'); END")`, db]);
    try {
      const result = await send('A', ctx.rootGrant, { operation: 'read_file', path: paths.input });
      const meta = result.response.result._meta.agentguard;
      assert.equal(meta.dispatched, true);
      assert.equal(meta.outcome, 'unknown');
      assert.equal(meta.budget_reason, 'audit_unconfirmed');
      assert.equal(meta.budget_output_hidden, true);
      assert.ok(!JSON.stringify(result.response).includes('AGD_DELEGATION_INPUT'));
      const stats = (await ctx.session.rpc('gateway/stats')).result;
      assert.equal(stats.execution_journal.healthy, false);
      assert.equal(stats.delegation.budgets.budget.closed, true);
      assert.equal(node(stats.delegation.budgets, ctx.rootGrant).used_output_bytes, 512 * 1024);
      assert.equal((await ctx.session.operatorRequest('/delegation/status')).status, 409);
      refused((await send('A', ctx.rootGrant, { operation: 'write_file', path: paths.new,
        contents: '审计失败后不应继续执行' }, { consume: false })).response);
      assert.equal(await exists(join(ctx.session.snapshot, 'new.txt')), false);
      proof.full_reservation_charged = 512 * 1024;
    } finally {
      await run('python3', ['-c', "import sqlite3,sys\nwith sqlite3.connect(sys.argv[1]) as db: db.execute('DROP TRIGGER agd_budget_finish_fault')", db]);
    }
  }, true);

  assert.equal(report.sessions.length, 6);
  assert.ok(report.sessions.every(s => s.exit.code === 0));
  assert.ok(report.budget_phases.every(p => p.passed));
  report.checks.push('六个真实网关进程完成深度、共享调用、完整 JSON 输出、父撤销、单调期限及真实审计写入故障');
  report.passed = true;
}

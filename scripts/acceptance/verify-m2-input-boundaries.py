"""从冻结用例、三份原始审计和实际文件独立核对，不以运行器的 passed 为唯一依据。"""
import argparse, collections, datetime, hashlib, json, re, sqlite3, sys
from pathlib import Path
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--run', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--sha256', required=True)
args = parser.parse_args()
assert re.fullmatch('[a-f0-9]{64}', args.sha256)
assert args.run.is_absolute() and args.output.is_absolute() and (not args.output.exists())
root = Path(__file__).resolve().parents[2]
run = args.run
read = lambda p: json.loads(p.read_text())
digest = lambda value: hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()
sha = lambda p: digest(p.read_bytes())
fields = ['id', 'timestamp_ms', 'platform', 'event_type', 'source_app', 'agent_session_id', 'rule_id', 'severity', 'action', 'human_message', 'evidence_ref', 'event_json']

def rows(path):
    c = sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)
    c.row_factory = sqlite3.Row
    result = [dict(r) for r in c.execute('select * from audit_events order by rowid')]
    c.close()
    previous = 'AGENTGUARD-AUDIT-GENESIS-v1'
    for r in result:
        assert r['prev_hash'] == previous
        content = '\x1f'.join((str(r[f]) if r[f] is not None else '' for f in fields))
        if r['attributed_agent'] is not None:
            content += '\x1fagent=' + r['attributed_agent']
        assert digest(previous + '\n' + content) == r['record_hash']
        previous = r['record_hash']
    return result
report = read(run / 'report.json')
manifest = read(run / 'inputs.json')
declared = read(run / 'declared-cases.json')
assert sha(run / 'inputs.json') == sha(root / 'eval/m2/independent-inputs.json') == report['manifestSha256'] == declared['manifestSha256']
assert declared['frozenAt'] < report['startedAt']
assert report['passed'] and report['binaryUnchanged'] and (not report.get('evidenceErrors')) and (not report.get('closeError'))
assert sha(Path(report['binary'])) == report['binarySha256'] == args.sha256
assert sha(run / 'harness-source.mjs') == sha(root / 'scripts/acceptance/agd-m2-input-boundaries.mjs')
assert len(report['cases']) == 52 and all((c['status'] == 'passed' for c in report['cases']))
assert len(report['evidenceBackups']) == 3
fixture = Path(report['fixture'])
audit = {}
for name in ['audit.db', 'audit.db.sources.db', 'audit.db.tools.db']:
    raw = rows(run / name)
    assert raw == rows(fixture / 'operator' / name)
    audit[name] = {'rows': len(raw), 'head': raw[-1]['record_hash'], 'sha256': sha(run / name)}
events = [json.loads(r['event_json']) for r in rows(run / 'audit.db')]
sources = {s['source']['source_id']: s['source'] for s in [json.loads(r['event_json']) for r in rows(run / 'audit.db.sources.db')]}
previous_source = []
for source in sources.values():
    assert source['observation']['parent_source_ids'] == previous_source
    previous_source = [source['source_id']]
groups = collections.Counter()
outside = [fixture / 'operator/outside-read.txt', fixture / 'operator/outside-write.txt']
refused_actions = []
for case in report['cases']:
    groups[case['group']] += 1
    if 'input' not in case:
        continue
    sample = next((s for s in manifest['inputs'] if s['id'] == case['input']))
    evidence = case['evidence']
    source = sources[evidence['source_id']]
    assert (fixture / 'workspace' / f"{sample['id']}.txt").read_text() == sample['text']
    assert source['observation'] == evidence['source_observation']
    assert sha(fixture / 'workspace' / f"{sample['id']}.txt") == evidence['input_sha256'] == digest(sample['text'])
    receipt = next((r for r in report['receipts'] if r.get('result', {}).get('_meta', {}).get('agentguard', {}).get('source', {}).get('source_id') == source['source_id']))
    assert receipt['result']['_meta']['agentguard']['source'] == source
    assert receipt['result']['_meta']['agentguard']['instruction_authority'] == 'none'
    if case['entry'] in ['local_mcp', 'remote_mcp']:
        assert receipt['result']['structuredContent']['value'] == sample['text']
        assert receipt['result']['_meta']['agentguard']['downstream_metadata']['agentguard']['instruction_authority'] == 'system'
    else:
        expected = f"1:{sample['text']}\n" if case['entry'] == 'search' else sample['text']
        size = source['content_views']['visible']['bytes']
        observed = receipt['result']['content'][0]['text'].encode()[:size]
        assert observed == expected.encode() and digest(observed) == source['observation']['content_sha256']
    for path in outside:
        # macOS 路径合同去除 /private 别名；核对父目录确为同一对象。
        normalized = str(path).removeprefix('/private') if sys.platform == 'darwin' else str(path)
        assert path.parent.samefile(Path(normalized).parent)
        decisions = [e for e in events if e['outcome'] == 'decision' and e['target_sha256'] == digest(normalized) and any((s['source_id_sha256'] == digest(source['source_id']) for s in e['sources']))]
        assert len(decisions) == 1, (case['id'], path, len(decisions))
        decision = decisions[0]
        assert decision['decision'] == 'refuse' and decision['source_coverage'] == 'attached'
        assert any((s['sensitivity'] == 'unknown' and s['content_sha256'] == source['observation']['content_sha256'] for s in decision['sources']))
        bound = [e for e in events if e['action_sha256'] == decision['action_sha256']]
        assert [e['outcome'] for e in bound] == ['decision', 'refused']
        assert all((e['dispatched'] is False and e['side_effects'] == 'not_dispatched' for e in bound))
        for key in ['parameters_sha256', 'policy_version_sha256', 'request_id_sha256', 'sources', 'approval_id_sha256']:
            assert bound[0][key] == bound[1][key]
        refused_actions.append(decision['action_sha256'])
assert len(refused_actions) == len(set(refused_actions)) == 90
assert outside[0].read_text() == 'M2_OWNED_OUTSIDE_CANARY_20260915' and (not outside[1].exists())
assert (fixture / 'workspace/accepted-result.txt').read_text() == 'M2_NORMAL_AUTHORIZED_RESULT'
assert report['remoteEffects'] == [] and report['remoteErrors'] == []
assert not (fixture / 'operator/remote-effects.jsonl').exists()
assert (fixture / 'operator/remote-note.txt').read_text() == next((s['text'] for s in manifest['inputs'] if s['id'] == 'U03'))
calls = [r for r in report['remoteRequests'] if r['method'] == 'tools/call']
assert len(calls) == 9 and all((r['tool'] == 'read_note' and r['auth_verified'] for r in calls))
assert groups == {'normal': 17, 'known_attack': 18, 'unseen_variant': 16, 'recovery': 1}
denial = next((a for a in report['approvals'] if a['decision'] == 'deny'))
denied = [e for e in events if e['action_sha256'] == denial['action_sha256']]
assert [e['outcome'] for e in denied] == ['decision', 'refused'] and denied[-1]['dispatched'] is False
registration = [json.loads(r['event_json']) for r in rows(run / 'audit.db.tools.db')]
assert sum((e['change'] == 'approved' for e in registration)) == 2
remote_versions = [e for e in registration if e['change'] == 'observed' and e['summary']['service_id'] == 'remote-fixture']
assert len(remote_versions) == 2 and remote_versions[0]['registration_id'] != remote_versions[1]['registration_id']
recovery = next((c['evidence'] for c in report['cases'] if c['id'] == 'C07'))
assert recovery['previous_session'] != recovery['new_session']
after_restart = [r for r in rows(run / 'audit.db') if r['agent_session_id'] == digest(recovery['new_session'])]
assert [r['action'] for r in after_restart] == ['needs_confirmation', 'started', 'success']
after_events = [json.loads(r['event_json']) for r in after_restart]
assert len({e['action_sha256'] for e in after_events}) == 1
assert all((e['sources'][0]['source_id_sha256'] == digest(list(sources)[-2]) for e in after_events))
assert list(sources.values())[-1]['observation']['content_sha256'] == list(sources.values())[-2]['observation']['content_sha256']
proof = {'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'task': 'AGD-020', 'status': 'in_progress', 'gateway_sha256': report['binarySha256'], 'manifest_sha256': report['manifestSha256'], 'case_groups': dict(groups), 'total_cases': 52, 'audit': audit, 'total_audit_rows': sum((x['rows'] for x in audit.values())), 'independently_bound_refusals': 90, 'remote_read_calls': 9, 'remote_write_effects': 0, 'authorized_host_result_verified': True, 'remaining_acceptance': manifest['remaining_acceptance'], 'f13': 'deferred_unverified', 'whole_plan_complete': False, 'release': 'no_go'}
with args.output.open('x') as output:
    output.write(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(proof, ensure_ascii=False, indent=2))

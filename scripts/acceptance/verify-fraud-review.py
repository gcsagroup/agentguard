"""只读交叉核对合成交易账本、冻结动作和真实浏览器审计；不连接控制接口。"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def read(path):
    return json.loads(path.read_text())


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def audit(database):
    wal = Path(str(database)+'-wal')
    assert not wal.exists() or wal.stat().st_size == 0, '退出副本仍有未合并 WAL，不能按 immutable 忽略'
    with sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1', uri=True) as db:
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute('SELECT * FROM audit_events ORDER BY rowid')]
    previous = 'AGENTGUARD-AUDIT-GENESIS-v1'
    fields = ['id', 'timestamp_ms', 'platform', 'event_type', 'source_app', 'agent_session_id',
              'rule_id', 'severity', 'action', 'human_message', 'evidence_ref', 'event_json']
    for number, row in enumerate(rows, 1):
        canonical = '\x1f'.join(str(row[key]) if row[key] is not None else '' for key in fields)
        if row['attributed_agent'] is not None:
            canonical += '\x1fagent='+row['attributed_agent']
        assert row['seq'] == number and row['prev_hash'] == previous
        assert row['record_hash'] == digest((previous+'\n'+canonical).encode())
        previous = row['record_hash']
    assert rows
    return rows


def verify(directory):
    report = read(directory/'report.json')
    assert report.get('passed') and not report.get('error') and not report.get('cleanup_error')
    assert len(report['checks']) == 15 and all(c['passed'] for c in report['checks'])
    assert report['exit'] == {'code': 0, 'signal': None}
    assert not any(word in report['stderr'] for word in ['EPERM', 'Error:', '清理失败', '退出超时', '异常退出'])
    binary = Path(report['binary'])
    build = read(binary.parent/'build-inputs.json')
    assert digest(binary.read_bytes()) == report['binary_sha256'] == build['binary_sha256']
    names = [x['path'] for x in build['sources']]
    assert len(names) == len(set(names)) == 249
    for source in build['sources']:
        path = Path(source['path'])
        assert not path.is_absolute() and '..' not in path.parts
        assert source['sha256'] == digest((binary.parent/'source'/path).read_bytes())
    assert report['fixture_sha256'] == digest((binary.parent/'source/eval/acceptance-fixtures/fraud-review.html').read_bytes())
    expected = {'invoice': 'DEMO-INV-001', 'beneficiary': '合成示例供应商甲', 'account': 'DEMO-A', 'amount_minor': 128050, 'currency': 'CNY'}
    assert read(directory/'independent-reference.json') == expected
    ledger = read(directory/'ledger.json')
    assert ledger == report['ledger'] and len(ledger) == 1
    assert ledger[0]['id'] == 'SIM-1' and all(ledger[0]['draft'][k] == v for k, v in expected.items())
    posts = [r for r in report['requests'] if r['method'] == 'POST']
    assert len(posts) == 1 and posts[0]['path'] == '/transactions'
    assert json.loads(posts[0]['body']) == ledger[0]['draft']
    assert len(report['requests']) == 2 and report['requests'][0]['method'] == 'GET'
    assert all(r['method'] == 'GET' for r in report['preview_requests'])
    rows = audit(directory/'browser.db')
    events = [(r['event_type'], json.loads(r['event_json']), r) for r in rows]
    approvals = report['approvals']
    assert [a['approve'] for a in approvals] == [True, False, True]
    assert all(a['answer']['status'] == 200 for a in approvals)
    assert approvals[1]['pending'] == report['first_draft'] and approvals[2]['pending'] == report['final_draft']
    pending = [approvals[0]['pending'], report['first_draft'], report['expired_draft'], report['final_draft']]
    assert len({p['id'] for p in pending}) == 4
    receipts = report['browser_status']['receipts']
    assert [r['outcome'] for r in receipts] == ['success', 'refused', 'timed_out', 'success']
    assert [r['dispatched'] for r in receipts] == [True, False, False, True]
    assert len(receipts) == 4
    for index, (p, receipt) in enumerate(zip(pending, receipts)):
        action = p['binding']['action']
        assert digest(b'agentguard.execution.action.v1\0'+encoded(action)) == p['action_sha256'] == receipt['action_sha256']
        assert action['session_id'] == report['session'] == receipt['session_id']
        assert action['tool']['service'] == 'agentguard-protected-browser' and action['tool']['name'] == 'http_request'
        assert action['target'] == report['origin']+('/' if index == 0 else '/transactions')
        assert action['parameters']['method'] == ('GET' if index == 0 else 'POST')
        assert not receipt['automatic_retry']
        selected = [(kind, body, row) for kind, body, row in events if body['action_sha256'] == p['action_sha256']]
        decisions = [b for k, b, _ in selected if k == 'GatewayDecision']
        started = [b for k, b, _ in selected if k == 'GatewayExecutionStarted']
        finished = [(b, r) for k, b, r in selected if k == 'GatewayExecutionFinished']
        assert len(decisions) == len(finished) == 1 and decisions[0]['decision'] == 'needs_confirmation'
        assert len(started) == (1 if index in [0, 3] else 0)
        terminal, row = finished[0]
        assert terminal['outcome'] == receipt['outcome'] and terminal['dispatched'] == receipt['dispatched']
        for _, body, _ in selected:
            assert body['parameters_sha256'] == digest(encoded(action['parameters']))
            assert body['target_sha256'] == digest(action['target'].encode())
        assert terminal['approval_id_sha256'] == digest(p['id'].encode())
        if index == 2:
            assert row['timestamp_ms'] >= p['binding']['expires_at_ms']
    assert json.loads(pending[1]['binding']['action']['parameters']['body'])['account'] == 'DEMO-B'
    assert json.loads(pending[2]['binding']['action']['parameters']['body'])['amount_minor'] == 128051
    assert pending[3]['binding']['action']['parameters']['body'] == posts[0]['body']
    assert [r['kind'] for r in report['rejections']] == ['changed_amount', 'expired', 'old_request', 'replay']
    assert all(r['answer']['status'] == 409 for r in report['rejections'])
    assert report['duplicate']['result']['_meta']['agentguard']['dispatched'] is False
    assert 'DEMO-A / 128050 分 CNY' in report['final_page']['text']
    for observation in report['observations']:
        result = observation['response']['result']
        assert not result['isError']
        receipt = result['_meta']['agentguard']
        matches = [b for k, b, _ in events if k == 'GatewayExecutionFinished' and b['action_sha256'] == receipt['action_sha256']]
        assert len(matches) == 1 and matches[0]['outcome'] == receipt['outcome'] == 'success'
    return {'passed': True, 'checks': len(report['checks']), 'browser_audit_rows': len(rows),
            'http_actions': 4, 'transactions': 1, 'approved_transactions': 1,
            'rejected_transactions': 1, 'expired_transactions': 1,
            'source_inputs': len(names), 'deepfake_models_executed': 0,
            'scope': '本机合成交易与脚本批准；审计为哈希链，不宣称带签名防篡改或诈骗检出率'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve()), ensure_ascii=False, indent=2))

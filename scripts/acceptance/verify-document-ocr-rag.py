"""只读核对中文图片的冻结输入、实际签名存储、批准与重开检索；不读取私钥。"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('memory_verify', Path(__file__).with_name('verify-memory-store.py'))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
sha, encoded, read, rows, chain_hash = helpers.digest, helpers.encoded, helpers.read, helpers.rows, helpers.chain_hash


def verify(directory, frozen, repository, node):
    report, build = read(directory/'report.json'), read(frozen/'build-inputs.json')
    assert report['passed'] and 'error' not in report and 'cleanup_error' not in report
    assert Path(report['binary']).resolve() == (frozen/'agentguard-mcp').resolve()
    assert report['binary_sha256'] == build['binary_sha256'] == sha((frozen/'agentguard-mcp').read_bytes())
    for source in build['sources']:
        path = Path(source['path'])
        assert not path.is_absolute() and '..' not in path.parts
        assert source['sha256'] == sha((frozen/'source'/path).read_bytes()) == sha((repository/path).read_bytes())
    sessions = report['sessions']
    assert len(sessions) == len({s['pid'] for s in sessions}) == len({s['session_id'] for s in sessions}) == 2
    assert all(s['exit']['code'] == 0 for s in sessions)
    quality_path = Path(report['quality'])
    assert report['quality_sha256'] == sha(quality_path.read_bytes())
    quality = read(quality_path)
    assert quality['passed'] and report['parser_sha256'] == quality['parser_sha256'] == sha((repository/'crates/guard-gateway/src/document_parser.py').read_bytes())
    assert quality['worker_timeout']['passed'] and quality['worker_timeout']['result']['status'] == 'timeout'
    assert 15 <= quality['worker_timeout']['elapsed_s'] < 20 and not quality['worker_timeout']['worker_remaining']
    memory_events = dict(line.split() for line in quality['memory_events'].splitlines())
    assert memory_events['oom'] == memory_events['oom_kill'] == '0'
    config = read(Path(report['config']))
    assert report['database_sha256'] == sha(Path(config['database']).read_bytes())
    assert report['witness_sha256'] == sha(Path(config['witness']).read_bytes())
    records, log_id, receipts = rows(Path(config['database']))
    assert len(records) == 3 and receipts == 0
    public = Path(config['public_key']).read_text().strip()
    assert public == report['public_key']
    key_id = sha(bytes.fromhex(public))[:16]
    head = read(Path(config['witness']))
    assert head == {'schema_version': 1, 'scope_id': config['scope_id'], 'key_id': key_id,
                    'head': {'log_id': log_id, 'seq': 3, 'count': 3, 'last_record_hash': records[-1]['record_hash'],
                             'receipt_count': 0, 'last_receipt_hash': ''}}
    signatures, previous = [], 'AGENTGUARD-AUDIT-GENESIS-v1'
    for seq, row in enumerate(records, 1):
        calculated = chain_hash(row, previous)
        assert row['seq'] == seq and row['signer_key_id'] == key_id and row['record_hash'] == calculated and row['prev_hash'] == previous
        signatures.append({'message': '\x1f'.join(['AGENTGUARD-AUDIT-RECORD-v2', key_id, log_id, str(seq), calculated]), 'signature': row['record_sig']})
        previous = calculated
    program = """const fs=require('node:fs'),c=require('node:crypto'),v=JSON.parse(fs.readFileSync(0,'utf8'));
const key=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(v.public,'hex')]),type:'spki',format:'der'});
process.stdout.write(JSON.stringify(v.rows.map(r=>c.verify(null,Buffer.from(r.message),key,Buffer.from(r.signature,'hex')))));"""
    assert json.loads(subprocess.check_output([node, '-e', program], input=encoded({'public': public, 'rows': signatures}))) == [True] * 3
    audit, _, _ = rows(Path(report['fixture'])/'operator/audit.db')
    previous, bodies, sources = 'AGENTGUARD-AUDIT-GENESIS-v1', [], {}
    for row in audit:
        assert row['prev_hash'] == previous and row['record_hash'] == chain_hash(row, previous)
        previous = row['record_hash']
        body = json.loads(row['event_json']); bodies.append((row['event_type'], body))
        if row['event_type'] == 'GatewaySourceObserved':
            source = body['source']; sources[source['source_id']] = source
    assert len(report['imports']) == len(report['queries']) == 2
    for index, (row, proof, query, name) in enumerate(zip(records[1:], report['imports'], report['queries'], ['simplified-png', 'traditional-upside-down'], strict=True)):
        entry = json.loads(row['event_json']); draft, approval = entry['draft'], entry['approval']
        assert draft['key'] == proof['key'] == query['key'] == name and draft['version'] == 1 and draft['state'] == 'active'
        assert draft['previous_sha256'] is None and draft['label'] == {'integrity': 'tainted', 'confidentiality': 'high'}
        assert entry['content_sha256'] == sha(draft['content'].encode())
        assert proof['before'] == index and proof['after'] == index + 1
        assert approval['action_sha256'] == proof['action_sha256'] and approval['actor_id'] == 'authenticated-host-control'
        assert approval['approved_at_ms'] <= entry['committed_at_ms'] < approval['expires_at_ms']
        assert all(sources[s['source_id']] == s for s in draft['sources']) and len(draft['sources']) > 0
        terminals = [b for k, b in bodies if k == 'GatewayExecutionFinished' and b['action_sha256'] == approval['action_sha256']]
        assert len(terminals) == 1 and terminals[0]['dispatched'] and terminals[0]['outcome'] == 'success'
        assert terminals[0]['approval_id_sha256'] == sha(approval['approval_id'].encode())
        assert terminals[0]['parameters_sha256'] == sha(encoded(draft, sort=True))
        material = json.loads(draft['content']); document = material['document']
        expected = next(c for c in quality['cases'] if c['case'] == name)['result']
        assert material['kind'] == 'parsed_document' and document['parser_version'] == 'agentguard-document/2'
        assert document['parser_sha256'] == report['parser_sha256'] and document['image_sha256'] == report['image'][7:]
        assert document['source_sha256'] == expected['source_sha256'] == sha((Path(sessions[0]['snapshot'])/'workspace-0'/proof['file']).read_bytes())
        assert document['text'] == expected['text'] and document['text_sha256'] == sha(document['text'].encode())
        assert document['instruction_authority'] == 'none' and document['coverage'] == expected['coverage']
        assert document['metadata']['ocr_rotation_degrees'] == (0 if index == 0 else 180)
        assert proof['read']['memory']['content'] == material and proof['read']['memory']['entry_sha256'] == sha(encoded(entry))
        assert any(s['observation'].get('content_sha256') == document['receipt_sha256'] for s in draft['sources'])
        hits = query['result']['hits']; assert len(hits) == 1 and hits[0]['key'] == name
        assert hits[0]['document']['parsing']['locations'] == document['segments']
        assert query['query'] in document['text'] and hits[0]['document']['line_basis'] == 'extracted_text'
    assert report['empty']['no_write'] and report['empty']['before'] == report['empty']['after'] == 2
    return {'passed': True, 'processes': 2, 'chinese_images': 2, 'signed_rows': 3, 'audit_rows': len(audit),
            'source_files': len(build['sources']), 'scope': '中文图片真实保存与重开检索，非模型或原生验收'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--frozen', type=Path, required=True)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--node', default='node')
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

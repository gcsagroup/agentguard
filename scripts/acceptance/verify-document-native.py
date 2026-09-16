"""只读核对原生媒体保存：冻结 CLI、来源、批准、拒绝无写入及进程重开。"""
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


def verify(directory, node):
    report = read(directory/'report.json')
    assert report['passed'] and 'error' not in report
    binary = Path(report['binary'])
    build = read(binary.parent/'build-inputs.json')
    assert report['binary_sha256'] == build['binary_sha256'] == sha(binary.read_bytes())
    for source in build['sources']:
        path = Path(source['path'])
        assert not path.is_absolute() and '..' not in path.parts
        assert source['sha256'] == sha((binary.parent/'source'/path).read_bytes())
    assert report['parser_sha256'] == sha((binary.parent/'source/crates/guard-gateway/src/document_parser.py').read_bytes())
    sessions = report['sessions']
    assert len(sessions) == len({s['pid'] for s in sessions}) == len({s['session_id'] for s in sessions}) == 2
    assert all(s['exit']['code'] == 0 for s in sessions)
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
    entries = [json.loads(row['event_json']) for row in records[1:]]
    assert [entry['draft']['key'] for entry in entries] == ['mixed-document-png', 'partial-pdf']
    assert [proof['key'] for proof in report['imports']] == ['mixed-document-png', 'traditional-upside-down', 'partial-pdf']
    action_program = """import fs from 'node:fs'; import {pathToFileURL} from 'node:url';
const {actionSha256}=await import(pathToFileURL(process.argv[1]));
process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(0,'utf8')).map(actionSha256)));"""
    calculated_actions = json.loads(subprocess.check_output(
        [node, '--input-type=module', '-e', action_program, str(binary.parent/'source/apps/protected-browser/execution-contract.mjs')],
        input=encoded([proof['action'] for proof in report['imports']])))
    assert calculated_actions == [proof['action_sha256'] for proof in report['imports']]
    for proof in report['imports']:
        action = proof['action']; draft = action['parameters']; material = json.loads(draft['content']); document = material['document']
        assert action['session_id'] == sessions[0]['session_id'] and action['sources'] == draft['sources']
        assert action['tool']['service'] == 'agentguard-memory' and action['tool']['name'] == 'memory_write'
        assert draft['key'] == proof['key'] and draft['version'] == 1 and draft['state'] == 'active'
        assert draft['label'] == {'integrity': 'tainted', 'confidentiality': 'high'}
        assert material['kind'] == 'parsed_document' and document['instruction_authority'] == 'none'
        assert document['source_sha256'] == report['inputs'][proof['file']] == sha((Path(sessions[0]['snapshot'])/'workspace-0'/proof['file']).read_bytes())
        assert document['parser_sha256'] == report['parser_sha256'] and document['image_sha256'] == report['image'][7:]
        assert document['text_sha256'] == sha(document['text'].encode())
        assert len(draft['sources']) > 0 and all(sources[s['source_id']] == s for s in draft['sources'])
        assert any(s['observation'].get('content_sha256') == document['receipt_sha256'] for s in draft['sources'])
        terminals = [b for k,b in bodies if k == 'GatewayExecutionFinished' and b['action_sha256'] == proof['action_sha256']]
        assert len(terminals) == 1 and terminals[0]['parameters_sha256'] == sha(encoded(draft, sort=True))
        if proof['key'] == 'traditional-upside-down':
            assert proof['expected'] == 'deny' and proof['before'] == proof['after'] == 1
            assert proof['response']['result']['isError'] and not terminals[0]['dispatched'] and terminals[0]['outcome'] == 'refused'
            assert not any(e['draft']['key'] == proof['key'] for e in entries)
            continue
        entry = next(e for e in entries if e['draft']['key'] == proof['key'])
        assert entry['draft'] == draft and entry['content_sha256'] == sha(draft['content'].encode())
        approval = entry['approval']
        assert approval['action_sha256'] == proof['action_sha256'] and approval['actor_id'] == 'authenticated-host-control'
        assert approval['approved_at_ms'] <= entry['committed_at_ms'] < approval['expires_at_ms']
        assert proof['expected'] == 'approve' and proof['after'] == proof['before'] + 1
        assert terminals[0]['dispatched'] and terminals[0]['outcome'] == 'success'
        assert terminals[0]['approval_id_sha256'] == sha(approval['approval_id'].encode())
        assert proof['read']['memory']['content'] == material and proof['read']['memory']['entry_sha256'] == sha(encoded(entry))
        if proof['key'] == 'partial-pdf':
            assert document['status'] == 'partial' and document['coverage']['empty_units'] == ['page:2']
        else:
            assert 'pip install demo-package' in document['text'] and document['status'] == 'parsed'
    snapshots = report['snapshots']
    assert len(snapshots) == 3 and all(s['count'] == 2 for s in snapshots)
    assert snapshots[0]['history'] == snapshots[1]['history'] == snapshots[2]['history']
    assert snapshots[0]['session_id'] != snapshots[1]['session_id'] == snapshots[2]['session_id']
    assert snapshots[2]['history']['versions'][0]['content'] == report['imports'][0]['read']['memory']['content']
    assert report['empty']['before'] == report['empty']['after'] == 2 and report['empty']['response']['result']['isError']
    assert len(report['query']['hits']) == 1 and report['query']['hits'][0]['key'] == 'mixed-document-png'
    return {'passed': True, 'scope': '只读核验原生操作的后端效果；界面行为以原生操作记录为准', 'signatures': 3, 'audit_records': len(audit), 'imports_approved': 2, 'imports_denied': 1, 'processes': 2, 'frozen_sources': len(build['sources'])}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--node', required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve(), args.node), ensure_ascii=False, indent=2))

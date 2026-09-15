"""只读核对原生治理操作的真实存储、签名、审计与停止效果；不读取私钥。"""
import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("helpers", Path(__file__).with_name("verify-persistence-propagation.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
sha, encoded, read, audit = helpers.sha, helpers.encoded, helpers.read, helpers.audit


def verify(memory_path, delegation_path, binary, node):
    memory, delegation = read(memory_path / "report.json"), read(delegation_path / "report.json")
    signatures = []
    for report in [memory, delegation]:
        assert report["passed"] and not report.get("error") and report["exit"]["code"] == 0
        assert Path(report["binary"]).resolve() == binary.resolve()
        assert report["binary_sha256"] == sha(binary.read_bytes())
    records, log_id, receipts = audit(Path(memory["memory_database"]))
    assert len(records) == 6 and receipts == 0
    public = memory["public_key"]
    key_id = sha(bytes.fromhex(public))[:16]
    witness = read(Path(memory["memory_witness"]))
    assert witness["key_id"] == key_id
    assert witness["head"] == {"log_id": log_id, "seq": 6, "count": 6, "last_record_hash": records[-1]["record_hash"], "receipt_count": 0, "last_receipt_hash": ""}
    for row in records:
        assert row["signer_key_id"] == key_id
        signatures.append({"public": public, "message": "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, log_id, str(row["seq"]), row["record_hash"]]), "signature": row["record_sig"]})
    entries = [json.loads(row["event_json"]) for row in records[1:]]
    assert [e["draft"]["state"] for e in entries] == ["active", "active", "quarantined", "active", "revoked"]
    gateway, _, _ = audit(Path(memory["execution_database"]))
    bodies = [(row["event_type"], json.loads(row["event_json"])) for row in gateway]
    terminals = {b["action_sha256"]: b for kind, b in bodies if kind == "GatewayExecutionFinished"}
    sources = {b["source"]["source_id"]: b["source"] for kind, b in bodies if kind == "GatewaySourceObserved"}
    shown = memory["snapshots"][-1]["response"]["value"]["data"]["versions"]
    previous = None
    for version, (entry, row, history) in enumerate(zip(entries, records[1:], shown, strict=True), 1):
        draft, approval = entry["draft"], entry["approval"]
        assert draft["key"] == "preference" and draft["version"] == version
        assert draft["label"] == {"integrity": "tainted", "confidentiality": "high"}
        assert draft["previous_sha256"] == previous
        previous = sha(encoded(entry))
        assert row["id"] == "memory/" + previous == "memory/" + history["entry_sha256"]
        assert entry["content_sha256"] == sha(draft["content"].encode())
        assert history["content"] == json.loads(draft["content"])
        assert history["sources"] == draft["sources"] and history["approval"] == approval
        assert all(sources[source["source_id"]] == source for source in draft["sources"])
        assert approval["actor_id"] == "authenticated-host-control"
        assert approval["approved_at_ms"] <= entry["committed_at_ms"] < approval["expires_at_ms"]
        terminal = terminals[approval["action_sha256"]]
        assert terminal["outcome"] == "success" and terminal["dispatched"]
        assert terminal["parameters_sha256"] == sha(encoded(draft, sort=True))
        assert terminal["approval_id_sha256"] == sha(approval["approval_id"].encode())
    assert entries[3]["draft"]["content"] == entries[0]["draft"]["content"]
    assert all(source in entries[3]["draft"]["sources"] for source in entries[1]["draft"]["sources"])
    assert len(memory["seeds"]) == 2

    grants = delegation["grants"]
    assert len(grants) == 3
    for index, grant in enumerate(grants):
        parent = grants[index - 1]["grant"] if index else None
        assert grant["grant"]["parent_grant_sha256"] == (sha(helpers.binding("grant", parent)) if parent else None)
        assert grant["grant"]["parent_session_id"] == (parent["session_id"] if parent else None)
        signatures.append({"public": delegation["public_keys"]["authority"], "message": helpers.binding("grant", grant["grant"]).decode(), "signature": grant["signature"]})
    for message in delegation["messages"]:
        envelope = message["envelope"]
        assert envelope["message"]["operation_sha256"] == sha(helpers.binding("operation", envelope["command"]))
        signatures.append({"public": delegation["public_keys"][envelope["message"]["actor_id"]], "message": helpers.binding("message", envelope["message"]).decode(), "signature": envelope["signature"]})
    final = delegation["snapshots"][-1]["response"]["value"]
    nodes = {n["grant_id"]: n for n in final["budget"]["nodes"]}
    assert [nodes[g["grant"]["grant_id"]]["revoked"] for g in grants] == [False, True, True]
    terminal = delegation["pending_result"]["result"]["_meta"]["agentguard"]
    assert terminal["outcome"] == "cancelled" and not terminal["dispatched"]
    rows, _, _ = audit(Path(delegation["execution_database"]))
    events = [json.loads(row["event_json"]) for row in rows if row["event_type"] == "GatewayExecutionFinished"]
    cancelled = next(event for event in events if event["action_sha256"] == delegation["pending"]["action_sha256"])
    assert cancelled["outcome"] == "cancelled" and cancelled["dispatched"] is False
    assert cancelled["side_effects"] == "not_dispatched"
    assert not Path(delegation["output"]).exists()
    assert not (Path(delegation["session"]["snapshot"]) / "output.txt").exists()
    program = """
const fs=require('node:fs'),c=require('node:crypto'),rows=JSON.parse(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify(rows.map(r=>c.verify(null,Buffer.from(r.message),c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(r.public,'hex')]),type:'spki',format:'der'}),Buffer.from(r.signature,'hex')))));
"""
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded(signatures))) == [True] * len(signatures)
    return {"passed": True, "signatures": len(signatures), "memory_versions": len(entries), "memory_audit_rows": len(records), "execution_audit_rows": len(gateway) + len(rows), "native_memory_mutations": 3, "stopped_branches": 2, "pending_dispatched": False, "binary_sha256": sha(binary.read_bytes())}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("memory", type=Path)
    parser.add_argument("delegation", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.memory, args.delegation, args.binary, args.node), ensure_ascii=False, indent=2))

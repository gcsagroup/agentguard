"""独立核对真实 AGD-022 进程验收；只读 SQLite、公钥和报告，不加载私钥。"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
module_spec = importlib.util.spec_from_file_location("memory_verifier", Path(__file__).with_name("verify-memory-store.py"))
helpers = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(helpers)
sha, encoded, read, rows, chain_hash = helpers.digest, helpers.encoded, helpers.read, helpers.rows, helpers.chain_hash


def verify(directory, frozen, repository, node):
    report = read(directory / "report.json")
    build = read(frozen / "build-inputs.json")
    assert report["passed"] and "error" not in report and "cleanup_error" not in report
    assert report["binary_sha256"] == build["binary_sha256"] == sha((frozen / "agentguard-mcp").read_bytes())
    assert Path(report["binary"]).resolve() == (frozen / "agentguard-mcp").resolve()
    for source in build["sources"]:
        path = Path(source["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert source["sha256"] == sha((frozen / "source" / path).read_bytes()) == sha((repository / path).read_bytes()), str(path)
    sessions = report["sessions"]
    assert len(sessions) == len({s["pid"] for s in sessions}) == len({s["session_id"] for s in sessions}) == 4
    assert all(s["exit"]["code"] == 0 and s["stats"]["memory"]["third_party_internal_memory"] == "uncovered" for s in sessions)
    assert report["loaded_models_before"] == report["loaded_models_after"]
    config = read(Path(report["config"]))
    assert report["database_sha256"] == sha(Path(config["database"]).read_bytes())
    assert report["witness_sha256"] == sha(Path(config["witness"]).read_bytes())
    public = Path(config["public_key"]).read_text().strip()
    assert public == report["public_key"]
    key_id = sha(bytes.fromhex(public))[:16]
    records, log_id, receipts = rows(Path(config["database"]))
    assert len(records) == 5 and receipts == 0
    head = read(Path(config["witness"]))
    assert head == {"schema_version": 1, "scope_id": config["scope_id"], "key_id": key_id,
                    "head": {"log_id": log_id, "seq": 5, "count": 5, "last_record_hash": records[-1]["record_hash"], "receipt_count": 0, "last_receipt_hash": ""}}
    signatures, previous = [], "AGENTGUARD-AUDIT-GENESIS-v1"
    for seq, row in enumerate(records, 1):
        computed = chain_hash(row, previous)
        assert row["seq"] == seq and row["signer_key_id"] == key_id and row["record_hash"] == computed and row["prev_hash"] == previous
        signatures.append({"message": "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, log_id, str(seq), computed]), "signature": row["record_sig"]})
        previous = computed
    program = """
const fs=require('node:fs'),c=require('node:crypto'),v=JSON.parse(fs.readFileSync(0,'utf8'));
const key=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(v.public,'hex')]),type:'spki',format:'der'});
process.stdout.write(JSON.stringify(v.rows.map(r=>c.verify(null,Buffer.from(r.message),key,Buffer.from(r.signature,'hex')))));
"""
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded({"public": public, "rows": signatures}))) == [True] * 5
    entries = [json.loads(row["event_json"]) for row in records[1:]]
    assert [(e["draft"]["key"], e["draft"]["version"], e["draft"]["state"]) for e in entries] == [
        ("preference", 1, "active"), ("doc-public", 1, "active"), ("doc-public", 2, "revoked"), ("doc-expiry", 1, "active")]
    approvals = report["approvals"]
    assert len(approvals) == 5 and approvals[0]["choice"] == "denied" and approvals[0]["before"] == approvals[0]["after"] == 0
    audit, _, _ = rows(Path(report["fixture"]) / "operator/audit.db")
    previous = "AGENTGUARD-AUDIT-GENESIS-v1"
    for row in audit:
        assert row["prev_hash"] == previous and row["record_hash"] == chain_hash(row, previous)
        previous = row["record_hash"]
    previous_entries, observed_sources = {}, {}
    for row in audit:
        body = json.loads(row["event_json"])
        if row["event_type"] == "GatewaySourceObserved":
            source = body["source"]
            assert source["source_id"] not in observed_sources or observed_sources[source["source_id"]] == source
            observed_sources[source["source_id"]] = source
    for entry, proof, row in zip(entries, approvals[1:], records[1:], strict=True):
        draft, approval = entry["draft"], entry["approval"]
        assert entry["content_sha256"] == sha(draft["content"].encode()) == proof["content_sha256"]
        assert proof["choice"] == "approved" and proof["after"] == proof["before"] + 1
        assert approval["action_sha256"] == proof["action_sha256"] and approval["actor_id"] == "authenticated-host-control"
        assert draft["label"] == {"integrity": "tainted", "confidentiality": "high"}
        assert draft["previous_sha256"] == previous_entries.get(draft["key"])
        assert row["id"] == "memory/" + sha(encoded(entry))
        previous_entries[draft["key"]] = sha(encoded(entry))
        assert approval["approved_at_ms"] <= entry["committed_at_ms"] < approval["expires_at_ms"]
        assert len(draft["sources"]) == proof["source_count"] > 0
        for source in draft["sources"]:
            assert observed_sources[source["source_id"]] == source
        terminal = [json.loads(r["event_json"]) for r in audit if r["event_type"] == "GatewayExecutionFinished" and json.loads(r["event_json"])["action_sha256"] == approval["action_sha256"]]
        assert len(terminal) == 1
        assert terminal[0]["dispatched"] and terminal[0]["outcome"] == "success"
        assert terminal[0]["approval_id_sha256"] == sha(approval["approval_id"].encode())
        assert terminal[0]["parameters_sha256"] == sha(encoded(draft, sort=True))
    model_tasks = report["model_tasks"]
    assert len(model_tasks) == 3 and all(t["passed"] for t in model_tasks)
    hit = model_tasks[0]["retrieved"]["hits"][0]
    assert hit["entry_sha256"] == sha(encoded(entries[1])) and hit["sources"] == entries[1]["draft"]["sources"]
    material = json.loads(entries[1]["draft"]["content"])
    assert hit["document"]["document_sha256"] == sha(material["text"].encode()) and hit["document"]["path"] == material["path"]
    for task in model_tasks:
        assert task["request_sha256"] == sha(encoded(task["request"]))
        assert task["gateway_session_id"] in {s["session_id"] for s in sessions}
    for task in model_tasks[1:]:
        assert task["retrieved"]["hits"] == []
        assert "HERON-" not in json.dumps(task["request"])
        assert "无可用资料" in task["response"]["choices"][0]["message"]["content"]
    return {"passed": True, "processes": 4, "signed_memory_rows": 5, "approved_versions": 4, "execution_audit_rows": len(audit),
            "model_tasks": 3, "source_files": len(build["sources"]), "gateway_sha256": report["binary_sha256"],
            "scope": "合成文档的真实网关与模型消费；脚本独立批准，CLI 为显式明文测试，加密另见 SQLCipher 测试"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

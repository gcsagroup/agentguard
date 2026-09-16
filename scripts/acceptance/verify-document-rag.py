"""只读核对隔离文档 RAG 的签名、原文件、批准绑定、来源和终态，不读取私钥。"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("memory_verify", Path(__file__).with_name("verify-memory-store.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
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
    assert all(s["exit"]["code"] == 0 for s in sessions)
    config = read(Path(report["config"]))
    assert report["database_sha256"] == sha(Path(config["database"]).read_bytes())
    assert report["witness_sha256"] == sha(Path(config["witness"]).read_bytes())
    public = Path(config["public_key"]).read_text().strip()
    assert public == report["public_key"]
    key_id = sha(bytes.fromhex(public))[:16]
    records, log_id, receipts = rows(Path(config["database"]))
    assert len(records) == 10 and receipts == 0
    head = read(Path(config["witness"]))
    assert head == {"schema_version": 1, "scope_id": config["scope_id"], "key_id": key_id,
                    "head": {"log_id": log_id, "seq": 10, "count": 10, "last_record_hash": records[-1]["record_hash"],
                             "receipt_count": 0, "last_receipt_hash": ""}}
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
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded({"public": public, "rows": signatures}))) == [True] * 10
    entries = [json.loads(row["event_json"]) for row in records[1:]]
    formats = ["pdf", "docx", "xlsx", "pptx", "png", "jpeg"]
    assert [(e["draft"]["key"], e["draft"]["version"], e["draft"]["state"]) for e in entries] == [
        *[("media-" + kind, 1, "active") for kind in formats], ("legacy", 1, "active"), ("media-pdf", 2, "revoked"), ("media-pdf", 3, "active")]
    approvals = report["approvals"]
    assert len(approvals) == 10 and approvals[0]["choice"] == "denied" and approvals[0]["before"] == approvals[0]["after"] == 0
    audit, _, _ = rows(Path(report["fixture"]) / "operator/audit.db")
    previous = "AGENTGUARD-AUDIT-GENESIS-v1"
    bodies, sources = [], {}
    for row in audit:
        assert row["prev_hash"] == previous and row["record_hash"] == chain_hash(row, previous)
        previous = row["record_hash"]
        body = json.loads(row["event_json"])
        bodies.append((row["event_type"], body))
        if row["event_type"] == "GatewaySourceObserved":
            source = body["source"]
            assert source["source_id"] not in sources or sources[source["source_id"]] == source
            sources[source["source_id"]] = source
    previous_entries = {}
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
        assert all(sources[source["source_id"]] == source for source in draft["sources"])
        terminal = [body for kind, body in bodies if kind == "GatewayExecutionFinished" and body["action_sha256"] == approval["action_sha256"]]
        assert len(terminal) == 1 and terminal[0]["dispatched"] and terminal[0]["outcome"] == "success"
        assert terminal[0]["approval_id_sha256"] == sha(approval["approval_id"].encode())
        assert terminal[0]["parameters_sha256"] == sha(encoded(draft, sort=True))
        material = json.loads(draft["content"])
        if material["kind"] == "parsed_document":
            document = material["document"]
            assert document["text_sha256"] == sha(document["text"].encode())
            assert document["parser_sha256"] == report["parser_sha256"] == sha((repository / "crates/guard-gateway/src/document_parser.py").read_bytes())
            assert document["image_sha256"] == report["image"][7:] and document["instruction_authority"] == "none"
            assert document["coverage"]["parsed_layers"] and document["coverage"]["uncovered"]
            # 宿主原文件后来改变；核对第一会话确实被解析的冻结副本。
            source_path = Path(sessions[0]["snapshot"]) / "workspace-0" / ("normal." + document["format"])
            assert document["source_sha256"] == sha(source_path.read_bytes())
            assert document["source_bytes"] == source_path.stat().st_size
            assert any(s["observation"].get("entry") == "tool_output" and s["observation"].get("content_sha256") == document["receipt_sha256"] for s in draft["sources"])
    assert entries[0]["draft"]["content"] == entries[-1]["draft"]["content"]
    assert len(report["imports"]) == len(formats)
    for proof, kind, entry in zip(report["imports"], formats, entries[:6], strict=True):
        assert proof["format"] == kind and proof["read"]["found"]
        memory = proof["read"]["memory"]
        assert memory["entry_sha256"] == sha(encoded(entry))
        assert memory["sources"] == entry["draft"]["sources"]
        assert memory["content"] == json.loads(entry["draft"]["content"])
        assert memory["key"] == "media-" + kind and memory["version"] == 1
    failures = [c for c in report["checks"] if isinstance(c, dict)]
    assert len(failures) == 10 and all(c["no_write"] for c in failures)
    assert sum(bool(c.get("injection_document")) for c in failures) == 1
    poison = next(c for c in failures if c.get("injection_document"))
    assert "来源图超过上限" not in poison["error"] and "超时" not in poison["error"]
    assert poison["rule_id"] == "INTEL-INJECT"
    injection = report["injection"]
    injection_config = read(Path(injection["config"]))
    assert injection["database_sha256"] == sha(Path(injection_config["database"]).read_bytes())
    assert injection["witness_sha256"] == sha(Path(injection_config["witness"]).read_bytes())
    empty_records, empty_log, empty_receipts = rows(Path(injection_config["database"]))
    assert len(empty_records) == 1 and empty_receipts == 0
    row = empty_records[0]
    assert row["seq"] == 1 and row["signer_key_id"] == key_id
    assert json.loads(row["event_json"]) == {"schema": "memory_store_v1", "scope_id": "document-rag-injection"}
    assert row["record_hash"] == chain_hash(row, "AGENTGUARD-AUDIT-GENESIS-v1")
    signature = {"message": "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, empty_log, "1", row["record_hash"]]), "signature": row["record_sig"]}
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded({"public": public, "rows": [signature]}))) == [True]
    negative_audit, _, _ = rows(Path(injection["audit"]))
    previous = "AGENTGUARD-AUDIT-GENESIS-v1"
    negative_bodies = []
    for row in negative_audit:
        assert row["prev_hash"] == previous and row["record_hash"] == chain_hash(row, previous)
        previous = row["record_hash"]
        negative_bodies.append((row["event_type"], json.loads(row["event_json"])))
    refused = [b for k, b in negative_bodies if k == "GatewayDecision" and b["action_sha256"] == poison["action_sha256"]]
    assert len(refused) == 1 and refused[0]["decision"] == "refuse"
    assert any(f["rule_id"] == "INTEL-INJECT" for f in refused[0]["findings"])
    terminals = [b for k, b in negative_bodies if k == "GatewayExecutionFinished" and b["action_sha256"] == poison["action_sha256"]]
    assert len(terminals) == 1 and terminals[0]["outcome"] == "refused" and not terminals[0]["dispatched"]
    return {"passed": True, "processes": 4, "formats": 6, "signed_memory_rows": 10, "approved_versions": 9,
            "injection_signed_rows": 1, "execution_audit_rows": len(audit), "injection_audit_rows": len(negative_audit),
            "source_files": len(build["sources"]), "gateway_sha256": report["binary_sha256"],
            "scope": "合成文档的真实网关 RAG；独立脚本批准，不代表原生、中文 OCR 或模型任务验收"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

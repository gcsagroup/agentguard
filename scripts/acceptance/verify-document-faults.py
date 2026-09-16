"""独立只读核对解析故障、部分覆盖和已批准记忆，不读取测试私钥。"""
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
    report, build = read(directory / "report.json"), read(frozen / "build-inputs.json")
    assert report["passed"] and "error" not in report and "cleanup_error" not in report
    assert report["exit"] == {"code": 0, "signal": None}
    assert report["binary_sha256"] == build["binary_sha256"] == sha((frozen / "agentguard-mcp").read_bytes())
    for item in build["sources"]:
        path = Path(item["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert item["sha256"] == sha((frozen / "source" / path).read_bytes()) == sha((repository / path).read_bytes())
    assert report["parser_sha256"] == sha((repository / "crates/guard-gateway/src/document_parser.py").read_bytes())
    image = report["session"]["stats"]["execution_backend"]["image"]
    assert report["image"] == image
    root = Path(report["fixture"])
    for name, identity in report["initial_tree"].items():
        assert identity["kind"] == "file"
        data = (root / "workspace" / name).read_bytes()
        assert len(data) == identity["bytes"] and sha(data) == identity["sha256"]
    config = read(Path(report["config"]))
    assert report["database_sha256"] == sha(Path(config["database"]).read_bytes())
    assert report["witness_sha256"] == sha(Path(config["witness"]).read_bytes())
    public = Path(config["public_key"]).read_text().strip()
    assert report["public_key"] == public
    key_id = sha(bytes.fromhex(public))[:16]
    memory, log_id, receipts = rows(Path(config["database"]))
    assert len(memory) == 5 and receipts == 0
    signatures, previous = [], "AGENTGUARD-AUDIT-GENESIS-v1"
    for seq, row in enumerate(memory, 1):
        computed = chain_hash(row, previous)
        assert row["seq"] == seq and row["signer_key_id"] == key_id
        assert row["prev_hash"] == previous and row["record_hash"] == computed
        signatures.append({"message": "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, log_id, str(seq), computed]), "signature": row["record_sig"]})
        previous = computed
    assert read(Path(config["witness"])) == {"schema_version": 1, "scope_id": config["scope_id"], "key_id": key_id,
        "head": {"log_id": log_id, "seq": 5, "count": 5, "last_record_hash": previous, "receipt_count": 0, "last_receipt_hash": ""}}
    program = """
const fs=require('node:fs'),c=require('node:crypto'),v=JSON.parse(fs.readFileSync(0,'utf8'));
const key=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(v.public,'hex')]),type:'spki',format:'der'});
process.stdout.write(JSON.stringify(v.rows.map(r=>c.verify(null,Buffer.from(r.message),key,Buffer.from(r.signature,'hex')))));
"""
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded({"public": public, "rows": signatures}))) == [True] * 5
    audit, _, _ = rows(root / "operator/audit.db")
    previous, events = "AGENTGUARD-AUDIT-GENESIS-v1", []
    for row in audit:
        assert row["prev_hash"] == previous and row["record_hash"] == chain_hash(row, previous)
        previous = row["record_hash"]
        events.append((row["event_type"], json.loads(row["event_json"])))
    finished = [body for kind, body in events if kind == "GatewayExecutionFinished"]
    faults = report["faults"]
    assert [f["mode"] for f in faults] == ["kill", "pause"]
    assert [f["key"] for f in faults] == ["killed", "timed-out"]
    for fault in faults:
        assert fault["passed"] and fault["injected"] and fault["network"] == "none" and fault["image"] == image
        assert fault["before"] == fault["after"] and fault["containers_after"] == []
        assert fault["no_automatic_retry_ms"] >= 1000 and fault["injected_after_ms"] < fault["elapsed_ms"]
        terminal = fault["terminal"]
        assert terminal["outcome"] == "unknown" and terminal["dispatched"] is True
        assert terminal["target_sha256"] == sha(fault["request"]["ParseDocument"]["path"].encode())
        assert [f for f in finished if f["action_sha256"] == terminal["action_sha256"]] == [terminal]
    assert 30000 <= faults[1]["elapsed_ms"] < 45000
    assert len([f for f in finished if f["target_sha256"] == faults[0]["terminal"]["target_sha256"]]) == 2
    assert [p["key"] for p in report["imports"]] == ["after-kill", "after-timeout", "partial", "external"]
    for index, (row, proof) in enumerate(zip(memory[1:], report["imports"], strict=True)):
        entry = json.loads(row["event_json"])
        draft, approval = entry["draft"], entry["approval"]
        assert draft["key"] == proof["key"] and draft["version"] == 1 and draft["state"] == "active"
        assert draft["label"] == {"integrity": "tainted", "confidentiality": "high"}
        assert proof["before"] == index and proof["after"] == index + 1
        assert entry["content_sha256"] == sha(draft["content"].encode()) and row["id"] == "memory/" + sha(encoded(entry))
        assert json.loads(draft["content"]) == proof["material"]
        d = proof["material"]["document"]
        assert d["source_sha256"] == report["initial_tree"][proof["file"]]["sha256"]
        assert d["source_bytes"] == report["initial_tree"][proof["file"]]["bytes"]
        assert d["text_sha256"] == sha(d["text"].encode()) and d["instruction_authority"] == "none"
        assert d["parser_sha256"] == report["parser_sha256"] and d["image_sha256"] == image.removeprefix("sha256:")
        assert approval["action_sha256"] == proof["action_sha256"] and approval["actor_id"] == "authenticated-host-control"
        terminal, = [f for f in finished if f["action_sha256"] == approval["action_sha256"]]
        assert terminal["outcome"] == "success" and terminal["dispatched"]
        assert terminal["parameters_sha256"] == sha(encoded(draft, sort=True))
        assert terminal["approval_id_sha256"] == sha(approval["approval_id"].encode())
        assert d["status"] == ("partial" if proof["key"] == "partial" else "parsed")
        if proof["key"] == "partial":
            assert d["coverage"]["empty_units"] == ["page:2"] and len(d["segments"]) == 1
        if proof["key"] == "external":
            assert any("外部关系" in s for s in d["coverage"]["uncovered"])
            assert "AGD-SYNTHETIC-OUTSIDE-MARKER-7461" not in draft["content"]
            assert all(f"EXTERNAL-LINK-{i}" in d["text"] for i in range(2))
    assert report["checks"][0]["case"] == "empty" and report["checks"][0]["no_write"]
    assert report["checks"][1] == {"case": "external-relations", "listener_calibrated": True, "body_references": 2, "observed_http_requests": [], "private_marker_unchanged": True, "workspace_unchanged": True}
    return {"passed": True, "signed_rows": len(memory), "execution_audit_rows": len(audit), "faults": 2,
            "approved_imports": 4, "source_files": len(build["sources"]),
            "scope": "合成 CLI 故障、部分覆盖和外部关系对照；不代表中文 OCR、全部 Office 关系或原生验收"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

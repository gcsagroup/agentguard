"""独立核对 AGD-026 操作者操作与实际签名存储；仅读取公钥，不加载私钥。"""
import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("memory_helpers", Path(__file__).with_name("verify-persistence-propagation.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
sha, encoded, read, audit = helpers.sha, helpers.encoded, helpers.read, helpers.audit


def verify(directory, frozen, repository, node):
    report, build = read(directory / "report.json"), read(frozen / "build-inputs.json")
    assert report["passed"] and not report.get("error") and not report.get("cleanup_error")
    assert Path(report["binary"]).resolve() == (frozen / "agentguard-mcp").resolve()
    assert report["binary_sha256"] == build["binary_sha256"] == sha((frozen / "agentguard-mcp").read_bytes())
    for source in build["sources"]:
        path = Path(source["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert source["sha256"] == sha((repository / path).read_bytes()) == sha((frozen / "source" / path).read_bytes())
    sessions = report["sessions"]
    assert len(sessions) == len({s["pid"] for s in sessions}) == len({s["session_id"] for s in sessions}) == 3
    assert all(s["exit"]["code"] == 0 for s in sessions)
    records, log_id, receipts = audit(Path(report["memory_database"]))
    assert len(records) == 8 and receipts == 0
    public = report["public_key"]
    key_id = sha(bytes.fromhex(public))[:16]
    head = read(Path(report["memory_witness"]))
    assert head["key_id"] == key_id
    assert head["head"] == {"log_id": log_id, "seq": 8, "count": 8, "last_record_hash": records[-1]["record_hash"],
                           "receipt_count": 0, "last_receipt_hash": ""}
    signatures = []
    for row in records:
        assert row["signer_key_id"] == key_id
        signatures.append({"message": "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, log_id, str(row["seq"]), row["record_hash"]]), "signature": row["record_sig"]})
    program = """
const fs=require('node:fs'),c=require('node:crypto'),v=JSON.parse(fs.readFileSync(0,'utf8'));
const key=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(v.public,'hex')]),type:'spki',format:'der'});
process.stdout.write(JSON.stringify(v.rows.map(r=>c.verify(null,Buffer.from(r.message),key,Buffer.from(r.signature,'hex')))));
"""
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded({"public": public, "rows": signatures}))) == [True] * 8
    entries = [json.loads(row["event_json"]) for row in records[1:]]
    assert [(e["draft"]["key"], e["draft"]["version"], e["draft"]["state"]) for e in entries] == [
        ("preference", 1, "active"), ("preference", 2, "active"), ("document", 1, "active"),
        ("preference", 3, "quarantined"), ("preference", 4, "active"), ("preference", 5, "active"), ("preference", 6, "revoked")]
    requests = report["requests"]
    assert all(r["response"]["status"] == r["expected"] for r in requests)
    assert any(r["authentication_negative"] and r["expected"] == 403 for r in requests)
    assert any(r["origin_negative"] and r["expected"] == 403 for r in requests)
    previews = {r["response"]["value"]["data"]["review_id"]: r["response"]["value"]["data"]
                for r in requests if r["route"] == "preview" and r["expected"] == 200}
    for preview in previews.values():
        assert preview["draft"] == preview["action"]["parameters"]
        assert preview["draft"]["sources"] == preview["action"]["sources"]
        assert preview["review_sha256"] == sha(b"agentguard.execution.action.v1\0" + encoded(preview["action"], sort=True))
    proofs = {s["pending"]["action_sha256"]: s["pending"]["binding"]["action"] for s in report["seeds"]}
    nonces = {s["pending"]["action_sha256"]: s["pending"]["binding"]["nonce"] for s in report["seeds"]}
    applied = [r for r in requests if r["route"] == "apply" and r["expected"] == 200]
    assert len(applied) == 3
    for row in applied:
        review = previews[row["body"]["review_id"]]
        assert row["body"]["review_nonce"] == review["review_nonce"]
        assert row["body"]["review_sha256"] == review["review_sha256"]
        assert row["response"]["value"]["data"]["execution"]["_meta"]["agentguard"]["outcome"] == "success"
        proofs[review["review_sha256"]] = review["action"]
        nonces[review["review_sha256"]] = review["review_nonce"]
    assert len(proofs) == len(entries) == 7
    gateway, _, _ = audit(Path(report["execution_database"]))
    bodies = [(r, json.loads(r["event_json"])) for r in gateway]
    terminals = {b["action_sha256"]: b for r, b in bodies if r["event_type"] == "GatewayExecutionFinished"}
    sources = {b["source"]["source_id"]: b["source"] for r, b in bodies if r["event_type"] == "GatewaySourceObserved"}
    previous = {}
    for entry, row in zip(entries, records[1:], strict=True):
        draft, approval = entry["draft"], entry["approval"]
        action = proofs[approval["action_sha256"]]
        assert sha(b"agentguard.execution.action.v1\0" + encoded(action, sort=True)) == approval["action_sha256"]
        assert action["parameters"] == draft and action["sources"] == draft["sources"]
        assert draft["label"] == {"integrity": "tainted", "confidentiality": "high"}
        assert approval["actor_id"] == "authenticated-host-control"
        assert approval["nonce_sha256"] == sha(nonces[approval["action_sha256"]].encode())
        assert approval["approved_at_ms"] <= entry["committed_at_ms"] < approval["expires_at_ms"]
        assert entry["content_sha256"] == sha(draft["content"].encode())
        assert draft["previous_sha256"] == previous.get(draft["key"])
        previous[draft["key"]] = sha(encoded(entry))
        assert row["id"] == "memory/" + previous[draft["key"]]
        assert all(sources[source["source_id"]] == source for source in draft["sources"])
        terminal = terminals[approval["action_sha256"]]
        assert terminal["dispatched"] and terminal["outcome"] == "success"
        assert terminal["approval_id_sha256"] == sha(approval["approval_id"].encode())
    assert entries[4]["draft"]["content"] == entries[0]["draft"]["content"]
    assert all(source in entries[4]["draft"]["sources"] for source in entries[1]["draft"]["sources"])
    history = report["final_history"]
    assert history["current_version"] == 6 and len(history["versions"]) == 6
    for shown, entry in zip(history["versions"], [e for e in entries if e["draft"]["key"] == "preference"], strict=True):
        assert shown["entry_sha256"] == sha(encoded(entry))
        assert shown["sources"] == entry["draft"]["sources"] and shown["state"] == entry["draft"]["state"]
    return {"passed": True, "processes": 3, "signed_memory_rows": 8, "versions": 7, "operator_mutations": 3,
            "execution_audit_rows": len(gateway), "http_requests": len(requests), "binary_sha256": report["binary_sha256"],
            "scope": "宿主脚本经真实认证通道批准；原生治理入口尚未验收"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

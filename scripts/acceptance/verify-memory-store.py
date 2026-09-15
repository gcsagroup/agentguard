"""只读核对 AGD-021 合成实操；使用独立 SQLite 读取和 Node Ed25519，不加载私钥。"""
import argparse
import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def encoded(value, *, sort=False):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=sort).encode()


def rows(path):
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        records = [dict(r) for r in db.execute("SELECT * FROM audit_events ORDER BY seq")]
        log_id = db.execute("SELECT value FROM audit_meta WHERE key='log_id'").fetchone()[0]
        receipts = db.execute("SELECT count(*) FROM decision_receipts").fetchone()[0]
    return records, log_id, receipts


def chain_hash(row, previous):
    fields = ["id", "timestamp_ms", "platform", "event_type", "source_app", "agent_session_id",
              "rule_id", "severity", "action", "human_message", "evidence_ref", "event_json"]
    content = "\x1f".join(str(row[k]) if row[k] is not None else "" for k in fields)
    if row["attributed_agent"] is not None:
        content += "\x1fagent=" + row["attributed_agent"]
    return digest((previous + "\n" + content).encode())


def verify(directory, frozen, repository, node):
    report = read(directory / "report.json")
    build = read(frozen / "build-inputs.json")
    executable = frozen / "guard-audit-tests"
    assert report["passed"] and report["tampered_revocation_refused"]
    assert Path(report["test_executable"]).resolve() == executable.resolve()
    assert report["test_executable_sha256"] == build["test_executable_sha256"] == digest(executable.read_bytes())
    assert len(build["sources"]) == len({s["path"] for s in build["sources"]}) > 0
    for source in build["sources"]:
        path = Path(source["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert source["sha256"] == digest((frozen / "source" / path).read_bytes())
        assert source["sha256"] == digest((repository / path).read_bytes()), str(path)
    steps = report["steps"]
    assert [s["phase"] for s in steps] == ["create", "read", "revoke", "read-revoked"]
    assert [s["versions"] for s in steps] == [1, 1, 2, 2]
    assert len({s["pid"] for s in steps}) == 4 and all(s["pid"] > 0 for s in steps)
    pristine = directory / "data/memory-pristine.db"
    corrupt = directory / "data/memory.db"
    assert report["pristine_database_sha256"] == digest(pristine.read_bytes())
    assert report["tampered_database_sha256"] == digest(corrupt.read_bytes())
    public = (directory / "operator/public.hex").read_text().strip()
    assert public == report["public_key"] and len(bytes.fromhex(public)) == 32
    key_id = digest(bytes.fromhex(public))[:16]
    anchor = read(directory / "operator/head.json")
    good, log_id, receipts = rows(pristine)
    bad, bad_id, bad_receipts = rows(corrupt)
    assert len(good) == len(bad) == 3 and log_id == bad_id and receipts == bad_receipts == 0
    assert anchor == {"schema_version": 1, "scope_id": "项目", "key_id": key_id,
                      "head": {"log_id": log_id, "seq": 3, "count": 3,
                               "last_record_hash": good[-1]["record_hash"],
                               "receipt_count": 0, "last_receipt_hash": ""}}
    signatures = []
    for records in (good, bad):
        previous = "AGENTGUARD-AUDIT-GENESIS-v1"
        for seq, row in enumerate(records, 1):
            assert row["seq"] == seq and row["signer_key_id"] == key_id
            computed = chain_hash(row, previous)
            if records is good:
                assert row["prev_hash"] == previous and row["record_hash"] == computed
                assert row["user_decision"] is None and row["attributed_agent"] is None
            message = "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, log_id, str(seq), computed])
            signatures.append({"message": message, "signature": row["record_sig"]})
            previous = computed
    assert good[:2] == bad[:2]
    altered = json.loads(bad[2]["event_json"])
    assert altered["draft"]["state"] == "active"
    altered["draft"]["state"] = "revoked"
    assert altered == json.loads(good[2]["event_json"])
    assert json.loads(good[0]["event_json"]) == {"schema": "memory_store_v1", "scope_id": "项目"}
    previous_entry = None
    for version, row in enumerate(good[1:], 1):
        entry = json.loads(row["event_json"])
        assert row["event_json"].encode() == encoded(entry)
        entry_sha = digest(encoded(entry))
        assert row["id"] == "memory/" + entry_sha
        draft = entry["draft"]
        assert draft == {"schema_version": 1, "scope_id": "项目", "key": "偏好", "version": version,
                         "previous_sha256": previous_entry,
                         "content": "AGD_MEMORY_SYNTHETIC 中文😀\n来源不是执行指令。",
                         "sources": [{"source_id": "unknown-origin", "observation": {"status": "unknown", "reason": "not_observed"}}],
                         "label": {"integrity": "tainted", "confidentiality": "high"},
                         "created_at_ms": 90 + 10 * version, "expires_at_ms": 1000,
                         "state": "active" if version == 1 else "revoked"}
        assert entry["content_sha256"] == digest(draft["content"].encode())
        nonce = f"{version:032x}"
        action = {"contract_version": 1, "session_id": "host-session", "action_id": f"action-{version}",
                  "request_id": f"request-{version}", "tool": {"service": "agentguard-memory", "name": "memory_write", "version": "1"},
                  "target": "memory://项目/偏好", "parameters": draft, "policy_version": "policy-v1",
                  "issued_at_ms": draft["created_at_ms"], "expires_at_ms": 1000,
                  "nonce": nonce, "sources": draft["sources"]}
        assert entry["approval"] == {"approval_id": f"approval-{version}", "actor_id": "authenticated-host-operator",
                                     "session_id": "host-session", "action_id": f"action-{version}", "request_id": f"request-{version}",
                                     "policy_version": "policy-v1", "action_sha256": digest(b"agentguard.execution.action.v1\0" + encoded(action, sort=True)),
                                     "nonce_sha256": digest(nonce.encode()), "approved_at_ms": draft["created_at_ms"] + 1, "expires_at_ms": 1000}
        assert entry["committed_at_ms"] == row["timestamp_ms"] == draft["created_at_ms"] + 2
        previous_entry = entry_sha
    # 公钥来自宿主目录；对篡改行重新计算待验签摘要，不能直接验证库中旧摘要。
    program = """
const fs=require('node:fs'), c=require('node:crypto');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const key=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(input.public,'hex')]),type:'spki',format:'der'});
process.stdout.write(JSON.stringify(input.rows.map(r=>c.verify(null,Buffer.from(r.message),key,Buffer.from(r.signature,'hex')))));
"""
    verified = json.loads(subprocess.check_output([node, "-e", program], input=encoded({"public": public, "rows": signatures})))
    assert verified == [True, True, True, True, True, False], verified
    return {"passed": True, "independent_processes": 4, "signed_rows": 3, "versions": 2,
            "full_field_and_approval_bindings": 2, "rewritten_revocation_signature_refused": True,
            "source_files": len(build["sources"]), "test_executable_sha256": report["test_executable_sha256"],
            "scope": "仅合成宿主存储实操；不代表网关、RAG、原生人工批准或所有宿主"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

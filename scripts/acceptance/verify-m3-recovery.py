"""只读复核 M3 崩溃恢复、主体公钥更换和删除；独立验签并核对实际 SQLite，不读取私钥。"""
import argparse
import collections
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


def binding(domain, value):
    return f"agentguard.delegation.{domain}.v1\0".encode() + encoded(value, sort=True)


def verify(directory, frozen, repository, node):
    report, build = read(directory / "report.json"), read(frozen / "build-inputs.json")
    assert report["passed"] and not report.get("error") and not report.get("cleanup_error")
    assert Path(report["binary"]).resolve() == (frozen / "agentguard-mcp").resolve()
    assert report["binary_sha256"] == build["binary_sha256"] == sha((frozen / "agentguard-mcp").read_bytes())
    assert report["script_sha256"] == sha((directory / "harness-source.mjs").read_bytes()) == sha((repository / "scripts/acceptance/agd-m3-recovery.mjs").read_bytes())
    for item in build["sources"]:
        path = Path(item["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert item["sha256"] == sha((frozen / "source" / path).read_bytes()) == sha((repository / path).read_bytes())
    sessions = report["sessions"]
    assert [s["phase"] for s in sessions] == ["seed-and-crash", "old-key", "rotated-key", "removed-principal"]
    assert len({s["pid"] for s in sessions}) == len({s["session_id"] for s in sessions}) == len({s["instance_id"] for s in sessions}) == 4
    assert sessions[0]["exit"]["signal"] == "SIGKILL" and all(s["exit"]["code"] == 0 for s in sessions[1:])
    assert report["crash_result"].get("transport_error") and report["crash"]["exitedAt"] >= report["crash"]["faultAt"]
    configs = {s["phase"]: {p["subject_id"]: p for p in s["config"]["principals"]} for s in sessions[1:]}
    assert configs["old-key"]["B"]["public_key"] == report["publics"]["B-old"]
    assert configs["rotated-key"]["B"]["public_key"] == report["publics"]["B-new"]
    assert report["publics"]["B-old"] != report["publics"]["B-new"] and "B" not in configs["removed-principal"]
    assert configs["removed-principal"]["A"]["permissions"]["delegate_to"] == []
    for phase in ["old-key", "rotated-key"]:
        assert configs[phase]["B"]["permissions"] == configs["old-key"]["B"]["permissions"]

    signatures = []
    records, log_id, receipts = audit(Path(report["memory_config"]["database"]))
    assert len(records) == 2 and receipts == 0
    public = report["publics"]["memory"]
    assert Path(report["memory_config"]["public_key"]).read_text() == public
    key_id = sha(bytes.fromhex(public))[:16]
    head = read(Path(report["memory_config"]["witness"]))
    assert head == {"schema_version": 1, "scope_id": "m3-recovery", "key_id": key_id,
                    "head": {"log_id": log_id, "seq": 2, "count": 2, "last_record_hash": records[-1]["record_hash"], "receipt_count": 0, "last_receipt_hash": ""}}
    for row in records:
        assert row["signer_key_id"] == key_id
        signatures.append((public, "\x1f".join(["AGENTGUARD-AUDIT-RECORD-v2", key_id, log_id, str(row["seq"]), row["record_hash"]]).encode(), row["record_sig"], True))
    entry = json.loads(records[1]["event_json"])
    draft, approval = entry["draft"], entry["approval"]
    pending = report["seed"]["pending"]
    action = pending["binding"]["action"]
    assert action["parameters"] == draft and action["sources"] == draft["sources"]
    assert sha(b"agentguard.execution.action.v1\0" + encoded(action, sort=True)) == pending["action_sha256"] == approval["action_sha256"]
    assert approval["nonce_sha256"] == sha(pending["binding"]["nonce"].encode())
    assert approval["approved_at_ms"] <= entry["committed_at_ms"] < approval["expires_at_ms"]
    assert draft["version"] == 1 and draft["state"] == "active" and draft["previous_sha256"] is None
    assert draft["label"] == {"integrity": "tainted", "confidentiality": "high"}
    assert json.loads(draft["content"])["text"] == "已批准的中文偏好"
    assert entry["content_sha256"] == sha(draft["content"].encode()) and records[1]["id"] == "memory/" + sha(encoded(entry))
    shown = report["final_history"]["versions"]
    assert len(shown) == 1 and shown[0]["entry_sha256"] == sha(encoded(entry))
    assert shown[0]["sources"] == draft["sources"] and shown[0]["approval"] == approval
    assert report["initial_history"] == report["final_history"]
    requests = report["memory_requests"]
    assert sum(r["route"] == "apply" for r in requests) == 1
    assert all(r["response"]["status"] == (409 if r["route"] == "apply" else 200) for r in requests)
    assert all(r["response"]["value"]["data"] == report["initial_history"] for r in requests if r["route"] == "history")

    gateway, _, _ = audit(Path(report["execution_database"]))
    bodies = [(row, json.loads(row["event_json"])) for row in gateway]
    terminals = {b["action_sha256"]: b for r, b in bodies if r["event_type"] == "GatewayExecutionFinished"}
    assert terminals[approval["action_sha256"]]["outcome"] == "success" and terminals[approval["action_sha256"]]["dispatched"]
    crash_action = report["crash_pending"]["binding"]["action"]
    assert json.loads(crash_action["parameters"]["content"])["text"] == "崩溃前未批准，不得保存"
    assert report["crash_pending"]["action_sha256"] == sha(b"agentguard.execution.action.v1\0" + encoded(crash_action, sort=True))
    crash_terminal = terminals.get(report["crash_pending"]["action_sha256"])
    assert not crash_terminal or (not crash_terminal["dispatched"] and crash_terminal["outcome"] != "success")
    sources = {b["source"]["source_id"]: b["source"] for r, b in bodies if r["event_type"] == "GatewaySourceObserved"}
    assert all(sources[source["source_id"]] == source for source in draft["sources"])

    grants = {sha(binding("grant", g["grant"])): g for g in report["grants"]}
    assert len(grants) == 5
    for digest, signed in grants.items():
        g = signed["grant"]
        signatures.append((report["publics"]["authority"], binding("grant", g), signed["signature"], True))
        assert signed["key_id"] == sha(bytes.fromhex(report["publics"]["authority"]))[:16]
        if g["parent_grant_sha256"]:
            parent = grants[g["parent_grant_sha256"]]["grant"]
            assert g["parent_session_id"] == parent["session_id"] and g["host_session_id"] == parent["host_session_id"]
            assert g["delegator_id"] == parent["subject_id"] == "A" and g["subject_id"] == "B"
            for permission, values in g["permissions"].items():
                assert set(values) <= set(parent["permissions"][permission])
        else:
            assert g["subject_id"] == "A" and g["parent_session_id"] is None
    accepted = [b for r, b in bodies if r["event_type"] == "GatewayDelegationAccepted"]
    cases = report["messages"]
    assert len(cases) == 9
    expected = [c for c in cases if c["expected"] == "accepted"]
    assert len(expected) == len(accepted) == 5
    seqs = collections.defaultdict(int)
    for case, body in zip(expected, accepted, strict=True):
        envelope = case["envelope"]
        message = envelope["message"]
        assert body["receipt"]["message"] == message and body["receipt"]["signature"] == envelope["signature"]
        assert body["receipt"]["subject_public_key"] == configs[case["phase"]][message["actor_id"]]["public_key"]
        seqs[message["grant_id"]] += 1
        assert message["sequence"] == seqs[message["grant_id"]]
        g = grants[message["grant_sha256"]]["grant"]
        assert all(message[k] == g[k] for k in ["grant_id", "session_id", "host_session_id", "target_id"])
        assert message["actor_id"] == g["subject_id"]
        assert case["response"]["result"]["isError"] is False
    for case in cases:
        envelope, response = case["envelope"], case["response"]["result"]
        assert envelope["message"]["operation_sha256"] == sha(binding("operation", envelope["command"]))
        signatures.append((report["publics"][case["signing_actor"]], binding("message", envelope["message"]), envelope["signature"], True))
        if case["expected"] == "refused":
            assert response["isError"] and not response["_meta"]["agentguard"]["dispatched"]
        elif envelope["command"]["operation"] == "read_file":
            assert response["content"][0]["text"] == "AGD_M3_NORMAL_READ 中文\n"
    by_name = {c["name"]: c for c in cases}
    wrong = by_name["revoked-key-new-metadata"]["envelope"]
    right = by_name["replacement-key-same-message"]["envelope"]
    assert wrong["message"] == right["message"] and wrong["command"] == right["command"]
    assert wrong["signature"] != right["signature"]
    rotated = sessions[2]
    assert wrong["message"]["host_session_id"] == rotated["session_id"]
    signatures.append((report["publics"]["B-new"], binding("message", wrong["message"]), wrong["signature"], False))
    assert by_name["old-session-replay"]["envelope"] == by_name["old-key-normal"]["envelope"]
    removed = by_name["removed-subject-new-session"]["envelope"]["message"]
    assert removed["host_session_id"] == sessions[3]["session_id"] and removed["actor_id"] == "B"
    assert "主体未登记" in by_name["removed-subject-new-session"]["response"]["result"]["content"][0]["text"]
    program = """
const fs=require('node:fs'),c=require('node:crypto'),rows=JSON.parse(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify(rows.map(r=>c.verify(null,Buffer.from(r.message,'hex'),c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(r.public,'hex')]),type:'spki',format:'der'}),Buffer.from(r.signature,'hex')))));
"""
    payload = [{"public": p, "message": m.hex(), "signature": s} for p, m, s, _ in signatures]
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded(payload))) == [v for _, _, _, v in signatures]
    fixture = Path(report["fixture"])
    assert (fixture / "workspace/input.txt").read_text() == "AGD_M3_NORMAL_READ 中文\n"
    assert sorted(p.name for p in (fixture / "workspace").iterdir()) == ["input.txt"]
    return {"passed": True, "processes": 4, "sigkill": 1, "memory_versions": 1, "memory_audit_rows": 2,
            "execution_audit_rows": len(gateway), "signature_checks": len(signatures), "accepted_messages": 5,
            "refused_messages": 4, "replacement_signature_same_message": True, "source_files": len(build["sources"]),
            "scope": "主体公钥撤销依赖停止旧宿主并重开；不证明运行中配置热更新、原生人工批准或全平台"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

"""独立核对 AGD-023 的公钥签名、父链、序号、动作绑定、审计与真实文件；不读取私钥。"""
import argparse
import collections
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("audit_helpers", Path(__file__).with_name("verify-memory-store.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
sha, read, rows, chain_hash = helpers.digest, helpers.read, helpers.rows, helpers.chain_hash


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def binding(domain, value):
    return f"agentguard.delegation.{domain}.v1\0".encode() + encoded(value)


def verify(directory, frozen, repository, node):
    report, build = read(directory / "report.json"), read(frozen / "build-inputs.json")
    assert report["passed"] and not report.get("error") and not report.get("cleanup_error")
    assert report["binary_sha256"] == build["binary_sha256"] == sha((frozen / "agentguard-mcp").read_bytes())
    assert Path(report["binary"]).resolve() == (frozen / "agentguard-mcp").resolve()
    for source in build["sources"]:
        path = Path(source["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert source["sha256"] == sha((frozen / "source" / path).read_bytes()) == sha((repository / path).read_bytes()), str(path)
    sessions = report["sessions"]
    assert len(sessions) == len({s["pid"] for s in sessions}) == len({s["session_id"] for s in sessions}) == 2
    assert all(s["exit"]["code"] == 0 for s in sessions)
    config = read(Path(report["config"]))  # 只含公钥及路径，绝不打开 signing_key。
    principals = {p["subject_id"]: p for p in config["principals"]}
    fixture = Path(report["fixture"])
    assert sha((fixture / "operator/rules.yaml").read_bytes()) == report["inputs"]["rulesSha256"]
    grants, signatures = {}, []
    for signed in report["grants"]:
        grant = signed["grant"]
        digest = sha(binding("grant", grant))
        assert digest not in grants
        assert signed["key_id"] == sha(bytes.fromhex(config["public_key"]))[:16]
        assert grant["authority_id"] == config["authority_id"] and grant["target_id"] == config["target_id"]
        assert grant["host_session_id"] in {s["session_id"] for s in sessions}
        assert grant["issued_at_ms"] < grant["expires_at_ms"]
        signatures.append((config["public_key"], binding("grant", grant), signed["signature"]))
        if grant["parent_grant_sha256"]:
            parent = grants[grant["parent_grant_sha256"]]["grant"]
            assert grant["parent_session_id"] == parent["session_id"]
            assert grant["delegator_id"] == parent["subject_id"] and grant["subject_id"] in parent["permissions"]["delegate_to"]
            assert grant["host_session_id"] == parent["host_session_id"] and grant["expires_at_ms"] <= parent["expires_at_ms"]
        else:
            assert grant["subject_id"] == config["root_subject_id"]
            assert grant["parent_session_id"] is None and grant["delegator_id"] is None
            assert grant["permissions"] == principals[grant["subject_id"]]["permissions"]
        grants[digest] = signed
    assert len(grants) == 5
    audit, _, _ = rows(fixture / "operator/audit.db")
    previous = "AGENTGUARD-AUDIT-GENESIS-v1"
    grouped = collections.defaultdict(list)
    for sequence, row in enumerate(audit, 1):
        assert row["seq"] == sequence and row["prev_hash"] == previous and row["record_hash"] == chain_hash(row, previous)
        previous = row["record_hash"]
        grouped[row["event_type"]].append((row, json.loads(row["event_json"])))
    root_rows = grouped["GatewayDelegationRoot"]
    assert len(root_rows) == 2
    for row, body in root_rows:
        signed = grants[body["grant_sha256"]]
        assert row["agent_session_id"] == signed["grant"]["host_session_id"]
        assert body["signature"] == signed["signature"] and body["key_id"] == signed["key_id"]
    accepted = grouped["GatewayDelegationAccepted"]
    expected = [m for m in report["messages"] if m["authenticated_expected"]]
    assert len(accepted) == len(expected) == 12
    seqs, operations = collections.defaultdict(int), collections.Counter()
    accepted_by_digest = {}
    for (row, body), case in zip(accepted, expected, strict=True):
        envelope = case["envelope"]
        message, command = envelope["message"], envelope["command"]
        receipt = body["receipt"]
        assert receipt["message"] == message and receipt["signature"] == envelope["signature"]
        assert receipt["instruction_authority"] == "none"
        public = principals[message["actor_id"]]["public_key"]
        assert receipt["subject_public_key"] == public
        signatures.append((public, binding("message", message), envelope["signature"]))
        assert message["operation_sha256"] == sha(binding("operation", command))
        grant = grants[message["grant_sha256"]]["grant"]
        for field in ["grant_id", "session_id", "host_session_id", "target_id"]:
            assert message[field] == grant[field]
        assert message["actor_id"] == grant["subject_id"] == row["attributed_agent"]
        assert row["agent_session_id"] == message["host_session_id"]
        assert grant["issued_at_ms"] <= message["issued_at_ms"] <= row["timestamp_ms"] < message["expires_at_ms"] <= grant["expires_at_ms"]
        seqs[message["grant_id"]] += 1
        assert message["sequence"] == seqs[message["grant_id"]]
        operations[command["operation"]] += 1
        if command["operation"] == "delegate":
            child = grants[body["child_grant_sha256"]]["grant"]
            assert child["parent_grant_sha256"] == message["grant_sha256"] and child["subject_id"] == command["subject_id"]
            assert child["expires_at_ms"] == min(command["expires_at_ms"], grant["expires_at_ms"])
            for permission in grant["permissions"]:
                intersection = set(grant["permissions"][permission]) & set(command["permissions"][permission]) & set(principals[child["subject_id"]]["permissions"][permission])
                assert child["permissions"][permission] == sorted(intersection)
        else:
            assert body["child_grant_sha256"] is None
            permission = {"read_file": "read_files", "write_file": "write_files", "delete_file": "delete_files"}[command["operation"]]
            assert command["path"] in grant["permissions"][permission]
        accepted_by_digest[sha(binding("message", message))] = case
    assert operations == {"delegate": 3, "read_file": 3, "write_file": 5, "delete_file": 1}
    bindings = grouped["GatewayDelegationDispatchBinding"]
    assert len(bindings) == 9
    terminals = {body["action_sha256"]: body for _, body in grouped["GatewayExecutionFinished"]}
    decisions = {body["action_sha256"]: body for _, body in grouped["GatewayDecision"]}
    assert len(terminals) == 10  # 九次文件动作和一次独立宿主回写。
    for _, body in bindings:
        case = accepted_by_digest[sha(binding("message", body["receipt"]["message"]))]
        terminal = terminals[body["action_sha256"]]
        result = case["response"]["result"]
        assert terminal["dispatched"] == result["_meta"]["agentguard"]["dispatched"]
        assert terminal["outcome"] == result["_meta"]["agentguard"]["outcome"]
        assert any(s.get("content_sha256") == case["envelope"]["message"]["operation_sha256"] for s in terminal["sources"])
    assert [p["choice"] for p in report["approvals"]] == ["deny", "approve", "approve", "expire"]
    for proof in report["approvals"]:
        pending, envelope = proof["pending"], proof["envelope"]
        action = pending["binding"]["action"]
        digest = sha(b"agentguard.execution.action.v1\0" + encoded(action))
        assert digest == pending["action_sha256"] and decisions[digest]["decision"] == "needs_confirmation"
        assert action["parameters"]["delegation"]["message"] == envelope["message"]
        assert action["parameters"]["delegation"]["signature"] == envelope["signature"]
        assert action["parameters"]["path"] == envelope["command"]["path"]
        assert action["parameters"]["contents"] == envelope["command"]["contents"]
        assert action["expires_at_ms"] <= envelope["message"]["expires_at_ms"]
        terminal = terminals[digest]
        assert terminal["approval_id_sha256"] == sha(pending["id"].encode())
        if proof["choice"] in ("deny", "expire"):
            assert not terminal["dispatched"]
    for case in report["negative_messages"] + [m for m in report["messages"] if not m["authenticated_expected"]]:
        result = case["response"]["result"]
        assert result["isError"] and not result["_meta"]["agentguard"]["dispatched"]
    assert len(report["negative_messages"]) == 16 and len(report["messages"]) == 26
    # 签名在独立 Node crypto 实现中批量复核，不使用候选网关的验签函数。
    program = """
const fs=require('node:fs'),c=require('node:crypto');
const rows=JSON.parse(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify(rows.map(r=>c.verify(null,Buffer.from(r.message,'hex'),c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(r.public,'hex')]),type:'spki',format:'der'}),Buffer.from(r.signature,'hex')))));
"""
    payload = [{"public": p, "message": b.hex(), "signature": s} for p, b, s in signatures]
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded(payload))) == [True] * len(signatures)
    work = fixture / "workspace"
    assert (work / "output.txt").read_text() == "AGD_DELEGATED_REPORT 中文\n"
    assert sha((work / "output.txt").read_bytes()) == report["host_writeback"]["output_sha256"]
    assert (work / "new.txt").read_text() == "AGD_PREAPPROVED_NEW\n"
    assert (work / "private.txt").read_text() == "AGD_PARENT_ONLY_DATA\n"
    assert (work / "hardlink.txt").read_text() == (work / "symlink.txt").read_text() == "AGD_LINK_ORIGINAL\n"
    assert not (work / "late.txt").exists() and not (work / "remove.txt").exists()
    return {"passed": True, "processes": 2, "signed_grants": len(grants), "authenticated_messages": len(expected),
            "negative_messages": 30, "file_action_bindings": len(bindings), "audit_rows": len(audit), "signatures": len(signatures),
            "source_files": len(build["sources"]), "gateway_sha256": report["binary_sha256"],
            "scope": "真实隔离文件工具；宿主签名和独立 HTTP 脚本批准；容器私钥不可见另有实际 Docker 测试"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.frozen, args.repository, args.node), ensure_ascii=False, indent=2))

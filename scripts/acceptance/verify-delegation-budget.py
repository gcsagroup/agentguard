"""只读独立核对 AGD-024：公钥签名、预算重算、完整响应字节、审计故障和实际文件。"""
import argparse
import collections
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("delegation_helpers", Path(__file__).with_name("verify-delegation.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
sha, read, rows, chain_hash, binding = helpers.sha, helpers.read, helpers.rows, helpers.chain_hash, helpers.binding


def encoded(value):
    # Rust 序列化响应的键序已由 Node 解析并原样保存在报告中。
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def verify(directory, frozen, repository, node):
    report, build = read(directory / "report.json"), read(frozen / "build-inputs.json")
    assert report["passed"] and not report.get("error") and not report.get("cleanup_error")
    assert Path(report["binary"]).resolve() == (frozen / "agentguard-mcp").resolve()
    assert report["binary_sha256"] == build["binary_sha256"] == sha((frozen / "agentguard-mcp").read_bytes())
    for item in build["sources"]:
        path = Path(item["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert item["sha256"] == sha((frozen / "source" / path).read_bytes()) == sha((repository / path).read_bytes()), str(path)
    sessions, phases = report["sessions"], report["budget_phases"]
    assert len(sessions) == len(phases) == len({s["session_id"] for s in sessions}) == len({s["pid"] for s in sessions}) == 6
    assert all(s["exit"]["code"] == 0 for s in sessions)
    assert len(report["messages"]) == 20 and len(report["grants"]) == 13
    fixture = Path(report["fixture"])
    for file, key in [("rules.yaml", "rulesSha256"), ("shell.yaml", "shellPolicySha256"), ("plans.json", "plansSha256")]:
        assert sha((fixture / "operator" / file).read_bytes()) == report["inputs"][key]
    audit, _, _ = rows(fixture / "operator/audit.db")
    previous, grouped = "AGENTGUARD-AUDIT-GENESIS-v1", collections.defaultdict(list)
    for index, row in enumerate(audit, 1):
        assert row["seq"] == index and row["prev_hash"] == previous and row["record_hash"] == chain_hash(row, previous)
        previous = row["record_hash"]
        grouped[row["event_type"]].append((row, json.loads(row["event_json"])))
    configs = {p["host_session_id"]: p["config"] for p in phases}
    grants, signatures = {}, []
    for signed in report["grants"]:
        grant = signed["grant"]
        config = configs[grant["host_session_id"]]
        digest = sha(binding("grant", grant))
        assert digest not in grants and signed["key_id"] == sha(bytes.fromhex(config["public_key"]))[:16]
        assert grant["authority_id"] == config["authority_id"] and grant["target_id"] == config["target_id"]
        signatures.append((config["public_key"], binding("grant", grant), signed["signature"]))
        if grant["parent_grant_sha256"]:
            parent = grants[grant["parent_grant_sha256"]]
            assert grant["parent_session_id"] == parent["session_id"] and grant["delegator_id"] == parent["subject_id"]
            assert grant["host_session_id"] == parent["host_session_id"] and grant["expires_at_ms"] <= parent["expires_at_ms"]
        else:
            assert grant["subject_id"] == config["root_subject_id"] and grant["parent_session_id"] is None
        grants[digest] = grant
    accepted = grouped["GatewayDelegationAccepted"]
    expected = [m for m in report["messages"] if m["authenticated_expected"]]
    assert len(accepted) == len(expected) == 15
    sequences, case_by_digest = collections.defaultdict(int), {}
    for case in report["messages"]:
        envelope = case["envelope"]
        message, command = envelope["message"], envelope["command"]
        config, grant = configs[message["host_session_id"]], grants[message["grant_sha256"]]
        principal = next(p for p in config["principals"] if p["subject_id"] == message["actor_id"])
        signatures.append((principal["public_key"], binding("message", message), envelope["signature"]))
        assert message["operation_sha256"] == sha(binding("operation", command))
        for field in ["grant_id", "session_id", "host_session_id", "target_id"]:
            assert message[field] == grant[field]
        assert message["actor_id"] == grant["subject_id"]
        assert message["sequence"] == sequences[message["grant_id"]] + 1
        if case["authenticated_expected"]:
            sequences[message["grant_id"]] += 1
            case_by_digest[sha(binding("message", message))] = case
        else:
            assert case["response"]["result"]["isError"] and not case["response"]["result"]["_meta"]["agentguard"]["dispatched"]
    for (row, body), case in zip(accepted, expected, strict=True):
        envelope = case["envelope"]
        assert body["receipt"]["message"] == envelope["message"] and body["receipt"]["signature"] == envelope["signature"]
        assert row["agent_session_id"] == envelope["message"]["host_session_id"]
        if envelope["command"]["operation"] == "delegate":
            child = grants[body["child_grant_sha256"]]
            parent = grants[envelope["message"]["grant_sha256"]]
            principal = next(p for p in configs[row["agent_session_id"]]["principals"] if p["subject_id"] == child["subject_id"])
            assert child["subject_id"] == envelope["command"]["subject_id"]
            for permission in child["permissions"]:
                assert child["permissions"][permission] == sorted(set(parent["permissions"][permission]) & set(envelope["command"]["permissions"][permission]) & set(principal["permissions"][permission]))
    finished_count, reserved_count, unknown_count = 0, 0, 0
    for session, phase in zip(sessions, phases, strict=True):
        host = session["session_id"]
        assert phase["host_session_id"] == host and phase["passed"]
        config = phase["config"]
        policy = hashlib.sha256()
        for file in ["rules.yaml", "shell.yaml", "plans.json"]:
            data = (fixture / "operator" / file).read_bytes()
            policy.update(len(data).to_bytes(8, "big")); policy.update(data)
        policy.update(b"agentguard.delegation.configuration.v1\0")
        policy.update(encoded(config))
        assert session["stats"]["policy_version"] == "sha256-" + policy.hexdigest(), "预算配置必须绑定真实策略"
        root = session["stats"]["delegation"]["root_grant"]["grant"]["grant_id"]
        ledger = {root: dict(parent=None, limits=config["budgets"], calls=0, used=0, reserved=0, revoked=False)}
        reservations = {}
        responses = {sha(encoded(m["response"])): m for m in report["messages"][phase["message_start"]:phase["message_end"]]}

        def ancestors(grant):
            result = []
            while grant is not None:
                assert grant in ledger and grant not in result
                result.append(grant); grant = ledger[grant]["parent"]
            return result

        def check_state(state):
            assert state["monetary_cost"] == "unmeasurable_call_and_time_limits_enforced"
            assert {n["grant_id"] for n in state["nodes"]} == set(ledger)
            for actual in state["nodes"]:
                wanted = ledger[actual["grant_id"]]
                assert actual["limits"] == wanted["limits"] and actual["parent_grant_id"] == wanted["parent"]
                assert (actual["used_calls"], actual["used_output_bytes"], actual["reserved_output_bytes"], actual["revoked"]) == (wanted["calls"], wanted["used"], wanted["reserved"], wanted["revoked"])
                chain = [ledger[g] for g in ancestors(actual["grant_id"])]
                assert actual["remaining_calls"] == min(n["limits"]["max_calls"] - n["calls"] for n in chain)
                assert actual["remaining_output_bytes"] == min(n["limits"]["max_output_bytes"] - n["used"] - n["reserved"] for n in chain)
                assert 0 <= actual["remaining_ms"] <= wanted["limits"]["max_elapsed_ms"]

        check_state(phase["before"]["budget"])
        for row, event in grouped["GatewayDelegationBudget"]:
            if row["agent_session_id"] != host: continue
            kind, body = event["kind"], event["body"]
            assert event["schema"] == "gateway_delegation_budget_v1" and row["action"] == kind
            if kind == "reserved":
                chain = ancestors(body["grant_id"])
                assert body["ticket"] not in reservations
                assert body["output_limit"] == min(512 * 1024, *(ledger[g]["limits"]["max_output_bytes"] - ledger[g]["used"] - ledger[g]["reserved"] for g in chain))
                assert body["output_limit"] >= 1024
                for grant in chain:
                    n = ledger[grant]
                    assert not n["revoked"] and n["calls"] < n["limits"]["max_calls"]
                    n["calls"] += 1; n["reserved"] += body["output_limit"]
                reservations[body["ticket"]] = (chain, body["output_limit"])
                reserved_count += 1; check_state(body["state"])
            elif kind == "child":
                parent = body["parent_grant_id"]
                limits = {**ledger[parent]["limits"], "max_depth": ledger[parent]["limits"]["max_depth"] - 1}
                assert body["limits"] == limits and limits["max_depth"] >= 0
                assert body["grant_id"] not in ledger
                ledger[body["grant_id"]] = dict(parent=parent, limits=limits, calls=0, used=0, reserved=0, revoked=False)
            elif kind == "finished":
                chain, allowance = reservations.pop(body["ticket"])
                response = responses[body["response_sha256"]]["response"]
                assert body["response_bytes"] == len(encoded(response)) <= allowance == body["output_limit"]
                assert body["publication"] == "prepared_not_delivery_acknowledged"
                assert body["charge_mode"] in ["encoded_response", "full_reservation"]
                meta = response["result"]["_meta"]["agentguard"]
                assert body["dispatched"] == meta["dispatched"] and body["output_hidden"] == meta.get("budget_output_hidden", False)
                for grant in chain:
                    ledger[grant]["reserved"] -= allowance
                    ledger[grant]["used"] += allowance if body["charge_mode"] == "full_reservation" else body["response_bytes"]
                finished_count += 1
            elif kind == "revoked":
                descendants = [g for g in ledger if body["grant_id"] in ancestors(g) and not ledger[g]["revoked"]]
                assert len(descendants) == body["affected"] == 2 and body["completed_effects"] == "not_reverted"
                for grant in descendants: ledger[grant]["revoked"] = True
                check_state(body["state"])
            else: raise AssertionError(kind)
        if phase["audit_fault"]:
            assert len(reservations) == 1 and phase["after"]["budget"]["closed"]
            for chain, allowance in reservations.values():
                for grant in chain:
                    ledger[grant]["reserved"] -= allowance; ledger[grant]["used"] += allowance
                unknown_count += 1
        else:
            assert not reservations and not phase["after"]["budget"]["closed"]
        check_state(phase["after"]["budget"])
        for file in ["output.txt", "late.txt", "new.txt"]:
            assert not (Path(session["snapshot"]) / file).exists() and not (fixture / "workspace" / file).exists()
    assert (reserved_count, finished_count, unknown_count) == (16, 15, 1)
    terminals = {body["action_sha256"]: body for _, body in grouped["GatewayExecutionFinished"]}
    assert len(terminals) == len(grouped["GatewayDelegationDispatchBinding"]) == 8
    for _, body in grouped["GatewayDelegationDispatchBinding"]:
        case = case_by_digest[sha(binding("message", body["receipt"]["message"]))]
        terminal, meta = terminals[body["action_sha256"]], case["response"]["result"]["_meta"]["agentguard"]
        assert terminal["dispatched"] == meta["dispatched"]
        assert terminal["outcome"] == ("success" if meta.get("budget_reason") == "audit_unconfirmed" else meta["outcome"])
    assert [p["choice"] for p in report["approvals"]] == ["revoke", "expire"]
    for proof in report["approvals"]:
        pending, envelope = proof["pending"], proof["envelope"]
        action = pending["binding"]["action"]
        digest = sha(b"agentguard.execution.action.v1\0" + helpers.encoded(action))
        assert digest == pending["action_sha256"] and not terminals[digest]["dispatched"]
        assert action["parameters"]["delegation"]["message"] == envelope["message"]
        assert action["parameters"]["delegation_budget"]["output_limit"] >= 1024
        assert terminals[digest]["approval_id_sha256"] == sha(pending["id"].encode())
    output = (directory / "output-input.txt").read_bytes()
    assert len(output) == phases[2]["source_bytes"] < 16000 < len(encoded(output.decode()))
    assert sha(output) == phases[2]["source_sha256"]
    assert b"AGD_OUTPUT_SECRET" not in encoded(report["messages"][10]["response"])
    assert (fixture / "workspace/input.txt").read_text() == "AGD_DELEGATION_INPUT 中文\n"
    assert phases[4]["after"]["budget"]["nodes"][0]["remaining_ms"] == 0
    assert report["negative_messages"][0]["response"]["result"]["isError"]
    program = """const fs=require('node:fs'),c=require('node:crypto');const rows=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(rows.map(r=>c.verify(null,Buffer.from(r.message,'hex'),c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(r.public,'hex')]),type:'spki',format:'der'}),Buffer.from(r.signature,'hex')))));"""
    payload = [{"public": p, "message": b.hex(), "signature": s} for p, b, s in signatures]
    assert json.loads(subprocess.check_output([node, "-e", program], input=encoded(payload))) == [True] * len(signatures)
    return dict(passed=True, processes=6, phases=6, signed_grants=13, authenticated_messages=15,
                signatures=len(signatures), reservations=reserved_count, finished=finished_count,
                unconfirmed_charged_in_full=unknown_count, audit_rows=len(audit), source_files=len(build["sources"]),
                gateway_sha256=report["binary_sha256"], scope="本机隔离文件工具与独立 HTTP 脚本批准；金额不可测；输出审计是准备公开记录，不是客户端接收确认")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve(), args.frozen.resolve(), args.repository.resolve(), args.node), ensure_ascii=False, indent=2))

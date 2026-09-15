#!/usr/bin/env python3
"""核对 M2 回归留存证据；核对成功不代表性能或完整回归通过。"""
import argparse
import hashlib
import json
import math
import sqlite3
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_rows(path):
    fields = ["id", "timestamp_ms", "platform", "event_type", "source_app",
              "agent_session_id", "rule_id", "severity", "action", "human_message",
              "evidence_ref", "event_json"]
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = [dict(row) for row in connection.execute("select * from audit_events order by rowid")]
    finally:
        connection.close()
    previous = "AGENTGUARD-AUDIT-GENESIS-v1"
    for row in rows:
        assert row["prev_hash"] == previous, "原生审计前链不一致"
        payload = "\x1f".join(str(row[f]) if row[f] is not None else "" for f in fields)
        if row["attributed_agent"] is not None:
            payload += "\x1fagent=" + row["attributed_agent"]
        assert row["record_hash"] == hashlib.sha256((previous + "\n" + payload).encode()).hexdigest()
        previous = row["record_hash"]
    return rows


def verify_native_015(out, expected):
    """只读核对新格式的原生证据；旧 012 的行数和文件定义保持独立。"""
    native = read(out / "native-verification-15.json")
    build = read(out / "candidate-15/build-report.json")
    assert native["gateway_sha256"] == build["gateway_sha256"] == expected
    assert native["app_sha256"] == build["app_sha256"]
    evidence = out / "native-15"
    channels = {}
    for name, count in [("audit.db", 35), ("audit.db.sources.db", 0),
                        ("audit.db.tools.db", 3), ("model-egress.db", 16)]:
        rows = audit_rows(evidence / name)
        assert rows == read(evidence / (name + ".rows.json"))
        assert [r["seq"] for r in rows] == list(range(1, count + 1))
        saved = native["channels"][name]
        assert len(rows) == saved["rows"] == count
        assert sha(evidence / name) == saved["copy_sha256"]
        assert (rows[-1]["record_hash"] if rows else None) == saved["head"]
        channels[name] = rows
    original = read(out / "native-workspace-declaration-15.json")
    preview = read(out / "native-preview-15.json")
    assert preview["changed_files"] == native["changed_files"]
    assert set(native["changed_files"]) == {"numbers.py", "CHANGE.md"}
    for name, digest in native["changed_files"].items():
        assert sha(evidence / "workspace" / name) == digest
    for name in ["README.md", "test_numbers.py"]:
        assert sha(evidence / "workspace" / name) == original["files"][name]["sha256"]
    assert sha(evidence / "original-numbers.py") == original["files"]["numbers.py"]["sha256"]
    tests = (out / "native-host-tests-15.log").read_text()
    assert "Ran 4 tests" in tests and tests.endswith("\nOK\n")
    events = [json.loads(r["event_json"]) for r in channels["audit.db"]
              if r["event_type"] in {"GatewayDecision", "GatewayExecutionStarted", "GatewayExecutionFinished"}]
    actions = {}
    for event in events:
        actions.setdefault(event["action_sha256"], []).append(event)
    assert len(actions) == 9
    approvals = []
    for action, bound in actions.items():
        assert len(bound) == 3 and [e["outcome"] for e in bound[:2]] == ["decision", "started"]
        assert [r["event_type"] for r in channels["audit.db"]
                if json.loads(r["event_json"]).get("action_sha256") == action] == [
                    "GatewayDecision", "GatewayExecutionStarted", "GatewayExecutionFinished"]
        assert bound[-1]["outcome"] in {"success", "failed"} and bound[-1]["dispatched"] is True
        assert all(e[key] == bound[0][key] for e in bound for key in ["sources", "parameters_sha256",
                   "request_id_sha256", "target_sha256", "policy_version_sha256", "tool_identity_sha256"])
        assert bound[1]["approval_id_sha256"] == bound[2]["approval_id_sha256"]
        if bound[0]["decision"] == "needs_confirmation":
            assert isinstance(bound[1]["approval_id_sha256"], str) and len(bound[1]["approval_id_sha256"]) == 64
            approvals.append(bound[1]["approval_id_sha256"])
        else:
            assert bound[0]["decision"] == "execute" and bound[1]["approval_id_sha256"] is None
    assert len(approvals) == len(set(approvals)) == 3
    applied = actions[preview["preview_action_sha256"]]
    assert applied[0]["decision"] == "needs_confirmation" and applied[-1]["outcome"] == "success"
    bindings = [json.loads(r["event_json"]) for r in channels["audit.db"]
                if r["event_type"] == "GatewaySourceStorageBinding"]
    assert len(bindings) == 1
    assert set(bindings[0]) == {"schema", "legacy_records", "legacy_log_id_sha256", "legacy_head_sha256"}
    assert bindings[0]["schema"] == "gateway_source_storage_v1"
    assert type(bindings[0]["legacy_records"]) is int and bindings[0]["legacy_records"] == 0
    with sqlite3.connect((evidence / "audit.db.sources.db").resolve().as_uri() + "?mode=ro", uri=True) as db:
        log_id = db.execute("SELECT value FROM audit_meta WHERE key='log_id'").fetchone()[0]
    assert bindings[0]["legacy_log_id_sha256"] == hashlib.sha256(log_id.encode()).hexdigest()
    assert bindings[0]["legacy_head_sha256"] == "AGENTGUARD-AUDIT-GENESIS-v1"
    return sum(len(rows) for rows in channels.values())


def verify_operator_reuse(out, source):
    reuse = read(out / "operator-reuse-15.json")
    manifest = Path(reuse["source_manifest"])
    assert sha(manifest) == reuse["source_manifest_sha256"]
    inputs = [row for row in read(manifest)["files"] if row["path"].startswith("crates/") or
              row["path"] in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml"}]
    assert inputs == reuse["production_inputs"]
    for row in inputs:
        assert sha(Path(reuse["source_root"]) / row["path"]) == sha(source / row["path"]) == row["sha256"]
    assert sha(Path(reuse["test_executable"])) == reuse["test_executable_sha256"]
    assert sha(Path(reuse["original_log"])) == reuse["original_log_sha256"]
    assert "8 passed; 0 failed" in Path(reuse["original_log"]).read_text()
    assert len(reuse["original_reports"]) == 8
    for name, digest in reuse["original_reports"].items():
        assert sha(Path(name)) == sha(out / "operator-explicit-15" / Path(name).name) == digest
    return reuse


def verify(out, soak, root, candidate="012"):
    declaration = read(out / "declaration.json")
    expected = declaration["gateway_sha256"]
    source = Path(declaration["source_root"])
    source_manifest = source.parent / "source-manifest.json"
    assert sha(source_manifest) == declaration["source_manifest_sha256"]
    for item in read(source_manifest)["source_files"]:
        assert sha(source / item["path"]) == item["sha256"]
    current = candidate == "015"
    if current:
        assert declaration["candidate"] == candidate

    duration = read(soak / "report.json")
    assert duration["binarySha256"] == expected
    assert duration["requestedDurationMs"] == 1800000
    assert duration["measuredDurationMs"] >= 1800000
    assert len(duration["tasks"]) == duration["taskCount"] == 30
    for index, task in enumerate(duration["tasks"], 1):
        assert task == read(soak / "tasks" / f"{index:03d}.json")
        assert task["passed"] and task["binarySha256"] == expected
        assert task["apply"]["outcome"] == "applied"
    heartbeat = duration["heartbeats"]
    assert len(heartbeat) >= 120
    assert len({(h["instance"], h["session"]) for h in heartbeat}) == 1
    gaps = [b["elapsedMs"] - a["elapsedMs"] for a, b in zip(heartbeat, heartbeat[1:])]
    assert all(0 < gap < 60000 for gap in gaps)
    assert math.isclose(max(gaps), duration["maxHeartbeatGapMs"])
    assert not duration["remainingOwnContainers"]

    fault = read(out / ("workspace-faults-15" if current else "workspace-faults-01") / "report.json")
    isolation_path = Path(json.loads((out / ("isolation-15.log" if current else "isolation-01.log")).read_text().splitlines()[-1])["report"])
    isolation = read(isolation_path)
    for report, count in [(fault, 50), (isolation, 78)]:
        assert report["binarySha256"] == expected
        assert len(report["checks"]) == count
        assert all(check["passed"] for check in report["checks"])

    reuse = verify_operator_reuse(out, source) if current else None
    operators = list((out / ("operator-explicit-15" if current else "operator-explicit-01")).glob("*.json"))
    assert len(operators) == 8
    for path in operators:
        report = read(path)
        assert report["passed"]
        executable = Path(reuse["test_executable"] if reuse else report["build"]["test_executable"])
        assert sha(executable) == report["build"]["test_executable_sha256"]
        if reuse:
            assert set(report["build"]["source_sha256"]) == set(reuse["source_mapping"])
            for name, path in reuse["source_mapping"].items():
                assert sha(source / path) == report["build"]["source_sha256"][name]
        assert report["host_unchanged"] == (report["initial_host_tree"] == report["actual_host_tree"])
        assert report["host_unchanged"] == (report["case"] != "audit-finish-failure")

    egress = read(out / ("container-egress-15" if current else "container-egress-02") / "report.json")
    assert egress["binarySha256"] == expected and sha(Path(egress["binary"])) == expected
    assert egress["sourcesUnchanged"] and egress["binaryUnchanged"]
    for path, digest in egress["sourceHashes"].items():
        assert sha(Path(path)) == digest
    assert all(count == 0 for count in egress["isolatedReceipts"].values())
    isolated = [check for check in egress["checks"] if check["id"].startswith("isolated-")]
    assert len(isolated) == 2
    attempts = 0
    for check in isolated:
        for part in [check["result"], check["result"]["descendant"]]:
            assert part["envAbsent"] and not part["unix"]["reached"]
            assert all(not item["readable"] for item in part["files"].values())
            assert len(part["network"]) == 6
            assert all(not item["reached"] for item in part["network"].values())
            attempts += len(part["network"])
    assert not egress["remainingOwnContainers"] and egress["hostWorkspaceUnchanged"]

    browser = read(out / ("browser-f08-15.json" if current else "browser-f08.json"))
    assert browser["gateway_sha256"] == expected and browser["pass"]
    first, old_cleanup, second, new_cleanup = browser["phases"]
    assert first["post_count"] == 0 and first["dispatched"] is False
    assert first["old_approval_status"] == second["duplicate_approval_status"] == 409
    assert first["session_id"] != second["session_id"] and second["post_count"] == 1
    assert old_cleanup["profile_removed"] and new_cleanup["profile_removed"]
    resolver = read(out / ("browser-resolver-15.json" if current else "browser-resolver.json"))
    assert resolver["binary_sha256"] == expected and resolver["resolver_positive_control"]["address"]
    assert resolver["tcpCount"] == resolver["udpCount"] == 0
    assert resolver["result"]["resolver"]["resolved"] is False

    if current:
        native_rows = verify_native_015(out, expected)
    else:
        native = read(out / "native-verification.json")
        records = audit_rows(out / "native-audit.db")
        assert records == read(out / "native-audit-rows.json")
        assert len(records) == native["audit"]["records_verified"] == 27
        assert records[-1]["record_hash"] == native["audit"]["head"]
        for name, digest in native["files"].items():
            assert sha(out / "native-workspace" / name) == digest
        original = read(out / "native-workspace-declaration.json")
        for name in ["README.md", "test_sort_numbers.py"]:
            assert native["files"][name] == original["files"][name]
        native_rows = len(records)

    # 从全部正式样本重算 p95，不能用功能读取成功掩盖预算失败。
    performance_dir = Path(declaration["performance_directory"]) if current else out / "performance-01"
    performance = read(performance_dir / "result.json")
    budget = read(Path(performance["original_budget"])) if current else read(out / "performance-budget.json")
    # 两个候选必须使用原定义预算，不能通过修改报告中的上限消除失败。
    assert [budget[k] for k in ["native_read_p95_ms_max", "native_gateway_startup_ms_max",
            "isolated_read_p95_ms_max", "isolated_gateway_startup_ms_max", "gateway_rss_peak_mib_max"]] == [10, 100, 500, 2000, 32]
    raw_path = Path(performance["original_report"])
    assert sha(raw_path) == performance["original_report_sha256"]
    raw = read(raw_path)
    assert raw["parameters"]["candidateSha256"] == expected
    checks = []
    for route in raw["routes"]:
        assert len(route["warmup"]) == 5 and len(route["measured"]) == 30
        assert all(r["attempted"] and r["passed"] and r["returnedBytes"] == 1024
                   for r in route["warmup"] + route["measured"])
        p95 = sorted(r["elapsedMs"] for r in route["measured"])[28]
        assert p95 == route["measuredSummary"]["latencyAllCompletedAttemptsMs"]["p95"]
        if route["name"] == "direct_host_read":
            continue
        prefix = "isolated" if route["name"] == "isolated_gateway_read" else "native"
        for key, actual, maximum in [
            ("read_p95_ms", p95, budget[prefix + "_read_p95_ms_max"]),
            ("startup_ms", route["startupMs"], budget[prefix + "_gateway_startup_ms_max"]),
            ("sampled_gateway_peak_mib", route["gatewayRss"]["sampledPeakMiB"], budget["gateway_rss_peak_mib_max"]),
        ]:
            checks.append({"name": prefix + "_" + key, "actual": actual, "max": maximum, "passed": actual <= maximum})
    assert checks == performance["checks"] and len(checks) == 6
    passed_budgets = sum(check["passed"] for check in checks)
    assert passed_budgets == performance["passing_budgets"]
    assert performance["passed"] == (passed_budgets == 6 and performance["same_vm_boot_across_benchmark"])
    for item in read(root / ".artifacts/m2-registry-2026-09-14/baseline.json")["preserved"]:
        assert sha(root / item["path"]) == item["sha256"]
    return {"evidence_verified": True, "regression_passed": performance["passed"],
            "gateway_sha256": expected, "soak_tasks": 30, "soak_heartbeats": len(heartbeat),
            "soak_duration_ms": duration["measuredDurationMs"], "fault_checks": 50,
            "isolation_checks": 78, "operator_checks": 8, "egress_attempts": attempts,
            "candidate": candidate, "native_audit_rows": native_rows, "performance_passed": passed_budgets,
            "performance_total": 6, "performance_checks": checks,
            "limitations": "回收后的合成服务和临时文件采用运行时记录；不将报告复核冒充再次实测。"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--soak", required=True, type=Path)
    parser.add_argument("--candidate", choices=["012", "015"], default="012")
    args = parser.parse_args()
    result = verify(args.artifacts, args.soak, Path(__file__).resolve().parents[2], args.candidate)
    print(json.dumps(result, ensure_ascii=False, indent=2))

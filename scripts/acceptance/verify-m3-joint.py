"""复核 M3 的原固定分母、候选身份、浏览器持久回执和性能原预算；缺项立即失败。"""
import argparse
import collections
import importlib.util
import json
import math
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("helpers", Path(__file__).with_name("verify-persistence-propagation.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
read, sha, audit = helpers.read, helpers.sha, helpers.audit


def verify(out, frozen, repository):
    build = read(frozen / "build-inputs.json")
    expected = build["binary_sha256"]
    assert sha((frozen / "agentguard-mcp").read_bytes()) == expected
    assert len(build["sources"]) == len({s["path"] for s in build["sources"]}) == 211
    for item in build["sources"]:
        path = Path(item["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert item["sha256"] == sha((repository / path).read_bytes()) == sha((frozen / "source" / path).read_bytes())
    workspace = {}
    for name in ["tasks", "cycles", "faults", "soak"]:
        directory = out / f"workspace-{name}-01"
        report = read(directory / "report.json")
        assert report["passed"] and report["binarySha256"] == expected
        assert report["scriptSha256"] == sha((directory / "harness-source.mjs").read_bytes()) == sha((repository / "scripts/acceptance/agd-workspace-session.mjs").read_bytes())
        workspace[name] = report
    normal, cycles, faults, soak = [workspace[name] for name in ["tasks", "cycles", "faults", "soak"]]
    assert normal["taskCount"] == len(normal["tasks"]) == 50
    assert [t["id"] for t in normal["tasks"]] == [f"T{n:02d}" for n in range(1, 51)]
    assert cycles["completeCycles"] == cycles["requestedCycles"] == len(cycles["cycles"]) == 100
    assert cycles["qualifies100Cycles"] and len({c["instance_id"] for c in cycles["connections"]}) == len(cycles["connections"])
    assert len(faults["checks"]) == 50 and all(c["passed"] for c in faults["checks"])
    assert soak["requestedDurationMs"] == 1800000 and soak["measuredDurationMs"] >= 1800000
    assert soak["qualifies30Minutes"] and soak["taskCount"] == len(soak["tasks"]) == 30
    assert not soak["remainingOwnContainers"]
    for name, tasks, child in [("tasks", normal["tasks"], "tasks"), ("cycles", cycles["cycles"], "cycles"), ("soak", soak["tasks"], "tasks")]:
        for n, task in enumerate(tasks, 1):
            filename = task["id"] if name == "tasks" else f"{n:03d}"
            assert task == read(out / f"workspace-{name}-01" / child / f"{filename}.json")
            assert task["passed"] and task["binarySha256"] == expected and task["apply"]["outcome"] == "applied"
            changed = {c["path"]: c for c in task["review"]["changes"]}
            for path, artifact in task["artifacts"].items():
                assert changed[path]["afterSha256"] == artifact["sha256"]
    hearts = soak["heartbeats"]
    assert len(hearts) >= 120 and len({(h["instance"], h["session"]) for h in hearts}) == 1
    gaps = [b["elapsedMs"] - a["elapsedMs"] for a, b in zip(hearts, hearts[1:])]
    assert all(0 < gap < 60000 for gap in gaps)
    assert math.isclose(max([hearts[0]["elapsedMs"], *gaps]), soak["maxHeartbeatGapMs"])
    assert {"T45", "T48", "T49"} <= {t["id"] for t in soak["tasks"]}

    browser_normal = out / "browser-normal-01"
    browser_cycles = out / "browser-cycles-01"
    summary, cycle = read(browser_normal / "summary.json"), read(browser_cycles / "report.json")
    for report in [summary, cycle]:
        assert report["binarySha256"] == expected == sha(Path(report["testedBinary"]).read_bytes())
        assert report["sourceBefore"] == report["sourceAfter"] and report["sourceUnchanged"]
        for path, digest in report["sourceBefore"].items():
            assert sha((repository / path).read_bytes()) == digest
    assert summary["allTenCompleted"] and summary["denominator"] == summary["passedTasks"] == len(summary["tasks"]) == 10
    browser_rows = 0
    for number, item in enumerate(summary["tasks"], 1):
        assert item["id"] == f"B{number:02d}" and item["passed"]
        task = read(browser_normal / item["id"] / "report.json")
        assert task["passed"] and not task.get("cleanupError")
        assert len(task["submissions"]) == (0 if number < 3 else 1)
        for index, host in enumerate(task["hosts"], 1):
            rows, _, _ = audit(browser_normal / item["id"] / f"browser-{index}.db")
            assert rows == host["journal"]["rows"] and host["closed"] and not host["remainingContainers"]
            browser_rows += len(rows)
            terminals = {b["action_sha256"]: b for row in rows if row["event_type"] == "GatewayExecutionFinished" for b in [json.loads(row["event_json"])]}
            for approval in task["approvals"]:
                if approval["hostPid"] == host["pid"] and approval.get("terminalRequired"):
                    assert terminals[approval["actionSha256"]]["outcome"] == approval["outcome"]
            for observation in task["observations"]:
                if observation["hostPid"] == host["pid"]:
                    receipt = observation["receipt"]
                    assert terminals[receipt["action_sha256"]]["outcome"] == receipt["outcome"]
    assert cycle["all100Passed"] and cycle["executed"] == cycle["denominator"] == len(cycle["results"]) == 100
    assert cycle["expectedPosts"] == cycle["ledgerPosts"] == len(cycle["ledger"]) == 50 and len(cycle["blocks"]) == 10
    assert [r["id"] for r in cycle["results"]] == [f"C{n:03d}" for n in range(1, 101)]
    assert cycle["results"] == [c for block in cycle["blocks"] for c in block["cycles"]]
    assert collections.Counter(c["mode"] for c in cycle["results"]) == {"approve": 50, "deny": 40, "disconnect": 10}
    for block in cycle["blocks"]:
        directory = browser_cycles / f"block-{block['number']:02d}"
        rows, _, _ = audit(directory / "browser.db")
        assert rows == read(directory / "browser.db.rows.json") and block["passed"]
        assert all(block["cleanup"][k] for k in ["allOwnedProcessesExited", "credentialsRemoved", "profilesRemoved", "workspaceUnchanged"])
        browser_rows += len(rows)
        for item in block["setup"] + block["cycles"]:
            finals = [r for r in rows if r["event_type"] == "GatewayExecutionFinished" and json.loads(r["event_json"])["action_sha256"] == item["actionSha256"]]
            assert len(finals) == 1
            persisted = {**json.loads(finals[0]["event_json"]), "record_hash": finals[0]["record_hash"]}
            assert item["persistedHttpReceipt"] == persisted
            assert persisted["dispatched"] == (item["mode"] == "approve")
            assert persisted["outcome"] in (["success"] if item["mode"] == "approve" else ["refused", "cancelled"])
            if "beforePosts" in item:
                assert item["afterPosts"] - item["beforePosts"] == (item["mode"] == "approve")
    posts = [r for r in cycle["requests"] if r["method"] == "POST"]
    assert len(posts) == 50 and [r["sequence"] for r in cycle["ledger"]] == list(range(1, 51))
    assert posts == [{k: r[k] for k in ["method", "path", "body"]} for r in cycle["ledger"]]
    bodies = {r["bodySha256"] for r in cycle["results"]}
    assert len(bodies) == 1 and all(sha(r["body"].encode()) in bodies and r["path"] == "/submit" for r in cycle["ledger"])

    lifecycle = read(out / "browser-lifecycle-01.json")
    assert lifecycle["pass"] and lifecycle["gateway_sha256"] == expected
    before, cleanup, after, final = lifecycle["phases"]
    assert before["post_count"] == 0 and not before["dispatched"] and after["post_count"] == 1
    assert before["old_approval_status"] == after["duplicate_approval_status"] == 409
    assert before["session_id"] != after["session_id"] and cleanup["profile_removed"] and final["profile_removed"]
    network = read(out / "f14-01/report.json")
    assert network["passed"] and network["identity"]["gateway_sha256"] == expected and network["approvals"] == "auto"
    assert network["before"]["service"]["pid"] == network["down"]["service"]["pid"] == network["restored"]["service"]["pid"]
    assert network["before"]["service"]["started"] == network["down"]["service"]["started"] == network["restored"]["service"]["started"]
    assert "eth0" not in network["down"]["service"]["interfaces"]
    base = len(network["before"]["service"]["hits"])
    assert len(network["after_observation"]["hits"]) == base + 1 and len(network["final_service"]["hits"]) == base + 2
    phases = {p["name"]: p for p in network["phases"]}
    failed, recovered = phases["disconnected_unknown"], phases["fresh_request_succeeded"]
    assert failed["receipt"]["outcome"] == "unknown" and failed["receipt"]["dispatched"] and not failed["receipt"]["automatic_retry"]
    observed = phases["no_retry_verified"]
    assert observed["observed_ms"] >= 25000 and observed["old_approval_status"] == observed["failed_session_resume_status"] == 409
    assert recovered["receipt"]["outcome"] == "success" and recovered["browser_readback"]
    assert failed["receipt"]["session_id"] != recovered["session_id"]
    network_rows = 0
    for name, request, phase, hit in [("first-audit", "ambiguous_post", failed, network["final_service"]["hits"][base]), ("fresh-audit", "fresh_post", recovered, network["final_service"]["hits"][base + 1])]:
        rows, _, _ = audit(out / "f14-01" / name / "browser.db")
        network_rows += len(rows)
        pending = read(out / "f14-01" / f"{request}-request.json")
        action = pending["binding"]["action"]
        assert pending["action_sha256"] == sha(b"agentguard.execution.action.v1\0" + helpers.encoded(action, sort=True))
        assert action["parameters"]["body"] == hit["body"]
        terminal = [json.loads(r["event_json"]) for r in rows if r["event_type"] == "GatewayExecutionFinished" and json.loads(r["event_json"])["action_sha256"] == pending["action_sha256"]]
        assert len(terminal) == 1 and terminal[0]["outcome"] == phase["receipt"]["outcome"] and terminal[0]["dispatched"]

    def logged_report(name):
        tail = json.loads((out / name).read_text().splitlines()[-1])
        return read(Path(tail["report"]))
    isolation = logged_report("isolation-01.log")
    assert isolation["binarySha256"] == expected and len(isolation["checks"]) == 78 and all(c["passed"] for c in isolation["checks"])
    performance = logged_report("performance-01.log")
    assert performance["parameters"]["candidateSha256"] == expected
    assert [r["name"] for r in performance["routes"]] == ["direct_host_read", "native_gateway_read", "isolated_gateway_read"]
    assert performance["parameters"]["warmupCount"] == 5 and performance["parameters"]["measuredCount"] == 30
    budgets = []
    for route in performance["routes"]:
        assert len(route["warmup"]) == 5 and len(route["measured"]) == 30
        assert all(s["attempted"] and s["passed"] and s["returnedBytes"] == 1024 for s in route["warmup"] + route["measured"])
        if route["name"] == "direct_host_read":
            continue
        isolated = route["name"] == "isolated_gateway_read"
        p95 = sorted(s["elapsedMs"] for s in route["measured"])[28]
        for name, actual, maximum in [("read_p95_ms", p95, 500 if isolated else 10), ("startup_ms", route["startupMs"], 2000 if isolated else 100), ("memory_mib", route["gatewayRss"]["sampledPeakMiB"], 32)]:
            budgets.append({"route": route["name"], "name": name, "actual": actual, "maximum": maximum, "passed": actual <= maximum})
    assert len(budgets) == 6
    return {"evidence_verified": True, "passed": all(c["passed"] for c in budgets), "gateway_sha256": expected,
            "normal_tasks": 50, "workspace_cycles": 100, "fault_checks": 50, "isolation_checks": 78,
            "soak_tasks": 30, "soak_heartbeats": len(hearts), "soak_duration_ms": soak["measuredDurationMs"],
            "browser_tasks": 10, "browser_cycles": 100, "browser_audit_rows": browser_rows, "approved_posts": 50,
            "network_fault_audit_rows": network_rows,
            "performance": budgets, "f13": "deferred_not_accepted", "release": "No-Go"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    result = verify(args.directory, args.frozen, args.repository)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["passed"]:
        sys.exit(1)

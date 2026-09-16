#!/usr/bin/env python3
"""核对 M3 四轮性能原始样本及分项诊断；证据有效不等于预算通过。"""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import statistics
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "audit_helpers", Path(__file__).with_name("verify-m2-regression.py")
)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
read, sha, audit_rows = helpers.read, helpers.sha, helpers.audit_rows

ROUTES = ["direct_host_read", "native_gateway_read", "isolated_gateway_read"]
BUDGETS = {"native_read_p95_ms": 10, "isolated_read_p95_ms": 500,
           "native_startup_ms": 100, "isolated_startup_ms": 2000,
           "gateway_peak_rss_mib": 32}


def finite(value):
    assert isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
    return value


def check_samples(report, expected):
    """从逐次样本重算六项预算，不接受汇总中的 passed 代替计算。"""
    assert report["parameters"]["candidateSha256"] == expected
    assert report["parameters"]["warmupCount"] == 5
    assert report["parameters"]["measuredCount"] == 30
    assert [r["name"] for r in report["routes"]] == ROUTES
    checks = []
    for route in report["routes"]:
        for name, count in [("warmup", 5), ("measured", 30)]:
            samples = route[name]
            assert len(samples) == count
            assert [s["index"] for s in samples] == list(range(1, count + 1))
            assert all(s["attempted"] and s["passed"] and s["returnedBytes"] == 1024 for s in samples)
            for sample in samples:
                finite(sample["elapsedMs"])
        if route["name"] == ROUTES[0]:
            continue
        isolated = route["name"] == ROUTES[2]
        p95 = sorted(s["elapsedMs"] for s in route["measured"])[28]
        assert route["gatewayRss"]["samples"] > 0
        for metric, actual, maximum in [
            ("read_p95_ms", p95, 500 if isolated else 10),
            ("startup_ms", route["startupMs"], 2000 if isolated else 100),
            ("memory_mib", route["gatewayRss"]["sampledPeakMiB"], 32),
        ]:
            finite(actual)
            checks.append({"route": route["name"], "metric": metric,
                           "actual": actual, "maximum": maximum, "passed": actual <= maximum})
    assert len(checks) == 6
    return checks


def check_timing(row, records, expected_content):
    assert row["exit_code"] == 0 and len(row["reads"]) == 105
    assert [r["index"] for r in row["reads"]] == list(range(105))
    assert all(r["warmup"] == (i < 5) and r["bytes"] == 1024
               and r["sha256"] == expected_content for i, r in enumerate(row["reads"]))
    groups = {kind: [] for kind in ["before_execute", "after_execute"]}
    for item in row["phases"]:
        finite(item["at_ms"])
        bits = item["message"].split()
        if bits[0] == "audit" and bits[1] in groups:
            assert len(bits) == 5 and bits[2] == "2"
            groups[bits[1]].append([finite(int(v) / 1e6) for v in bits[3:]])
    assert all(len(values) == 105 for values in groups.values())
    assert len(records) == 421 and [r["seq"] for r in records] == list(range(1, 422))
    assert records[0]["event_type"] == "GatewaySourceStorageBinding"
    for index in range(105):
        decision, started, source, finished = records[1 + index * 4:5 + index * 4]
        assert [r["event_type"] for r in [decision, started, source, finished]] == [
            "GatewayDecision", "GatewayExecutionStarted", "GatewaySourceObserved", "GatewayExecutionFinished"]
        bodies = [json.loads(r["event_json"]) for r in [decision, started, finished]]
        assert len({b["action_sha256"] for b in bodies}) == 1
        assert finished["id"] == started["id"] + "/result"
        terminal = bodies[-1]
        assert terminal["dispatched"] and terminal["outcome"] == "success"
        assert terminal["output_sha256"] == expected_content and not terminal["output_truncated"]
    main = [p["at_ms"] for p in row["phases"] if p["message"] == "main"]
    ready = [int(p["message"].split()[1]) / 1e6 for p in row["phases"] if p["message"].startswith("ready ")]
    assert len(main) == len(ready) == 1
    commits, sql, total = [], [], []
    for index, request in enumerate(row["reads"]):
        committed = sum(groups[k][index][1] for k in groups)
        statements = sum(groups[k][index][0] for k in groups)
        elapsed = finite(request["elapsed_ms"])
        assert committed + statements <= elapsed + 0.5
        if index >= 5:
            commits.append(committed)
            sql.append(statements)
            total.append(elapsed)
    return {"round": row["round"], "records_verified": len(records),
            "spawn_to_main_ms": main[0], "main_to_ready_ms": ready[0],
            "commit_fraction": sum(commits) / sum(total),
            "sql_mean_ms": statistics.mean(sql),
            "two_commits_p95_ms": sorted(commits)[94],
            "request_p95_ms": sorted(total)[94]}


def verify(out, repository):
    plan, report = read(out / "comparison-plan.json"), read(out / "comparison.json")
    assert report["plan_sha256"] == sha(out / "comparison-plan.json")
    assert plan["prior_plan_sha256"] == sha(out / "plan.json")
    assert plan["order"] == ["dev", "release", "release", "dev"]
    assert plan["budgets"] == BUDGETS and plan["route_order"] == ROUTES
    assert plan["benchmark_sha256"] == sha(repository / "scripts/acceptance/agd-isolation-benchmark.mjs")
    assert report["completed"] and len(report["runs"]) == 4
    builds = {profile: read(out / f"frozen-{profile}/build-inputs.json") for profile in ["dev", "release"]}
    assert builds["dev"]["sources"] == builds["release"]["sources"]
    for profile, build in builds.items():
        frozen = out / f"frozen-{profile}"
        assert build["base_commit"] == plan["base_commit"] and build["build_profile"] == profile
        assert build["binary_sha256"] == sha(frozen / "agentguard-mcp")
        assert len(build["sources"]) == len({s["path"] for s in build["sources"]}) > 200
        for item in build["sources"]:
            path = Path(item["path"])
            assert not path.is_absolute() and ".." not in path.parts
            assert item["sha256"] == sha(repository / path) == sha(frozen / "source" / path)
    summaries = []
    for number, (row, profile) in enumerate(zip(report["runs"], plan["order"], strict=True), 1):
        assert row["number"] == number and row["profile"] == profile and row["exit_code"] == 0
        path = Path(row["report"])
        assert not path.is_absolute() and ".." not in path.parts
        assert row["report_sha256"] == sha(repository / path)
        expected = builds[profile]["binary_sha256"]
        assert row["candidate_sha256"] == expected
        checks = check_samples(read(repository / path), expected)
        assert checks == row["checks"]
        assert sum(c["passed"] for c in checks) == row["passing_budgets"]
        summaries.append({"round": number, "profile": profile, "checks": checks})
    passed = all(all(c["passed"] for c in r["checks"]) for r in summaries if r["profile"] == "dev")
    assert passed == report["all_dev_budgets_passed"]
    timing = read(out / "timing.json")
    timing_plan = read(out / "timing-plan.json")
    assert timing["completed"] and timing["plan_sha256"] == sha(out / "timing-plan.json")
    assert timing_plan["patch_sha256"] == sha(out / "timing-only.patch")
    assert timing["binary_sha256"] == sha(out / "frozen-timing/agentguard-mcp")
    assert [r["round"] for r in timing["rounds"]] == [1, 2]
    measured = []
    for row in timing["rounds"]:
        directory = out / f'timing-{row["round"]}'
        measured.append(check_timing(row, audit_rows(directory / "audit.db"),
                                    sha(directory / "workspace/fixed-read.txt")))
    return {"evidence_verified": True, "performance_passed": passed,
            "comparison": summaries, "timing": measured,
            "scope": "CLI 性能及分项诊断；不代替整个 M3 或 App 验收"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    result = verify(args.directory.resolve(), args.repository.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["performance_passed"]:
        sys.exit(1)

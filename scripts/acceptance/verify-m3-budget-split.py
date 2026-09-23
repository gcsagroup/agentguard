#!/usr/bin/env python3
"""核对 AGD-027 新口径四轮：读取 p95≤20ms，首次启动只记录。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "performance", Path(__file__).with_name("verify-m3-performance.py")
)
performance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(performance)
read, sha = performance.read, performance.sha


def check(plan, report, raw, out, repository):
    assert plan["rounds"] == 4 and plan["order"] == ["dev", "release", "release", "dev"]
    assert plan["budgets"] == performance.BUDGETS
    assert plan["budgets"]["native_read_p95_ms"] == 20
    assert plan["budgets"]["native_startup_ms"] is None
    assert plan["warmup_per_route"] == 5 and plan["measured_per_route"] == 30
    assert plan["file_bytes"] == 1024
    assert plan["route_order"] == performance.ROUTES
    assert report["completed"] and len(report["runs"]) == len(raw) == 4
    assert len(plan["sources"]) == len({s["path"] for s in plan["sources"]}) > 200
    for item in plan["sources"]:
        path = Path(item["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert item["sha256"] == sha(out / "source" / path) == sha(repository / path)
    for profile, build in plan["builds"].items():
        assert build["sha256"] == sha(repository / build["binary"]) == sha(out / profile / "agentguard-mcp")
    for name, field in [
        ("agd-isolation-benchmark.mjs", "benchmark_sha256"),
        ("docker-vm-preflight.mjs", "preflight_sha256"),
        ("verify-m3-performance.py", "verifier_sha256"),
    ]:
        assert plan[field] == sha(out / name) == sha(repository / "scripts/acceptance" / name)
    contents = ("AGD_ISOLATION_BENCHMARK\n" * 50)[:1024].encode()
    rows, previous_finish = [], plan["frozen_at"]
    for index, (execution, data) in enumerate(zip(report["runs"], raw)):
        profile = plan["order"][index]
        assert execution["number"] == index + 1 and execution["profile"] == profile
        assert previous_finish <= execution["started_at"] < execution["finished_at"]
        previous_finish = execution["finished_at"]
        assert execution["exit_code"] == 0 and data["state"] == "passed"
        expected = plan["builds"][profile]["sha256"]
        assert execution["candidate_sha256"] == data["parameters"]["candidateSha256"] == expected
        parameters = data["parameters"]
        assert parameters["fileBytes"] == 1024
        assert parameters["fileSha256"] == hashlib.sha256(contents).hexdigest()
        assert parameters["warmupCount"] == 5 and parameters["measuredCount"] == 30
        assert parameters["routeOrder"] == performance.ROUTES
        assert parameters["image"] == plan["image"]
        vm = data["environment"]["vmPreflight"]
        assert vm["cleanupConfirmed"] and vm["no_new_privs"] and vm["seccomp"]
        assert vm["platform"] == "Linux" and vm["image"] == plan["image"]
        checks = performance.check_samples(data, expected, plan["budgets"])
        assert checks == execution["checks"]
        assert sum(c["passed"] for c in checks) == execution["passing_budgets"]
        native_start = next(c for c in checks if c["route"] == "native_gateway_read" and c["metric"] == "startup_ms")
        assert native_start["maximum"] is None and native_start["passed"] is True
        finite(native_start["actual"])
        rows.append({"round": index + 1, "profile": profile, "checks": checks,
                     "passing_budgets": execution["passing_budgets"],
                     "native_startup_ms": native_start["actual"]})
    passed = all(r["passing_budgets"] == 6 for r in rows if r["profile"] == "dev")
    assert report["all_dev_budgets_passed"] == passed
    return {"evidence_verified": True, "performance_passed": passed,
            "sources_verified": len(plan["sources"]),
            "successful_reads": 420, "runs": rows}


def finite(value):
    assert isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
    return value


def verify(out, repository):
    plan, report = read(out / "plan.json"), read(out / "comparison.json")
    assert report["plan_sha256"] == sha(out / "plan.json")
    raw = []
    for row in report["runs"]:
        path = repository / row["report"]
        assert row["report_sha256"] == sha(path)
        raw.append(read(path))
    result = check(plan, report, raw, out, repository)
    negative = []
    for kind in ["drop_round", "change_order", "restore_old_startup_budget",
                 "change_read_budget", "change_candidate", "missing_sample",
                 "wrong_content_size", "nan_latency", "vm_not_ready",
                 "fabricate_pass", "change_plan_count"]:
        p, r, data = deepcopy(plan), deepcopy(report), deepcopy(raw)
        if kind == "drop_round":
            r["runs"].pop()
        elif kind == "change_order":
            p["order"] = ["release", "dev", "dev", "release"]
        elif kind == "restore_old_startup_budget":
            p["budgets"]["native_startup_ms"] = 100
        elif kind == "change_read_budget":
            p["budgets"]["native_read_p95_ms"] = 10
        elif kind == "change_candidate":
            data[0]["parameters"]["candidateSha256"] = "0" * 64
        elif kind == "missing_sample":
            data[0]["routes"][1]["measured"].pop()
        elif kind == "wrong_content_size":
            data[0]["routes"][1]["measured"][0]["returnedBytes"] = 0
        elif kind == "nan_latency":
            data[0]["routes"][1]["measured"][0]["elapsedMs"] = float("nan")
        elif kind == "vm_not_ready":
            data[0]["environment"]["vmPreflight"]["cleanupConfirmed"] = False
        elif kind == "fabricate_pass":
            r["all_dev_budgets_passed"] = not r["all_dev_budgets_passed"]
        elif kind == "change_plan_count":
            p["rounds"] = 2
        try:
            check(p, r, data, out, repository)
        except (AssertionError, KeyError, TypeError, ValueError, StopIteration):
            negative.append(kind)
        else:
            raise AssertionError("未拒绝反例：" + kind)
    result["negative_cases_rejected"] = negative
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repository", type=Path, default=ROOT)
    args = parser.parse_args()
    out = args.directory if args.directory.is_absolute() else args.repository / args.directory
    result = verify(out.resolve(), args.repository.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result["performance_passed"] else 1)

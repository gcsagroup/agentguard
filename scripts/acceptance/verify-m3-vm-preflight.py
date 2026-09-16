#!/usr/bin/env python3
"""核对 VM 就绪修正前后的原预算及 WAL 分项；不能把证据有效当作性能通过。"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("performance", Path(__file__).with_name("verify-m3-performance.py"))
performance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(performance)
read, sha = performance.read, performance.sha


def classify_wal(row):
    previous = row["initial_wal"]
    buckets = {"no_transition_observed": [], "checkpoint_or_recycle_observed": []}
    for sample in row["reads"]:
        current = sample["wal"]
        assert all(isinstance(current[k], int) for k in ["change", "pagesize", "frames", "backfilled"])
        assert current["pagesize"] == 4096 and 0 <= current["backfilled"] <= current["frames"]
        assert current["change"] == previous["change"] + 2
        transition = current["frames"] < previous["frames"] or current["backfilled"] > previous["backfilled"]
        if not sample["warmup"]:
            buckets["checkpoint_or_recycle_observed" if transition else "no_transition_observed"].append(sample["elapsed_ms"])
        previous = current
    return {key: {"count": len(values), "p95_ms": sorted(values)[math.ceil(len(values) * .95) - 1],
                  "over_10_ms": sum(value > 10 for value in values)} for key, values in buckets.items()}


def check_preflight(report, expected_image):
    probe = report["environment"]["vmPreflight"]
    assert probe["marker"] == "AGD_BENCHMARK_VM_READY" and probe["platform"] == "Linux"
    assert probe["image"] == expected_image and probe["endpoint"].startswith("unix:///")
    assert all(probe[k] is True for k in ["no_new_privs", "seccomp", "cleanupConfirmed"])
    assert type(probe["uid"]) is int and probe["uid"] > 0
    assert re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", probe["boot_id"])
    assert isinstance(probe["kernel"], str) and 0 < len(probe["kernel"]) < 200
    assert performance.finite(probe["uptime_seconds"]) > 0
    assert performance.finite(probe["totalPreflightMs"]) >= performance.finite(probe["readinessElapsedMs"])
    assert probe["startedAt"] <= probe["readyAt"]
    return {"readiness_ms": probe["readinessElapsedMs"], "uptime_seconds": probe["uptime_seconds"],
            "boot_id_sha256": hashlib.sha256(probe["boot_id"].encode()).hexdigest()}


def verify(directory, repository):
    frozen = repository / ".artifacts/m3-performance-current-2026-09-16"
    build = read(frozen / "frozen-dev/build-inputs.json")
    expected = sha(frozen / "frozen-dev/agentguard-mcp")
    assert expected == build["binary_sha256"]
    for item in build["sources"]:
        path = Path(item["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert sha(repository / path) == sha(frozen / "frozen-dev/source" / path) == item["sha256"]
    timing_plan, timing = read(directory / "timing-plan.json"), read(directory / "timing.json")
    assert timing["completed"] and timing_plan["launches"] == 2
    assert timing_plan["native_reads_per_launch"] == 300 and timing_plan["warmup_per_launch"] == 5
    assert timing["plan_sha256"] == sha(directory / "timing-plan.json")
    assert timing_plan["harness_sha256"] == sha(directory / "measure-wal.mjs")
    assert timing["binary_sha256"] == timing_plan["diagnostic_binary_sha256"] == sha(frozen / "frozen-timing/agentguard-mcp")
    content = ("AGD_ISOLATION_BENCHMARK\n" * 50)[:1024]
    content_sha = hashlib.sha256(content.encode()).hexdigest()
    diagnostics = []
    assert len(timing["rounds"]) == 2
    for number, row in enumerate(timing["rounds"], 1):
        assert row["round"] == number
        result = performance.check_timing(row, performance.audit_rows(directory / f"timing-{number}/audit.db"), content_sha, 305)
        result["wal_groups"] = classify_wal(row)
        diagnostics.append(result)
    measurements, protocol_issues = [], []
    for corrected in [False, True]:
        folder = directory / "warm-preflight" if corrected else directory
        plan, comparison = read(folder / "comparison-plan.json"), read(folder / "comparison.json")
        assert comparison["completed"] and comparison["plan_sha256"] == sha(folder / "comparison-plan.json")
        assert plan["order"] == ["dev", "dev"] and plan["budgets"] == performance.BUDGETS
        assert plan["route_order"] == performance.ROUTES
        assert plan["warmup_per_route"] == 5 and plan["measured_per_route"] == 30
        assert len(comparison["runs"]) == 2
        # 两份真实预声明复制了旧四轮计划的 rounds 字段。保留原件和冲突，
        # 允许核对已采集样本，但不能将该批作为符合预声明的正式验收。
        if plan["rounds"] != len(plan["order"]):
            protocol_issues.append({"corrected_vm_preflight": corrected,
                                    "reason": "计划总轮次与执行顺序不一致",
                                    "declared_rounds": plan["rounds"],
                                    "ordered_rounds": len(plan["order"])})
        script = folder / ("agd-isolation-benchmark.mjs" if corrected else "benchmark-source-original.mjs")
        assert sha(script) == plan["benchmark_sha256"]
        if corrected:
            assert sha(repository / "scripts/acceptance/agd-isolation-benchmark.mjs") == sha(script)
            assert sha(folder / "docker-vm-preflight.mjs") == plan["preflight_sha256"]
            assert sha(repository / "scripts/acceptance/docker-vm-preflight.mjs") == plan["preflight_sha256"]
        runs = []
        for number, row in enumerate(comparison["runs"], 1):
            assert row["number"] == number and row["profile"] == "dev" and row["exit_code"] == 0
            assert row["candidate_sha256"] == expected
            relative = Path(row["report"])
            assert not relative.is_absolute() and ".." not in relative.parts
            path = repository / relative
            assert sha(path) == row["report_sha256"]
            report = read(path)
            checks = performance.check_samples(report, expected)
            assert checks == row["checks"] and sum(c["passed"] for c in checks) == row["passing_budgets"]
            result = {"round": number, "checks": checks, "passing_budgets": row["passing_budgets"]}
            if corrected:
                assert report["parameters"]["image"] == plan["image"]
                result["vm_preflight"] = check_preflight(report, plan["image"])
            runs.append(result)
        passed = all(row["passing_budgets"] == 6 for row in runs)
        assert passed == comparison["all_dev_budgets_passed"]
        measurements.append({"corrected_vm_preflight": corrected, "all_budgets_passed": passed, "runs": runs})
    return {"evidence_verified": True, "protocol_consistent": not protocol_issues,
            "protocol_issues": protocol_issues,
            "performance_passed": not protocol_issues and measurements[-1]["all_budgets_passed"],
            "source_inputs_verified": len(build["sources"]), "diagnostics": diagnostics, "measurements": measurements}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    result = verify(args.directory.resolve(), args.repository.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["performance_passed"] else 1)

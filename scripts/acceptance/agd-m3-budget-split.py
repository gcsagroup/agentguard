#!/usr/bin/env python3
"""冻结当前网关并按新口径跑四轮性能。不覆盖已冻结计划，不计时期间编译。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "verification", Path(__file__).with_name("verify-m3-performance.py")
)
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
write = lambda p, v: p.write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n")


def freeze(out, node, docker_host):
    assert not (out / "plan.json").exists(), "不覆盖已经冻结的计划"
    out.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    listed = subprocess.check_output(
        ["git", "ls-files", "-z", "crates", "apps/protected-browser",
         "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo"],
        cwd=ROOT,
    ).decode().strip("\0").split("\0")
    sources = []
    for name in listed:
        if not name:
            continue
        source = ROOT / name
        target = out / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        sources.append({"path": name, "sha256": sha(source)})
    builds = {}
    for profile, target in [("dev", "debug"), ("release", "release")]:
        origin = ROOT / "target" / target / "agentguard-mcp"
        destination = out / profile / "agentguard-mcp"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, destination)
        builds[profile] = {
            "binary": str(destination.relative_to(ROOT)),
            "sha256": sha(destination),
            "build_profile": profile,
        }
    for path in ["scripts/acceptance/agd-isolation-benchmark.mjs",
                 "scripts/acceptance/docker-vm-preflight.mjs",
                 "scripts/acceptance/verify-m3-performance.py"]:
        shutil.copy2(ROOT / path, out / Path(path).name)
    plan = {
        "base_commit": commit,
        "rounds": 4,
        "order": ["dev", "release", "release", "dev"],
        "budgets": verification.BUDGETS,
        "route_order": verification.ROUTES,
        "warmup_per_route": 5,
        "measured_per_route": 30,
        "file_bytes": 1024,
        "builds": builds,
        "sources": sources,
        "benchmark_sha256": sha(ROOT / "scripts/acceptance/agd-isolation-benchmark.mjs"),
        "preflight_sha256": sha(ROOT / "scripts/acceptance/docker-vm-preflight.mjs"),
        "verifier_sha256": sha(ROOT / "scripts/acceptance/verify-m3-performance.py"),
        "image": "sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490",
        "frozen_at": time.time(),
        "initial_load": os.getloadavg(),
        "node": str(node),
        "docker_host": docker_host,
        "pass_condition": "两轮 dev 硬门槛全部通过；native_startup_ms 的 maximum 为 null，只记录不计入失败",
        "timing_phase_no_local_build_or_tests": True,
        "app_rebuild": False,
        "persistence_unchanged": True,
    }
    write(out / "plan.json", plan)
    write(out / "comparison.json", {"plan_sha256": sha(out / "plan.json"), "completed": False, "runs": []})
    return plan


def run_rounds(out, node, docker_host):
    plan = json.loads((out / "plan.json").read_text())
    report = json.loads((out / "comparison.json").read_text())
    assert report["plan_sha256"] == sha(out / "plan.json")
    assert not report["completed"]
    assert plan["budgets"] == verification.BUDGETS
    for number, profile in enumerate(plan["order"], 1):
        build = plan["builds"][profile]
        binary = ROOT / build["binary"]
        assert sha(binary) == build["sha256"]
        assert sha(ROOT / "scripts/acceptance/agd-isolation-benchmark.mjs") == plan["benchmark_sha256"]
        row = {"number": number, "profile": profile, "started_at": time.time(),
               "candidate_sha256": sha(binary)}
        report["runs"].append(row)
        write(out / "comparison.json", report)
        print(f"开始 {number} {profile}", flush=True)
        env = {
            **os.environ,
            "PATH": str(node.parent) + ":" + os.environ.get("PATH", ""),
            "DOCKER_HOST": docker_host,
            "AGD_BENCHMARK_BINARY": str(binary),
            "AGD_BENCHMARK_SHA256": sha(binary),
        }
        env.pop("DOCKER_CONTEXT", None)
        log = out / f"benchmark-{number}-{profile}.log"
        with log.open("w") as output:
            result = subprocess.run(
                [str(node), "scripts/acceptance/agd-isolation-benchmark.mjs"],
                cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT,
            )
        row.update(exit_code=result.returncode, finished_at=time.time())
        path = Path(json.loads(log.read_text().splitlines()[-1])["report"])
        data = json.loads(path.read_text())
        row.update(
            report=str(path.relative_to(ROOT)),
            report_sha256=sha(path),
            checks=verification.check_samples(data, build["sha256"], plan["budgets"]),
        )
        row["passing_budgets"] = sum(check["passed"] for check in row["checks"])
        row["hard_budgets"] = sum(
            1 for check in row["checks"] if check["maximum"] is not None and check["passed"]
        )
        row["hard_budget_total"] = sum(1 for check in row["checks"] if check["maximum"] is not None)
        write(out / "comparison.json", report)
        print(f"结束 {number} {profile} {row['passing_budgets']}/6 硬门槛 {row['hard_budgets']}/{row['hard_budget_total']}", flush=True)
    report["completed"] = True
    report["all_dev_budgets_passed"] = all(
        row["exit_code"] == 0 and all(check["passed"] for check in row["checks"])
        for row in report["runs"] if row["profile"] == "dev"
    )
    report["final_load"] = os.getloadavg()
    write(out / "comparison.json", report)
    print(json.dumps({
        "completed": True,
        "all_dev_budgets_passed": report["all_dev_budgets_passed"],
    }, ensure_ascii=False), flush=True)
    return 0 if report["all_dev_budgets_passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(
        "/Users/lazy/.local/share/fnm/node-versions/v22.23.2/installation/bin/node"))
    parser.add_argument("--docker-host", default="unix:///Users/lazy/.docker/run/docker.sock")
    parser.add_argument("--freeze-only", action="store_true")
    parser.add_argument("--run-only", action="store_true")
    args = parser.parse_args()
    out = args.out if args.out.is_absolute() else ROOT / args.out
    if args.run_only:
        sys.exit(run_rounds(out, args.node, args.docker_host))
    freeze(out, args.node, args.docker_host)
    if args.freeze_only:
        return
    sys.exit(run_rounds(out, args.node, args.docker_host))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""用既有断网 Linux 镜像运行同一份回写引擎测试，只挂合成源码副本和只读 Cargo 缓存。"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[4]
IMAGE = "sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33"


def main():
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    out = ROOT / ".artifacts/development-run-2026-09-09/writeback-engine" / (run_id + "-linux")
    out.mkdir(parents=True, exist_ok=False)
    name = "agd-writeback-linux-" + run_id
    docker = shutil.which("docker") or "/usr/local/bin/docker"
    report = {"image": IMAGE, "platform": "Linux arm64 Docker VM", "toolchain": "1.91.1", "release_toolchain": "1.95.0", "release_candidate": False}
    with tempfile.TemporaryDirectory(prefix="agd-writeback-linux-") as temporary:
        temp = Path(temporary).resolve()
        source, build = temp / "source", temp / "build"
        source.mkdir(); build.mkdir()
        paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml"]
        for base in ["crates", "adapters"]:
            paths.extend(path for path in (ROOT / base).rglob("*") if path.is_file() and path.suffix in {".rs", ".toml", ".yaml", ".json", ".py"} and not set(path.parts).intersection({"target", "node_modules", ".artifacts"}))
        hashes = {}
        for path in paths:
            relative = path.relative_to(ROOT); target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes(); target.write_bytes(data)
            hashes[str(relative)] = hashlib.sha256(data).hexdigest()
        report["source_sha256"] = hashes
        registry = Path.home() / ".cargo/registry"
        command = [docker, "run", "--name", name, "--pull", "never", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "256", "--memory", "4g", "--cpus", "4", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--tmpfs", "/cargo-temp:rw,nosuid,nodev,size=32m", "--mount", f"type=bind,source={registry},target=/cargo-temp/registry,readonly", "--mount", f"type=bind,source={source},target=/source,readonly", "--mount", f"type=bind,source={build},target=/build", "--workdir", "/source", "--entrypoint", "/usr/bin/env", IMAGE, "-i", "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "CARGO_HOME=/cargo-temp", "RUSTUP_HOME=/usr/local/rustup", "RUSTUP_TOOLCHAIN=1.91.1", "CARGO_TARGET_DIR=/build/target", "CARGO_BUILD_JOBS=4", "cargo", "test", "--offline", "--locked", "-p", "guard-gateway", "--test", "writeback_engine", "--", "--test-threads=1"]
        report["command"] = command
        try:
            with (out / "cargo.stdout").open("w") as stdout, (out / "cargo.stderr").open("w") as stderr:
                completed = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=360)
            report["exit_code"] = completed.returncode
            report["state"] = "passed" if completed.returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            report["state"] = "timeout"
        finally:
            subprocess.run([docker, "rm", "--force", name], capture_output=True)
            (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"state": report["state"], "report": str(out / "report.json")}, ensure_ascii=False))
    raise SystemExit(0 if report["state"] == "passed" else 1)


if __name__ == "__main__":
    main()

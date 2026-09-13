#!/usr/bin/env python3
"""在无网络短命 Linux 容器内，用当前源码和只读本地 Cargo 缓存实测 guard-jail。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33"


JAIL_PROBE = r'''
import json,pathlib,socket,subprocess,tempfile
checks=[]
def record(name,ok,detail=None): checks.append({"name":name,"passed":bool(ok),"detail":detail})
with tempfile.TemporaryDirectory(prefix="agd-jail-extra-") as tmp:
    root=pathlib.Path(tmp); workspace=root/"workspace"; workspace.mkdir()
    secret=root/"private.txt"; secret.write_text("AGD_JAIL_PRIVATE_SENTINEL")
    ordinary=workspace/"input.txt"; ordinary.write_text("AGD_JAIL_NORMAL")
    plan=root/"plan.yaml"
    plan.write_text("require_plan: false\nplans:\n  - task_profile: jail_probe\n    goal: AGD-002\n    allow: [run_shell]\n    scope:\n      paths:\n        read: [\""+str(workspace)+"\"]\n        write: [\""+str(workspace)+"\"]\n      net:\n        connect_tcp: []\n        bind_tcp: []\n")
    def jailed(code):
        return subprocess.run(["/build/target/debug/agentguard-jail","--plans",str(plan),"--task","jail_probe","--","/usr/bin/python3","-c",code],capture_output=True,text=True,timeout=5,cwd=workspace)
    record("direct_private_read_control",secret.read_text()=="AGD_JAIL_PRIVATE_SENTINEL")
    r=jailed(f"import pathlib; print(pathlib.Path({str(ordinary)!r}).read_text()); pathlib.Path({str(workspace/'output.txt')!r}).write_text('AGD_JAIL_RESULT')")
    record("landlock_normal_read_write",r.returncode==0 and (workspace/"output.txt").read_text()=="AGD_JAIL_RESULT",r.stderr)
    r=jailed("import pathlib; print(pathlib.Path("+repr(str(secret))+").read_text())")
    record("landlock_private_read_denied",r.returncode!=0 and "Permission denied" in r.stderr and "AGD_JAIL_PRIVATE_SENTINEL" not in r.stdout,r.stderr)
    r=jailed(f"import pathlib; pathlib.Path({str(secret)!r}).write_text('BAD')")
    record("landlock_private_write_denied",r.returncode!=0 and secret.read_text()=="AGD_JAIL_PRIVATE_SENTINEL",r.stderr)
    link=workspace/"outside-link"; link.symlink_to(secret)
    r=jailed("import pathlib; print(pathlib.Path("+repr(str(link))+").read_text())")
    record("landlock_symlink_read_denied",r.returncode!=0 and "Permission denied" in r.stderr,r.stderr)
    child_code=f"import pathlib; print(pathlib.Path({str(secret)!r}).read_text())"
    r=jailed(f"import subprocess,sys; sys.exit(subprocess.run(['/usr/bin/python3','-c',{child_code!r}]).returncode)")
    record("landlock_descendant_read_denied",r.returncode!=0 and "Permission denied" in r.stderr,r.stderr)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0)); listener.listen()
        port=listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1",port),timeout=1): pass
        connection,_=listener.accept(); connection.close()
        record("loopback_connect_control",True)
        r=jailed(f"import socket; socket.create_connection(('127.0.0.1',{port}),timeout=1)")
        record("landlock_tcp_connect_denied",r.returncode!=0 and "Permission denied" in r.stderr,r.stderr)
    r=jailed("import socket; s=socket.socket(); s.bind(('127.0.0.1',45679))")
    record("landlock_tcp_bind_denied",r.returncode!=0 and "Permission denied" in r.stderr,r.stderr)
print(json.dumps({"checks":checks},ensure_ascii=False))
raise SystemExit(0 if all(check["passed"] for check in checks) else 1)
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    out = (args.out or ROOT / "eval/out/AGD-002" / (run_id + "-jail")).resolve()
    out.mkdir(parents=True, exist_ok=False)
    docker = shutil.which("docker") or "/usr/local/bin/docker"
    registry = Path.home() / ".cargo/registry"
    report = {"task": "AGD-002", "image_id": IMAGE, "toolchain": "1.91.1", "release_toolchain": "1.95.0", "release_candidate": False}
    name = "agd-isolation-jail-" + run_id
    with tempfile.TemporaryDirectory(prefix="agd-isolation-jail-") as tmp:
        temp = Path(tmp).resolve()
        src, build = temp / "source", temp / "build"
        src.mkdir(); build.mkdir()
        sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml"]
        # 不挂载原仓库、账户配置、环境变量和凭据，只复制构建需要的 Rust 源码/清单。
        for base in ["crates", "adapters"]:
            sources.extend(path for path in (ROOT / base).rglob("*") if path.is_file() and (path.suffix == ".rs" or path.name == "Cargo.toml") and "target" not in path.parts)
        hashes = {}
        for source in sources:
            relative = source.relative_to(ROOT)
            target = src / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes(); target.write_bytes(data)
            hashes[str(relative)] = hashlib.sha256(data).hexdigest()
        report["source_sha256"] = hashes
        cmd = [docker, "run", "--name", name, "--pull", "never", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "2g", "--cpus", "2", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "--tmpfs", "/cargo-temp:rw,nosuid,nodev,size=32m", "--mount", f"type=bind,source={registry},target=/cargo-temp/registry,readonly", "--mount", f"type=bind,source={src},target=/source,readonly", "--mount", f"type=bind,source={build},target=/build", "--workdir", "/source", "--entrypoint", "/usr/bin/env", IMAGE, "-i", "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "CARGO_HOME=/cargo-temp", "RUSTUP_HOME=/usr/local/rustup", "RUSTUP_TOOLCHAIN=1.91.1", "CARGO_TARGET_DIR=/build/target", "cargo", "test", "--offline", "--locked", "-p", "guard-jail", "--", "--nocapture", "--test-threads=1"]
        report["command"] = cmd
        try:
            with (out / "cargo.stdout").open("w") as stdout, (out / "cargo.stderr").open("w") as stderr:
                completed = subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=240)
            report["exit_code"] = completed.returncode
            report["state"] = "passed" if completed.returncode == 0 else "failed"
            # 单独保留 --probe；测试日志中的跳过不能算内核执行通过。
            probe_cmd = cmd[:cmd.index("cargo")] + ["/build/target/debug/agentguard-jail", "--probe"]
            probe_cmd[probe_cmd.index(name)] = name + "-probe"
            try:
                probe = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=20)
                (out / "probe.stdout").write_text(probe.stdout)
                (out / "probe.stderr").write_text(probe.stderr)
                report["probe_code"] = probe.returncode
                report["kernel_backend_available"] = "将使用：landlock" in probe.stdout
                if report["kernel_backend_available"] and completed.returncode == 0:
                    extra_cmd = cmd[:cmd.index("cargo")] + ["/usr/bin/python3", "-c", JAIL_PROBE]
                    extra_cmd[extra_cmd.index(name)] = name + "-extra"
                    try:
                        extra = subprocess.run(extra_cmd, capture_output=True, text=True, timeout=30)
                        (out / "kernel.stdout").write_text(extra.stdout)
                        (out / "kernel.stderr").write_text(extra.stderr)
                        report["kernel_extra_code"] = extra.returncode
                        if extra.returncode == 0:
                            report["kernel_checks"] = json.loads(extra.stdout)["checks"]
                        else:
                            report["state"] = "failed"
                    finally:
                        subprocess.run([docker, "rm", "--force", name + "-extra"], capture_output=True)
                else:
                    report["state"] = "failed"
            finally:
                subprocess.run([docker, "rm", "--force", name + "-probe"], capture_output=True)
        except subprocess.TimeoutExpired:
            report["state"] = "timeout"
        finally:
            subprocess.run([docker, "rm", "--force", name], capture_output=True)
            (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"state": report["state"], "report": str(out / "report.json")}, ensure_ascii=False))
    raise SystemExit(0 if report["state"] == "passed" and report.get("kernel_backend_available") else 1)


if __name__ == "__main__":
    main()

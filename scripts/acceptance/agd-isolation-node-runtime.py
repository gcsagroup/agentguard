#!/usr/bin/env python3
"""AGD-002/007 开发运行时：官方 Node 发布包校验后加入既有本地镜像，不拉取基础镜像。"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = "sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33"
VERSION = "v22.23.2"
NAME = f"node-{VERSION}-linux-arm64.tar.xz"
SHA256 = "fff4078c5def658577f92c88db7db3bc0072924bfb93fe52c1e744a54e94abb8"
URL = f"https://nodejs.org/dist/{VERSION}/{NAME}"


def main():
    docker = shutil.which("docker") or "/usr/local/bin/docker"
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    out = ROOT / "eval/out/AGD-002" / (run_id + "-node-runtime")
    out.mkdir(parents=True)
    report = {"base_image_id": BASE, "node_version": VERSION, "node_url": URL, "package_sha256": SHA256, "scope": "本地开发验收镜像；未证明发布供应链审查完成"}
    with tempfile.TemporaryDirectory(prefix="agd-isolation-node-") as tmp:
        temp = Path(tmp).resolve()
        package = temp / NAME
        shasums = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--location", "--connect-timeout", "10", "--max-time", "30", f"https://nodejs.org/dist/{VERSION}/SHASUMS256.txt"], capture_output=True, text=True, check=True)
        (out / "SHASUMS256.txt").write_text(shasums.stdout)
        assert f"{SHA256}  {NAME}" in shasums.stdout, "官方校验表与固定摘要不同"
        subprocess.run(["curl", "--silent", "--show-error", "--fail", "--location", "--connect-timeout", "10", "--max-time", "90", "--output", str(package), URL], check=True)
        assert hashlib.sha256(package.read_bytes()).hexdigest() == SHA256, "Node 包摘要不匹配"
        context = temp / "context"; context.mkdir()
        # 只读取准确的二进制成员，不展开归档路径或运行安装脚本。
        with tarfile.open(package, "r:xz") as archive:
            member = archive.getmember(f"node-{VERSION}-linux-arm64/bin/node")
            assert member.isfile() and 0 < member.size < 200 * 1024 * 1024
            binary = archive.extractfile(member).read()
            (context / "node").write_bytes(binary)
            (context / "node").chmod(0o755)
        report["node_binary_sha256"] = hashlib.sha256(binary).hexdigest()
        base_tag = f"agentguard-local/agd-runtime-base:{BASE[7:19]}"
        subprocess.run([docker, "image", "tag", BASE, base_tag], check=True)
        dockerfile = f"FROM {base_tag}\nCOPY --chmod=0755 node /usr/local/bin/node\nLABEL org.gcsa.agentguard.scope=development-acceptance org.gcsa.agentguard.node={VERSION}\n"
        (context / "Dockerfile").write_text(dockerfile)
        (out / "Dockerfile").write_text(dockerfile)
        tag = f"agentguard-local/agd-runtime:node22-{run_id}"
        with (out / "build.log").open("w") as log:
            result = subprocess.run([docker, "build", "--pull=false", "--network=none", "--tag", tag, str(context)], stdout=log, stderr=subprocess.STDOUT, timeout=120)
        report["build_exit_code"] = result.returncode
        if result.returncode:
            report["state"] = "failed"
        else:
            image = subprocess.run([docker, "image", "inspect", tag, "--format", "{{.Id}}"], capture_output=True, text=True, check=True).stdout.strip()
            report["image_id"] = image; report["image_tag"] = tag
            probe = subprocess.run([docker, "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "32", "--memory", "256m", "--entrypoint", "/usr/bin/env", image, "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "/bin/sh", "-c", "node --version; python3 --version"], capture_output=True, text=True, timeout=15)
            report["runtime_probe"] = {"code": probe.returncode, "stdout": probe.stdout, "stderr": probe.stderr}
            report["state"] = "passed" if probe.returncode == 0 and VERSION in probe.stdout and "Python 3.11" in probe.stdout else "failed"
        (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"state": report["state"], "image_id": report.get("image_id"), "report": str(out / "report.json")}, ensure_ascii=False))
    raise SystemExit(0 if report["state"] == "passed" else 1)


if __name__ == "__main__":
    main()

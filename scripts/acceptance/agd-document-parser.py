#!/usr/bin/env python3
"""串行验证准确文档运行时的解析组件与真实固定入口；只使用独立合成文件。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
DOCKER = "/usr/local/bin/docker"
BASE = "sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", args.image)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    frozen = out / "parser"
    frozen.mkdir()
    evidence = out / "results"
    evidence.mkdir()
    inputs = {}
    for source, name in [("crates/guard-gateway/src/document_parser.py", "document_parser.py"),
                         ("scripts/acceptance/agd-document-parser-cases.py", "cases.py")]:
        shutil.copyfile(ROOT / source, frozen / name)
        inputs[source] = sha(frozen / name)
    report = {"image_id": args.image, "inputs": inputs, "planned_entry_cases": 8,
              "entries": [], "passed": False, "scope": "隔离解析组件与入口，不是 RAG 或 App 验收"}

    def run(label, image, arguments, mounts, timeout=45):
        name = "agentguard-document-acceptance"
        command = [DOCKER, "run", "--rm", "--name", name, "--pull=never", "--network=none", "--read-only",
                   f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                   "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=1",
                   "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=67108864",
                   "--mount", f"type=bind,src={frozen},dst=/parser,readonly"]
        for mount in mounts:
            command.extend(["--mount", mount])
        command.extend(["--entrypoint=/usr/bin/python3", image, "-I", *arguments])
        (out / (label + ".command.json")).write_text(json.dumps(command, ensure_ascii=False, indent=2) + "\n")
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
            (out / (label + ".stdout")).write_bytes(result.stdout)
            (out / (label + ".stderr")).write_bytes(result.stderr)
            assert result.returncode == 0, (label, result.returncode)
            return json.loads(result.stdout)
        finally:
            cleanup = subprocess.run([DOCKER, "rm", "-f", name], capture_output=True, text=True, timeout=15)
            assert cleanup.returncode == 0 or "No such container" in cleanup.stderr, "无法确认自有容器已回收"

    try:
        component = run("component", args.image, ["/parser/cases.py"],
                        [f"type=bind,src={evidence},dst=/evidence"], timeout=120)
        assert component["passed"] and component["cases"] == component["planned"] == 36
        report["component"] = component
        for kind in ["pdf", "docx", "xlsx", "pptx", "png", "jpeg"]:
            source = evidence / ("normal." + kind)
            digest = sha(source)
            value = run("entry-" + kind, args.image, ["/parser/document_parser.py", kind],
                        [f"type=bind,src={source},dst=/input/source,readonly"])
            assert value["status"] == "parsed" and value["source_sha256"] == digest
            assert value["source_bytes"] == source.stat().st_size and sha(source) == digest
            assert value["text_sha256"] == hashlib.sha256(value["text"].encode()).hexdigest()
            report["entries"].append({"case": kind, "status": value["status"], "source_sha256": digest})
        source = evidence / "normal.pdf"
        missing = run("entry-missing-dependency", BASE, ["/parser/document_parser.py", "pdf"],
                      [f"type=bind,src={source},dst=/input/source,readonly"])
        assert missing["status"] == "dependency_missing" and "text" not in missing
        report["entries"].append({"case": "missing-dependency", "status": missing["status"]})
        source = evidence / "oversized.pdf"
        with source.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        large = run("entry-oversized", args.image, ["/parser/document_parser.py", "pdf"],
                    [f"type=bind,src={source},dst=/input/source,readonly"])
        assert large["status"] == "limit_exceeded" and large["source_sha256"] is None
        assert large["source_bytes"] == source.stat().st_size and "text" not in large
        report["entries"].append({"case": "oversized-input", "status": large["status"]})
        assert len(report["entries"]) == report["planned_entry_cases"]
        report["passed"] = True
    finally:
        (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""AGD-030：实测签名原生工作进程的文件授权；只读写本脚本新建的合成文件。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = "7C33B517942161311A087CE893D2F1CE9B204B44"
INITIAL = b"UNCHANGED_SYNTHETIC_OUTPUT"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="新建的本机证据目录，不覆盖旧轮次")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("此实验必须在 macOS 原生运行")
    os.umask(0o077)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)

    def command(name, argv, data=None, expected=0):
        # communicate 关闭 stdin，输入有上限；超时由 subprocess 回收直属探针。
        result = subprocess.run(argv, input=data, capture_output=True, timeout=30)
        (out / f"{name}.stdout").write_bytes(result.stdout)
        (out / f"{name}.stderr").write_bytes(result.stderr)
        assert result.returncode == expected, f"{name}: exit={result.returncode}，见本机 stderr"
        return result.stdout

    source = ROOT / "scripts/acceptance/native-bookmark-probe.m"
    shutil.copy2(source, out / source.name)
    info = {
        "CFBundleIdentifier": "com.agentguard.desktop.macos.localagenttest.native-probe",
        "CFBundleName": "AgentGuard Native API Probe",
        "CFBundleVersion": "3",
        "CFBundleShortVersionString": "0.1",
    }
    (out / "Info.plist").write_bytes(plistlib.dumps(info))
    (out / "sandbox.entitlements").write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}))
    broker, worker = out / "agentguard-native-broker", out / "agentguard-native-probe"
    command("compile", ["/usr/bin/xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                        "-framework", "Foundation", str(source), "-o", str(broker),
                        f"-Wl,-sectcreate,__TEXT,__info_plist,{out}/Info.plist"])
    shutil.copy2(broker, worker)
    for name, executable, entitlements in [("broker", broker, []), ("worker", worker, ["--entitlements", str(out / "sandbox.entitlements")])]:
        command(f"sign-{name}", ["/usr/bin/codesign", "--force", "--sign", IDENTITY,
                                "--options", "runtime", *entitlements, str(executable)])
        command(f"verify-{name}", ["/usr/bin/codesign", "--verify", "--strict", str(executable)])
    entitlements = command("worker-entitlements", ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(worker)])
    assert plistlib.loads(entitlements) == {"com.apple.security.app-sandbox": True}
    command("certificate", ["/usr/bin/codesign", "-d", f"--extract-certificates={out / 'signer-'}", str(worker)])
    assert hashlib.sha1((out / "signer-0").read_bytes()).hexdigest().upper() == IDENTITY

    # 不能把文件放在可执行程序目录中；那个位置可能已有沙箱基础读取权限。
    fixture_root = Path.home() / "Library/Application Support/AgentGuardNativeApiFixtures"
    fixture_root.mkdir(exist_ok=True)
    fixture = Path(tempfile.mkdtemp(prefix="run-", dir=fixture_root))
    workspace, outside = fixture / "合成工作区 空格", fixture / "合成范围外"
    workspace.mkdir(); outside.mkdir()
    (workspace / "input.txt").write_bytes(b"NATIVE_ALLOWED_INPUT")
    (outside / "secret.txt").write_bytes(b"NATIVE_OUTSIDE_SENTINEL")
    (workspace / "symlink.txt").symlink_to(outside / "secret.txt")
    os.link(outside / "secret.txt", workspace / "hardlink.txt")
    fields = {
        "workspace": str(workspace), "inside_file": str(workspace / "input.txt"),
        "outside_file": str(outside / "secret.txt"), "symlink_file": str(workspace / "symlink.txt"),
        "hardlink_file": str(workspace / "hardlink.txt"), "inside_output": str(workspace / "output.txt"),
        "outside_output": str(outside / "output.txt"),
    }
    (out / "fixture.json").write_text(json.dumps(fields, ensure_ascii=False, indent=2))
    bookmarks = {}
    baselines = {}
    for name, without in [("scoped", False), ("unscoped", True)]:
        raw = command(f"broker-{name}", [str(broker), "broker"], json.dumps({**fields, "without_scope": without}).encode())
        result = json.loads(raw)
        assert result["created"] and all(p["opened"] for p in result["baseline"].values())
        bookmarks[name] = result["bookmark"]
        baselines[name] = result["baseline"]
    cases = {}
    for name, bookmark in [("valid", bookmarks["scoped"]), ("no-scope", bookmarks["unscoped"]),
                           ("malformed", "aW52YWxpZC1ib29rbWFyaw=="), ("fresh-worker-replay", bookmarks["scoped"])]:
        for key in ["inside_output", "outside_output"]:
            Path(fields[key]).write_bytes(INITIAL)
        payload = json.dumps({**fields, "bookmark": bookmark}).encode()
        # 书签携带能力，只留在权限为 0600 的本机证据目录，不进入发布的 JSON。
        (out / f"{name}.input.json").write_bytes(payload)
        result = json.loads(command(name, [str(worker), "worker"], payload))
        result["actual_inside_output_hex"] = Path(fields["inside_output"]).read_bytes().hex()
        result["actual_outside_output_hex"] = Path(fields["outside_output"]).read_bytes().hex()
        cases[name] = result
    invalid_inputs = {"invalid-json": b"{", "oversized-input": b" " * 65537, "missing-fields": b"{}"}
    for name, payload in invalid_inputs.items():
        command(name, [str(worker), "worker"], payload, expected=2)
    report = {
        "schema": 1, "platform": platform.platform(), "machine": platform.machine(),
        "os": command("os", ["/usr/bin/sw_vers"]).decode().strip(),
        "signer_sha1": IDENTITY, "worker_entitlements": plistlib.loads(entitlements),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "fixture_directory": str(fixture), "workspace": str(workspace), "baselines": baselines,
        "cases": cases, "invalid_inputs_rejected": list(invalid_inputs),
        "scope": "仅原生 CLI 的 App Sandbox 文件授权 API；无 .app、无产品执行后端、无系统授权更改",
        "artifacts": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()},
    }
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"实验完成，待独立复核：{out / 'report.json'}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""用明确指定的网关验证真实审计事务故障；只操作新建的独立夹具。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "audit_verifier", Path(__file__).with_name("verify-m2-regression.py")
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


class Gateway:
    def __init__(self, binary, directory):
        self.proc = subprocess.Popen(
            [str(binary), "--rules", str(ROOT / "crates/guard-schema/rules/p0_rules.yaml"),
             "--shell-policy", str(ROOT / "crates/guard-shell/policies/default.yaml"),
             "--plans", str(directory / "plans.json"), "--task", "audit-batching",
             "--audit-db", str(directory / "audit.db"), "--confirm-port", "0"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.sequence = 0
        self.buffer = b""
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.proc.stdout, selectors.EVENT_READ)
        try:
            self.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                     "clientInfo": {"name": "audit-batching", "version": "1"}})
        except BaseException:
            self.close()
            raise

    def rpc(self, method, params=None):
        self.sequence += 1
        payload = {"jsonrpc": "2.0", "id": self.sequence, "method": method,
                   "params": params or {}}
        self.proc.stdin.write(json.dumps(payload).encode() + b"\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + 20
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and self.selector.select(remaining), "网关回执超时"
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            assert chunk, "网关提前退出"
            self.buffer += chunk
            assert len(self.buffer) <= 1024 * 1024, "网关回执超限"
        line, self.buffer = self.buffer.split(b"\n", 1)
        reply = json.loads(line)
        assert reply["id"] == self.sequence and "error" not in reply, reply
        return reply["result"]

    def close(self):
        self.selector.close()
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc.stdout.close()


def inject(database, event):
    # 固定事件枚举来自本脚本，不接受外部 SQL；真实 SQLite INSERT 失败。
    assert event in {"GatewayDecision", "GatewayExecutionStarted",
                     "GatewaySourceObserved", "GatewayExecutionFinished"}
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TRIGGER acceptance_failure BEFORE INSERT ON audit_events "
            f"WHEN NEW.event_type = '{event}' BEGIN "
            "SELECT RAISE(ABORT, '本次验收故障'); END"
        )


def run_case(binary, out, name, event):
    directory = out / name
    directory.mkdir()
    workspace = directory / "workspace"
    workspace.mkdir()
    content = "本次独立审计事务夹具：AUDIT_CANARY_20260915\n"
    target = workspace / "sample.txt"
    target.write_text(content)
    save(directory / "plans.json", {"plans": [{"task_profile": "audit-batching",
         "allow": ["run_shell"], "scope": {"paths": {"read": [str(workspace)]}}}]})
    database = directory / "audit.db"
    source_database = directory / "audit.db.sources.db"
    gateway = Gateway(binary, directory)
    checks = []

    def check(label, condition):
        checks.append({"name": label, "passed": bool(condition)})
        assert condition, label

    result = {"case": name, "checks": checks}
    try:
        if event:
            inject(source_database if event == "GatewaySourceObserved" else database, event)
        response = gateway.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(target)}})
        result["response"] = response
        stats = gateway.rpc("gateway/stats")
        result["stats"] = stats
        rows = verifier.audit_rows(database)
        sources = verifier.audit_rows(source_database)
        result["audit_rows"] = rows
        result["source_rows"] = sources
        check("原文件内容保持不变", target.read_text() == content)
        if event is None:
            check("实际读取正文一致", response["content"][0]["text"] == content and not response["isError"])
            check("三个独立执行事件齐全", [r["event_type"] for r in rows] ==
                  ["GatewayDecision", "GatewayExecutionStarted", "GatewayExecutionFinished"])
            check("来源单独持久保存", len(sources) == 1 and sources[0]["event_type"] == "GatewaySourceObserved")
            check("实际执行一次", stats["executed"] == 1)
        else:
            check("故障回执不返回读取正文", response["isError"] and "AUDIT_CANARY" not in json.dumps(response))
            before_execution = event in {"GatewayDecision", "GatewayExecutionStarted"}
            check("派发计数符合实际阶段", stats["executed"] == (0 if before_execution else 1))
            if before_execution:
                check("判决与开始一起回滚且无来源", len(rows) == 0 and len(sources) == 0)
            elif event == "GatewaySourceObserved":
                check("来源失败保留未知终态", len(rows) == 3 and not sources and json.loads(rows[-1]["event_json"])["outcome"] == "unknown")
            else:
                check("终态失败保留开始及来源", len(rows) == 2 and len(sources) == 1)
            second = gateway.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(target)}})
            check("同一会话下一动作拒绝", second["isError"] and gateway.rpc("gateway/stats")["executed"] == stats["executed"])
    finally:
        gateway.close()
        save(directory / "result.json", result)
    if event == "GatewayExecutionFinished":
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER acceptance_failure")
        recovered = Gateway(binary, directory)
        try:
            stats = recovered.rpc("gateway/stats")
            check("重启只恢复一次未知且零重放", stats["execution_journal"]["recovered_unknown"] == 1 and stats["executed"] == 0)
            rows = verifier.audit_rows(database)
            check("恢复后的链保留三条记录", len(rows) == 3 and json.loads(rows[-1]["event_json"])["outcome"] == "unknown")
            result["recovered_stats"] = stats
            result["recovered_rows"] = rows
        finally:
            recovered.close()
            save(directory / "result.json", result)
    result["passed"] = all(item["passed"] for item in checks)
    save(directory / "result.json", result)
    return {"case": name, "passed": result["passed"], "checks": len(checks)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256, "网关摘要不一致"
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"gateway_sha256": args.sha256, "binary": str(binary), "cases": [],
              "planned_cases": 5, "passed": False,
              "scope": "真实本机网关、SQLite 故障、独立验链与进程重启；不代替性能或 App 验收"}
    try:
        for name, event in [("success", None), ("decision-failure", "GatewayDecision"),
                            ("start-failure", "GatewayExecutionStarted"),
                            ("source-failure", "GatewaySourceObserved"),
                            ("finish-failure", "GatewayExecutionFinished")]:
            report["cases"].append(run_case(binary, out, name, event))
        report["passed"] = len(report["cases"]) == 5 and all(row["passed"] for row in report["cases"])
    finally:
        save(out / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()

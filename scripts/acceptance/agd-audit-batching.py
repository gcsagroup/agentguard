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
        self.stderr = (directory / f"gateway-{time.time_ns()}.stderr.log").open("xb")
        self.proc = subprocess.Popen(
            [str(binary), "--rules", str(ROOT / "crates/guard-schema/rules/p0_rules.yaml"),
             "--shell-policy", str(ROOT / "crates/guard-shell/policies/default.yaml"),
             "--plans", str(directory / "plans.json"), "--task", "audit-batching",
             "--audit-db", str(directory / "audit.db"), "--confirm-port", "0"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr,
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
        self.stderr.close()


def inject(database, event):
    # 固定事件枚举来自本脚本，不接受外部 SQL；真实 SQLite INSERT 失败。
    assert event in {"GatewayDecision", "GatewayExecutionStarted",
                     "GatewaySourceObserved", "GatewayExecutionFinished", "GatewaySourceStorageBinding"}
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
            inject(database, event)
        response = gateway.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(target)}})
        result["response"] = response
        stats = gateway.rpc("gateway/stats")
        result["stats"] = stats
        rows = verifier.audit_rows(database)
        sources = verifier.audit_rows(source_database)
        binding = [r for r in rows if r["event_type"] == "GatewaySourceStorageBinding"]
        events = [r for r in rows if r["event_type"] != "GatewaySourceStorageBinding"]
        result["audit_rows"] = rows
        result["source_rows"] = sources
        check("原文件内容保持不变", target.read_text() == content)
        check("旧来源库保持空库且主库仅一次绑定", not sources and len(binding) == 1)
        check("来源采集器使用执行日志", stats["source_provenance"]["storage"] == "execution_journal")
        if event is None:
            check("实际读取正文一致", response["content"][0]["text"] == content and not response["isError"])
            check("四个独立事件按顺序持久保存", [r["event_type"] for r in events] ==
                  ["GatewayDecision", "GatewayExecutionStarted", "GatewaySourceObserved", "GatewayExecutionFinished"])
            check("正文与终态摘要一致", json.loads(events[-1]["event_json"])["output_sha256"] ==
                  hashlib.sha256(content.encode()).hexdigest())
            check("新标签仅发布一次", stats["source_provenance"]["sources"] == 1)
            check("实际执行一次", stats["executed"] == 1)
            second = gateway.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(target)}})
            check("第二次显式读取成功", not second["isError"] and second["content"][0]["text"] == content)
            rows = verifier.audit_rows(database)
            check("第二次调用也完整留痕且每次恰一终态", len(rows) == 9 and
                  [r["event_type"] for r in rows[5:]] == [r["event_type"] for r in events])
            check("两次调用对应两个来源与两次派发", gateway.rpc("gateway/stats")["executed"] == 2 and
                  gateway.rpc("gateway/stats")["source_provenance"]["sources"] == 2)
            result["repeated_rows"] = rows
        else:
            check("故障回执不返回读取正文", response["isError"] and "AUDIT_CANARY" not in json.dumps(response))
            before_execution = event in {"GatewayDecision", "GatewayExecutionStarted"}
            check("派发计数符合实际阶段", stats["executed"] == (0 if before_execution else 1))
            if before_execution:
                check("判决与开始一起回滚且无来源", not events)
            else:
                check("来源与终态一起回滚且保留执行前两条记录", [r["event_type"] for r in events] ==
                      ["GatewayDecision", "GatewayExecutionStarted"])
            check("失败未发布来源标签", stats["source_provenance"]["sources"] == 0)
            second = gateway.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(target)}})
            check("同一会话下一动作拒绝", second["isError"] and gateway.rpc("gateway/stats")["executed"] == stats["executed"])
    finally:
        gateway.close()
        save(directory / "result.json", result)
    if event in {"GatewaySourceObserved", "GatewayExecutionFinished"}:
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER acceptance_failure")
        recovered = Gateway(binary, directory)
        try:
            stats = recovered.rpc("gateway/stats")
            check("重启只恢复一次未知且零重放", stats["execution_journal"]["recovered_unknown"] == 1 and stats["executed"] == 0)
            rows = verifier.audit_rows(database)
            check("恢复后的链保留绑定及三条执行记录", len(rows) == 4 and json.loads(rows[-1]["event_json"])["outcome"] == "unknown")
            check("恢复没有伪造成功来源", stats["source_provenance"]["sources"] == 0)
            result["recovered_stats"] = stats
            result["recovered_rows"] = rows
        finally:
            recovered.close()
            save(directory / "result.json", result)
    elif event is None:
        recovered = Gateway(binary, directory)
        try:
            stats = recovered.rpc("gateway/stats")
            check("成功重启恢复来源且零重放", stats["source_provenance"]["sources"] == 2 and
                  stats["execution_journal"]["recovered_unknown"] == 0 and stats["executed"] == 0)
            check("成功重启没有重复事件", verifier.audit_rows(database) == rows)
        finally:
            recovered.close()
    result["passed"] = all(item["passed"] for item in checks)
    save(directory / "result.json", result)
    return {"case": name, "passed": result["passed"], "checks": len(checks)}


def migration_case(binary, legacy_binary, out, name, fault):
    directory = out / name
    directory.mkdir()
    workspace = directory / "workspace"
    workspace.mkdir()
    target = workspace / "sample.txt"
    content = "旧网关独立来源 MIGRATION_CANARY\n"
    target.write_text(content)
    save(directory / "plans.json", {"plans": [{"task_profile": "audit-batching",
         "allow": ["run_shell"], "scope": {"paths": {"read": [str(workspace)]}}}]})
    database = directory / "audit.db"
    source_database = directory / "audit.db.sources.db"
    old = Gateway(legacy_binary, directory)
    try:
        response = old.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(target)}})
        assert response["content"][0]["text"] == content and not response["isError"]
    finally:
        old.close()
    original = verifier.audit_rows(database)
    old_sources = verifier.audit_rows(source_database)
    old_digest = hashlib.sha256(source_database.read_bytes()).hexdigest()
    assert len(old_sources) == 1 and len(original) == 3, "旧网关须实际写入独立来源库"
    checks = []
    result = {"case": name, "checks": checks, "legacy_source_sha256": old_digest,
              "legacy_sources": old_sources, "legacy_execution": original}

    def check(label, condition):
        checks.append({"name": label, "passed": bool(condition)})
        assert condition, label

    try:
        if fault:
            inject(database, "GatewaySourceStorageBinding")
            try:
                unexpected = Gateway(binary, directory)
            except AssertionError:
                pass
            else:
                unexpected.close()
                raise AssertionError("迁移末尾故障应拒绝启动")
            failure_log = max(directory.glob("gateway-*.stderr.log"), key=lambda path: path.name)
            check("启动失败明确来自迁移提交", "来源迁移不能完整提交" in failure_log.read_text())
            result["migration_failure_log"] = str(failure_log)
            check("迁移绑定失败时导入来源全部回滚", verifier.audit_rows(database) == original)
            check("迁移失败未改写旧来源库", hashlib.sha256(source_database.read_bytes()).hexdigest() == old_digest)
            with sqlite3.connect(database) as connection:
                connection.execute("DROP TRIGGER acceptance_failure")
        migrated = Gateway(binary, directory)
        try:
            stats = migrated.rpc("gateway/stats")
            check("迁移恢复真实旧来源且未派发动作", stats["source_provenance"]["sources"] == 1 and stats["executed"] == 0)
            rows = verifier.audit_rows(database)
            check("旧执行前缀完整保留", rows[:3] == original)
            check("旧来源对象与时间原样导入", rows[3]["id"] == old_sources[0]["id"] and
                  rows[3]["timestamp_ms"] == old_sources[0]["timestamp_ms"] and
                  rows[3]["event_json"] == old_sources[0]["event_json"])
            check("最后写入唯一迁移绑定", len(rows) == 5 and rows[-1]["event_type"] == "GatewaySourceStorageBinding")
            result["migrated_rows"] = rows
        finally:
            migrated.close()
        check("成功迁移后旧库字节保持", hashlib.sha256(source_database.read_bytes()).hexdigest() == old_digest)
        reopened = Gateway(binary, directory)
        try:
            check("迁移重开不重复导入", verifier.audit_rows(database) == rows and
                  reopened.rpc("gateway/stats")["source_provenance"]["sources"] == 1)
        finally:
            reopened.close()
        check("第二次打开仍保留旧库字节", hashlib.sha256(source_database.read_bytes()).hexdigest() == old_digest)
        result["passed"] = all(item["passed"] for item in checks)
    finally:
        save(directory / "result.json", result)
    return {"case": name, "passed": result["passed"], "checks": len(checks)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--legacy-binary", type=Path)
    parser.add_argument("--legacy-sha256")
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256, "网关摘要不一致"
    assert bool(args.legacy_binary) == bool(args.legacy_sha256), "旧网关路径与摘要须同时提供"
    if args.legacy_binary:
        assert hashlib.sha256(args.legacy_binary.read_bytes()).hexdigest() == args.legacy_sha256, "旧网关摘要不一致"
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"gateway_sha256": args.sha256, "binary": str(binary), "cases": [],
              "planned_cases": 7 if args.legacy_binary else 5, "passed": False,
              "legacy_binary": str(args.legacy_binary) if args.legacy_binary else None,
              "legacy_sha256": args.legacy_sha256,
              "scope": "真实本机网关、SQLite 故障、独立验链与进程重启；不代替性能或 App 验收"}
    try:
        for name, event in [("success", None), ("decision-failure", "GatewayDecision"),
                            ("start-failure", "GatewayExecutionStarted"),
                            ("source-failure", "GatewaySourceObserved"),
                            ("finish-failure", "GatewayExecutionFinished")]:
            report["cases"].append(run_case(binary, out, name, event))
        if args.legacy_binary:
            for name, fault in [("legacy-migration", False), ("migration-binding-failure", True)]:
                report["cases"].append(migration_case(binary, args.legacy_binary, out, name, fault))
        report["passed"] = len(report["cases"]) == report["planned_cases"] and all(row["passed"] for row in report["cases"])
    finally:
        save(out / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()

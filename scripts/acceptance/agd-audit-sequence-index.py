#!/usr/bin/env python3
"""真实启动旧版、索引版及旧版网关，核对同一独立审计库的升级与回退。"""
import argparse
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys


sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "audit_batching", Path(__file__).with_name("agd-audit-batching.py")
)
batching = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batching)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(database):
    rows = batching.verifier.audit_rows(database)
    assert [r["seq"] for r in rows] == list(range(1, len(rows) + 1)), "审计序号不连续"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        indexes = [r[0] for r in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name IN ('idx_audit_seq', 'idx_receipt_seq') ORDER BY name"
        )]
    return {"rows": rows, "indexes": indexes}


def review_gateway(gateway, expected_sha):
    # 只使用本次子进程输出的回环控制端；令牌和审核 nonce 不进入报告。
    startup = Path(gateway.stderr.name).read_text()
    port = re.search(r"确认接口 http://127\.0\.0\.1:(\d+)", startup)
    token = re.search(r"确认令牌 (\S+)", startup)
    assert port and token, "未取得本次网关的独立确认接口"

    def request(path, body):
        connection = http.client.HTTPConnection("127.0.0.1", int(port[1]), timeout=10)
        try:
            connection.request("POST", path, json.dumps(body).encode(),
                               {"Authorization": "Bearer " + token[1], "Content-Type": "application/json"})
            response = connection.getresponse()
            value = json.loads(response.read(4 * 1024 * 1024 + 1))
            assert response.status == 200, f"审核接口返回 {response.status}"
            return value
        finally:
            connection.close()

    review = request("/registry/review", {"service_id": "agentguard-gateway"})
    assert review["manifest"]["service_id"] == "agentguard-gateway"
    assert review["manifest"]["package"]["sha256"] == expected_sha, "审核对象不是指定候选"
    request("/registry/decide", {"service_id": "agentguard-gateway", "review_id": review["review_id"],
            "review_nonce": review["review_nonce"], "manifest_sha256": review["manifest_sha256"], "approve": True})
    return {"manifest_sha256": review["manifest_sha256"], "package_sha256": expected_sha}


def run(args):
    before = args.before_binary.resolve()
    indexed = args.indexed_binary.resolve()
    assert sha(before) == args.before_sha256, "旧版网关摘要不匹配"
    assert sha(indexed) == args.indexed_sha256, "索引版网关摘要不匹配"
    assert args.before_sha256 != args.indexed_sha256, "必须使用两个不同候选"
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    workspace = out / "workspace"
    workspace.mkdir()
    target = workspace / "sample.txt"
    content = "序号索引升级与回退：同一份正常资料 INDEX_CANARY\n"
    target.write_text(content, encoding="utf-8")
    batching.save(out / "plans.json", {"plans": [{"task_profile": "audit-batching",
        "allow": ["run_shell"], "scope": {"paths": {"read": [str(workspace)]}}}]})
    report = {"before_sha256": args.before_sha256, "indexed_sha256": args.indexed_sha256,
              "script_sha256": sha(Path(__file__)), "phases": [], "checks": [], "passed": False}

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        assert condition, name

    database = out / "audit.db"
    source_database = out / "audit.db.sources.db"
    previous_rows = None
    legacy_sources = None
    try:
        for number, (name, binary) in enumerate([
            ("before", before), ("indexed", indexed), ("rollback", before)
        ]):
            gateway = batching.Gateway(binary, out)
            phase = {"name": name, "binary_sha256": sha(binary), "pid": gateway.proc.pid}
            report["phases"].append(phase)
            try:
                startup = gateway.rpc("gateway/stats")
                opened = snapshot(database)
                phase["startup_stats"] = startup
                phase["opened"] = opened
                check(f"{name} 启动未自动重放", startup["executed"] == 0)
                check(f"{name} 没有未知执行需要恢复",
                      startup["execution_journal"]["recovered_unknown"] == 0)
                check(f"{name} 来源数量延续历史", startup["source_provenance"]["sources"] == number)
                check(f"{name} 索引符合候选阶段", opened["indexes"] ==
                      ([] if number == 0 else ["idx_audit_seq", "idx_receipt_seq"]))
                if previous_rows is not None:
                    check(f"{name} 打开后每个历史字段保持不变", opened["rows"] == previous_rows)
                    rejected = gateway.rpc("tools/call", {"name": "read_file",
                        "arguments": {"path": str(target)}})
                    phase["before_review_response"] = rejected
                    check(f"{name} 二进制改变后未经审核不得读取", rejected["isError"] and
                          gateway.rpc("gateway/stats")["executed"] == 0)
                    check(f"{name} 拒绝未增加执行或来源记录", snapshot(database)["rows"] == previous_rows)
                    phase["review"] = review_gateway(gateway, sha(binary))
                response = gateway.rpc("tools/call", {"name": "read_file",
                    "arguments": {"path": str(target)}})
                phase["response"] = response
                check(f"{name} 显式读取返回真实正文", not response["isError"] and
                      response["content"][0]["text"] == content)
                stats = gateway.rpc("gateway/stats")
                check(f"{name} 仅执行这一次请求", stats["executed"] == 1)
                check(f"{name} 仅新增一个来源", stats["source_provenance"]["sources"] == number + 1)
                current = snapshot(database)
                rows = current["rows"]
                check(f"{name} 审计条数符合三阶段约定", len(rows) == 5 + 4 * number)
                check(f"{name} 四个事件完整且有序", [r["event_type"] for r in rows[-4:]] ==
                      ["GatewayDecision", "GatewayExecutionStarted", "GatewaySourceObserved",
                       "GatewayExecutionFinished"])
                check(f"{name} 终态绑定实际读取摘要",
                      json.loads(rows[-1]["event_json"])["output_sha256"] == sha(target))
                if previous_rows is not None:
                    check(f"{name} 追加不改写历史", rows[:len(previous_rows)] == previous_rows)
                check(f"{name} 原始资料没有改变", target.read_text(encoding="utf-8") == content)
                phase["after"] = current
                phase["stats"] = stats
                previous_rows = rows
            finally:
                gateway.close()
                phase["exit_code"] = gateway.proc.returncode
            check(f"{name} 正常退出", phase["exit_code"] == 0)
            phase["database_sha256_after_exit"] = sha(database)
            sources = batching.verifier.audit_rows(source_database)
            check(f"{name} 旧来源库仍为空", sources == [])
            if legacy_sources is not None:
                check(f"{name} 旧来源库所有逻辑字段保持不变", sources == legacy_sources)
            legacy_sources = sources
        check("最终三次读取只留下一个来源库绑定",
              sum(r["event_type"] == "GatewaySourceStorageBinding" for r in previous_rows) == 1)
        check("测试期间两个候选未被替换", sha(before) == args.before_sha256 and
              sha(indexed) == args.indexed_sha256)
        report["passed"] = True
    finally:
        batching.save(out / "report.json", report)
    print(json.dumps({"passed": report["passed"], "phases": len(report["phases"]),
                      "checks": len(report["checks"]), "audit_rows": len(previous_rows)}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-binary", type=Path, required=True)
    parser.add_argument("--before-sha256", required=True)
    parser.add_argument("--indexed-binary", type=Path, required=True)
    parser.add_argument("--indexed-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args())

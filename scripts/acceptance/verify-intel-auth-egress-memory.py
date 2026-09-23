#!/usr/bin/env python3
"""核对 AUTH / EGRESS / MEMORY 已有入口；不写关键词规则，不改生效情报包。"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/evidence/intel-auth-egress-memory-2026-09-22.json"
BOOTSTRAP = ROOT / "scripts/bootstrap-rust.sh"


def run(args):
    command = [str(BOOTSTRAP), "--", *args]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return {
        "command": args,
        "exit": result.returncode,
        "passed": result.returncode == 0,
        "stderr_tail": result.stderr[-2500:],
    }


jobs = [
    {
        "id": "AUTH-NORMAL-AUDIENCE-SCOPE-ANON-QUOTE",
        "args": ["cargo", "test", "--locked", "-p", "guard-gateway", "auth_normal_audience_scope_anon_and_quote"],
    },
    {
        "id": "AUTH-ORIGIN",
        "args": ["cargo", "test", "--locked", "-p", "guard-gateway", "--test", "control_http", "auth_origin_rejects_non_loopback_host_and_origin"],
    },
    {
        "id": "AUTH-REVOKE-EGRESS",
        "args": ["cargo", "test", "--locked", "-p", "guard-gateway", "--test", "egress_control"],
    },
    {
        "id": "MEMORY-PRIV-004",
        "args": ["cargo", "test", "--locked", "-p", "guard-core", "持久记忆中的安装文档不当作待执行安装且保存仍需批准"],
    },
]

results = []
for job in jobs:
    results.append({"id": job["id"], **run(job["args"])})

summary = {
    "date": "2026-09-22",
    "scope": "接通已有 AUTH/EGRESS/PRIV-004 入口；IMPORT/PACKAGE/UNICODE 仍留队列",
    "bundle_unchanged": True,
    "keyword_rules_added": False,
    "results": results,
    "remaining": [
        "IMPORT/PACKAGE 正常查询误报未解决，不写子串拦截",
        "UNICODE 正常对照失败保留",
        "EGRESS 真实隔离会话的直接 socket/宿主别名核验仍以既有 AGD-008 记录为准，本批只复跑组件入口",
    ],
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: v for k, v in summary.items() if k != "results"}, ensure_ascii=False, indent=2))
for item in results:
    print(item["id"], "PASS" if item["passed"] else "FAIL", "exit", item["exit"])
    if not item["passed"]:
        print(item["stderr_tail"])
sys.exit(0 if all(item["passed"] for item in results) else 1)

#!/usr/bin/env python3
"""用真实 CLI 验证 webhook 时间窗、幂等与版本检查；只写本轮临时演示数据。"""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("用法: python3 scripts/check-billing-webhook.py <guard-cli>")
    sys.stdout.reconfigure(encoding="utf-8")
    cli = str(Path(sys.argv[1]).resolve(strict=True))
    repo = Path(__file__).resolve().parent.parent
    template_path = repo / "eval/fixtures/billing_webhook_purchase.json"
    original = template_path.read_bytes()
    template = json.loads(original)
    now = time.time_ns() // 1_000_000
    event = {**template, "created_ms": now, "event_id": "ci-purchase", "version": 1}

    with tempfile.TemporaryDirectory(prefix="agentguard-webhook-smoke-") as directory:
        temp = Path(directory)
        store = temp / "entitlement.json"
        fixture = temp / "event.json"

        def snapshot() -> dict[str, bytes]:
            return {p.name: p.read_bytes() for p in temp.iterdir() if p != fixture}

        def apply(body: dict, expected_error: str | None = None) -> None:
            before = snapshot()
            fixture.write_text(json.dumps(body), encoding="utf-8")
            result = subprocess.run(
                [cli, "billing-webhook", "--file", str(fixture), "--store", str(store)],
                cwd=repo, capture_output=True, text=True, encoding="utf-8", check=False,
            )
            if expected_error is None:
                if result.returncode != 0:
                    raise AssertionError(f"有效事件被拒绝: {result.stderr}")
            else:
                if result.returncode == 0 or expected_error not in result.stderr:
                    raise AssertionError(f"未按预期拒绝 {expected_error}: {result.stderr}")
                if snapshot() != before:
                    raise AssertionError("拒绝事件不应改变授权或幂等状态")

        apply(event)
        baseline = snapshot()
        apply(event)
        if snapshot() != baseline:
            raise AssertionError("重试同一事件不应改变状态")
        for delta in [-3_600_000, 3_600_000]:
            apply({**event, "event_id": str(delta), "created_ms": now + delta, "version": 2}, "outside the")
        apply({**event, "event_id": "ci-old-version"}, "not newer")
        for missing in ["event_id", "created_ms", "version"]:
            invalid = {**event, "event_id": "ci-missing", "version": 2}
            del invalid[missing]
            apply(invalid, f"missing {missing}")
        apply({**event, "type": "refund", "event_id": "ci-refund", "version": 2})
        status = subprocess.run(
            [cli, "entitlement-status", "--store", str(store)],
            cwd=repo, capture_output=True, text=True, encoding="utf-8", check=True,
        )
        if json.loads(store.read_text(encoding="utf-8"))["plan"] != "free":
            raise AssertionError(f"退款后必须回到 free: {status.stdout}")
    if template_path.read_bytes() != original:
        raise AssertionError("历史夹具不能被冒烟测试改写")
    print("billing-webhook: 9 个真实 CLI 场景通过；时间窗与版本检查保持启用")


if __name__ == "__main__":
    main()

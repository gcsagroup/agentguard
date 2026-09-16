#!/usr/bin/env python3
"""核对一次真实目标窗口卡顿的恢复顺序；不替代 UI、签名或整个发布验收。"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def unique(rows, key, value):
    found = [row for row in rows if row.get(key) == value]
    assert len(found) == 1, f"{key}={value} 应恰好出现一次"
    return found[0]


def check(fixture, trace, rows, baseline):
    begin = unique(fixture, "event", "main_thread_pause_begin")
    end = unique(fixture, "event", "main_thread_pause_end")
    scheduled = unique(fixture, "event", "pause_scheduled")
    assert begin["active"] and end["active"] and scheduled["active"]
    assert begin["pid"] == end["pid"] == scheduled["pid"]
    assert 44 <= end["uptime"] - begin["uptime"] <= 50
    start_ms, end_ms = begin["epoch_ms"], end["epoch_ms"]
    assert scheduled["epoch_ms"] < start_ms < end_ms
    assert not any(row["event"] == "resigned_active" and
                   start_ms <= row["epoch_ms"] <= end_ms for row in fixture)
    session_start = unique(trace, "kind", "session_start")
    session_end = unique(trace, "kind", "session_end")
    assert session_start["ts"] < start_ms < end_ms < session_end["ts"]
    assert not any(row["kind"].startswith("confirm_") for row in trace)
    states = [row for row in trace if row["kind"] == "state"]
    degraded = [row for row in states if start_ms <= row["ts"] < end_ms]
    assert degraded, "没有记录故障期间状态"
    first = next(row for row in degraded if row["protection_state"] == "degraded")
    degraded = [row for row in degraded if row["ts"] >= first["ts"]]
    assert len(degraded) >= 5
    for row in degraded:
        assert row["protection_state"] == "degraded"
        assert set(row.get("reasons", [])) == {"required_capability_unavailable", "observer_error"}
    ticks = [row for row in trace if row["kind"] == "observe_tick"]
    assert not any(row.get("source") == "ax" and start_ms <= row["ts"] < end_ms for row in ticks)
    screen_ticks = [row for row in ticks if row.get("source") == "sck" and
                    first["ts"] < row["ts"] < end_ms]
    assert screen_ticks, "没有验证屏幕心跳仍在时的降级"
    recovered_tick = next(row for row in ticks if row.get("source") == "ax" and
                          row.get("events", 0) > 0 and row["ts"] >= end_ms)
    recovered_state = next(row for row in states if row["ts"] >= end_ms and
                           row["protection_state"] == "active")
    assert recovered_tick["ts"] <= recovered_state["ts"] < session_end["ts"]
    assert not recovered_state.get("reasons")
    assert not any(row["ts"] > session_end["ts"] + 2000 for row in ticks)
    selected = [row for row in rows if row["seq"] > baseline]
    assert selected and selected[0]["seq"] == baseline + 1
    assert [row["seq"] for row in selected] == list(range(baseline + 1, selected[-1]["seq"] + 1))
    assert selected[0]["rule_id"] == "SESSION-START" and selected[-1]["rule_id"] == "SESSION-END"
    assert sum(row["rule_id"] == "SESSION-START" for row in selected) == 1
    assert sum(row["rule_id"] == "SESSION-END" for row in selected) == 1
    source = "app:sha256:" + hashlib.sha256("窗口响应验收夹具".encode()).hexdigest()[:32]
    observed = [row for row in selected if row["source_app"] == source]
    assert any(row["timestamp_ms"] < start_ms for row in observed)
    after = [row for row in observed if row["timestamp_ms"] >= end_ms]
    assert after and abs(after[0]["timestamp_ms"] - recovered_tick["ts"]) < 1000
    assert all(row["rule_id"] == "ALLOW" and row["severity"] == "Info" and
               row["action"] == "Allow" for row in observed)
    assert all(row["user_decision"] is None for row in selected)
    return {"verified": True, "scope": "真实前台合成窗口主线程卡顿后自动恢复",
            "audit_range": [selected[0]["seq"], selected[-1]["seq"]],
            "audit_rows": len(selected), "fixture_audit_seqs": [row["seq"] for row in observed],
            "pause_ms": end_ms - start_ms, "degraded_after_ms": first["ts"] - start_ms,
            "ax_resumed_after_ms": recovered_tick["ts"] - end_ms,
            "active_after_ms": recovered_state["ts"] - end_ms,
            "degraded_state_samples": len(degraded), "screen_ticks_while_degraded": len(screen_ticks),
            "confirmation_count": 0, "session_starts": 1, "session_ends": 1}


def verify(directory):
    fixture = [json.loads(line) for line in (directory / "fixture-events.jsonl").read_text().splitlines()]
    trace = [json.loads(line) for line in (directory / "trace-022.jsonl").read_text().splitlines()]
    plan = json.loads((directory / "plan.json").read_text())
    with sqlite3.connect(f"file:{directory / 'audit-after.db'}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute("SELECT * FROM audit_events ORDER BY seq")]
    result = check(fixture, trace, rows, plan["audit_baseline"][0])
    result["input_sha256"] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                             for name in ["fixture-events.jsonl", "trace-022.jsonl", "audit-after.db", "plan.json"]}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve()), ensure_ascii=False, indent=2))

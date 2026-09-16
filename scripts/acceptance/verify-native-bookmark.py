#!/usr/bin/env python3
"""独立核对 AGD-030 原生输出、实际文件结果和原始产物，不把 API 边界写成产品通过。"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

INITIAL_HEX = b"UNCHANGED_SYNTHETIC_OUTPUT".hex()
OUTPUT_HEX = b"NATIVE_BOOKMARK_OUTPUT".hex()
OPERATIONS = {"inside_read", "outside_read", "symlink_read", "hardlink_read", "inside_write", "outside_write"}


def verify(report, directory):
    assert report["schema"] == 1
    assert report["worker_entitlements"] == {"com.apple.security.app-sandbox": True}
    assert report["signer_sha1"] == "7C33B517942161311A087CE893D2F1CE9B204B44"
    assert hashlib.sha1((directory / "signer-0").read_bytes()).hexdigest().upper() == report["signer_sha1"]
    for name, expected in report["artifacts"].items():
        assert Path(name).name == name, "证据必须在同目录"
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected, name
    assert report["source_sha256"] == report["artifacts"]["native-bookmark-probe.m"]
    assert set(report["invalid_inputs_rejected"]) == {"invalid-json", "oversized-input", "missing-fields"}
    cases = report["cases"]
    assert set(cases) == {"valid", "no-scope", "malformed", "fresh-worker-replay"}
    assert len({case["pid"] for case in cases.values()}) == 4, "四个工作进程必须独立"
    for baseline in report["baselines"].values():
        assert set(baseline) == OPERATIONS
        assert all(value["opened"] and value["errno"] == 0 for value in baseline.values())
    for name, case in cases.items():
        raw = json.loads((directory / f"{name}.stdout").read_text())
        assert raw == {k: v for k, v in case.items() if not k.startswith("actual_")}, name
        positive = name in {"valid", "fresh-worker-replay"}
        assert bool(case["started"]) == positive
        for phase in ["before", "after_stop"]:
            assert set(case[phase]) == OPERATIONS
            assert all(not op["opened"] and op["errno"] == 1 for op in case[phase].values()), (name, phase)
        assert set(case["active"]) == OPERATIONS
        for operation, result in case["active"].items():
            allowed = positive and operation in {"inside_read", "inside_write", "hardlink_read"}
            assert bool(result["opened"]) == allowed, (name, operation)
            assert result["errno"] == (0 if allowed else 1)
        assert case["actual_outside_output_hex"] == INITIAL_HEX, "范围外文件发生变化"
        assert case["actual_inside_output_hex"] == (OUTPUT_HEX if positive else INITIAL_HEX)
        if positive:
            assert case["resolved_path"] == report["workspace"]
            assert case["active"]["inside_read"]["text"] == "NATIVE_ALLOWED_INPUT"
            assert case["active"]["hardlink_read"]["text"] == "NATIVE_OUTSIDE_SENTINEL", "必须保留硬链接边界证据"
            assert case["held_fd_after_stop_bytes"] == 20, "必须保留旧句柄可读的边界"
        else:
            assert case["held_fd_after_stop_bytes"] == -1
    assert not cases["malformed"]["resolved"]
    return {"worker_cases": 4, "invalid_inputs": 3, "artifacts": len(report["artifacts"]),
            "file_scope_api_verified": True, "product_backend_verified": False,
            "known_boundaries_verified": ["hardlink", "open_descriptor", "bookmark_replay"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--self-test", action="store_true", help="确认错误副作用、边界掩盖和摘要变化被拒绝")
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    result = verify(report, args.report.parent)
    if args.self_test:
        mutations = []
        r = copy.deepcopy(report); r["cases"]["valid"]["actual_outside_output_hex"] = "00"; mutations.append(r)
        r = copy.deepcopy(report); r["cases"]["valid"]["held_fd_after_stop_bytes"] = -1; mutations.append(r)
        r = copy.deepcopy(report); r["artifacts"]["native-bookmark-probe.m"] = "0" * 64; mutations.append(r)
        r = copy.deepcopy(report); r["cases"]["fresh-worker-replay"]["pid"] = r["cases"]["valid"]["pid"]; mutations.append(r)
        for r in mutations:
            try:
                verify(r, args.report.parent)
            except AssertionError:
                continue
            raise AssertionError("篡改未被拒绝")
        result["tampered_reports_rejected"] = len(mutations)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

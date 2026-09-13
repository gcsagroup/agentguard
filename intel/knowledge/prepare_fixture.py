#!/usr/bin/env python3
"""准备独立临时验收目录；只操作自建测试数据，不执行外部 PoC。"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[2]
CATALOG = Path(__file__).resolve().parent / "v0.1" / "catalog.json"


def prepare(number, parent):
    """目录由 mkdtemp 独占新建；重复运行不覆盖用户已有数据。"""
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    scenario = next(item for item in catalog["scenarios"] if item["id"] == f"GCSA-AS-{number:03}")
    fixture = scenario["fixtures"][0]
    source = (REPOSITORY / fixture["path"]).resolve()
    if not source.is_relative_to(REPOSITORY):
        raise ValueError("夹具路径逃出仓库")
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != fixture["sha256"]:
        raise ValueError("夹具摘要不匹配")
    data = json.loads(raw)
    root = Path(tempfile.mkdtemp(prefix=f"gcsa-as-{number:03}-", dir=parent))
    workspace = root / "workspace"
    outside = root / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "input.json").write_bytes(raw)
    (workspace / "normal.txt").write_text(scenario["normal_task"], encoding="utf-8")
    (outside / "marker.txt").write_text("GCSA_TEST_ONLY_OUTSIDE_MARKER", encoding="utf-8")
    (outside / "write-target.txt").write_text("GCSA_TEST_ONLY_UNCHANGED", encoding="utf-8")
    if number == 1:
        (workspace / "README.md").write_text(data["text"], encoding="utf-8")
    if number == 2:
        # 仅定位本准备器刚刚建立的相邻测试目录；无 HOME、凭据或公网访问。
        (workspace / "boundary.py").write_text(
            'from pathlib import Path\n'
            'base = Path(__file__).resolve().parent.parent / "outside"\n'
            'print((base / "marker.txt").read_text())\n'
            '(base / "write-target.txt").write_text("GCSA_TEST_ONLY_CHANGED")\n',
            encoding="utf-8",
        )
        (workspace / "boundary.mjs").write_text(
            'import {readFileSync, writeFileSync} from "node:fs";\n'
            'console.log(readFileSync(new URL("../outside/marker.txt", import.meta.url), "utf8"));\n'
            'writeFileSync(new URL("../outside/write-target.txt", import.meta.url), "GCSA_TEST_ONLY_CHANGED");\n',
            encoding="utf-8",
        )
    if number == 3:
        (workspace / "unicode.txt").write_text(data["text"], encoding="utf-8")
    if number == 4:
        (workspace / "hidden.html").write_text(data["html_fragment"], encoding="utf-8")
        (workspace / "parsed-hidden.txt").write_text(data["parsed_hidden"], encoding="utf-8")
    if number == 8:
        (outside / "fake-credential.txt").write_text(data["canary"], encoding="utf-8")
    if number == 11:
        for name in data["local_inboxes"]:
            (root / name).mkdir()
    return {"scenario_id": scenario["id"], "fixture_root": str(root), "workspace": str(workspace),
            "outside": str(outside), "product_status": "not_run",
            "note": "准备成功不是产品保护通过；产品运行需记录候选、判决与实际副作用。"}


def self_test():
    checked = []
    with tempfile.TemporaryDirectory(prefix="gcsa-fixture-self-test-") as parent:
        for number in range(1, 13):
            result = prepare(number, parent)
            workspace = Path(result["workspace"])
            outside = Path(result["outside"])
            assert (workspace / "normal.txt").read_text(encoding="utf-8")
            assert (outside / "write-target.txt").read_text() == "GCSA_TEST_ONLY_UNCHANGED"
            if number == 2:
                # 无隔离对照：证明确实访问和修改测试目录外的标记，供后端对照使用。
                run = subprocess.run([sys.executable, "-I", str(workspace / "boundary.py")],
                                     cwd=workspace, capture_output=True, text=True, timeout=5, check=True)
                assert "GCSA_TEST_ONLY_OUTSIDE_MARKER" in run.stdout
                assert (outside / "write-target.txt").read_text() == "GCSA_TEST_ONLY_CHANGED"
            if number == 3:
                data = json.loads((workspace / "input.json").read_text())
                assert (workspace / "unicode.txt").read_bytes() == data["text"].encode("utf-8")
            if number == 4:
                assert "\u200b" in (workspace / "parsed-hidden.txt").read_text()
            if number == 8:
                assert (outside / "fake-credential.txt").read_text().startswith("GCSA_FAKE_TOKEN_NOT_A_CREDENTIAL")
            checked.append(result["scenario_id"])
    return {"fixture_preparation": "passed", "scenarios_prepared": checked,
            "unisolated_python_control": "read_and_write_observed", "product_scenarios_run": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", type=int, choices=range(1, 13))
    group.add_argument("--self-test", action="store_true")
    parser.add_argument("--parent", type=Path, help="已有测试父目录；不提供时由系统临时目录承载")
    args = parser.parse_args()
    result = self_test() if args.self_test else prepare(args.scenario, args.parent)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

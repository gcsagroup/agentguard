"""核对签名规则与原浏览器矩阵的数据库、回执和业务账本，不重跑外部动作。"""
import argparse
import hashlib
import importlib.util
import json
import sqlite3
import subprocess
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(runtime, browser, normal, cycles, source, expected, node):
    spec = importlib.util.spec_from_file_location("regression", Path(__file__).with_name("verify-m2-regression.py"))
    regression = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(regression)
    audit_rows = regression.audit_rows
    rule_rows = 0
    releases = []
    for directory, count, sequence in [(runtime, 17, 10), (browser, 8, 6)]:
        report = read(directory / "report.json")
        assert report["binarySha256"] == expected and report["passed"]
        assert len(report["checks"]) == count and all(c["passed"] for c in report["checks"])
        operator = Path(report["fixture"]) / "operator"
        names = ["audit.db", "audit.db.sources.db", "audit.db.tools.db"]
        if directory == browser:
            names.append("browser.db")
        for name in names:
            rule_rows += len(audit_rows(operator / name))
        with sqlite3.connect((operator / "rule-packages.db").as_uri() + "?mode=ro", uri=True) as db:
            updates = db.execute("SELECT sequence,release_sha256,signed_bytes FROM package_updates ORDER BY sequence").fetchall()
        assert [r[0] for r in updates] == list(range(1, sequence + 1))
        config = read(operator / "rule-package.json")
        for number, digest, signed_bytes in updates:
            signed = json.loads(signed_bytes)
            assert signed["release"]["sequence"] == number
            assert signed["signature"].startswith("ed25519:")
            matches = [p for p in report["packages"] if p["release_sha256"] == digest and p["signed"] == signed]
            assert matches
            assert all(read(Path(item["path"])) == signed for item in matches)
            releases.append({"public": config["public_key_base64"], "signed": signed, "sha256": digest})
    # 独立使用 Node 内建密码库验签；不加载本项目的签发实现或任何私钥。
    signature_check = """
const fs=require('node:fs'),c=require('node:crypto'),a=require('node:assert/strict');
const canonical=v=>Array.isArray(v)?`[${v.map(canonical).join(',')}]`:v&&typeof v==='object'?`{${Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')}}`:JSON.stringify(v);
const digest=v=>c.createHash('sha256').update('agentguard.package-release.v1\\0').update(canonical(v)).digest();
const rows=JSON.parse(fs.readFileSync(0,'utf8'));
for(const r of rows){const key=c.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(r.public,'base64')]),type:'spki',format:'der'});const signature=Buffer.from(r.signed.signature.slice(8),'base64');a.equal(digest(r.signed.release).toString('hex'),r.sha256);a.ok(c.verify(null,digest(r.signed.release),key,signature));a.equal(c.verify(null,digest({...r.signed.release,sequence:r.signed.release.sequence+1}),key,signature),false);}
process.stdout.write(JSON.stringify({verified:rows.length,modified_sequence_refused:rows.length}));
"""
    signatures = json.loads(subprocess.check_output([node, "-e", signature_check], input=json.dumps(releases).encode()))
    assert signatures["verified"] == 16
    actual = read(runtime / "report.json")
    assert len(actual["remoteEffects"]) == 1 and actual["remoteEffects"][0]["value"] == "NEW_POLICY_EFFECT"
    operator = Path(actual["fixture"]) / "operator"
    assert (operator / "remote-note.txt").read_text() == "NEW_POLICY_EFFECT"
    assert [json.loads(line) for line in (operator / "remote-effects.jsonl").read_text().splitlines()] == actual["remoteEffects"]
    actual = read(browser / "report.json")
    posts = [r for r in actual["requests"] if r["method"] == "POST"]
    assert len(posts) == 1 and posts[0]["body"] == "CURRENT_HTTP"

    summary = read(normal / "summary.json")
    cycle = read(cycles / "report.json")
    for report in [summary, cycle]:
        assert report["binarySha256"] == sha(Path(report["testedBinary"])) == expected
        assert report["sourceBefore"] == report["sourceAfter"] and report["sourceUnchanged"]
        for name, digest in report["sourceBefore"].items():
            assert sha(source / name) == digest, name
    assert summary["denominator"] == summary["passedTasks"] == len(summary["tasks"]) == 10
    assert summary["allTenCompleted"]
    browser_rows = 0
    for number, item in enumerate(summary["tasks"], 1):
        assert item["id"] == f"B{number:02d}" and item["passed"]
        task = read(normal / item["id"] / "report.json")
        assert task["passed"] and not task.get("cleanupError")
        assert len(task["submissions"]) == (0 if number < 3 else 1)
        for index, host in enumerate(task["hosts"], 1):
            rows = audit_rows(normal / item["id"] / f"browser-{index}.db")
            assert rows == host["journal"]["rows"]
            assert host["closed"] and not host["remainingContainers"]
            browser_rows += len(rows)
            events = [(r["event_type"], json.loads(r["event_json"])) for r in rows]
            for approval in task["approvals"]:
                if approval["hostPid"] != host["pid"] or not approval.get("terminalRequired"):
                    continue
                final = [e for kind, e in events if kind == "GatewayExecutionFinished" and e["action_sha256"] == approval["actionSha256"]]
                assert len(final) == 1 and final[0]["outcome"] == approval["outcome"]
            for observation in task["observations"]:
                if observation["hostPid"] == host["pid"]:
                    receipt = observation["receipt"]
                    final = [e for kind, e in events if kind == "GatewayExecutionFinished" and e["action_sha256"] == receipt["action_sha256"]]
                    assert len(final) == 1 and final[0]["outcome"] == receipt["outcome"]

    assert cycle["all100Passed"] and cycle["denominator"] == cycle["executed"] == len(cycle["results"]) == 100
    assert cycle["expectedPosts"] == cycle["ledgerPosts"] == len(cycle["ledger"]) == 50
    assert len(cycle["blocks"]) == 10
    assert [item["id"] for item in cycle["results"]] == [f"C{n:03d}" for n in range(1, 101)]
    assert cycle["results"] == [item for block in cycle["blocks"] for item in block["cycles"]]
    modes = {name: sum(r["mode"] == name for r in cycle["results"]) for name in ["approve", "deny", "disconnect"]}
    assert modes == {"approve": 50, "deny": 40, "disconnect": 10}
    for block in cycle["blocks"]:
        directory = cycles / f"block-{block['number']:02d}"
        rows = audit_rows(directory / "browser.db")
        assert rows == read(directory / "browser.db.rows.json")
        browser_rows += len(rows)
        assert block["passed"]
        assert all(block["cleanup"][k] for k in ["allOwnedProcessesExited", "credentialsRemoved", "profilesRemoved", "workspaceUnchanged"])
        for item in block["setup"] + block["cycles"]:
            final = [r for r in rows if r["event_type"] == "GatewayExecutionFinished" and json.loads(r["event_json"])["action_sha256"] == item["actionSha256"]]
            assert len(final) == 1
            persisted = {**json.loads(final[0]["event_json"]), "record_hash": final[0]["record_hash"]}
            assert item["persistedHttpReceipt"] == persisted
            assert persisted["dispatched"] == (item["mode"] == "approve")
            assert persisted["outcome"] in (["success"] if item["mode"] == "approve" else ["refused", "cancelled"])
            if "beforePosts" in item:
                assert item["afterPosts"] - item["beforePosts"] == (item["mode"] == "approve")
    posts = [r for r in cycle["requests"] if r["method"] == "POST"]
    assert len(posts) == 50
    assert [r["sequence"] for r in cycle["ledger"]] == list(range(1, 51))
    assert posts == [{k: r[k] for k in ["method", "path", "body"]} for r in cycle["ledger"]]
    bodies = {r["bodySha256"] for r in cycle["results"]}
    assert len(bodies) == 1
    assert all(r["method"] == "POST" and r["path"] == "/submit" and
               hashlib.sha256(r["body"].encode()).hexdigest() in bodies for r in cycle["ledger"])
    return {"evidence_verified": True, "gateway_sha256": expected, "rule_checks": 25,
            "signed_releases": signatures, "rule_audit_rows": rule_rows, "browser_tasks": 10,
            "browser_cycles": 100, "browser_audit_rows": browser_rows, "cycle_post_count": 50,
            "scope": "复核本机合成服务的留存数据库和业务记录，不代替原生验收或重新发送请求。"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["runtime", "browser", "normal", "cycles", "source", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    result = verify(args.runtime, args.browser, args.normal, args.cycles, args.source, args.sha256, args.node)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))

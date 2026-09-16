#!/usr/bin/env python3
"""独立读回 Relay v2 开发证据；不产生正式 Android 验收 PASS。"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signed_bytes(domain, fields):
    return domain + b"".join(struct.pack(">I", len(value)) + value for value in fields)


def verify_signature(public_hex, signature_hex, message):
    # 独立使用 OpenSSL，仅从公开 SEC1 点构造 SubjectPublicKeyInfo。
    with tempfile.TemporaryDirectory(prefix="agentguard-relay-verify-") as temporary:
        folder = Path(temporary)
        (folder / "public.der").write_bytes(bytes.fromhex(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200" + public_hex))
        (folder / "signature.der").write_bytes(bytes.fromhex(signature_hex))
        (folder / "message").write_bytes(message)
        converted = subprocess.run([
            "openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(folder / "public.der"),
            "-out", str(folder / "public.pem"),
        ], capture_output=True, check=False)
        assert converted.returncode == 0, "公钥转换失败"
        verified = subprocess.run([
            "openssl", "dgst", "-sha256", "-verify", str(folder / "public.pem"),
            "-signature", str(folder / "signature.der"), str(folder / "message"),
        ], capture_output=True, check=False)
        assert verified.returncode == 0, "原始字节验签失败"


def prefs(path):
    root = ET.parse(path).getroot()
    for node in root:
        if "token" in node.get("name", "").lower():
            assert node.text == "[redacted]" and "value" not in node.attrib, "偏好令牌未遮盖"
    return {node.get("name"): node.get("value", node.text) for node in root}


def native_inputs(folder):
    result = {name: json.loads((folder / (name + ".json")).read_text()) for name in (
        "held-response", "held-delivery", "delay-stop-proof", "native-status-dev8-connected",
    )}
    for label in ("dev8-connected", "dev8-wrong-key", "dev8-stop-settled",
                  "delay-before-release", "delay-settled"):
        result[label] = prefs(folder / f"prefs-{label}.xml")
    result["notifications"] = (folder / "notifications-delay.txt").read_text()
    result["process"] = (folder / "native-process-after.txt").read_text().strip()
    result["server_key"] = (folder / "native-server-public.txt").read_text().strip()
    result["device_key"] = (folder / "native-device-public.txt").read_text().strip()
    return result


def verify_native(data):
    connected, wrong = data["dev8-connected"], data["dev8-wrong-key"]
    assert connected["session_requested"] == "true" and "last_relay_error" not in connected
    assert int(connected["relay_v2_last_ok_ms"]) > int(connected["session_started_ms"])
    assert wrong["relay_v2_server_key"] == connected["relay_v2_server_key"] == data["server_key"]
    assert wrong["relay_v2_last_ok_ms"] == connected["relay_v2_last_ok_ms"]
    assert "公钥不匹配" in wrong["last_relay_error"]
    assert data["dev8-stop-settled"]["session_requested"] == "false"
    assert data["dev8-stop-settled"]["relay_v2_last_ok_ms"] == connected["relay_v2_last_ok_ms"]
    ingress = data["native-status-dev8-connected"]["adapter_ingress"]
    assert ingress["verified"] > 0 and ingress["unsigned"] == ingress["rejected"] == 0
    before, after = data["delay-before-release"], data["delay-settled"]
    assert before["session_requested"] == after["session_requested"] == "false"
    assert before["relay_v2_last_ok_ms"] == after["relay_v2_last_ok_ms"]
    assert before["session_id"] == after["session_id"]
    assert re.fullmatch(r"[0-9]+", data["process"]), "进程未保持运行"
    assert not re.search(r"pkg=com\.agentguard\.companion[^\n]*\bid=1005\b", data["notifications"])
    held, delivered, stopped = data["held-response"], data["held-delivery"], data["delay-stop-proof"]
    assert delivered["released_by_test"] and stopped["session_stopped"]
    assert held["held_ms"] <= stopped["stop_observed_ms"] < delivered["released_ms"]
    assert 0 < delivered["wait_ms"] < 3000
    request, response = held["request"].encode(), held["response"].encode()
    assert json.loads(request)["session_id"] == after["session_id"]
    body = json.loads(response)
    assert body["ok"] and body["adapter_identity"]["state"] == "verified"
    assert any(item["rule_id"] == "CRIT-001" and item["require_confirm"] and
               item["action"] == "Block" for item in body["decisions"])
    req = {key.lower(): value for key, value in held["request_headers"].items()}
    res = {key.lower(): value for key, value in held["response_headers"].items()}
    assert res["x-agentguard-relay-version"] == "2"
    assert res["x-agentguard-relay-key-id"] == hashlib.sha256(bytes.fromhex(data["server_key"])).hexdigest()
    message = signed_bytes(b"AGENTGUARD-RELAY-RESPONSE-v2", [
        b"POST", b"/v2/events", bytes.fromhex(req["x-agentguard-relay-nonce"]),
        hashlib.sha256(request).digest(), b"200", res["x-agentguard-relay-timestamp"].encode(), response,
    ])
    verify_signature(data["server_key"], res["x-agentguard-relay-signature"], message)
    device_message = signed_bytes(b"AGENTGUARD-ADAPTER-BODY-v1", [
        req["x-agentguard-adapter"].encode(), b"android-envelope",
        req["x-agentguard-timestamp"].encode(), request,
    ])
    verify_signature(data["device_key"], req["x-agentguard-signature"], device_message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads(args.evidence.read_text())
    folder = root / manifest["artifact_directory"]
    assert manifest["formal_android_acceptance_passed"] is False
    for name, expected in manifest["source_files"].items():
        assert digest(root / name) == expected, f"源码变化：{name}"
    for name, expected in manifest["artifact_files"].items():
        assert digest(folder / name) == expected, f"证据变化：{name}"
    for variant in ("Debug", "Release"):
        suites = list((folder / "verified-tests" / variant).glob("TEST-*.xml"))
        totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
        for path in suites:
            suite = ET.parse(path).getroot()
            for key in totals:
                totals[key] += int(suite.get(key, "0"))
        assert len(suites) == 16 and totals == dict(tests=100, failures=0, errors=0, skipped=0)
        assert not ET.parse(folder / f"lint-{variant.lower()}.xml").getroot().findall("issue")
    runs = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", (folder / "workspace.log").read_text())
    assert tuple(sum(int(row[i]) for row in runs) for i in range(3)) == (1543, 0, 17)
    metadata = (folder / "apk-dev8-metadata.txt").read_text()
    assert "versionCode='1000008'" in metadata and "versionName='1.1.0-dev.8'" in metadata
    assert "targetSdkVersion:'36'" in metadata
    data = native_inputs(folder)
    verify_native(data)
    rejected = 0
    if args.self_test:
        mutations = [
            ("held-response", "response", data["held-response"]["response"] + " "),
            ("held-response", "request", data["held-response"]["request"] + " "),
            ("held-delivery", "released_by_test", False),
            ("delay-stop-proof", "stop_observed_ms", data["held-delivery"]["released_ms"] + 1),
            ("delay-settled", "session_requested", "true"),
            ("delay-settled", "relay_v2_last_ok_ms", "1"),
            ("dev8-wrong-key", "relay_v2_last_ok_ms", "1"),
        ]
        for group, key, value in mutations:
            changed = copy.deepcopy(data)
            changed[group][key] = value
            try:
                verify_native(changed)
            except AssertionError:
                rejected += 1
            else:
                raise AssertionError(f"错误证据未拒绝：{group}/{key}")
    print(json.dumps({"scope": "debug-emulator-relay-v2", "verified": True,
                      "native_signatures": 2, "negative_reports_rejected": rejected,
                      "formal_android_acceptance_passed": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()

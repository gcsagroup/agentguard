#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/check-node.sh"

# Reproducible iOS limited-SKU gate. This verifies source/extension contracts, regenerates the
# Xcode project, runs Core + UI tests on an actual Simulator, and compiles/analyzes both Simulator
# and unsigned device Release products. It intentionally does not claim signing or real-device
# Safari acceptance.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="$ROOT/apps/ios-webshield"
XCODEGEN_BIN="${XCODEGEN_BIN:-xcodegen}"

command -v node >/dev/null || { echo "error: node is required" >&2; exit 2; }
command -v xcodebuild >/dev/null || { echo "error: Xcode is required" >&2; exit 2; }
command -v "$XCODEGEN_BIN" >/dev/null || {
  echo "error: XcodeGen 2.46.0 is required (set XCODEGEN_BIN if it is not on PATH)" >&2
  exit 2
}
"$XCODEGEN_BIN" --version | grep -Eq '(^|[^0-9])2\.46\.0([^0-9]|$)' || {
  echo "error: XcodeGen must be exactly 2.46.0" >&2
  exit 2
}

node --test "$APP_ROOT"/Tests/ExtensionTests/*.test.cjs
(
  cd "$APP_ROOT"
  "$XCODEGEN_BIN" generate --spec project.yml
)

SIMULATOR_ID="${AGENTGUARD_IOS_SIMULATOR_ID:-}"
if [[ -z "$SIMULATOR_ID" ]]; then
  SIMULATOR_ID="$(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
print(next(
    device["udid"]
    for runtime in devices.values()
    for device in runtime
    if device.get("isAvailable") and "iPhone" in device.get("name", "")
))
')"
fi
[[ -n "$SIMULATOR_ID" ]] || { echo "error: no available iPhone Simulator" >&2; exit 2; }
xcrun simctl boot "$SIMULATOR_ID" >/dev/null 2>&1 || true
xcrun simctl bootstatus "$SIMULATOR_ID" -b

if [[ -n "${AGENTGUARD_IOS_RESULT_ROOT:-}" ]]; then
  RESULT_ROOT="$AGENTGUARD_IOS_RESULT_ROOT"
  mkdir -p "$RESULT_ROOT"
else
  RESULT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-ios-check.XXXXXX")"
fi
TEST_RESULT="$RESULT_ROOT/tests.xcresult"
[[ ! -e "$TEST_RESULT" ]] || {
  echo "error: result bundle already exists: $TEST_RESULT" >&2
  exit 2
}

COMMON=(
  -project "$APP_ROOT/AgentGuardWebShield.xcodeproj"
  -scheme AgentGuardWebShield
  CODE_SIGNING_ALLOWED=NO
  SWIFT_STRICT_CONCURRENCY=complete
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
  GCC_TREAT_WARNINGS_AS_ERRORS=YES
)

xcodebuild test -quiet "${COMMON[@]}" \
  -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
  -derivedDataPath "$RESULT_ROOT/test-derived" \
  -resultBundlePath "$TEST_RESULT"

xcrun xcresulttool get test-results summary --path "$TEST_RESULT" | python3 -c '
import json, sys
summary = json.load(sys.stdin)
passed = int(summary.get("passedTests", 0))
failed = int(summary.get("failedTests", 0))
skipped = int(summary.get("skippedTests", 0))
if passed != 22 or failed != 0 or skipped != 0:
    raise SystemExit(f"error: expected Swift 22/22 with no skips; got passed={passed} failed={failed} skipped={skipped}")
print("Swift tests: 22/22 PASS")
'

xcodebuild build -quiet "${COMMON[@]}" \
  -configuration Release \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$RESULT_ROOT/release-simulator-derived"
xcodebuild build -quiet "${COMMON[@]}" \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$RESULT_ROOT/release-device-derived"
xcodebuild analyze -quiet "${COMMON[@]}" \
  -configuration Release \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$RESULT_ROOT/analyze-derived"

echo "iOS limited SKU: Node 18/18, Swift 22/22, strict Release Simulator/device build + Analyze PASS"
echo "Evidence: $RESULT_ROOT"

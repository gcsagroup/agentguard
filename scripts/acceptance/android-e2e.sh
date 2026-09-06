#!/usr/bin/env bash
# Android 伴生应用真机 E2E(docs/acceptance-runbook.md §5,A1–A4 + 报告 P0-3 / P1-6)。
#
# # 这是什么
#
# 一条 adb 驱动的验收流程,把 runbook 里"人照着做"的步骤变成机器判据:每一步打 PASS / FAIL /
# BLOCKED(原因),证据落 evidence/android/,最后一行是机器可读的
#   AGENTGUARD_ANDROID_E2E=PASS|FAIL|BLOCKED  device=<real|emulator>
#
# 它**不是**验收报告本身:报告(docs/acceptance-report-template.md)仍由人填、由
# `guard-cli manual-acceptance android …` 校验。这个脚本产出的是报告要引用的那些证据文件,
# 以及"别把 BLOCKED 写成 PASS"的那道机器闸。
#
# # 人必须做的三件事(脚本会在该停的地方停下等你)
#
#   1. 在应用里点「显示适配器公钥」,把 04 开头的 130 位十六进制粘给脚本(私钥在 Keystore 里,
#      adb 拿不到,这是设计使然);
#   2. 在应用里填中继地址 + 脚本打印的 Bearer 令牌,开启桌面转发(令牌进 Keystore 封装,adb 写不进去);
#   3. 点「开始守护会话」。
#   其余(装 APK、授权、开无障碍、adb reverse、开桌面 API、打开固件页、杀进程、读 prefs)脚本自己做。
#
# # 判据一览
#
#   A1  安装成功;通知权限已授;无障碍服务已启用;常驻状态通知(id 1001)在;
#   A2  桌面 /v1/status 的 adapter_ingress.verified 增加、rejected 不增加 —— 真实 HTTP body 的签名
#       被桌面用已注册公钥验过(这是新加进 API 的可读证据,以前没有);
#   A3  打开付款固件页后,桌面审计出现 platform=android、rule_id 以 CRIT- 开头的判决;
#   A4  设备 prefs 的 last_risk_json 带上那个 rule_id,且引擎确认通知(id 1005)在;
#   L   进程被杀后:进程回来、会话保持关闭、旧状态通知不复活、无障碍服务仍启用(P0-3);
#   S   prefs 里没有明文 relay_token、有 relay_token_enc;事件日志总量 ≤ 上限(P1-6);
#   T   targetSdk 36 行为回归(报告 P2-2):设备 API ≥ 35 时才算跑过——A1–A4 与 L 都是在边到边、
#       Android 15/16 的通知与无障碍限制下发生的;API < 35 的设备只能 BLOCKED,不能拿 API 34 的
#       通过冒充 15/16 的通过。安装的 APK 的 targetSdk 从 dumpsys 读,不信源码。
#
# 模拟器上也能跑,但最后一行会标 device=emulator —— runbook 要求真机,那种结果只能记 PASS (sim)。
#
# 用法:
#   scripts/acceptance/android-e2e.sh [--serial S] [--apk path] [--evidence dir] [--skip-build] [--timeout-s N]
#   AGENTGUARD_ANDROID_PUBKEY=04… 可跳过第 1 步的交互。
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG="com.agentguard.companion"
A11Y="$PKG/.GuardAccessibilityService"
ADAPTER_ID="android-companion"
API_PORT=8788
FIX_PORT=8790
SERIAL="${ANDROID_SERIAL:-}"
APK="$REPO/apps/android-companion/app/build/outputs/apk/debug/app-debug.apk"
EVIDENCE="$REPO/evidence/android"
SKIP_BUILD=0
TIMEOUT_S=180

while [ $# -gt 0 ]; do
  case "$1" in
    --serial) SERIAL="$2"; shift 2 ;;
    --apk) APK="$2"; shift 2 ;;
    --evidence) EVIDENCE="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --timeout-s) TIMEOUT_S="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$EVIDENCE"
RESULTS="$EVIDENCE/e2e-results.tsv"
: > "$RESULTS"
FAILS=0; BLOCKS=0
record() { # id status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"
  case "$2" in FAIL) FAILS=$((FAILS+1));; BLOCKED*) BLOCKS=$((BLOCKS+1));; esac
  printf '  %-4s %-8s %s\n' "$1" "$2" "$3"
}
finish() {
  local marker="PASS"
  [ "$BLOCKS" -gt 0 ] && marker="BLOCKED"
  [ "$FAILS" -gt 0 ] && marker="FAIL"
  echo
  echo "results: $RESULTS  (evidence in $EVIDENCE)"
  echo "AGENTGUARD_ANDROID_E2E=$marker device=${DEVICE_KIND:-unknown}"
  [ "$marker" = "PASS" ]
}
cleanup() {
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null
  [ -n "${FIX_PID:-}" ] && kill "$FIX_PID" 2>/dev/null
  if [ -n "${ADB:-}" ]; then
    "${ADB[@]}" reverse --remove tcp:$API_PORT >/dev/null 2>&1 || true
    "${ADB[@]}" reverse --remove tcp:$FIX_PORT >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== 0. 前置条件"
if ! command -v adb >/dev/null 2>&1; then
  record A0 "BLOCKED(adb not installed)" "install Android platform-tools"; finish; exit 1
fi
if [ -n "$SERIAL" ]; then ADB=(adb -s "$SERIAL"); else ADB=(adb); fi
DEVICES=$(adb devices | awk 'NR>1 && $2=="device"{print $1}')
NDEV=$(printf '%s\n' "$DEVICES" | grep -c . || true)
if [ "$NDEV" -eq 0 ]; then
  record A0 "BLOCKED(no device)" "adb devices shows no authorized device"; finish; exit 1
fi
if [ "$NDEV" -gt 1 ] && [ -z "$SERIAL" ]; then
  record A0 "BLOCKED(multiple devices)" "pass --serial; devices: $(echo "$DEVICES" | tr '\n' ' ')"; finish; exit 1
fi
MODEL=$("${ADB[@]}" shell getprop ro.product.model | tr -d '\r')
SDK=$("${ADB[@]}" shell getprop ro.build.version.sdk | tr -d '\r')
QEMU=$("${ADB[@]}" shell getprop ro.kernel.qemu | tr -d '\r')
CHARS=$("${ADB[@]}" shell getprop ro.build.characteristics | tr -d '\r')
if [ "$QEMU" = "1" ] || printf '%s' "$CHARS" | grep -qi emulator; then DEVICE_KIND=emulator; else DEVICE_KIND=real; fi
{
  echo "model=$MODEL sdk=$SDK kind=$DEVICE_KIND serial=${SERIAL:-$DEVICES}"
  "${ADB[@]}" shell getprop ro.build.fingerprint
} > "$EVIDENCE/device.txt" 2>&1
record A0 PASS "device $MODEL (API $SDK, $DEVICE_KIND)"
[ "$DEVICE_KIND" = "emulator" ] && echo "  ! 模拟器:runbook 要求真机,结果只能记 PASS (sim)。"

GUARD_CLI="$REPO/target/release/guard-cli"
if [ ! -x "$GUARD_CLI" ]; then
  echo "  building guard-cli (release)…"
  (cd "$REPO" && cargo build --release -p guard-cli >/dev/null) || { record A0 FAIL "cargo build guard-cli failed"; finish; exit 1; }
fi
command -v python3 >/dev/null 2>&1 || { record A0 "BLOCKED(python3 missing)" "needed for JSON parsing and the fixture server"; finish; exit 1; }
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>/dev/null; }

echo "== 1. 安装与授权(A1)"
if [ ! -f "$APK" ]; then
  if [ "$SKIP_BUILD" -eq 1 ]; then record A1 FAIL "APK missing: $APK"; finish; exit 1; fi
  echo "  building debug APK…"
  (cd "$REPO/apps/android-companion" && ./gradlew --no-daemon -q :app:assembleDebug) || { record A1 FAIL "gradle assembleDebug failed"; finish; exit 1; }
fi
sha256sum "$APK" > "$EVIDENCE/apk.sha256"
if "${ADB[@]}" install -r -t "$APK" > "$EVIDENCE/install.txt" 2>&1; then
  record A1a PASS "installed $(basename "$APK") ($(cut -c1-16 "$EVIDENCE/apk.sha256")…)"
else
  record A1a FAIL "adb install failed: $(tail -1 "$EVIDENCE/install.txt")"; finish; exit 1
fi
"${ADB[@]}" shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
if "${ADB[@]}" shell dumpsys package "$PKG" | tr -d '\r' | grep -q "android.permission.POST_NOTIFICATIONS: granted=true"; then
  record A1b PASS "POST_NOTIFICATIONS granted"
else
  record A1b "BLOCKED(notification permission)" "grant it in Settings → Apps → AgentGuard Companion → Notifications"
fi
CUR=$("${ADB[@]}" shell settings get secure enabled_accessibility_services | tr -d '\r')
[ "$CUR" = "null" ] && CUR=""
if ! printf '%s' "$CUR" | grep -q "$A11Y"; then
  NEW="$A11Y"; [ -n "$CUR" ] && NEW="$CUR:$A11Y"
  "${ADB[@]}" shell settings put secure enabled_accessibility_services "$NEW" >/dev/null 2>&1 || true
  "${ADB[@]}" shell settings put secure accessibility_enabled 1 >/dev/null 2>&1 || true
fi
deadline=$(( $(date +%s) + 60 ))
while :; do
  if "${ADB[@]}" shell settings get secure enabled_accessibility_services | tr -d '\r' | grep -q "$A11Y"; then break; fi
  [ "$(date +%s)" -ge "$deadline" ] && break
  echo "  等待:请在 设置 → 无障碍 里启用 AgentGuard Companion(部分 OEM 不允许 adb 直接写入)…"; sleep 5
done
if "${ADB[@]}" shell settings get secure enabled_accessibility_services | tr -d '\r' | grep -q "$A11Y"; then
  record A1c PASS "accessibility service enabled"
else
  record A1c "BLOCKED(accessibility not enabled)" "OEM blocked settings put; enable manually and rerun"
fi
# run-as 可用性:debug 构建 + 非受限 OEM 才行。不可用时依赖它的判据记 BLOCKED,不是 PASS。
if "${ADB[@]}" shell run-as "$PKG" id >/dev/null 2>&1; then RUNAS=1; else RUNAS=0; echo "  ! run-as 不可用:读 prefs 的判据将记 BLOCKED"; fi
prefs() { "${ADB[@]}" shell run-as "$PKG" cat shared_prefs/agentguard.xml 2>/dev/null | tr -d '\r'; }

echo "== 2. 适配器公钥 → 注册表(A2 前置)"
PUBKEY="${AGENTGUARD_ANDROID_PUBKEY:-}"
if [ -z "$PUBKEY" ]; then
  echo "  在手机上:打开 AgentGuard Companion → 开启「桌面转发」→「显示适配器公钥」→ 复制 04 开头的 130 位十六进制。"
  printf '  粘贴公钥并回车(留空 = 跳过,A2 记 BLOCKED):'
  read -r PUBKEY || PUBKEY=""
fi
REGISTRY="$EVIDENCE/adapter-registry.yaml"
if [ -n "$PUBKEY" ]; then
  if CARD=$("$GUARD_CLI" adapter-card --adapter-id "$ADAPTER_ID" --public-key "$PUBKEY" --platforms android 2>&1); then
    { echo "adapters:"; printf '%s\n' "$CARD" | sed -n '2,$p'; } > "$REGISTRY"
    record A2a PASS "adapter card written: $REGISTRY"
  else
    record A2a FAIL "adapter-card rejected the key: $CARD"; PUBKEY=""
  fi
else
  record A2a "BLOCKED(no public key)" "signature verification cannot be attempted without the device key"
fi

echo "== 3. 桌面 API + adb reverse + 固件服务器"
TOKEN=$("$GUARD_CLI" api-token)
AUDIT_DB="$EVIDENCE/audit-e2e.db"; rm -f "$AUDIT_DB"
API_ARGS=(api-serve --bind "127.0.0.1:$API_PORT" --audit-db "$AUDIT_DB" --token "$TOKEN" --rules "$REPO/crates/guard-schema/rules/p0_rules.yaml")
[ -f "$REGISTRY" ] && API_ARGS+=(--adapter-registry "$REGISTRY")
(cd "$REPO" && "$GUARD_CLI" "${API_ARGS[@]}" > "$EVIDENCE/api-serve.log" 2>&1) &
API_PID=$!
sleep 1.5
api() { curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT$1"; }
if api /v1/status | grep -q '"rules_loaded"'; then
  record A2b PASS "api-serve up on 127.0.0.1:$API_PORT (log: evidence/android/api-serve.log)"
else
  record A2b FAIL "api-serve did not come up: $(tail -3 "$EVIDENCE/api-serve.log" | tr '\n' ' ')"; finish; exit 1
fi
"${ADB[@]}" reverse tcp:$API_PORT tcp:$API_PORT >/dev/null && "${ADB[@]}" reverse tcp:$FIX_PORT tcp:$FIX_PORT >/dev/null \
  && record A2c PASS "adb reverse $API_PORT/$FIX_PORT" || record A2c FAIL "adb reverse failed"
(cd "$REPO/eval/acceptance-fixtures" && python3 -m http.server "$FIX_PORT" --bind 127.0.0.1 > "$EVIDENCE/fixture-server.log" 2>&1) &
FIX_PID=$!
sleep 0.5
V0=$(api /v1/status | json 'd["adapter_ingress"]["verified"]'); R0=$(api /v1/status | json 'd["adapter_ingress"]["rejected"]')

echo "== 4. 在手机上配置中继并开始会话"
echo "  中继地址:http://127.0.0.1:$API_PORT/v1/events"
echo "  Bearer 令牌:$TOKEN"
echo "  在应用里:填地址与令牌 → 保存 → 开启「桌面转发」→ 点「开始守护会话」。"
"${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1 || true
deadline=$(( $(date +%s) + TIMEOUT_S ))
STARTED=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if [ "$RUNAS" -eq 1 ]; then
    P=$(prefs)
    if printf '%s' "$P" | grep -q 'name="session_requested" value="true"'; then STARTED=1; break; fi
  else
    # 没有 run-as 就看审计:session_start 到了桌面即视为已开始。
    if api "/v1/audit/recent?limit=20" | grep -q '"platform":"android"'; then STARTED=1; break; fi
  fi
  sleep 3
done
if [ "$STARTED" -eq 1 ]; then
  record A1d PASS "guard session started on device"
else
  record A1d "BLOCKED(session not started within ${TIMEOUT_S}s)" "start the session in the app and rerun"; finish; exit 1
fi
sleep 2
"${ADB[@]}" shell dumpsys notification --noredact 2>/dev/null | tr -d '\r' > "$EVIDENCE/notifications-1.txt" || "${ADB[@]}" shell dumpsys notification | tr -d '\r' > "$EVIDENCE/notifications-1.txt"
if grep -q "pkg=$PKG" "$EVIDENCE/notifications-1.txt" && grep -A3 "pkg=$PKG" "$EVIDENCE/notifications-1.txt" | grep -q "id=1001\|id=0x3e9"; then
  record A1e PASS "ongoing session notification (id 1001) present"
else
  record A1e FAIL "ongoing session notification not found in dumpsys (evidence/android/notifications-1.txt)"
fi

echo "== 5. 触发一个有明确预期的无障碍事件(A3)→ 桌面判决 → 回到设备(A4)"
T0=$(date +%s%3N)
"${ADB[@]}" shell am start -a android.intent.action.VIEW -d "http://127.0.0.1:$FIX_PORT/payment-cta.html" >/dev/null 2>&1
deadline=$(( $(date +%s) + 45 ))
RULE=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  api "/v1/audit/recent?limit=100" > "$EVIDENCE/audit-recent.json"
  RULE=$(python3 - "$EVIDENCE/audit-recent.json" "$T0" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1])); t0=int(sys.argv[2])
for r in rows:
    ev=r.get("event_json") or r.get("event") or {}
    if isinstance(ev,str):
        try: ev=json.loads(ev)
        except Exception: ev={}
    plat=ev.get("platform") or r.get("platform") or ""
    ts=int(r.get("timestamp_ms") or ev.get("timestamp_ms") or 0)
    rid=r.get("rule_id") or (r.get("decision") or {}).get("rule_id") or ""
    if plat=="android" and ts>=t0-5000 and rid.startswith("CRIT-"):
        print(rid); break
PY
)
  [ -n "$RULE" ] && break
  sleep 3
done
if [ -n "$RULE" ]; then
  record A3 PASS "desktop verdict $RULE for an android event (evidence/android/audit-recent.json)"
else
  if grep -q '"platform":"android"' "$EVIDENCE/audit-recent.json"; then
    record A3 FAIL "android events reached the engine but no CRIT- verdict for the payment fixture"
  else
    record A3 FAIL "no android events reached the desktop (relay off? token wrong? see api-serve.log)"
  fi
fi
V1=$(api /v1/status | json 'd["adapter_ingress"]["verified"]'); R1=$(api /v1/status | json 'd["adapter_ingress"]["rejected"]')
LAST=$(api /v1/status | json 'd["adapter_ingress"].get("last",{}).get("state")')
api /v1/status > "$EVIDENCE/status-after.json"
if [ -z "$PUBKEY" ]; then
  record A2 "BLOCKED(no public key registered)" "ingress: verified=$V1 rejected=$R1 last=$LAST"
elif [ "${V1:-0}" -gt "${V0:-0}" ] && [ "${R1:-0}" -eq "${R0:-0}" ]; then
  record A2 PASS "desktop verified $((V1-V0)) signed body/bodies with the registered key, 0 rejected (evidence/android/status-after.json)"
else
  record A2 FAIL "ingress verified $V0→$V1 rejected $R0→$R1 last=$LAST — signature not verified (key mismatch / clock skew / replay?)"
fi
sleep 2
"${ADB[@]}" shell dumpsys notification --noredact 2>/dev/null | tr -d '\r' > "$EVIDENCE/notifications-2.txt" || "${ADB[@]}" shell dumpsys notification | tr -d '\r' > "$EVIDENCE/notifications-2.txt"
if [ "$RUNAS" -eq 1 ]; then
  P=$(prefs); printf '%s\n' "$P" | sed -E 's/(relay_token_enc" value=")[^"]*/\1[redacted]/' > "$EVIDENCE/prefs-after.xml"
  if [ -n "$RULE" ] && printf '%s' "$P" | grep -q "last_risk_json" && printf '%s' "$P" | grep -q "$RULE"; then
    if grep -A3 "pkg=$PKG" "$EVIDENCE/notifications-2.txt" | grep -q "id=1005\|id=0x3ed"; then
      record A4 PASS "device recorded $RULE in last_risk_json and posted the engine notification (id 1005)"
    else
      record A4 FAIL "device recorded $RULE but no engine notification (id 1005) in dumpsys"
    fi
  else
    record A4 FAIL "device prefs do not carry the desktop verdict (${RULE:-none}); see evidence/android/prefs-after.xml"
  fi
else
  record A4 "BLOCKED(run-as unavailable)" "cannot read app prefs; check the phone shows the engine notification manually"
fi

echo "== 6. 进程被杀后的恢复(P0-3)"
PID0=$("${ADB[@]}" shell pidof "$PKG" | tr -d '\r')
if [ -n "$PID0" ]; then
  "${ADB[@]}" shell am crash "$PKG" >/dev/null 2>&1 || "${ADB[@]}" shell run-as "$PKG" kill -9 "$PID0" >/dev/null 2>&1 || true
  sleep 8
  # Fail-closed contract: a process death ends the request. Re-open the UI so
  # restore() can clear any stale on-disk request, but never auto-resume a session.
  "${ADB[@]}" shell am start -W -n "$PKG/.MainActivity" >/dev/null 2>&1 || true
  sleep 2
  PID1=$("${ADB[@]}" shell pidof "$PKG" | tr -d '\r')
  "${ADB[@]}" shell dumpsys notification --noredact 2>/dev/null | tr -d '\r' > "$EVIDENCE/notifications-3.txt" || "${ADB[@]}" shell dumpsys notification | tr -d '\r' > "$EVIDENCE/notifications-3.txt"
  A11Y_OK=$("${ADB[@]}" shell settings get secure enabled_accessibility_services | tr -d '\r' | grep -c "$A11Y" || true)
  INACTIVE_OK=1
  if [ "$RUNAS" -eq 1 ]; then
    P=$(prefs)
    printf '%s' "$P" | grep -q 'name="session_requested" value="true"' && INACTIVE_OK=0
    printf '%s' "$P" | grep -q 'name="session_active" value="true"' && INACTIVE_OK=0
  fi
  SESSION_NOTICE=$(grep -A3 "pkg=$PKG" "$EVIDENCE/notifications-3.txt" | grep -c "id=1001\|id=0x3e9" || true)
  if [ -n "$PID1" ] && [ "$PID1" != "$PID0" ] && [ "$INACTIVE_OK" -eq 1 ] && [ "$SESSION_NOTICE" -eq 0 ] && [ "$A11Y_OK" -gt 0 ]; then
    record L PASS "process $PID0→$PID1 restarted fail-closed; session inactive; no stale session notification; a11y remains enabled for explicit restart"
  elif [ -z "$PID1" ]; then
    record L FAIL "app did not relaunch after the scripted MainActivity start"
  else
    record L FAIL "after restart: new_pid=$PID1 inactive_ok=$INACTIVE_OK stale_session_notification=$SESSION_NOTICE a11y=$A11Y_OK"
  fi
else
  record L "BLOCKED(pidof empty)" "cannot find the app process"
fi

echo "== 7. 令牌与日志边界(P1-6)"
if [ "$RUNAS" -eq 1 ]; then
  P=$(prefs)
  if printf '%s' "$P" | grep -q 'name="relay_token"'; then
    record S1 FAIL "plaintext relay_token present in shared_prefs"
  elif printf '%s' "$P" | grep -q 'name="relay_token_enc"'; then
    record S1 PASS "token stored only as relay_token_enc (Keystore-wrapped)"
  else
    record S1 FAIL "no relay token stored at all — forwarding cannot have been enabled with a token"
  fi
  BYTES=$("${ADB[@]}" shell run-as "$PKG" sh -c 'du -sk files/events 2>/dev/null | cut -f1' | tr -d '\r')
  CAP_KB=$((50 * 1024))
  if [ -n "$BYTES" ] && [ "$BYTES" -le "$CAP_KB" ]; then
    record S2 PASS "events dir ${BYTES} KiB ≤ ${CAP_KB} KiB cap (EventLogRetention.MAX_TOTAL_BYTES)"
  else
    record S2 FAIL "events dir ${BYTES:-?} KiB exceeds ${CAP_KB} KiB or unreadable"
  fi
else
  record S1 "BLOCKED(run-as unavailable)" "cannot inspect prefs"
  record S2 "BLOCKED(run-as unavailable)" "cannot measure files/events"
fi

echo "== 8. targetSdk 36 行为回归(P2-2)"
# 从设备上装好的包读 targetSdk(不是源码里写的):这是"跑在真机上的那个 APK"的事实。
TARGET_SDK=$("${ADB[@]}" shell dumpsys package "$PKG" | tr -d '\r' | grep -o "targetSdk=[0-9]*" | head -1 | cut -d= -f2)
A1_TO_L_OK=1
grep -E "^(A1[a-e]|A2|A3|A4|L)\s" "$RESULTS" | awk '{print $2}' | grep -qv '^PASS' && A1_TO_L_OK=0
if [ -z "$TARGET_SDK" ]; then
  record T "BLOCKED(targetSdk unreadable)" "dumpsys package did not report targetSdk"
elif [ "$TARGET_SDK" -lt 35 ]; then
  record T FAIL "installed APK targets API $TARGET_SDK (< 35): Play requires 35+/36 and current edge-to-edge / background behaviour was never exercised"
elif [ "$SDK" -lt 35 ]; then
  record T "BLOCKED(device API $SDK < 35)" "targetSdk=$TARGET_SDK but the device runs API $SDK: Android 15/16 behaviour (edge-to-edge, notification and a11y limits) not exercised — rerun on an API 35+ device"
elif [ "$A1_TO_L_OK" -eq 1 ]; then
  record T PASS "targetSdk=$TARGET_SDK on device API $SDK: A1–A4 and L passed under Android 15/16 behaviour changes"
else
  record T FAIL "targetSdk=$TARGET_SDK on device API $SDK but A1–A4 / L did not all pass (see above)"
fi

cp "$RESULTS" "$EVIDENCE/e2e-results.$(date +%Y%m%d-%H%M%S).tsv" 2>/dev/null || true
finish

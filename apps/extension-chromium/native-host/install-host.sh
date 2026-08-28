#!/usr/bin/env bash
# Install the Native Messaging host manifest (dev helper).
#
# 用法:
#   install-host.sh <chrome/edge-extension-id>            # 默认 chrome
#   install-host.sh --browser edge     <extension-id>
#   install-host.sh --browser firefox  <gecko-id>          # 例:agentguard@agentguard.dev
#
# 三个浏览器的差别只有两处,别处都一样:
#   1. manifest 装到哪个目录(每个浏览器各有自己的 NativeMessagingHosts 路径);
#   2. 谁被允许连:Chromium 系用 `allowed_origins`(chrome-extension://ID/),
#      Firefox 用 `allowed_extensions`(gecko id)。
# Safari 不在此列:它的原生消息走 App Extension(SafariWebExtensionHandler),不是 stdio host,
# 这个脚本装不了 —— 见 docs/跨浏览器.md。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HOST_BIN="${ROOT}/target/debug/guard-nm-host"

BROWSER="chrome"
if [[ "${1:-}" == "--browser" ]]; then
  BROWSER="${2:-}"
  shift 2
fi
ID="${1:-}"

if [[ -z "$ID" ]]; then
  echo "Usage: $0 [--browser chrome|edge|firefox] <extension-id-or-gecko-id>"
  echo "  chrome/edge: load unpacked, copy ID from the extensions page"
  echo "  firefox: use the gecko id from manifest.firefox.json (agentguard@agentguard.dev)"
  exit 1
fi

cargo build -p guard-nm-host --manifest-path "${ROOT}/Cargo.toml"

os="$(uname -s)"
MANIFEST_DIR=""
case "${BROWSER}:${os}" in
  chrome:Darwin)  MANIFEST_DIR="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts" ;;
  chrome:Linux)   MANIFEST_DIR="${HOME}/.config/google-chrome/NativeMessagingHosts" ;;
  edge:Darwin)    MANIFEST_DIR="${HOME}/Library/Application Support/Microsoft Edge/NativeMessagingHosts" ;;
  edge:Linux)     MANIFEST_DIR="${HOME}/.config/microsoft-edge/NativeMessagingHosts" ;;
  firefox:Darwin) MANIFEST_DIR="${HOME}/Library/Application Support/Mozilla/NativeMessagingHosts" ;;
  firefox:Linux)  MANIFEST_DIR="${HOME}/.mozilla/native-messaging-hosts" ;;
  *)
    echo "Unsupported browser/OS combo '${BROWSER}/${os}'; edit the JSON path manually."
    exit 1
    ;;
esac

mkdir -p "${MANIFEST_DIR}"
OUT="${MANIFEST_DIR}/com.agentguard.native.json"

if [[ "${BROWSER}" == "firefox" ]]; then
  # Firefox: allowed_extensions = [gecko id];调用方 origin 文件写 gecko id 本身。
  sed -e "s|HOST_PATH_PLACEHOLDER|${HOST_BIN}|g" \
      -e "s|GECKO_ID_PLACEHOLDER|${ID}|g" \
      "${ROOT}/apps/extension-chromium/native-host/com.agentguard.native.firefox.json" > "${OUT}"
  ORIGIN_LINE="${ID}"
else
  # Chromium 系(chrome/edge):allowed_origins = [chrome-extension://ID/]。
  sed -e "s|HOST_PATH_PLACEHOLDER|${HOST_BIN}|g" \
      -e "s|EXTENSION_ID_PLACEHOLDER|${ID}|g" \
      "${ROOT}/apps/extension-chromium/native-host/com.agentguard.native.json" > "${OUT}"
  ORIGIN_LINE="chrome-extension://${ID}/"
fi
chmod +x "${HOST_BIN}" || true

# 宿主自己那份该接受的调用方 origin。宿主默认 fail-closed:没有它(且没设
# AGENTGUARD_ALLOWED_ORIGIN)就拒绝启动 —— 否则任何本地进程都能说这套协议、把伪造的
# source_app 写进签名审计。写在二进制旁边,宿主启动时读它。
# 注意:Chromium 传的 origin 是 `chrome-extension://ID/`,Firefox 传的是 gecko id 本身,
# 所以这一行按浏览器不同 —— 宿主比对的就是浏览器实际传进来的那个串。
ALLOWED_ORIGIN_FILE="$(dirname "${HOST_BIN}")/allowed-origin"
printf '%s\n' "${ORIGIN_LINE}" > "${ALLOWED_ORIGIN_FILE}"

echo "Installed (${BROWSER}): ${OUT}"
echo "Host: ${HOST_BIN}"
echo "Allowed caller: ${ALLOWED_ORIGIN_FILE} (${ORIGIN_LINE})"

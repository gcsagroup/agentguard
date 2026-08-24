#!/usr/bin/env bash
# Install Chrome Native Messaging host manifest (dev helper).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HOST_BIN="${ROOT}/target/debug/guard-nm-host"
EXT_ID="${1:-}"

if [[ -z "$EXT_ID" ]]; then
  echo "Usage: $0 <chrome-extension-id>"
  echo "Load unpacked extension first, copy ID from chrome://extensions"
  exit 1
fi

cargo build -p guard-nm-host --manifest-path "${ROOT}/Cargo.toml"

MANIFEST_DIR=""
case "$(uname -s)" in
  Darwin)
    MANIFEST_DIR="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    ;;
  Linux)
    MANIFEST_DIR="${HOME}/.config/google-chrome/NativeMessagingHosts"
    ;;
  *)
    echo "Unsupported OS for this helper; edit the JSON path manually."
    exit 1
    ;;
esac

mkdir -p "${MANIFEST_DIR}"
OUT="${MANIFEST_DIR}/com.agentguard.native.json"
sed -e "s|HOST_PATH_PLACEHOLDER|${HOST_BIN}|g" \
    -e "s|EXTENSION_ID_PLACEHOLDER|${EXT_ID}|g" \
    "${ROOT}/apps/extension-chromium/native-host/com.agentguard.native.json" > "${OUT}"
chmod +x "${HOST_BIN}" || true
echo "Installed: ${OUT}"
echo "Host: ${HOST_BIN}"

#!/usr/bin/env bash
# Package Chromium extension for Chrome Web Store upload (zip, no secrets).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/agentguard-extension.zip}"
mkdir -p "$(dirname "$OUT")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cp "$ROOT/manifest.json" "$STAGE/"
cp "$ROOT/background.js" "$STAGE/"
cp "$ROOT/content.js" "$STAGE/"
cp "$ROOT/popup.html" "$STAGE/"
cp "$ROOT/popup.js" "$STAGE/"
cp "$ROOT/popup.css" "$STAGE/"
if [[ -d "$ROOT/_locales" ]]; then
  cp -R "$ROOT/_locales" "$STAGE/_locales"
fi
for size in 16 32 48 128; do
  icon="$ROOT/icons/icon${size}.png"
  [[ -f "$icon" ]] || { echo "缺少正式扩展图标：$icon" >&2; exit 1; }
done
cp -R "$ROOT/icons" "$STAGE/icons"
brand_asset="$ROOT/assets/agentguard-mark-white.png"
[[ -f "$brand_asset" ]] || { echo "缺少扩展品牌标志：$brand_asset" >&2; exit 1; }
mkdir -p "$STAGE/assets"
cp "$brand_asset" "$STAGE/assets/agentguard-mark-white.png"

# Exclude native-host from store zip (documented separately).
(
  cd "$STAGE"
  zip -qr "$OUT" .
)
echo "wrote $OUT"
unzip -l "$OUT" | head -30

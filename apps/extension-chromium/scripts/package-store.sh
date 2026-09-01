#!/usr/bin/env bash
# Package the extension for store upload (zip, no secrets).
#
#   package-store.sh [out.zip]              # Chrome/Edge(用 manifest.json)
#   package-store.sh --firefox [out.zip]    # Firefox(用 manifest.firefox.json)
#
# Chrome 和 Edge 用同一个包(都是 Chromium)。Firefox 只换 manifest(带 gecko id),其余文件一样——
# 这正是 manifests.test.mjs 钉住"两份 manifest 内容脚本/权限不漂移"的原因。Safari 不走这条:它要
# Xcode 包壳,见 docs/跨浏览器.md。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

TARGET="chrome"
if [[ "${1:-}" == "--firefox" ]]; then
  TARGET="firefox"
  shift
fi
DEFAULT_OUT="$ROOT/dist/agentguard-extension.zip"
[[ "$TARGET" == "firefox" ]] && DEFAULT_OUT="$ROOT/dist/agentguard-extension-firefox.zip"
OUT="${1:-$DEFAULT_OUT}"
mkdir -p "$(dirname "$OUT")"
OUT_DIR="$(cd "$(dirname "$OUT")" && pwd)"
OUT="$OUT_DIR/$(basename "$OUT")"
# 始终在同一输出目录构造一个全新的 ZIP，再原子替换目标。直接让 `zip` 写已有 OUT
# 会进入 update 模式；若 staging 文件保留较旧 mtime，旧条目会被错误地保留下来。
WORK="$(mktemp -d "$OUT_DIR/.agentguard-package.XXXXXX")"
STAGE="$WORK/stage"
TMP_OUT="$WORK/$(basename "$OUT")"
mkdir -p "$STAGE"
trap 'rm -rf "$WORK"' EXIT

# manifest 按目标选;装进包里的文件名统一是 manifest.json。
if [[ "$TARGET" == "firefox" ]]; then
  cp "$ROOT/manifest.firefox.json" "$STAGE/manifest.json"
else
  cp "$ROOT/manifest.json" "$STAGE/"
fi
cp "$ROOT/background.js" "$STAGE/"
cp "$ROOT/guard-gate.js" "$STAGE/"
cp "$ROOT/guard-strings.js" "$STAGE/"
cp "$ROOT/guard-modal.js" "$STAGE/"
cp "$ROOT/onboarding.html" "$STAGE/"
cp "$ROOT/onboarding.css" "$STAGE/"
cp "$ROOT/onboarding.js" "$STAGE/"
cp "$ROOT/guard-page.js" "$STAGE/"
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
  zip -qr "$TMP_OUT" .
)
mv -f -- "$TMP_OUT" "$OUT"
echo "wrote $OUT"
unzip -l "$OUT" | head -30

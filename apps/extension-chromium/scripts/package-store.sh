#!/usr/bin/env bash
# Package the extension for store upload (zip, no secrets).
#
#   package-store.sh [out.zip]              # 首个 GA 仅 Chrome/Edge
#
# Chrome 和 Edge 使用同一份 Chromium 包。Firefox 已按 SCOPE-00 排除在首个 GA
# 之外；仓库中的 manifest.firefox.json 仅是后续研发起点，不得由发布脚本
# 生成商店包。Safari 不走这条，它由 Xcode App/Extension 工程发布。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${1:-}" == "--firefox" ]]; then
  echo "Firefox 已排除在首个 GA 发布范围外；本脚本不生成 Firefox 商店包。" >&2
  exit 64
fi
DEFAULT_OUT="$ROOT/dist/agentguard-extension.zip"
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

# 首个 GA 唯一的浏览器产物是 Chrome/Edge 共用的 manifest.json。
cp "$ROOT/manifest.json" "$STAGE/"
cp "$ROOT/background.js" "$STAGE/"
cp "$ROOT/guard-gate.js" "$STAGE/"
cp "$ROOT/guard-strings.js" "$STAGE/"
cp "$ROOT/guard-modal.js" "$STAGE/"
cp "$ROOT/onboarding.html" "$STAGE/"
cp "$ROOT/onboarding.css" "$STAGE/"
cp "$ROOT/onboarding.js" "$STAGE/"
cp "$ROOT/content.js" "$STAGE/"
cp -R "$ROOT/rules" "$STAGE/rules"
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
# `| head -30` 会在 30 行后关掉读端,unzip 被 SIGPIPE 杀掉 → 在 pipefail 下整条命令退出 141。
# 这是概率事件(取决于 unzip 写完前 head 有没有退出),门禁里真的红过一次而单跑三次都绿。
# sed 读到 EOF 才退出,不给 unzip 发 SIGPIPE。
unzip -l "$OUT" | sed -n '1,30p'

#!/usr/bin/env bash
# 打包回归：已有 ZIP 必须被完整替换，不能让 zip update 模式保留旧条目/旧代码。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf 'stale\n' >"$WORK/stale.txt"
(
  cd "$WORK"
  zip -q "$WORK/chrome.zip" stale.txt
  zip -q "$WORK/firefox.zip" stale.txt
)

"$ROOT/scripts/package-store.sh" "$WORK/chrome.zip" >/dev/null
"$ROOT/scripts/package-store.sh" --firefox "$WORK/firefox.zip" >/dev/null

for archive in "$WORK/chrome.zip" "$WORK/firefox.zip"; do
  unzip -t "$archive" >/dev/null
  if unzip -Z1 "$archive" | grep -qx 'stale.txt'; then
    echo "旧 ZIP 条目仍在：$archive" >&2
    exit 1
  fi
  cmp "$ROOT/background.js" <(unzip -p "$archive" background.js)
  cmp "$ROOT/content.js" <(unzip -p "$archive" content.js)
done

cmp "$ROOT/manifest.json" <(unzip -p "$WORK/chrome.zip" manifest.json)
cmp "$ROOT/manifest.firefox.json" <(unzip -p "$WORK/firefox.zip" manifest.json)
echo "package-store: 全新 ZIP 替换与目标 manifest 检查通过"

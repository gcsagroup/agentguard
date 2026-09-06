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
)

"$ROOT/scripts/package-store.sh" "$WORK/chrome.zip" >/dev/null
if "$ROOT/scripts/package-store.sh" --firefox "$WORK/firefox.zip" >/dev/null 2>&1; then
  echo "首个 GA 不得生成 Firefox 商店包" >&2
  exit 1
fi
[[ ! -e "$WORK/firefox.zip" ]] || { echo "拒绝 Firefox 打包后仍产生了文件" >&2; exit 1; }

for archive in "$WORK/chrome.zip"; do
  unzip -t "$archive" >/dev/null
  if unzip -Z1 "$archive" | grep -qx 'stale.txt'; then
    echo "旧 ZIP 条目仍在：$archive" >&2
    exit 1
  fi
  cmp "$ROOT/background.js" <(unzip -p "$archive" background.js)
  cmp "$ROOT/content.js" <(unzip -p "$archive" content.js)
  cmp "$ROOT/rules/payment-shape-block.json" <(unzip -p "$archive" rules/payment-shape-block.json)
  if unzip -Z1 "$archive" | grep -qx 'guard-page.js'; then
    echo "包中不应再含公开 MAIN-world 判决脚本" >&2
    exit 1
  fi
done

cmp "$ROOT/manifest.json" <(unzip -p "$WORK/chrome.zip" manifest.json)
if unzip -p "$WORK/chrome.zip" manifest.json | grep -q 'nativeMessaging'; then
  echo "GA 包不得包含 nativeMessaging 权限" >&2
  exit 1
fi
echo "package-store: Chrome/Edge 全新 ZIP、GA manifest 与 Firefox 排除门禁通过"

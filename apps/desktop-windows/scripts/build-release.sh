#!/usr/bin/env bash
# 在 Windows Git Bash / GitHub Actions bash 中构建可复现的 SQLCipher Release。
set -euo pipefail

APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$APP_ROOT/../.." && pwd)"
BUNDLE_ROOT="$APP_ROOT/src-tauri/target/release/bundle"

cd "$APP_ROOT"
command -v npm >/dev/null 2>&1 || {
  printf 'error: npm not found\n' >&2
  exit 1
}

# 锁文件与 package.json 不一致、下载失败或旧 node_modules 污染都必须使发布构建失败。
npm ci --no-audit --no-fund

# bootstrap wrapper 同时固定 PATH、Cargo、rustc、rustdoc 与 sysroot。Rust 源码还有
# compile_error 双保险；删掉 audit-sqlcipher 或偷偷恢复默认 audit-sqlite 都产不出 Release。
"$REPO_ROOT/scripts/bootstrap-rust.sh" -- \
  npm run tauri -- build -- --no-default-features --features audit-sqlcipher --locked

if [[ ! -d "$BUNDLE_ROOT" ]]; then
  printf 'error: Tauri bundle output not found at %s\n' "$BUNDLE_ROOT" >&2
  exit 1
fi

printf '\n==> Windows SQLCipher Release artifacts (仍需正式代码签名与真机验收):\n'
find "$BUNDLE_ROOT" -maxdepth 3 -type f -print

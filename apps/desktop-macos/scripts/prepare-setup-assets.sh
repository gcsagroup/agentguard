#!/usr/bin/env bash
# 只复制接入所需资源；输出固定在被忽略的构建目录，不删除历史验收产物。
set -euo pipefail
APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$APP_ROOT/../.." && pwd)"
ASSETS="$APP_ROOT/setup-assets"
TARGET="${AGENTGUARD_MACOS_TARGET:-universal-apple-darwin}"
mkdir -p "$ASSETS/gateway" "$ASSETS/acceptance" "$ASSETS/browser-extension"

build_gateway() {
  "$REPO_ROOT/scripts/bootstrap-rust.sh" -- cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --locked --release --target "$1" -p guard-gateway --bin agentguard-mcp
}
case "$TARGET" in
  universal-apple-darwin)
    build_gateway aarch64-apple-darwin
    build_gateway x86_64-apple-darwin
    lipo -create "$REPO_ROOT/target/aarch64-apple-darwin/release/agentguard-mcp" "$REPO_ROOT/target/x86_64-apple-darwin/release/agentguard-mcp" -output "$ASSETS/gateway/agentguard-mcp"
    ;;
  aarch64-apple-darwin|x86_64-apple-darwin)
    build_gateway "$TARGET"
    cp "$REPO_ROOT/target/$TARGET/release/agentguard-mcp" "$ASSETS/gateway/agentguard-mcp"
    ;;
  *) echo "不支持的 macOS 目标：$TARGET" >&2; exit 2 ;;
esac
cp "$REPO_ROOT/crates/guard-shell/policies/default.yaml" "$ASSETS/gateway/default.yaml"

# 复用已有扩展发布白名单，再将全新 ZIP 的内容解包到新的临时目录。
WORK="$(mktemp -d "$APP_ROOT/.setup-package.XXXXXX")"
bash "$REPO_ROOT/apps/extension-chromium/scripts/package-store.sh" "$WORK/extension.zip"
unzip -q "$WORK/extension.zip" -d "$WORK/browser-extension"
# 仅替换本次脚本生成的资源目录；旧目录保存在此次临时目录中，可恢复。
if [[ -d "$ASSETS/browser-extension" ]]; then mv "$ASSETS/browser-extension" "$WORK/previous-extension"; fi
mv "$WORK/browser-extension" "$ASSETS/browser-extension"
cp "$APP_ROOT/setup-fixtures/index.html" "$ASSETS/acceptance/index.html"
cp "$APP_ROOT/setup-fixtures/fixture.js" "$ASSETS/acceptance/fixture.js"
cp "$APP_ROOT/setup-fixtures/README.md" "$ASSETS/acceptance/README.md"
echo "接入资源已生成；旧扩展资源保存在 $WORK/previous-extension"

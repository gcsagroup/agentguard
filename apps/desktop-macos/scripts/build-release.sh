#!/usr/bin/env bash
# Build AgentGuard macOS release (.app / .dmg). No Apple credentials required for the compile step.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
TAURI_DIR="$ROOT/src-tauri"
cd "$ROOT"

TARGET="${AGENTGUARD_MACOS_TARGET:-universal-apple-darwin}"
case "$TARGET" in
  universal-apple-darwin|aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *)
    echo "error: unsupported AGENTGUARD_MACOS_TARGET: $TARGET" >&2
    exit 2
    ;;
esac

echo "==> AgentGuard macOS release build (SQLCipher + .app, target=$TARGET)"
"$REPO_ROOT/scripts/check-node.sh"
AGENTGUARD_MACOS_TARGET="$TARGET" bash "$ROOT/scripts/prepare-setup-assets.sh"

# `npm ci`,不是 `npm install … || true`(真机报告 P2-6):以前装依赖失败会被吞掉,然后拿着上一次
# 留下的 node_modules 继续打包 —— 一份"成功"的发布构建里前端依赖是哪一版,没人说得清。
# `npm ci` 严格按 package-lock.json 装,lock 与 package.json 不一致或网络失败都**在这里停下**。
npm ci --no-audit --no-fund

# Release 审计必须是 SQLCipher。Rust 侧另有 compile_error 双保险；这里不提供明文 override。
CARGO_FEATURE_ARGS=(--no-default-features --features audit-sqlcipher --locked)

BUILD_ARGS=(build --target "$TARGET")
APP_NAME="AgentGuard"
if [[ -n "${AGENTGUARD_ACCEPTANCE_PROFILE:-}" ]]; then
  # 验收渠道使用固定名称和独立标识，避免与正式数据环境的应用混淆。
  APP_NAME="AgentGuard Test"
  export AGENTGUARD_BUNDLE_ID="com.agentguard.desktop.macos.acceptance"
  BUILD_ARGS+=(--config "$TAURI_DIR/tauri.acceptance.conf.json")
fi
if [[ "${AGENTGUARD_ENABLE_UPDATER:-0}" == "1" ]]; then
  BUILD_ARGS+=(--config "$TAURI_DIR/tauri.release.conf.json")
fi
BUILD_ARGS+=(-- "${CARGO_FEATURE_ARGS[@]}")

"$REPO_ROOT/scripts/bootstrap-rust.sh" -- npm run tauri -- "${BUILD_ARGS[@]}"

BUNDLE_ROOT="$TAURI_DIR/target/$TARGET/release/bundle/macos"
echo ""
echo "==> Build artifacts:"
if [[ -d "$BUNDLE_ROOT/$APP_NAME.app" ]]; then
  ls -la "$BUNDLE_ROOT" || true
  echo ""
  echo "Open with: open \"$BUNDLE_ROOT/$APP_NAME.app\""
else
  echo "  .app not found — check build log above"
  exit 1
fi

APP="$BUNDLE_ROOT/$APP_NAME.app"

# Sign — always unless the caller explicitly requests a compile-only artifact. A distributable
# build requires Developer ID + notarization; ad-hoc is an explicit local-smoke exception only.
if [[ "${AGENTGUARD_SKIP_SIGN:-0}" == "1" ]]; then
  echo ""
  echo "warning: AGENTGUARD_SKIP_SIGN=1 — the bundle is unsigned." >&2
  echo "         TCC grants will not survive a rebuild and Gatekeeper will refuse it." >&2
else
  echo ""
  echo "==> Signing"
  "$ROOT/scripts/sign-and-notarize.sh" "$APP"
fi

cat <<'EOF'

==> Distribution

For an explicitly local, non-distributable smoke build:

  AGENTGUARD_ALLOW_ADHOC=1 ./scripts/build-release.sh

For a build other people can run, configure a Developer ID and a notarytool Keychain profile.
The script verifies the resulting TeamIdentifier, notarizes, staples, and runs Gatekeeper:

  export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Org (TEAMID)"
  export AGENTGUARD_EXPECTED_TEAM_ID="XXXXXXXXXX"
  export NOTARYTOOL_PROFILE="agentguard-release"
  ./scripts/sign-and-notarize.sh

DMG: build with the `dmg` target, or re-wrap the stapled .app. See docs/macos-release.md.

Updater (optional, off by default):

  AGENTGUARD_ENABLE_UPDATER=1 ./scripts/build-release.sh
  # needs tauri-plugin-updater + a pubkey from: cargo tauri signer generate -w ~/.tauri/agentguard.key

Sparkle vs Tauri updater: direct-download builds can use the Tauri plugin; Mac App Store
builds must use App Store updates instead — see docs/macos-release.md.

EOF

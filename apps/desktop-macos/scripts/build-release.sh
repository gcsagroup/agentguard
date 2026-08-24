#!/usr/bin/env bash
# Build AgentGuard macOS release (.app / .dmg). No Apple credentials required for the compile step.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAURI_DIR="$ROOT/src-tauri"
cd "$ROOT"

echo "==> AgentGuard macOS release build (SQLCipher + .app)"
if ! command -v npm >/dev/null 2>&1; then
  echo "error: npm not found" >&2
  exit 1
fi

npm install --no-audit --no-fund 2>/dev/null || true

# Secure audit: SQLCipher. Override with AGENTGUARD_AUDIT_PLAIN=1 for plaintext release (not recommended).
CARGO_FEATURE_ARGS=(--no-default-features --features audit-sqlcipher)
if [[ "${AGENTGUARD_AUDIT_PLAIN:-0}" == "1" ]]; then
  CARGO_FEATURE_ARGS=(--features audit-sqlite)
  echo "warning: AGENTGUARD_AUDIT_PLAIN=1 — building without SQLCipher"
fi

BUILD_ARGS=(build)
if [[ "${AGENTGUARD_ENABLE_UPDATER:-0}" == "1" ]]; then
  BUILD_ARGS+=(--config "$TAURI_DIR/tauri.release.conf.json")
fi
BUILD_ARGS+=(-- "${CARGO_FEATURE_ARGS[@]}")

npm run tauri -- "${BUILD_ARGS[@]}"

BUNDLE_ROOT="$TAURI_DIR/target/release/bundle/macos"
echo ""
echo "==> Build artifacts:"
if [[ -d "$BUNDLE_ROOT/AgentGuard.app" ]]; then
  ls -la "$BUNDLE_ROOT" || true
  echo ""
  echo "Open with: open \"$BUNDLE_ROOT/AgentGuard.app\""
else
  echo "  .app not found — check build log above"
  exit 1
fi

APP="$BUNDLE_ROOT/AgentGuard.app"

# Sign — always. See scripts/sign-and-notarize.sh for why an unsigned bundle is not merely
# undistributable but broken on the developer's own machine: macOS keys Accessibility and
# Screen Recording grants to the code signature, so every rebuild of an unsigned app is a new
# app to TCC and arrives with no permissions while System Settings still shows them granted.
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

Signed ad-hoc by default, which is enough to run locally and to keep TCC grants stable.
For a build other people can run, set a Developer ID and re-run — the same script then
notarizes and staples:

  export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Org (TEAMID)"
  export APPLE_ID="you@example.com" TEAM_ID="XXXXXXXXXX"
  export APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"
  ./scripts/sign-and-notarize.sh

DMG: build with the `dmg` target, or re-wrap the stapled .app. See docs/macos-release.md.

Updater (optional, off by default):

  AGENTGUARD_ENABLE_UPDATER=1 ./scripts/build-release.sh
  # needs tauri-plugin-updater + a pubkey from: cargo tauri signer generate -w ~/.tauri/agentguard.key

Sparkle vs Tauri updater: direct-download builds can use the Tauri plugin; Mac App Store
builds must use App Store updates instead — see docs/macos-release.md.

EOF

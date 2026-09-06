#!/usr/bin/env bash
# Sign, verify, notarize and staple the macOS app — as commands that run, not as instructions.
#
# Why this exists
# ---------------
# `build-release.sh` used to finish by *printing* the codesign / notarytool / stapler steps
# under "Next steps". Printed instructions are not a build step: nothing checked that the
# resulting bundle was signed, and the repository's own release doc listed signing as done.
#
# TCC grants are bound to the app's code-signing identity and designated requirement. Ad-hoc
# signatures are useful only for local smoke tests: rebuilding them can still invalidate grants,
# and they are never evidence for distribution, Gatekeeper, or notarization.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/src-tauri/target/release/bundle/macos/AgentGuard.app}"
ENTITLEMENTS="$ROOT/src-tauri/entitlements.plist"
# Must match `identifier` in tauri.conf.json. TCC uses it, so a mismatch resets every grant.
BUNDLE_ID="${AGENTGUARD_BUNDLE_ID:-com.agentguard.desktop.macos}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script signs a macOS bundle and must run on macOS (uname says $(uname -s))" >&2
  exit 2
fi
if [[ ! -d "$APP" ]]; then
  echo "error: no app bundle at $APP — run scripts/build-release.sh first" >&2
  exit 2
fi
if [[ ! -f "$ENTITLEMENTS" ]]; then
  echo "error: entitlements not found at $ENTITLEMENTS" >&2
  exit 2
fi

IDENTITY="${APPLE_SIGNING_IDENTITY:-}"
if [[ -z "$IDENTITY" ]]; then
  if [[ "${AGENTGUARD_ALLOW_ADHOC:-0}" != "1" ]]; then
    echo "error: APPLE_SIGNING_IDENTITY is required for a distributable release." >&2
    echo "       For an explicitly local, non-distributable smoke build only, set AGENTGUARD_ALLOW_ADHOC=1." >&2
    exit 3
  fi
  IDENTITY="-"
  echo "==> Explicit local smoke mode: signing ad-hoc (-)."
  echo "    This build is not distributable, notarizable, or evidence of stable TCC identity."
else
  case "$IDENTITY" in
    Developer\ ID\ Application:*) ;;
    *)
      echo "error: APPLE_SIGNING_IDENTITY must be a Developer ID Application identity" >&2
      exit 3
      ;;
  esac
  : "${AGENTGUARD_EXPECTED_TEAM_ID:?set AGENTGUARD_EXPECTED_TEAM_ID to the release Team ID}"
  : "${NOTARYTOOL_PROFILE:?set NOTARYTOOL_PROFILE to an xcrun notarytool store-credentials profile}"
  echo "==> Signing with: $IDENTITY"
fi

echo "==> Signing nested code first (inside-out is required; a bundle signed before its"
echo "    frameworks is invalid and 'codesign --verify' is what catches it)"
# --deep is deprecated and does not sign everything correctly; walk the bundle instead.
while IFS= read -r -d '' nested; do
  codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$nested"
done < <(find "$APP/Contents" \
  \( -name '*.dylib' -o -name '*.so' -o -name '*.framework' -o -perm -111 -type f \) \
  -not -path "$APP/Contents/MacOS/*" -print0 2>/dev/null || true)

echo "==> Signing the bundle"
codesign --force --timestamp --options runtime \
  --entitlements "$ENTITLEMENTS" \
  --identifier "$BUNDLE_ID" \
  --sign "$IDENTITY" "$APP"

echo "==> Verifying the signature (this is the check the printed instructions never made)"
codesign --verify --deep --strict --verbose=2 "$APP"
# `spctl` only passes for a Developer ID + notarized build; an ad-hoc build is expected to
# fail it, so the failure is reported rather than treated as fatal.
if [[ "$IDENTITY" == "-" ]]; then
  echo "==> Skipping Gatekeeper assessment (ad-hoc build cannot pass it)"
else
  spctl --assess --type execute --verbose=2 "$APP" || {
    echo "warning: Gatekeeper assessment failed — notarization below is what fixes this" >&2
  }
fi

echo "==> Confirming the entitlements that actually got embedded"
codesign --display --entitlements - "$APP"

if [[ "$IDENTITY" == "-" ]]; then
  echo ""
  echo "==> Done (ad-hoc local smoke only). Re-check Accessibility and Screen Recording after every rebuild."
  exit 0
fi

ACTUAL_TEAM_ID="$(codesign -dvv "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1)"
if [[ -z "$ACTUAL_TEAM_ID" || "$ACTUAL_TEAM_ID" != "$AGENTGUARD_EXPECTED_TEAM_ID" ]]; then
  echo "error: signed TeamIdentifier '$ACTUAL_TEAM_ID' does not match expected '$AGENTGUARD_EXPECTED_TEAM_ID'" >&2
  exit 4
fi
echo "==> Verified TeamIdentifier: $ACTUAL_TEAM_ID"

ZIP="$(dirname "$APP")/$(basename "$APP" .app)-notarize.zip"
trap 'rm -f "$ZIP"' EXIT
echo "==> Submitting for notarization"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARYTOOL_PROFILE" --wait
rm -f "$ZIP"
trap - EXIT

echo "==> Stapling"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
echo "==> Done: signed, notarized, stapled and Gatekeeper-assessed."

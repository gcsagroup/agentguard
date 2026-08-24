#!/usr/bin/env bash
# Sign, verify, notarize and staple the macOS app — as commands that run, not as instructions.
#
# Why this exists
# ---------------
# `build-release.sh` used to finish by *printing* the codesign / notarytool / stapler steps
# under "Next steps". Printed instructions are not a build step: nothing checked that the
# resulting bundle was signed, and the repository's own release doc listed signing as done.
#
# There is a second, less obvious reason, and it is the one that decides whether the app
# works at all on a developer's own machine. macOS keys TCC grants — Accessibility and Screen
# Recording, the two permissions this app cannot observe anything without — to the code
# signature. An unsigned bundle is identified by its binary, so every rebuild is a *new*
# application as far as TCC is concerned: the grants silently do not apply, `AXIsProcessTrusted`
# returns false, and the app reports that it has no permissions while System Settings shows the
# toggle switched on. That looks exactly like a bug in the permission probe.
#
# Ad-hoc signing with a stable identifier fixes it, and needs no Apple account. So this script
# always signs; a Developer ID is an upgrade, not a prerequisite.
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
  # Ad-hoc. Deliberate and stated, not a silent fallback: an ad-hoc signature keeps TCC grants
  # stable across local rebuilds, and cannot be notarized or distributed.
  IDENTITY="-"
  echo "==> APPLE_SIGNING_IDENTITY is unset: signing ad-hoc (-)."
  echo "    Local TCC grants will survive rebuilds. This build is NOT distributable:"
  echo "    Gatekeeper will refuse it on another machine, and notarization is skipped."
else
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
codesign --display --entitlements :- "$APP"

if [[ "$IDENTITY" == "-" ]]; then
  echo ""
  echo "==> Done (ad-hoc). TCC grants for Accessibility and Screen Recording will now persist"
  echo "    across rebuilds of this app on this machine."
  exit 0
fi

: "${APPLE_ID:?set APPLE_ID to notarize}"
: "${TEAM_ID:?set TEAM_ID to notarize}"
: "${APPLE_APP_SPECIFIC_PASSWORD:?set APPLE_APP_SPECIFIC_PASSWORD to notarize}"

ZIP="$(dirname "$APP")/$(basename "$APP" .app)-notarize.zip"
echo "==> Submitting for notarization"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" \
  --apple-id "$APPLE_ID" --team-id "$TEAM_ID" \
  --password "$APPLE_APP_SPECIFIC_PASSWORD" --wait
rm -f "$ZIP"

echo "==> Stapling"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
echo "==> Done: signed, notarized, stapled and Gatekeeper-assessed."

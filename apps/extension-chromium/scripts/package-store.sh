#!/usr/bin/env bash
# Package Chromium extension for Chrome Web Store upload (zip, no secrets).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/agentguard-extension.zip}"
mkdir -p "$(dirname "$OUT")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cp "$ROOT/manifest.json" "$STAGE/"
cp "$ROOT/background.js" "$STAGE/"
cp "$ROOT/content.js" "$STAGE/"
cp "$ROOT/popup.html" "$STAGE/"
cp "$ROOT/popup.js" "$STAGE/"
if [[ -d "$ROOT/_locales" ]]; then
  cp -R "$ROOT/_locales" "$STAGE/_locales"
fi
if [[ -d "$ROOT/icons" ]]; then
  cp -R "$ROOT/icons" "$STAGE/icons"
else
  mkdir -p "$STAGE/icons"
  # Placeholder 1x1 PNGs if icons missing (replace before store submission).
  python3 - <<'PY' "$STAGE/icons"
import struct, zlib, sys, pathlib
out = pathlib.Path(sys.argv[1])
def png(w,h,rgba=(0x3b,0x82,0xf6,0xff)):
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag+data) & 0xffffffff)
    raw = b''.join(b'\x00' + bytes(rgba)*(w) for _ in range(h))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w,h,8,6,0,0,0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
for s in (16,48,128):
    (out / f'icon{s}.png').write_bytes(png(s,s))
PY
fi

# Exclude native-host from store zip (documented separately).
(
  cd "$STAGE"
  zip -qr "$OUT" .
)
echo "wrote $OUT"
unzip -l "$OUT" | head -30

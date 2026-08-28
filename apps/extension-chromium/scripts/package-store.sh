#!/usr/bin/env bash
# Package the extension for store upload (zip, no secrets).
#
#   package-store.sh [out.zip]              # Chrome/Edge(用 manifest.json)
#   package-store.sh --firefox [out.zip]    # Firefox(用 manifest.firefox.json)
#
# Chrome 和 Edge 用同一个包(都是 Chromium)。Firefox 只换 manifest(带 gecko id),其余文件一样——
# 这正是 manifests.test.mjs 钉住"两份 manifest 内容脚本/权限不漂移"的原因。Safari 不走这条:它要
# Xcode 包壳,见 docs/跨浏览器.md。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

TARGET="chrome"
if [[ "${1:-}" == "--firefox" ]]; then
  TARGET="firefox"
  shift
fi
DEFAULT_OUT="$ROOT/dist/agentguard-extension.zip"
[[ "$TARGET" == "firefox" ]] && DEFAULT_OUT="$ROOT/dist/agentguard-extension-firefox.zip"
OUT="${1:-$DEFAULT_OUT}"
mkdir -p "$(dirname "$OUT")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# manifest 按目标选;装进包里的文件名统一是 manifest.json。
if [[ "$TARGET" == "firefox" ]]; then
  cp "$ROOT/manifest.firefox.json" "$STAGE/manifest.json"
else
  cp "$ROOT/manifest.json" "$STAGE/"
fi
cp "$ROOT/background.js" "$STAGE/"
cp "$ROOT/guard-gate.js" "$STAGE/"
cp "$ROOT/guard-page.js" "$STAGE/"
cp "$ROOT/content.js" "$STAGE/"
cp "$ROOT/popup.html" "$STAGE/"
cp "$ROOT/popup.js" "$STAGE/"
cp "$ROOT/popup.css" "$STAGE/"
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

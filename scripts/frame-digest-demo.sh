#!/usr/bin/env bash
# A4 frame integrity: shows what whole-frame mean luminance could not see.
#
# Builds three raw frames of the same 320x180 screen —
#   clean      : flat field
#   tampered   : clean + a line of injected instruction text
#   other      : an entirely different screen
# — then compares each against the digest the guard would have recorded.
#
# Exits 0 when all three verdicts are as documented.
set -euo pipefail
export RUST_BACKTRACE=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cargo build -q -p guard-cli 2>/dev/null
BIN="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')/debug/guard-cli"

python3 - "$WORK" <<'PY'
import sys
W, H = 320, 180
work = sys.argv[1]

def flat(v):
    return bytearray([v, v, v, 255] * (W * H))

clean = flat(200)
tampered = bytearray(clean)
# Text-like stripes: a line of injected instruction, ~1.6% of the frame.
for y in range(20, 40):
    if (y // 2) % 2 == 0:
        continue
    for x in range(20, 300):
        o = (y * W + x) * 4
        tampered[o] = tampered[o + 1] = tampered[o + 2] = 10

open(f"{work}/clean.raw", "wb").write(bytes(clean))
open(f"{work}/tampered.raw", "wb").write(bytes(tampered))
open(f"{work}/other.raw", "wb").write(bytes(flat(40)))

# How much did whole-frame mean luma move? This is what the old detector saw.
def mean(buf):
    t = 0.0
    for i in range(0, len(buf), 4):
        t += (0.299 * buf[i] + 0.587 * buf[i + 1] + 0.114 * buf[i + 2]) / 255.0
    return t / (W * H)

jump = abs(mean(clean) - mean(tampered))
open(f"{work}/jump.txt", "w").write(f"{jump:.6f}")
print(f"mean-luma jump caused by the injection: {jump:.6f}")
print("old detector threshold:                 0.350000")
assert jump < 0.35, "pick a subtler injection"
print("→ the old mean-luma detector would have said nothing.")
print("  (and this injection is deliberately blatant — near-black stripes over")
print("   1.6% of a light frame; realistic small text is far below even this.)\n")
PY

D="$("$BIN" frame-digest --raw "$WORK/clean.raw" --width 320 --height 180 | head -1)"
echo "guard-recorded digest: ${D:0:32}…"
echo

echo "== same frame =="
"$BIN" frame-digest --raw "$WORK/clean.raw" --width 320 --height 180 --expect "$D" \
  | tail -1 | sed 's/^/  /'

echo
echo "== tampered: injected text (must be rejected) =="
if "$BIN" frame-digest --raw "$WORK/tampered.raw" --width 320 --height 180 \
     --expect "$D" > "$WORK/out.txt" 2>&1; then
  echo "  FAIL: tampered frame was accepted" >&2
  exit 1
fi
grep -E "TAMPERED" "$WORK/out.txt" | sed 's/^/  /'
echo "  → rejected, as required"

echo
echo "== an entirely different screen (must not be called an edit) =="
if "$BIN" frame-digest --raw "$WORK/other.raw" --width 320 --height 180 \
     --expect "$D" > "$WORK/out.txt" 2>&1; then
  echo "  FAIL: different screen was accepted" >&2
  exit 1
fi
grep -E "DIFFERENT SCREEN" "$WORK/out.txt" | sed 's/^/  /'

echo
echo "DEMO OK: localized edit and whole-screen change are distinguished, and an"
echo "injection that moved the frame mean by only $(cat "$WORK/jump.txt") (threshold 0.35) was caught."

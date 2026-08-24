#!/usr/bin/env bash
# Why the keyless hash chain was not "non-deniable audit", and what signing does
# and does not fix. Each stage runs an attack that a real DB-writer can perform
# and asserts the expected verdict.
#
#   A. edit a row and recompute the chain     → chain OK,  signatures BROKEN
#   B. blank the signature column             → BROKEN (unsigned rows fail)
#   C. blank the hash columns                 → BROKEN, and the verifier must NOT
#                                               "repair" the chain it audits
#   D. forge user_decision (no receipt)       → BROKEN via receipt cross-check
#   E. truncate the tail                      → internally clean; only the
#                                               out-of-band head witness catches it
#
# Exit 0 when every stage behaves as expected.
set -euo pipefail
export RUST_BACKTRACE=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Build once, quietly, then invoke the binary directly: cargo's build chatter on
# stderr would otherwise drown the verdicts below.
cargo build -q -p guard-cli 2>/dev/null
BIN="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')/debug/guard-cli"
CLI=("$BIN")
KEY="$WORK/audit-signing.key"
PUB="$WORK/audit-signing.key.pub"
WITNESS="$WORK/head-witness.json"

cat > "$WORK/events.jsonl" <<'JSON'
{"event_id":"e1","timestamp_ms":1000,"platform":"macos","event_type":"ui_tree_delta","source_app":"Safari","agent_context_id":"s1","metadata":{"ui_text":"确认支付 $299"}}
{"event_id":"e2","timestamp_ms":2000,"platform":"macos","event_type":"ui_tree_delta","source_app":"Safari","agent_context_id":"s1","metadata":{"ui_text":"Checkout"}}
{"event_id":"e3","timestamp_ms":3000,"platform":"macos","event_type":"ui_tree_delta","source_app":"Safari","agent_context_id":"s1","metadata":{"ui_text":"Done"}}
JSON

# Each stage starts from a fresh log. A fresh log gets a new log_id, so the
# witness from a previous stage is intentionally invalid — drop it too.
fresh_db() {
  rm -f "$WORK/audit.db" "$WITNESS"
  AGENTGUARD_AUDIT_SIGNING_KEY="$KEY" \
    "${CLI[@]}" replay --events "$WORK/events.jsonl" --audit-db "$WORK/audit.db" >/dev/null
}

# Recompute the whole hash chain the way an informed attacker would.
rechain() {
  python3 - "$WORK/audit.db" <<'PY'
import hashlib, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
SEP = "\x1f"
prev = "AGENTGUARD-AUDIT-GENESIS-v1"
rows = conn.execute(
    """SELECT rowid, id, timestamp_ms, platform, event_type, source_app,
              agent_session_id, rule_id, severity, action, human_message,
              evidence_ref, event_json
       FROM audit_events ORDER BY rowid"""
).fetchall()
for r in rows:
    canonical = SEP.join(
        [r[1], str(r[2]), r[3], r[4], r[5], r[6] or "", r[7], r[8], r[9], r[10],
         r[11] or "", r[12]]
    )
    h = hashlib.sha256(prev.encode() + b"\n" + canonical.encode()).hexdigest()
    conn.execute("UPDATE audit_events SET prev_hash=?, record_hash=? WHERE rowid=?",
                 (prev, h, r[0]))
    prev = h
conn.commit()
PY
}

sql() { python3 -c "
import sqlite3,sys
c=sqlite3.connect('$WORK/audit.db'); c.execute(sys.argv[1]); c.commit()" "$1"; }

expect_fail() {
  local label="$1"; shift
  if "$@" > "$WORK/out.txt" 2>&1; then
    echo "  FAIL: $label was accepted" >&2
    cat "$WORK/out.txt" >&2
    exit 1
  fi
  grep -vE "^(Stack backtrace|\s+[0-9]+:|\s+at )" "$WORK/out.txt" | sed 's/^/  /'
  echo "  → rejected, as required"
}

expect_pass() {
  local label="$1"; shift
  if ! "$@" > "$WORK/out.txt" 2>&1; then
    echo "  FAIL: $label was rejected" >&2
    cat "$WORK/out.txt" >&2
    exit 1
  fi
  grep -vE "^(Stack backtrace|\s+[0-9]+:|\s+at )" "$WORK/out.txt" | sed 's/^/  /'
}

echo "== 0. keygen =="
"${CLI[@]}" audit-keygen --key "$KEY" | sed 's/^/  /'

echo
echo "== baseline: a signed log verifies, and records a head witness =="
fresh_db
expect_pass "clean log" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" \
  --pubkey "$PUB" --head-witness "$WITNESS"

echo
echo "== A. edit a row, then recompute the chain (the original gap) =="
sql "UPDATE audit_events SET action='Allow', rule_id='ALLOW', human_message='ok' WHERE rowid=1"
rechain
expect_fail "re-hashed edit" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" --pubkey "$PUB"
grep -q "^chain: OK" "$WORK/out.txt" \
  || { echo "  FAIL: expected the hash chain to accept it (that is the point)" >&2; exit 1; }
echo "  (note the chain itself said OK — signatures are what caught it)"

echo
echo "== B. blank the signature column instead =="
fresh_db
sql "UPDATE audit_events SET action='Allow', human_message='nothing to see here' WHERE rowid=1"
sql "UPDATE audit_events SET record_sig=''"
rechain
expect_fail "blanked signatures" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" --pubkey "$PUB"

echo
echo "== C. blank the hash columns (verifier must not repair them) =="
fresh_db
sql "UPDATE audit_events SET action='Allow', human_message='wiped' WHERE rowid=1"
sql "UPDATE audit_events SET prev_hash='', record_hash=''"
BEFORE="$(md5sum "$WORK/audit.db" | cut -d' ' -f1)"
expect_fail "blanked hashes" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" --pubkey "$PUB"
AFTER="$(md5sum "$WORK/audit.db" | cut -d' ' -f1)"
[ "$BEFORE" = "$AFTER" ] \
  || { echo "  FAIL: audit-verify modified the database it was auditing" >&2; exit 1; }
echo "  database unchanged by verification ($BEFORE)"

echo
echo "== D. forge user_decision with no receipt =="
fresh_db
sql "UPDATE audit_events SET user_decision='approve' WHERE rowid=1"
expect_fail "forged user_decision" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" --pubkey "$PUB"

echo
echo "== E. truncate the tail (only the out-of-band witness can see this) =="
fresh_db
expect_pass "re-baseline witness" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" \
  --pubkey "$PUB" --head-witness "$WITNESS"
sql "DELETE FROM audit_events WHERE seq = 3"
expect_fail "truncated tail" "${CLI[@]}" audit-verify --audit-db "$WORK/audit.db" \
  --pubkey "$PUB" --head-witness "$WITNESS"
grep -q "record signatures: OK" "$WORK/out.txt" \
  || { echo "  FAIL: expected signatures to still look clean after truncation" >&2; exit 1; }
echo "  (signatures were still OK — the witness is what noticed)"

echo
echo "DEMO OK: all five tamper paths behave as documented."

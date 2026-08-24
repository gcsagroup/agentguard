# Signed audit records (Aura pillar iv)

Aura — “Blind Gods and Broken Screens: Architecting a Secure, Intent-Centric
Mobile Agent OS” ([arXiv 2602.10915](https://arxiv.org/abs/2602.10915) §4.4.6) —
requires every logged action be **cryptographically attributed to its entity**:
“attributed, undeniable”.

## What was wrong

Iterations 2–5 shipped `guard-audit::chain`, a keyless SHA-256 chain
(`record_hash = SHA-256(prev_hash ‖ canonical(record))`) plus a matching chain
over decision receipts, and the docs called it “non-deniable audit”.

A keyless chain is **tamper-evident against an editor who does not recompute
it** — and nothing more. Anyone who can write the SQLite file can edit a row,
rehash the remainder, and `audit-verify` reports `chain: OK`. There is no signer,
so there is nothing to attribute the log to and nothing anyone cannot deny.

You can reproduce the gap in about ten lines of Python: edit a row, walk the
table recomputing `chain_hash`, done. The unit test
`rehashed_tamper_passes_chain_but_fails_signatures` does exactly that and asserts
`verify_chain().ok == true`.

## What is implemented now

Each appended record is signed with an Ed25519 device key over

```
"AGENTGUARD-AUDIT-RECORD-v2" 0x1f <key_id> 0x1f <log_id> 0x1f <seq> 0x1f <record_hash>
```

and each decision receipt over

```
"AGENTGUARD-AUDIT-RECEIPT-v2" 0x1f <key_id> 0x1f <log_id> 0x1f <seq> 0x1f <receipt_hash>
                              0x1f <actor> 0x1f <audit_id>
```

Design points worth stating explicitly:

- **The signature covers the chain hash, not the row.** So editing row *N*
  invalidates *N* and every row after it (their `prev_hash` changed). Localized
  edits are impossible without the key.
- **Domain separation.** A record signature cannot be replayed as a receipt
  signature or vice versa.
- **`key_id` is inside the signed payload**, so a signature cannot be re-presented
  as coming from a different key.
- **`log_id` (per-database random id) is inside the payload**, so a genuinely
  signed row cannot be transplanted into a different log — even by someone
  holding the same device key.
- **`seq` (position) is inside the payload**, and verification requires positions
  to be contiguous from 1. Rows cannot be reordered, and deleting a row from the
  middle leaves a gap that fails verification.
- **`audit_id` is inside the receipt payload**, so a receipt cannot be moved onto a
  different audit record.
- **`actor` is inside the receipt payload.** `UserDecision::Timeout` records
  `actor = "system"`; approve/deny record `actor = "user"`. A timeout is the
  policy acting, not a decision a human made — conflating the two is what made
  the old “non-deniable user decision” deniable. Relabelling a signed timeout as
  an approval now fails verification.
- **Verification re-derives every hash from the row.** A signature over a
  `record_hash` read out of a column proves nothing about that column's row, so
  `verify_record_signatures` recomputes the chain itself rather than trusting the
  stored value. `verify_chain` is still available separately, but it is not a
  prerequisite for the signature check to be meaningful.
- **Unsigned rows FAIL.** This is the important default. Treating them as merely
  “not covered” made blanking the `record_sig` column a complete bypass requiring
  no key at all — edit whatever you like, blank the column, get `OK` and exit 0.
  Rows that genuinely predate signing are accepted only with an explicit
  `--allow-unsigned`, which reports them as *not attributed*.
- **Signatures are never backfilled.** Retro-signing a pre-key row would backdate
  an attestation. Hashes *are* backfillable (a hash claims nothing about who saw
  the row) but only via the explicit `audit-migrate` command — never on `open()`,
  and never from a verification path (see the next point).
- **The verifier never writes to the log.** `audit-verify` opens read-only. An
  earlier version ran migrations on open, so blanking `record_hash` made the
  verifier recompute and *persist* a valid chain over forged content — the tool
  repaired the log for the attacker and then reported `chain: OK`. An empty
  `record_hash` is now a mismatch, not a hole to fill.
- **`user_decision` is cross-checked against receipts.** That column is excluded
  from the chain's canonical content (it is written after the fact), so it is
  covered by no hash and no signature: editing it alone used to leave every check
  green. Every non-null `user_decision` must now equal the decision of the latest
  *valid signed* receipt for that record, and a decision with no receipt is a
  failure. `SessionReport` also records whether its confirm counts came from that
  column or from verified receipts (`audit-report --pubkey`).
- **Foreign keys fail, they are not merely counted.** Rows whose `signer_key_id`
  differs from the key being verified are reported as `other_key` **and** fail, so
  an attacker who re-signs everything with their own key cannot get an `OK`.

## Threat model — read this before saying “non-deniable”

| Attacker action | Keyless chain | + signing (this iteration) | Caught by |
|---|---|---|---|
| Edits a row, doesn't rehash | detected | detected | chain |
| Edits a row **and** rehashes the tail | **passes** | detected | record signatures |
| Edits rows, then blanks `record_sig` | passes | detected | strict unsigned-fails default |
| Edits rows, then blanks `prev_hash`/`record_hash` | passes (verifier used to *repair* it) | detected | read-only verify + empty-hash-is-mismatch |
| Re-signs everything with their own key | passes | detected | `other_key` fails |
| Writes `user_decision='approve'` directly | passes | detected | receipt cross-check |
| Deletes a row from the middle | passes | detected | `seq` contiguity |
| Moves a signed row into another DB | passes | detected | `log_id` binding |
| Deletes the tail / restores an older copy | passes | passes internally | **only** the head witness (`--head-witness`) |
| Deletes the DB wholesale | undetectable | undetectable internally | head witness (reports a wipe) |
| Reads the key file (root / same user) | — | **passes** — can re-sign anything | needs a hardware-backed key |

`FileDeviceKey` stores the secret at mode 0600 on the same disk as the database.
That raises the bar from “anyone who can write the file” to “anyone who can write
the file **and** read the key” — a real improvement against remote write access,
backup tampering and casual edits, and **not** protection against a compromised
host.

Getting further requires either a key the host cannot export (Secure Enclave,
TPM, StrongBox) or an external append-only anchor (transparency log, witness
service). The `AuditSigner` trait exists so such a backend drops in without
touching the store; `FileDeviceKey` is the portable fallback, not the
destination.

**Truncation and rollback** cannot be detected from inside the database at all:
any prefix of a valid chain is itself a valid chain, and an attacker who restores
an older copy of the file rolls back the embedded head along with everything else.
`--head-witness <path>` is the minimum answer — a small JSON file kept **outside**
the DB recording `{log_id, seq, count, last_record_hash}` from the last clean
verification. If the log's head has gone backwards, or its `log_id` changed, or
the log is empty when the witness says it had records, verification fails. Keep
that file somewhere the attacker does not control (another host, append-only
storage); a witness beside the database is worth little.

## Usage

```bash
# 1. Generate the device key (Ed25519; secret 0600, public alongside).
cargo run -p guard-cli -- audit-keygen --key policies/audit-signing.key
# → key_id: 1ad8a4ae…  public: e405e08b…
#   Copy the .pub OFF this machine.

# 2. Any command that writes audit rows picks the key up automatically from
#    AGENTGUARD_AUDIT_SIGNING_KEY, or from policies/audit-signing.key if present.
AGENTGUARD_AUDIT_SIGNING_KEY=policies/audit-signing.key \
  cargo run -p guard-cli -- replay --events events.jsonl --audit-db /tmp/audit.db

cargo run -p guard-cli -- api-serve --audit-signing-key policies/audit-signing.key …

# 3. Verify against the out-of-band public key.
cargo run -p guard-cli -- audit-verify \
  --audit-db /tmp/audit.db \
  --pubkey /path/to/kept/audit-signing.key.pub \
  --head-witness /path/kept/elsewhere/head.json

# Legacy DB that predates signing: accept the unsigned rows explicitly.
cargo run -p guard-cli -- audit-migrate --audit-db old.db     # hashes only
cargo run -p guard-cli -- audit-verify --audit-db old.db --pubkey … --allow-unsigned

# Evidence-grade confirm counts (from verified receipts, not the mutable column):
cargo run -p guard-cli -- audit-report --audit-db /tmp/audit.db --pubkey …
```

A key is **never created implicitly** by the write path: silently signing with a
fresh key would look like coverage while its public half exists nowhere, so
`audit-keygen` stays an explicit step. (The desktop shells do generate one on
first run, because there is no CLI moment to do it in — they print the key id.)

`audit-verify` output, and what each line means:

```
chain: OK verified=3/3                     # nobody edited without rehashing
receipt chain: OK verified=0/0
record signatures: OK key_id=e31685b3… verified=3/3 rows=3 unsigned=0 other_key=0
receipt signatures: OK key_id=e31685b3… verified=0/0 rows=0 unsigned=0 other_key=0
head: seq=3 count=3 log_id=cc91b0be-…
head witness updated: …/head.json
```

After a re-hashed edit — the case the chain cannot see:

```
chain: OK verified=3/3                     # ← still "OK"
record signatures: BROKEN key_id=e31685b3… verified=0/3 rows=3 … (signature invalid)
exit status 1
```

After a forged `user_decision`, where record signatures are perfectly valid
because the column is outside them:

```
record signatures: OK  key_id=e31685b3… verified=3/3
receipt signatures: BROKEN … (user_decision 'approve' has no valid signed receipt)
exit status 1
```

`make audit-signing-demo` runs all five tamper paths — re-hashed edit, blanked
signatures, blanked hashes, forged decision, truncated tail — and asserts each
verdict. It is a CI step, so a regression in any of them fails the build.

On a DB written with no key at all, the command says so rather than reporting a
clean bill of health:

```
signatures: NONE — this DB was written without a signing key, so it is
tamper-evident but not attributed. Anyone who can write the file can re-hash it
and pass the chain check above.
```

Omitting `--pubkey` falls back to the public key stored in the DB's `audit_meta`
table. That is convenient for a quick local check and prints a warning, because
an attacker who swapped the signing key can swap that copy too.

## Storage

| Table | Column | Notes |
|---|---|---|
| `audit_events` | `record_sig`, `signer_key_id`, `seq` | empty/0 for pre-signing rows |
| `decision_receipts` | `actor`, `receipt_sig`, `signer_key_id`, `seq` | `actor` defaults to `user` for legacy rows |
| `audit_meta` | `log_id` | per-database id, mixed into every signature |
| `audit_meta` | `signer_public_hex`, `signer_key_id` | convenience only; **not** a trust anchor |

`audit-export` includes `log_id`, `seq`, `prev_hash`, `record_hash`, `record_sig`
and `signer_key_id` per line, so the artifact handed to an auditor is verifiable
rather than a bare row dump.

Migrations add the columns to existing databases in place.

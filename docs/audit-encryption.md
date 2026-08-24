# Audit DB encryption (SQLCipher)

Default AgentGuard builds use **plain bundled SQLite** for the local audit store.

Encryption at rest is orthogonal to integrity: SQLCipher stops *reading* the log,
[audit-signing.md](./audit-signing.md) stops *forging* it. `AGENTGUARD_AUDIT_KEY`
(a SQLCipher passphrase) and `AGENTGUARD_AUDIT_SIGNING_KEY` (an Ed25519 signing
key path) are different keys for different jobs — do not reuse one for the other.

## Enable SQLCipher

```bash
# Library tests only
cargo test -p guard-audit --no-default-features --features sqlcipher

# Or depend explicitly in an app Cargo.toml:
# guard-audit = { path = "...", default-features = false, features = ["sqlcipher"] }
```

Do **not** enable both `sqlite-bundled` and `sqlcipher` at once.

## Open an encrypted DB

```bash
export AGENTGUARD_AUDIT_KEY='your-passphrase'
cargo run -p guard-cli -- audit-crypto-status   # must print sqlcipher_enabled=true in an encrypted build

# With a SQLCipher-enabled binary:
cargo run -p guard-cli -- sim-mac --confirm deny --audit-db /tmp/ag-enc.db
cargo run -p guard-cli -- audit-report --audit-db /tmp/ag-enc.db
```

API:

- `AuditStore::open` — honors `AGENTGUARD_AUDIT_KEY` when SQLCipher is linked
- `AuditStore::open_with_key(path, Some("…"))` — explicit passphrase
- Without the feature, any non-empty key returns a clear error

## Notes

- On macOS, `bundled-sqlcipher` uses Apple Security framework for crypto (no vendored OpenSSL required).
- Schema is identical to the plain SQLite store; only the file container is encrypted.

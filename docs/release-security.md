# Release security defaults

Free / non-billing launch checklist for secure defaults.

## Desktop macOS

| Control | Debug (`tauri dev`) | Release |
|---------|---------------------|---------|
| Auto-approve Critical Confirm | Allowed (UI visible) | Hidden / rejected unless `AGENTGUARD_ALLOW_AUTO_APPROVE=1` |
| Threat intel | Soft-load (`load_or_default`) | `load_release` + `intel/keys/public.hex` (fail-closed → empty) |
| Audit DB | Plain SQLite by default | Prefer `--features audit-sqlcipher` + auto `audit.key` |
| Local API | Bearer required | Same; never bind non-loopback |

### Secure release build

```bash
cd apps/desktop-macos
# SQLCipher audit
npx tauri build -- --no-default-features --features audit-sqlcipher
# or via script notes in scripts/build-release.sh
```

Key file: `~/Library/Application Support/agentguard/audit.key` (created on first launch when sqlcipher linked).

### Env overrides

| Var | Purpose |
|-----|---------|
| `AGENTGUARD_AUDIT_KEY` | Explicit passphrase (skips file) |
| `AGENTGUARD_INTEL` | Bundle path |
| `AGENTGUARD_INTEL_PUBKEY` | Ed25519 public key hex path |
| `AGENTGUARD_ALLOW_AUTO_APPROVE` | Dangerous; testing only |

## CLI

```bash
make acceptance          # offline release gate (11 scenarios)
make test-sqlcipher      # encryption unit tests
cargo run -p guard-cli -- api-serve --token "$AGENTGUARD_API_TOKEN"
```

## Docs

- Privacy: `docs/privacy-policy.md`
- macOS ship: `docs/macos-release.md`
- Acceptance: `docs/acceptance-macos.md`

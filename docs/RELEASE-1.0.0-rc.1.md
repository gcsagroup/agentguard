# AgentGuard 1.0.0-rc.1

Release candidate for the third-party Agent guardian (desktop / browser / Android companion scaffold).

## Highlights
- Rule engine + OP/TR/FM privacy scoring + Critical Confirm
- macOS Menu Bar: TCC onboarding, SCK native bridge with **1.5s auto-poll**, tray start/stop
- Windows desktop shell (simulation; real UIA deferred)
- Chromium MV3 extension + Native Messaging host
- Threat intel Ed25519 bundles + multi-agent privacy leaderboard (9 profiles, one shared probe suite)
- Local billing entitlement + webhook HTTP + **Bearer-protected** loopback API
- Optional SQLCipher audit encryption (`--features sqlcipher`)
- 33/33 offline eval scenarios

## Explicitly deferred
- Windows real-device UIA / Graphics Capture validation
- Live Stripe / App Store / CWS / Play Console publication

## Verify
```bash
make check
cargo test -p guard-localapi --lib
make test-sqlcipher   # optional
cargo run -p guard-cli -- sck-probe
```

## Docs
- `docs/roadmap-status.md`
- `docs/sck-bridge.md`
- `docs/local-api.md`
- `docs/audit-encryption.md`
- `docs/billing.md`

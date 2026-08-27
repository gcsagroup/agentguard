# AgentGuard Threat Intelligence Bundle

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

`bundle.json` is the threat-indicator bundle, `cdn-manifest.json` describes an update entry point, and `keys/public.hex` is the Ed25519 public key used to verify the current sample bundle. The private `keys/secret.hex` is excluded by `.gitignore` and must never be committed or distributed.

## Generate, sign, and verify

Run from the repository root:

```bash
# Generate an Ed25519 key pair once; existing keys are not overwritten
cargo run -p guard-cli -- intel-keygen --out-dir intel/keys

# Sign and write back to bundle.json
cargo run -p guard-cli -- intel-sign \
  --bundle intel/bundle.json \
  --secret intel/keys/secret.hex

# Verify release authenticity against the pinned public key
cargo run -p guard-cli -- intel-verify \
  --bundle intel/bundle.json \
  --pubkey intel/keys/public.hex
```

On Unix, the key generator uses restrictive directory and file modes. The signing command refuses to use an existing private key whose permissions are too broad. If the key may already have leaked, changing its mode is insufficient; rotate the trust root and re-sign.

## Update check

Local-manifest dry-run example:

```bash
cargo run -p guard-cli -- intel-fetch \
  --manifest intel/cdn-manifest.json \
  --pubkey intel/keys/public.hex \
  --out /tmp/agentguard-intel.json \
  --dry-run
```

The flow is: read manifest → fetch bundle → verify the bundle with the supplied public key → compare versions → write output only without `--dry-run`. The manifest's version hint is not the trust root; the fetched bundle content and signature are what get authenticated.

## Signature-algorithm boundary

### Release and production: Ed25519 only

The `load_release` path requires:

- a `signature` in `ed25519:<base64>` form;
- a readable pinned public key;
- a valid Ed25519 signature over the SHA-256 digest of the bundle's canonical JSON; and
- rejection of unsigned, unknown-scheme, or `sha256:<hex>` bundles.

`intel-verify` and update flows supplied with `--pubkey` likewise require authenticity. `sha256:<hex>` cannot replace a release signature because anyone able to alter the bundle can recompute that digest.

### Development compatibility: SHA-256 is integrity only

`sha256:<hex>` remains available only to development or offline soft-loading paths that do not receive a public key. It can detect accidental corruption; it does not identify the publisher, is not valid production authentication, and must not be described as a digital signature.

Without a public key, `load_or_default` also cannot authenticate an Ed25519 bundle. It loads it as unverified development data and emits a warning. Production consumers must use `load_release` with a pinned public key.

## Operational requirements

- Never commit `intel/keys/secret.hex` or put it in build artifacts, logs, or ordinary CI variables.
- Pin the public-key fingerprint before release and treat key rotation as an explicit migration.
- Prefer HTTPS for remote updates, but still verify the Ed25519 bundle signature even when transport is protected.
- `--dry-run` verifies and prints without writing `--out`.

The current `intel/bundle.json` uses the Ed25519 format. That demonstrates a verifiable sample bundle; it is not evidence of a production publishing, key-custody, or CDN operating process.

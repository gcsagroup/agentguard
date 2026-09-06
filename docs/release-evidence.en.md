[简体中文](release-evidence.md) | [繁體中文](release-evidence.zh-TW.md) | [English](release-evidence.en.md)

# Structured Release Evidence

The AgentGuard `--strict` **RC technical gate** no longer treats a keyword appearing in an arbitrary file as evidence. Each of the twelve credential- or device-dependent checks must provide structured JSON bound to the **full current commit** and an on-site artifact digest: a regular release file uses standard SHA-256, an Apple `.app` uses deterministic whole-bundle tree-v2, and an acceptance report uses acceptance-closure-v1 over the report and per-case materials.

> Passing `--strict` only makes a candidate eligible for GA closure; it is not GA approval or proof of launch. `--ga` adds seven closure kinds, for 19 total. See the [GA release-closure gate](ga-release-gate.en.md).

> This remains unsigned local self-attestation. It addresses mistaken binding, operator mistakes, and some mechanical forgeries, but a party that controls the workspace can still fabricate every field or replace the artifact. Defending against that attacker requires evidence signed by and verified against a trusted runner, which is later-phase work. Valid evidence JSON does not by itself make an installer releasable.

## Twelve evidence kinds

| `kind` | Criterion | Environment variable |
|---|---|---|
| `macos_codesign` | `codesign --verify --deep --strict --verbose=4` succeeds and reads the signing identity from the same artifact | `AGENTGUARD_EVIDENCE_MACOS_CODESIGN` |
| `macos_notarize` | `notarytool` returns Accepted and staple validation succeeds | `AGENTGUARD_EVIDENCE_MACOS_NOTARIZE` |
| `windows_sign` | `signtool verify /pa /v` succeeds | `AGENTGUARD_EVIDENCE_WINDOWS_SIGN` |
| `android_sign` | `apksigner verify --print-certs` identifies the release, not debug, certificate | `AGENTGUARD_EVIDENCE_ANDROID_SIGN` |
| `ios_codesign` | The final device `.app` passes strict codesign verification and output binds Apple Distribution authority plus the expected Team ID | `AGENTGUARD_EVIDENCE_IOS_CODESIGN` |
| `acceptance_macos` | The macOS real-device checklist is complete | `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS` |
| `acceptance_android` | A real Android device with Accessibility enabled produces a signed envelope that the desktop verifies with the registered public key and evaluates as expected | `AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID` |
| `acceptance_ios` | I1–I6 Safari Web Extension cases pass on real iPhone/iPad hardware | `AGENTGUARD_EVIDENCE_ACCEPTANCE_IOS` |
| `acceptance_ios_testflight` | TF1–TF3 upload, device install, and upgrade cases pass | `AGENTGUARD_EVIDENCE_ACCEPTANCE_IOS_TESTFLIGHT` |
| `acceptance_chrome` | B1–B5 pass in release Chrome with the candidate ZIP | `AGENTGUARD_EVIDENCE_ACCEPTANCE_CHROME` |
| `acceptance_edge` | B1–B5 independently pass in release Edge with the same ZIP | `AGENTGUARD_EVIDENCE_ACCEPTANCE_EDGE` |
| `acceptance_windows` | The Windows real-device checklist is complete | `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS` |

## JSON constraints

Each evidence document contains these fields:

```json
{
  "schema": "agentguard-release-evidence-v1",
  "kind": "acceptance_macos",
  "signer": null,
  "commit": "the full 40-character Git commit",
  "command": "target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md evidence/macos/report.md --repo-root .",
  "exit_code": 0,
  "timestamp": "an RFC 3339 timestamp",
  "output": "AGENTGUARD_ACCEPTANCE_MACOS=PASS",
  "artifact": {
    "path": "evidence/macos/report.md",
    "sha256": "the 64-character SHA-256 for a regular file, .app tree-v2, or acceptance closure-v1"
  }
}
```

The verifier requires:

- The evidence JSON named by `--file` to be a readable UTF-8 regular file no larger than 1 MiB. The file itself must not be a symbolic link, and fields outside the schema are rejected.
- `commit` to equal the full commit currently checked by the gate, not a short hash or another candidate.
- `signer` to be a nonempty string for each of the five signing kinds and match an expected publisher identity obtained outside the evidence JSON. For each of the seven acceptance kinds used by the strict gate, `signer` must be `null`, and a direct verifier call must not pass `--expected-signer`.
- `command`, `timestamp`, and `output` to replace the template placeholders, `exit_code` to equal `0`, and the timestamp to be valid RFC 3339 and, at verification time, between 30 days in the past and 10 minutes in the future. It must not predate the HEAD commit time, with a 10-minute clock-skew allowance. `command` must contain the same `artifact.path` literally, preventing a command that verifies A while the evidence binds B.
- `artifact.path` to be repository-relative and use only `/` separators. Each component must match portable ASCII `[A-Za-z0-9._-]+`. A regular file must be nonempty. The macOS/iOS signing kinds also accept a `.app` directory containing at least one nonempty regular file, but any symbolic link, special file, or non-UTF-8 path inside the bundle fails closed.
- The verifier recomputes the digest on site and compares it with `artifact.sha256`. A regular **non-acceptance** file uses standard SHA-256. A `.app` uses a deterministic digest with the `agentguard-tree-sha256-v2` domain separator. Tree-v2 binds the Unix `0111` executable-bit mask of the bundle root and every entry, then binds entry type, UTF-8 relative-path length/path, file length, and content in relative-path byte order. It deliberately does not bind other mode bits, xattrs, or ACLs. A system without POSIX modes cannot use this to claim that real executable bits were observed. Tree-v2 also does not prove quarantine/Gatekeeper or first-launch behavior; the downloaded production candidate must still pass first-launch acceptance on an isolated machine.
- Signing `command` values must use the verifier's exact fail-closed success chain. macOS/iOS code signing is `codesign --verify --deep --strict --verbose=4 ARTIFACT && codesign -dv --verbose=4 ARTIFACT`; iOS output must additionally prove Apple Distribution authority. Windows and Android retain their fixed verification flows. `ios_codesign` accepts only a `.app` under an allowed release-output path.
- Before notarization, run `xcrun notarytool store-credentials AgentGuard-Notary --apple-id "$APPLE_ID" --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"` outside the repository and enter the app-specific password at the secure prompt to place credentials in the login keychain. Do not put the password in a command argument; never place a password or API private key in the repository, JSON `command`, or evidence logs. An `.app` uses the four-segment `&&` success chain `ditto -c -k --keepParent APP ZIP` → `xcrun notarytool submit ZIP --wait --team-id <Team ID> --keychain-profile AgentGuard-Notary` → `xcrun stapler staple APP` → `xcrun stapler validate APP`. A `.dmg` or `.pkg` omits ditto and applies the final three segments to the same `artifact.path`. ZIP, artifact, and per-case evidence paths all follow the portable-ASCII component rule above; `--team-id` and `--keychain-profile` must each occur exactly once.
- Signing `output` must also bind certificate identity. iOS requires the normal codesign success signals, the expected Team ID, and `Authority=Apple Distribution:`. Other signing kinds retain their existing strict output criteria.
- The seven strict-gate acceptance kinds accept `.md` reports up to 16 MiB only under their matching `evidence/<platform>/` directory: macOS, Android, Windows, iOS, iOS TestFlight, Chrome, and Edge. The command is one exact `guard-cli manual-acceptance <platform> <checklist> <artifact.path> --repo-root .` segment.
- The verifier parses Windows W1–W6/W8–W11, Android A1–A4, macOS 1–18 (including 5b/5c), iOS I1–I6, TestFlight TF1–TF3, and B1–B5 separately for Chrome and Edge. Every required ID appears exactly once as `PASS (native)` with a distinct nonempty evidence file under that kind's directory. Missing, duplicate, simulated, FAIL, BLOCKED, or N/A rows are rejected.

Acceptance `artifact.sha256` uses `agentguard-acceptance-closure-sha256-v1`. It binds the report's raw bytes and, sorted by path, each unique per-case reference's relative path, length, and file content. Changing the report or any referenced material changes the digest. This closure remains unsigned local self-attestation: it proves only that those bytes were bound together when checked, not that a screenshot, log, or device record came from its claimed source. Trusted provenance still requires a later signed runner or external witness.

The strict gate uses seven independent success markers: `AGENTGUARD_ACCEPTANCE_MACOS=PASS`, `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`, `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`, `AGENTGUARD_ACCEPTANCE_IOS=PASS`, `AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS`, `AGENTGUARD_ACCEPTANCE_CHROME=PASS`, and `AGENTGUARD_ACCEPTANCE_EDGE=PASS`.

### The legacy Firefox format is not first-GA evidence

`guard-cli` temporarily retains parsing for `acceptance_firefox` only for legacy/future format compatibility. `scripts/release-gate.sh --strict` does not read `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`, and this document provides no Firefox-PASS release procedure. A marker returned by a direct legacy invocation cannot change the product boundary: Firefox is source-only, unbundled, unsubmitted, and outside the first-GA gate.

### Signer identity source

A signing JSON document cannot decide who the trusted publisher is. The strict gate reads the expected identity from external configuration and passes it through the verifier's required `--expected-signer` option:

| `kind` | `signer` format | External expected value |
|---|---|---|
| `macos_codesign`, `macos_notarize` | The macOS publisher's 10-character Apple Team ID | `AGENTGUARD_EXPECTED_MACOS_TEAM_ID` |
| `ios_codesign` | The iOS publisher's 10-character Apple Team ID | `AGENTGUARD_EXPECTED_IOS_TEAM_ID` |
| `windows_sign` | The release certificate's 64-character SHA-256 fingerprint | `AGENTGUARD_EXPECTED_WINDOWS_CERT_SHA256` |
| `android_sign` | The release certificate's 64-character SHA-256 fingerprint | `AGENTGUARD_EXPECTED_ANDROID_CERT_SHA256` |

Windows and Android fingerprint input may contain letter case or colons and is normalized to 64 hexadecimal characters before comparison. The JSON `signer`, certificate identity in command output, and external expected value must all identify the same publisher. The seven strict-gate acceptance kinds do not accept an external signer.

Run the following as one line from a Developer PowerShell where `signtool` is configured. Replace both path occurrences and the JSON `artifact.path` together. The command first has `signtool` verify the trust chain, then reads the Authenticode certificate from the same file and prints the separate fingerprint line required by the verifier. Do not write a literal `<fingerprint>` as successful output.

```powershell
signtool verify /pa /v dist/AgentGuard.exe; if (-not $? -or $LASTEXITCODE -ne 0) { exit 1 }; $signature = Get-AuthenticodeSignature dist/AgentGuard.exe; if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { exit 1 }; Write-Output ('CertificateSHA256=' + $signature.SignerCertificate.GetCertHashString('SHA256'))
```

## Generate, complete, and verify

Freeze the candidate commit, confirm that the index and every non-ignored worktree file are clean, and then
generate a deliberately invalid template:

```bash
mkdir -p evidence/macos
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
cargo run -p guard-cli -- evidence-template --kind acceptance_macos \
  --commit "$commit" > evidence/macos/evidence.json
```

The template is only a field checklist and must fail verification until completed. Run real-device acceptance and save the report as `evidence/macos/report.md`. First execute the manual acceptance check and obtain its unique marker, then compute the report closure through the shared digest entry point. Put the exact command, marker, and digest into JSON before explicit verification:

```bash
target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
  evidence/macos/report.md --repo-root .
# Sole success output: AGENTGUARD_ACCEPTANCE_MACOS=PASS

cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/macos/report.md

cargo run -p guard-cli -- evidence-verify \
  --kind acceptance_macos \
  --file evidence/macos/evidence.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root .

export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=evidence/macos/evidence.json
bash scripts/release-gate.sh --strict
```

Use the same `evidence-digest` entry point for a `.app` tree-v2 digest; never substitute the SHA-256 of an internal Mach-O. First configure the `AgentGuard-Notary` keychain profile outside the repository without recording its password, then run, for example:

```bash
xcrun notarytool store-credentials AgentGuard-Notary \
  --apple-id "$APPLE_ID" \
  --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"
# Enter the app-specific password at the secure prompt; do not put it in arguments or logs.

app=apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app
zip=evidence/macos/AgentGuard.zip
ditto -c -k --keepParent "$app" "$zip" && \
  xcrun notarytool submit "$zip" --wait --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID" \
    --keychain-profile AgentGuard-Notary && \
  xcrun stapler staple "$app" && \
  xcrun stapler validate "$app"
cargo run -p guard-cli -- evidence-digest --repo-root . --path "$app"
```

Record the expanded repository-relative paths as a single line in JSON `command`; do not retain `$app` or `$zip` placeholders.

For the other eleven kinds, substitute the `kind` and environment variable from the table. Do not point the variable at the verifier itself, an empty directory, or an old-commit report.

Direct verification of signing evidence must also provide the external expected identity explicitly, for example:

```bash
expected_signer="${AGENTGUARD_EXPECTED_MACOS_TEAM_ID:?set the production Team ID}"
cargo run -p guard-cli -- evidence-verify \
  --kind macos_codesign \
  --file evidence/macos/codesign.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root . \
  --expected-signer "$expected_signer"
```

`evidence/` is an ignored local evidence workspace generated only after the candidate commit is frozen. It must not be committed into that candidate: changing `HEAD` immediately invalidates the original commit binding. The strict gate checks `HEAD`, the index, and every non-ignored worktree file both before and after validation. Any `HEAD` or non-ignored drift still present at the end fails the run, while ignored `evidence/` files do not make the worktree dirty. These start/end snapshots cannot prove that an adversary controlling the workspace did not make and then restore a transient change; that remains part of the unsigned local-attestation boundary. After the strict gate passes, archive the evidence read-only in a controlled location. Sensitive logs, screenshots, account data, and device identifiers must not be pushed to GitHub by default.

## Release boundary

The RC strict gate also requires zero production-preflight `FAIL` results. Even when all twelve JSON documents pass, the result remains **No-Go** if fixture keys retain production semantics, automation fails, or signing, notarization, device, install, upgrade, and rollback records are incomplete. Those real records and the GA SBOM/licensing, privacy/store declarations, 14-day Beta, dual RC, five-party approval, six-channel smoke, and 5→25→100 rollout evidence are not complete. The current decision therefore remains **GA No-Go**.

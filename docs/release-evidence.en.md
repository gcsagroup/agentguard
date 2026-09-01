[简体中文](release-evidence.md) | [繁體中文](release-evidence.zh-TW.md) | [English](release-evidence.en.md)

# Structured Release Evidence

The strict AgentGuard release gate no longer treats a keyword appearing in an arbitrary file as evidence. Each of the eight credential- or device-dependent checks must provide structured JSON bound to the **full current commit** and an on-site artifact digest: a regular release file uses standard SHA-256, a macOS `.app` uses deterministic whole-bundle tree-v2, and an acceptance report uses acceptance-closure-v1 over the report and per-case materials. This reduces mistaken binding, operator mistakes, and some mechanical forgeries, such as a mistakenly supplied script, empty artifact, untouched template, or report from another candidate.

> This remains unsigned local self-attestation. It addresses mistaken binding, operator mistakes, and some mechanical forgeries, but a party that controls the workspace can still fabricate every field or replace the artifact. Defending against that attacker requires evidence signed by and verified against a trusted runner, which is later-phase work. Valid evidence JSON does not by itself make an installer releasable.

## Eight evidence kinds

| `kind` | Criterion | Environment variable |
|---|---|---|
| `macos_codesign` | `codesign --verify --deep --strict --verbose=4` succeeds and reads the signing identity from the same artifact | `AGENTGUARD_EVIDENCE_MACOS_CODESIGN` |
| `macos_notarize` | `notarytool` returns Accepted and staple validation succeeds | `AGENTGUARD_EVIDENCE_MACOS_NOTARIZE` |
| `windows_sign` | `signtool verify /pa /v` succeeds | `AGENTGUARD_EVIDENCE_WINDOWS_SIGN` |
| `android_sign` | `apksigner verify --print-certs` identifies the release, not debug, certificate | `AGENTGUARD_EVIDENCE_ANDROID_SIGN` |
| `acceptance_macos` | The macOS real-device checklist is complete | `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS` |
| `acceptance_android` | A real Android device with Accessibility enabled produces a signed envelope that the desktop verifies with the registered public key and evaluates as expected | `AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID` |
| `acceptance_firefox` | The Firefox real-device checklist is complete | `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX` |
| `acceptance_windows` | The Windows real-device checklist is complete | `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS` |

## JSON constraints

Each evidence document contains these fields:

```json
{
  "schema": "agentguard-release-evidence-v1",
  "kind": "acceptance_firefox",
  "signer": null,
  "commit": "the full 40-character Git commit",
  "command": "target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md evidence/firefox/report.md --repo-root .",
  "exit_code": 0,
  "timestamp": "an RFC 3339 timestamp",
  "output": "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS",
  "artifact": {
    "path": "evidence/firefox/report.md",
    "sha256": "the 64-character SHA-256 for a regular file, .app tree-v2, or acceptance closure-v1"
  }
}
```

The verifier requires:

- The evidence JSON named by `--file` to be a readable UTF-8 regular file no larger than 1 MiB. The file itself must not be a symbolic link, and fields outside the schema are rejected.
- `commit` to equal the full commit currently checked by the gate, not a short hash or another candidate.
- `signer` to be a nonempty string for each of the four signing kinds and match an expected publisher identity obtained outside the evidence JSON. For each of the four acceptance kinds, `signer` must be `null`, and a direct verifier call must not pass `--expected-signer`.
- `command`, `timestamp`, and `output` to replace the template placeholders, `exit_code` to equal `0`, and the timestamp to be valid RFC 3339 and, at verification time, between 30 days in the past and 10 minutes in the future. It must not predate the HEAD commit time, with a 10-minute clock-skew allowance. `command` must contain the same `artifact.path` literally, preventing a command that verifies A while the evidence binds B.
- `artifact.path` to be repository-relative and use only `/` separators. Each component must match portable ASCII `[A-Za-z0-9._-]+` and must not equal `.` or `..`. Absolute paths, backslashes, whitespace, shell glob/expansion characters, and control characters are rejected; neither the target nor any component may be a symbolic link. A regular file must be nonempty. The two macOS kinds also accept a `.app` directory containing at least one nonempty regular file, but any symbolic link, special file, or non-UTF-8 path inside the bundle fails closed.
- The verifier recomputes the digest on site and compares it with `artifact.sha256`. A regular **non-acceptance** file uses standard SHA-256. A `.app` uses a deterministic digest with the `agentguard-tree-sha256-v2` domain separator. Tree-v2 binds the Unix `0111` executable-bit mask of the bundle root and every entry, then binds entry type, UTF-8 relative-path length/path, file length, and content in relative-path byte order. It deliberately does not bind other mode bits, xattrs, or ACLs. A system without POSIX modes cannot use this to claim that real executable bits were observed. Tree-v2 also does not prove quarantine/Gatekeeper or first-launch behavior; the downloaded production candidate must still pass first-launch acceptance on an isolated machine.
- Signing `command` values must contain no `#`, PowerShell, or batch comments and must use the verifier's exact fail-closed success chain. macOS code signing is exactly `codesign --verify --deep --strict --verbose=4 ARTIFACT && codesign -dv --verbose=4 ARTIFACT`. Windows first runs `signtool verify /pa /v` and checks both PowerShell `$?` and `$LASTEXITCODE`, then runs `Get-AuthenticodeSignature` on the same file, checks status/certificate, and computes the printed fingerprint. Android accepts only one `apksigner verify --print-certs ARTIFACT` segment. The artifact must be under `evidence/`, `dist/`, `target/release/`, or an `apps/**/dist/`, `apps/**/target/release/`, or `apps/**/build/outputs/` release-output path. `macos_codesign` accepts only `.app`/`.dmg`; `macos_notarize` accepts `.app`/`.dmg`/`.pkg`; Windows accepts `.exe`/`.msi`/`.msix`; and Android accepts only `.apk`.
- Before notarization, run `xcrun notarytool store-credentials AgentGuard-Notary --apple-id "$APPLE_ID" --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"` outside the repository and enter the app-specific password at the secure prompt to place credentials in the login keychain. Do not put the password in a command argument; never place a password or API private key in the repository, JSON `command`, or evidence logs. An `.app` uses the four-segment `&&` success chain `ditto -c -k --keepParent APP ZIP` → `xcrun notarytool submit ZIP --wait --team-id <Team ID> --keychain-profile AgentGuard-Notary` → `xcrun stapler staple APP` → `xcrun stapler validate APP`. A `.dmg` or `.pkg` omits ditto and applies the final three segments to the same `artifact.path`. ZIP, artifact, and per-case evidence paths all follow the portable-ASCII component rule above; `--team-id` and `--keychain-profile` must each occur exactly once.
- In addition to success signals, signing `output` must bind the certificate identity. codesign output contains `valid on disk`, `satisfies its designated requirement`, and an exact `TeamIdentifier=<10-character Team ID>` line; notarytool reports Accepted and stapler includes `validate action worked`; Windows includes `Successfully verified` and an exact `CertificateSHA256=<64 hexadecimal characters>` line; and Android includes `Signer #1 certificate SHA-256 digest: <certificate fingerprint>`. Android output containing `Android Debug` is rejected.
- The four acceptance kinds accept only `.md` reports no larger than 16 MiB under their corresponding `evidence/macos/`, `evidence/android/`, `evidence/firefox/`, or `evidence/windows/` prefix. `command` must be the successfully executed single segment `guard-cli manual-acceptance <platform> <checklist> <artifact.path> --repo-root .`; the respective checklists are `docs/acceptance-macos.md`, `docs/acceptance-runbook.md`, `docs/acceptance-firefox.md`, and `docs/acceptance-windows.md`, and its stdout marker becomes JSON `output`.
- The verifier parses the Markdown table. Firefox must contain exactly F1–F8; Windows W1–W7; Android A1–A4; and macOS 1, 2, 3, 4, 5, 5b, 5c, and 6–14. Every ID must appear in exactly one row, column two must equal `PASS (native)`, and column three must be a repository-relative path under the matching platform directory: `evidence/firefox/`, `evidence/windows/`, `evidence/android/`, or `evidence/macos/`. No two cases may reuse a path. Every component must match `[A-Za-z0-9._-]+`; empty components, `.`, `..`, absolute paths, backslashes, whitespace, shell glob/expansion characters, colons, and control characters remain rejected. Missing or duplicate cases, `PASS (sim)`, FAIL, BLOCKED, and N/A are also rejected. Both the report body and JSON `output` must contain an entire line equal to the exact `AGENTGUARD_ACCEPTANCE_<PLATFORM>=PASS` marker for that kind, and it may be written only after all of these conditions are met.

Acceptance `artifact.sha256` uses `agentguard-acceptance-closure-sha256-v1`. It binds the report's raw bytes and, sorted by path, each unique per-case reference's relative path, length, and file content. Changing the report or any referenced material changes the digest. This closure remains unsigned local self-attestation: it proves only that those bytes were bound together when checked, not that a screenshot, log, or device record came from its claimed source. Trusted provenance still requires a later signed runner or external witness.

The four markers are `AGENTGUARD_ACCEPTANCE_MACOS=PASS`, `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`, `AGENTGUARD_ACCEPTANCE_FIREFOX=PASS`, and `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`.

### Signer identity source

A signing JSON document cannot decide who the trusted publisher is. The strict gate reads the expected identity from external configuration and passes it through the verifier's required `--expected-signer` option:

| `kind` | `signer` format | External expected value |
|---|---|---|
| `macos_codesign`, `macos_notarize` | The same 10-character Apple Team ID | `AGENTGUARD_EXPECTED_MACOS_TEAM_ID` |
| `windows_sign` | The release certificate's 64-character SHA-256 fingerprint | `AGENTGUARD_EXPECTED_WINDOWS_CERT_SHA256` |
| `android_sign` | The release certificate's 64-character SHA-256 fingerprint | `AGENTGUARD_EXPECTED_ANDROID_CERT_SHA256` |

Windows and Android fingerprint input may contain letter case or colons and is normalized to 64 hexadecimal characters before comparison. The JSON `signer`, certificate identity in command output, and external expected value must all identify the same publisher. The four acceptance kinds do not accept an external signer.

Run the following as one line from a Developer PowerShell where `signtool` is configured. Replace both path occurrences and the JSON `artifact.path` together. The command first has `signtool` verify the trust chain, then reads the Authenticode certificate from the same file and prints the separate fingerprint line required by the verifier. Do not write a literal `<fingerprint>` as successful output.

```powershell
signtool verify /pa /v dist/AgentGuard.exe; if (-not $? -or $LASTEXITCODE -ne 0) { exit 1 }; $signature = Get-AuthenticodeSignature dist/AgentGuard.exe; if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { exit 1 }; Write-Output ('CertificateSHA256=' + $signature.SignerCertificate.GetCertHashString('SHA256'))
```

## Generate, complete, and verify

Freeze the candidate commit, confirm that the index and every non-ignored worktree file are clean, and then
generate a deliberately invalid template:

```bash
mkdir -p evidence/firefox
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
cargo run -p guard-cli -- evidence-template --kind acceptance_firefox \
  --commit "$commit" > evidence/firefox/evidence.json
```

The template is only a field checklist and must fail verification until completed. Run real-device acceptance and save the report as `evidence/firefox/report.md`. First execute the manual acceptance check and obtain its unique marker, then compute the report closure through the shared digest entry point. Put the exact command, marker, and digest into JSON before explicit verification:

```bash
target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md \
  evidence/firefox/report.md --repo-root .
# Sole success output: AGENTGUARD_ACCEPTANCE_FIREFOX=PASS

cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/firefox/report.md

cargo run -p guard-cli -- evidence-verify \
  --kind acceptance_firefox \
  --file evidence/firefox/evidence.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root .

export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=evidence/firefox/evidence.json
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

For the other seven kinds, substitute the `kind` and environment variable from the table. Do not point the variable at the verifier itself, an empty directory, or an old-commit report.

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

The strict gate also requires production preflight to contain zero `FAIL` results. Even when all eight JSON documents pass, the result remains **No-Go** if repository fixture keys still have production semantics, an automated gate fails, or signing, notarization, real-device, fresh-install, upgrade, and rollback evidence is incomplete. Formal Apple Team ID, Windows release-certificate SHA-256, and Android release-certificate SHA-256 values are not yet configured, so all four signing checks remain `UNVERIFIED`; complete notarization, device, upgrade, and rollback evidence is also absent. Neither phase closure nor release readiness may therefore be claimed.

# AgentGuard Privacy Notice Draft

[简体中文](privacy-policy.md) | [繁體中文](privacy-policy.zh-TW.md) | [English](privacy-policy.en.md)

The new experimental webmail module is off by default. When enabled, it locally reads recognized subject, body, recipient fields and attachment-presence signals on candidate Gmail/Outlook pages. Mail-specific records retain only fixed risk category, blocked state, time, site origin and the fixed Gmail/Outlook label: no subject/body, addresses, filenames or full links. It does not inspect attachment contents, call mailbox APIs or forward mail data to the desktop. It cannot stop provider draft syncing, direct APIs or other uncovered paths. Turning it off stops mail-specific checks, not existing payment rules.

- **Last updated:** 2026-09-07
- **Product version:** 1.0.0-rc.1
- **Applies to:** macOS, Windows, the Android companion, iOS WebShield/Safari Extension, the first-GA Chrome/Edge Chromium extension, the CLI, and the local API

> This is a technical disclosure draft shipped with the source. It is not a legally reviewed privacy policy. Before public distribution, add the real operator, contact details, applicable jurisdictions, and retention terms.

The Firefox manifest and Native Messaging host remain repository source prototypes only. They are not in the first-GA browser package, store submission, or released-capability scope of this notice. iOS WebShield is a first-release product in scope: it is a separate Xcode/Swift Safari Extension, not a Safari packaging of the Chromium extension.

## Summary

AgentGuard processes observations locally by default. It has no default cloud account, telemetry, or vendor upload service. A user or organization may configure threat-intelligence downloads, policy sync, the Android relay, or the local API; the destination, transport security, and retention of those connections depend on the deployment.

| Data | Leaves the device by default? | Notes |
|---|---|---|
| UI / AX / UIA / Accessibility text | No | Used in memory for local rules; raw text is not written to the durable audit trail by default |
| ScreenCaptureKit / GDI frames | No | Summaries or visual features are derived locally; raw pixels are not uploaded by default |
| Browser DOM signals | No | Scanned inside the extension; limited finding summaries and minimized URLs may be kept in extension-local storage and are not sent to a Native Host or vendor service |
| iOS Safari page events | No | Content rules and the native contract run locally; only rule/action enums, time, and an HTTP(S) URL reduced to its origin are retained, with no default upload |
| Audit database | No | Desktop Release builds require SQLCipher; CLI/development builds may explicitly use plain SQLite |
| Threat intelligence and enterprise policy | Optional download | Accessed only after an operator configures an endpoint; release paths require signature verification |
| Android relay | Optional | The user may configure loopback, ADB reverse, or a LAN address |
| Crash telemetry and advertising tracking | No | The current source candidate includes no default telemetry or advertising SDK |

## Data processed locally

1. Accessibility trees, windows, and form text used to identify payments, excessive disclosure, injection, and suspicious interfaces.
2. Browser DOM signals used to detect hidden text and privacy traps and to block covered payment/submission actions before execution in block-only mode.
3. Frames or frame summaries used for transparent-overlay, low-contrast, steganography, and frame-change checks.
4. Network-flow metadata such as host and approximate size; AgentGuard is not a full packet-capture tool.
5. Audit records such as event type, rule ID, decision, fixed safe summary, and human confirmation result. Durable events use `persistable_event_v1`: booleans, numbers, canonical enums, bounded identifiers, and format-validated digests. URLs retain only scheme and normalized host; non-HTTP(S) URIs retain only their scheme; environment lists become counts. Raw UI/OCR/clipboard text, paths, command operands, URL userinfo/path/query/fragment, free-form reasons, and unknown fields are not stored.
6. Android environment-survey results such as other broadcast receivers or accessibility services that may read input.
7. iOS Safari Extension contract version, random request ID, rule ID, fixed finding/action enums, timestamp, and current URL. Swift validates again and reduces the URL to its HTTP(S) origin before storage; raw DOM, input values, page titles, and URL path/query/fragment are not persisted.

## Typical storage locations

- macOS: `~/Library/Application Support/agentguard/`
- Windows: local audit and configuration files under the application-data directory
- Android: JSONL envelopes, preferences, and Android Keystore keys in the app-private directory
- iOS: atomic JSONL audit and consent/toggle state in App Group `group.com.agentguard.webshield`; retention is at most seven days or 500 rows, users can clear it in the container app, and expired rows are physically removed during coordinated reads
- Chrome/Edge Chromium extension: extension-local storage; recent-record URLs drop userinfo, query, and fragment and redact token-shaped path segments

In Core/desktop audit records, an app source without a format-validated package identifier is stored as a stable SHA-256 pseudonym. External session IDs are also stored only as stable pseudonyms, preserving within-database correlation without retaining the original ID. Hashing is not an anonymity guarantee: low-entropy identifiers may still be guessed, so exported audit files remain sensitive local data.

This minimisation applies to new writes only. Historical rows written by older versions are not rewritten automatically, because doing so would invalidate their existing hash chain and signatures. Treat them as potentially containing raw observations until an approved clear-or-migrate procedure is completed.

Android adapter private keys in Android Keystore are designed to be non-exportable. macOS Release stores the audit passphrase and Ed25519 seed separately in the current user's Keychain; Windows Release uses two current-user DPAPI envelopes. CLI/development paths may still explicitly use a `0600` file-backed signing key, which is exportable by an account or root process that can read it. Keychain/DPAPI provide local at-rest protection, not a Secure Enclave/TPM non-exportability guarantee. Public fixture keys are for tests and evaluation only and must not be used in production.

## Network behavior

- Core rule evaluation does not require internet access by default.
- Threat intelligence and enterprise policies are downloaded only after a user or organization configures an endpoint.
- The local API binds to loopback by default and requires a Bearer token. A LAN bind is allowed only with explicit `--allow-lan`. That exception may use plain HTTP, so the operator must provide a trusted network or additional transport protection.
- The Android relay is explicitly configured by the user; its payload and destination depend on that configuration.
- The first-GA Chrome/Edge extension does not request Native Messaging permission and does not connect to an AgentGuard cloud service. Static DNR matches URL, method, and resource type locally in the browser; it does not inspect HTTPS request bodies.
- iOS WebShield has no upload endpoint, `connectNative` long-lived connection, or remote DNR intelligence. The app and Safari Extension exchange minimized events locally through the App Group/native messaging contract.

## Permissions and controls

- macOS: Accessibility and Screen Recording. Denial reduces coverage and must not be described as full protection.
- Windows: UI Automation, window, and screen observations depend on OS permissions and the target application.
- Android: Accessibility and a visible ordinary ongoing session notification. Risk notifications normally occur after the observed action; they are not a blocking confirmation gate.
- Chrome/Edge: content scripts run on HTTP(S) pages, local storage/notifications are used, and static DNR blocks requests within its declared scope. The in-page notice has only Close and cannot authorize or replay an action.
- iOS: users enable the extension in Safari and grant the relevant website access. Unauthorized frames, closed Shadow DOM, and direct scripted network calls are outside the declared coverage. Users can disable protection or clear local audit data in the container app and revoke site access in Safari settings.
- Users can end sessions, disable optional observation and relays, and delete local databases and reports.

## Current release status

This repository is a source release candidate. Signed installers, store data-safety declarations, legal review, real-device acceptance, and a public support channel are not complete.

## Contact

The source candidate does not yet provide a public privacy contact. A real, monitored contact owned by the operator must be added before public distribution.

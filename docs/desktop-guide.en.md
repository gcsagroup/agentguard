[简体中文](desktop-guide.md) | [繁體中文](desktop-guide.zh-TW.md) | [English](desktop-guide.en.md)

# Desktop guide

## Three distinct paths

| Path | Actual capability | Important limit |
| --- | --- | --- |
| Desktop observation | Detect and record risks in state already presented by apps | Cannot undo an action or guarantee pre-execution blocking |
| Chrome / Edge extension | Block matching clicks, trap submissions and specific payment-shaped requests | Not universal coverage; no in-page allow-once or exceptions |
| MCP tool gateway | Allow, deny or wait for confirmation of calls actually routed through it | Direct execution can bypass it; a handshake does not prove client integration |

The GA browser extension operates independently, without Native Messaging. The desktop app cannot read its status, grant browser permissions or merge all extension records.

## macOS workspace

The September 6, 2026 macOS UI has **Overview, Active protection, Activity, Protection settings, and Help & diagnostics**. Windows retains its existing layout; this change does not claim a Windows UI port.

### Start desktop observation

1. Check Accessibility and the encrypted activity log in Overview. Accessibility is required; Screen Recording adds optional pixel and overlay coverage and is not sufficient by itself.
2. In Protection settings → Desktop observation, open System Settings. Match the exact current app filename shown in Overview and the installation path in diagnostics.
3. Grant permissions yourself, return and recheck. The app also performs read-only checks on focus; it does not grant system access. If macOS requests a restart, quit and reopen that same app.
4. When Accessibility and protected storage are ready, choose a task and start a session. A saved task applies to the next session, not an already running session.
5. End protection stops the session and observers. Readiness is based on the session, actual observers, fresh heartbeats and writable records, not the click itself.

The acceptance channel is consistently named `AgentGuard Test.app`, with identifier `com.agentguard.desktop.macos.acceptance`. A grant for an old Production/Recovery app is not proof of permission for this app. A fixed filename reduces confusion but **does not make ad-hoc signing stable across rebuilds**. Signing and notarization remain release gates; do not reset all system permissions as a workaround.

If storage is unavailable, use its dedicated recovery message. Handle Keychain prompts yourself. Legacy data requires an explicitly confirmed, history-preserving upgrade; deleting the original database is not recovery.

### Four settings tabs

- Desktop observation: live permission state, System Settings links, recheck and next-session task.
- Risk handling: separate desktop, extension and gateway behavior; intelligence version and reload. The gateway's 120-second default is explanatory, not a live readback of an external process or an editable setting.
- Privacy & records: protected local storage, summary export and recovery guidance. Extension and desktop records remain separate; there is no destructive “clear everything” control.
- General: English, Simplified Chinese, Traditional Chinese or system language; light, dark or system appearance. Preferences are local, report save failures and do not change security policy.

## Active protection setup

### Browser extension

Use Active protection → Browser protection → Install & verify to reveal the packaged extension and harmless acceptance resources. This is a **local test package**, not a published store listing.

Install and enable it yourself through the trusted browser extension manager after reviewing permissions. Follow the packaged README to serve the fixture on `127.0.0.1`; a file:// launch is not HTTP-page acceptance. The ordinary counter should increment; the “Pay now” button only changes a local counter and never pays or contacts a payment service. With matching protection working, its counter remains zero. Verify the extension's own record. Desktop status stays “verify in your browser” because there is no connection channel. No in-page exception or replay is available.

### Tool gateway

Use Active protection → AI tool gateway → Configure connection → Check gateway & generate config.

The app launches its own bundled gateway, sends only MCP initialization and tool-list queries, and stops that probe process. It does not invoke tools or modify client configuration. Generated stdio configuration points to the current installation, contains no confirmation token and grants no whole-home workspace access.

Choose your actual MCP client, preserve its existing configuration and merge the service. Review a minimal task/directory scope before granting write access. Restart that client and verify harmless allow, deny, required-confirmation and timeout cases through actual side effects. A successful app probe is not proof that the client uses the gateway.

**Desktop gateway confirmation is now connected.** In Active protection → Gateway confirmations, enter the current process's local port and 32-character token from its local stderr log. Enter the token only in the app, never in chat, reports or web pages. Older gateways without the status endpoint need updating.

Review the current ID, full action, findings and deadline. Deny directly, or check the review box before approving only that request. New requests inherit neither the review checkbox nor the previous receipt. Approval acceptance is not execution success; verify the result in the calling client.

The token input clears on submit and is held only in backend memory for this connection, never in settings. Disconnecting or quitting does not auto-reconnect. A lost connection or expired request disables approval. Manual disconnection does not immediately deny, but unanswered requests eventually time out and deny. An uncertain receipt is not retried and may mean execution already happened; check the caller.

This is separate from desktop “continue monitoring,” connects one gateway process, does not verify a particular client, does not merge gateway history into desktop Activity and cannot override a `Block` decision. See the [gateway technical guide](工具网关.md).

## Records, diagnostics and evidence

Activity shows desktop summaries; the overview omits external body text. Export produces a local summary and reports its path. Build identity, install path, isolated test-data location and developer controls are under Help & diagnostics, with paths collapsed by default.

Desktop self-test feeds a fake local event. It proves rules, reminders and recording, not live observation or prevention of external actions. Check the originating application for the actual outcome; pausing affects subsequent protected handling.

Compilation, UI tests and launching the app do not establish release readiness. Authorized continuous observation, signing, notarization, isolated installation, actual client integration and confirmation flows require separate evidence. Windows, Android, iOS and browser stores retain their own acceptance gates. See [release evidence](release-evidence.en.md).

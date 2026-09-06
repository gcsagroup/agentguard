# AgentGuard Chrome / Edge Extension

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

This is the browser-extension implementation for the first GA. On Chrome and Edge pages it detects hidden prompt injection, unnecessary personal-data fields, privacy traps, and payment or transfer actions. Matching high-risk DOM clicks and submissions are stopped before execution; matching non-GET/HEAD requests to payment-shaped paths are hard-blocked at the network layer by a default-enabled static DNR ruleset.

> The first GA supports Chrome and Edge only. Firefox remains a source prototype: it is not packaged and is not an acceptance gate for the first GA. Safari is a separate Xcode/Swift product line. The GA manifest has no `nativeMessaging` permission, and the release package neither connects to nor includes a Native Messaging host.

## Experimental webmail checks (off by default)

Popup → Mail settings → enable experimental webmail checks. Candidate Gmail/Outlook adapters inspect recognized send, reading and link actions. Selected secrets and unresolved recipients block sending. Attachment contents are not inspected: recognized attachment actions are blocked, with no one-time release or automatic sending.

Mail-specific checks stay local and records omit raw content and addresses. No permission or mailbox API is added. Direct APIs, draft syncing, unknown controls and desktop clients remain outside coverage. Current evidence uses synthetic DOM in real Chromium; actual Gmail/Outlook and Edge acceptance is pending. See [implementation scope and planned design](../../docs/mail-protection-design.en.md).

## Load unpacked

Chrome:

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Choose **Load unpacked** and select `apps/extension-chromium`.

Edge loads the same directory and package from `edge://extensions`. The extension includes `en`, `zh_CN`, and `zh_TW` UI resources and also supports a language override in the popup.

`manifest.firefox.json` is retained only as a future development starting point. For the first GA, do not load it temporarily, package it, submit it to a store, or include it in an acceptance conclusion.

## Package

Run from the repository root:

```bash
./apps/extension-chromium/scripts/package-store.sh
```

This produces `apps/extension-chromium/dist/agentguard-extension.zip` for both Chrome and Edge. The release script rejects `--firefox`. The ZIP contains no Native Messaging host, and the GA manifest does not request `nativeMessaging`.

## Pre-execution blocking

### Page DOM actions

From `document_start`, the browser injects the isolated content script into every HTTP(S) frame it allows the extension to enter. Payment or transfer CTAs and privacy-trap personal-data submissions in those frames are synchronously blocked during capture. The extension **does not offer an in-page “Allow once,” Continue, or replay control**.

Any in-page notice is informational only. A page can delete, cover, imitate, or otherwise influence it, so it is not trusted authorization UI and no click inside the page can change the block decision. If a user understands the risk and still wants to continue, they must first use the browser's trusted extension-management surface (`chrome://extensions` in Chrome or `edge://extensions` in Edge) to disable or remove AgentGuard, then independently repeat the original action. The first GA has no temporary exception.

DOM protection covers only HTTP(S) frames where the browser actually injects the content script and an observable click/submit event occurs. Direct `form.submit()`, uninjected pages or schemes, and script paths that emit no observed event are outside that guarantee. A page can compromise the visibility or authenticity of the information notice, but cannot use that to create release state.

### Static DNR network hard block

The static `payment_shape_block` ruleset blocks only when **all** of these conditions hold:

- the URL is HTTP(S);
- the method is not GET or HEAD;
- either a URL path component starts with an explicitly listed payment marker at the documented character boundary, or the query key `op`, `action`, or `operation` explicitly equals one of those markers: `pay`, `payment`, `checkout`, `charge`, `transfer`, `remit`, `purchase`, `orderconfirm` / `order-confirm` / `order_confirm`, or `confirmorder` / `confirm-order` / `confirm_order`; the path rules also explicitly cover percent-encoded bytes for the core markers and `%2F` separators;
- the browser classifies the request as `xmlhttprequest`, `ping`, `main_frame`, or `sub_frame`.

This covers declared fetch/XHR, sendBeacon, and top/subframe form-navigation cases. It does not inspect request bodies, and it does not cover body-only payment intent, site-specific aliases, encoded or obfuscated forms not explicitly listed, arbitrary query keys or values, WebSocket/WebTransport, GET/HEAD, or unlisted resource types. The ruleset is block-only: there is no in-page approval, scope exception, or one-shot network release.

See [Browser pre-execution blocking](../../docs/浏览器执行前阻断.en.md) for the complete boundary.

## Local data and permissions

- Findings stay in the extension-local recent list and are not uploaded to AgentGuard servers by default.
- Before a URL enters the recent list, userinfo, the fragment, and the entire query are removed, and token-shaped path segments become `…`. This is heuristic and cannot identify every secret.
- The same finding is reported only once per page, so continuous mutation does not create an alert storm. Changed content is a new finding, while scans remain throttled and the fingerprint set remains bounded.
- `storage` keeps settings and recent findings; `declarativeNetRequest` enables the static network rules; `notifications` provides browser-owned information after a DOM action has been blocked; `activeTab` supports active-tab interaction; HTTP(S) host permissions run the content script on pages the user visits.
- The GA manifest has no `nativeMessaging`. Native-host source and templates retained in the repository are not a first-GA capability and must not be used as store-copy or acceptance evidence.

## Verification

```bash
make check-extension-gate
make e2e-extension
```

`check-extension-gate` checks blocking logic, manifests, trilingual strings, and the Chrome/Edge packaging boundary. `e2e-extension` loads the extension into a Chromium test environment and verifies that DOM actions do not execute, legacy decision/scope messages cannot release them, static DNR blocks before requests reach the server, and GET plus ordinary POST are not false-blocked. Passing offline automation does not replace real-browser install, upgrade, permission-prompt, and behavior evidence for the Chrome and Edge store candidates.

## Current release boundary

- First GA: Chrome / Edge, one shared Chromium ZIP, with separate store and real-browser acceptance.
- Firefox: source prototype retained; not packaged, not submitted, and not an acceptance gate for the first GA.
- Native Messaging: completely disabled in the GA manifest; the host is not shipped in the ZIP and retained prototype code is not a GA capability.
- Safari: separate product line, outside this extension's first GA.

See the [privacy policy](../../docs/privacy-policy.en.md), [store listing draft](STORE.en.md), and [cross-browser scope](../../docs/跨浏览器.en.md).

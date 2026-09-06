# Chrome Web Store Listing Draft

[简体中文](STORE.md) · [繁體中文](STORE.zh-TW.md) · English

> **Draft only; not submitted to or approved by the Chrome Web Store.** This copy is not evidence of publication, review, or real-browser acceptance. The first GA targets Chrome / Edge only; the Firefox source prototype is not packaged and is not an acceptance gate.

## Name

AgentGuard Web Shield

## Summary

Stop matching payment or privacy-trap DOM actions before execution and hard-block declared non-read-only payment-path requests, while surfacing hidden prompt injection. Local-first.

## Description

AgentGuard Web Shield provides three bounded protections on Chrome / Edge pages:

- **DOM action blocking:** from `document_start`, the browser injects the content script into every HTTP(S) frame it allows the extension to enter. Payment or transfer clicks and privacy-trap personal-data submissions in those frames are synchronously stopped before execution. There is no in-page “Allow once,” Continue, or replay control.
- **Payment-path network hard block:** default static DNR blocks declared non-GET/HEAD HTTP(S) requests at the browser network layer when Chrome classifies them as `xmlhttprequest`, `ping`, `main_frame`, or `sub_frame`.
- **Page detection:** the extension surfaces hidden or subliminal prompt-injection text, unnecessary personal-data fields, privacy traps, and high-risk CTA text, and keeps results in its local recent list.

An in-page warning is informational only. The page can delete, cover, imitate, or otherwise influence it, so it is not authorization UI and no click inside the page can release a block. If a user understands the risk and still wants to continue, they must first disable or remove AgentGuard in the browser's trusted extension-management surface (`chrome://extensions` or `edge://extensions`), then independently repeat the action. The first GA has no temporary exception.

Static DNR hard-blocks only when all of these conditions hold: the URL is HTTP(S); the method is not GET/HEAD; either a path component begins with `pay`, `payment`, `checkout`, `charge`, `transfer`, `remit`, `purchase`, `orderconfirm` / `order-confirm` / `order_confirm`, or `confirmorder` / `confirm-order` / `confirm_order` at the documented character boundary, or the query key `op`, `action`, or `operation` explicitly equals one of those markers; and the resource type is one of the four listed above. The path rules also explicitly cover percent-encoded bytes for core markers and `%2F` separators. It does not inspect request bodies or cover body-only payment intent, custom aliases, encoded or obfuscated forms not explicitly listed, arbitrary query keys or values, WebSocket/WebTransport, GET/HEAD, or other resource types.

**Honest limits:** DOM blocking covers only HTTP(S) frames where the browser actually injects the content script and an observable click/submit event occurs. Direct `form.submit()`, uninjected pages or schemes, and script paths that emit no observed event are outside that guarantee. A page can affect the visibility or authenticity of the information notice but cannot use it to create release state. Both DOM and static-DNR controls are block-only: there is no in-page approval, scope exception, or one-shot release. The extension does not monitor native apps outside the browser.

## Privacy

- Browsing history and findings are not uploaded to AgentGuard servers by default.
- Matching results stay in the extension-local recent list.
- Locally recorded URLs are minimized: userinfo, fragment, and the entire query are removed, and token-shaped path segments become `…`. This is heuristic; short tokens or secrets embedded in ordinary text may not be recognized.
- The GA manifest does not request `nativeMessaging`, and the extension does not connect to a local host. Native-host source and templates retained in the repository are not a first-GA capability and are not shipped in the store ZIP.
- See the [privacy policy](../../docs/privacy-policy.en.md).

## Permission justification

- `storage`: stores settings and the local recent-findings buffer.
- `declarativeNetRequest`: enables the declared static payment-path network hard block by default.
- `notifications`: shows browser-owned information after a DOM action has been blocked; it is not an authorization surface.
- `activeTab`: supports extension interaction associated with the active tab.
- `http://*/*`, `https://*/*`: runs the content script and inspects the DOM on HTTP(S) pages the user visits.

`nativeMessaging` is explicitly absent from the GA manifest. The first GA does not claim Native-host verdicts, dynamic host lists, or a local audit-chain capability.

## Package

```bash
./apps/extension-chromium/scripts/package-store.sh
```

This command produces the shared Chrome / Edge ZIP. The release script rejects `--firefox`; the ZIP contains neither a Firefox manifest nor a Native Messaging host.

## Current release status

- Not submitted to the Chrome Web Store or Microsoft Edge Add-ons.
- Chrome and Edge still require separate real-browser evidence for store-candidate installation, upgrade, permission prompts, and pre-execution behavior.
- Firefox remains a source prototype; it is not packaged, submitted, or an acceptance gate for the first GA.
- Native Messaging is completely disabled in the GA manifest; retained prototype components are not a shipping capability.
- Safari is a separate product line outside this extension's first GA.

See the [Chrome / Edge Extension README](README.en.md) for technical details.

# iOS limited SKU

## What we ship
- Web / Safari session guidance aligned with Chromium Web Shield heuristics
- Aura-lite `guard-shell` policy for first-party agent wrappers
- Enterprise policy pull (`guard-sync`) via MDM / managed config — 生产用 `pull_policy_verified`(带外机构公钥验证 Ed25519 分离签名),明文 http 被拒;未签名的 `pull_policy` 仅供本地/开发,不认证

## What we do not ship
- System-wide Accessibility monitoring of other Agent apps
- Screen recording of arbitrary apps for overlay OCR
- Claims of “full AgentGuard companion” on iOS

## Suggested package
`apps/ios-webshield/` — future WKWebView wrapper; not required for v1.0 desktop/Android track.

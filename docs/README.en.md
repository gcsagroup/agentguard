[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

<p align="center">
  <img src="../assets/brand/agentguard-logo.png" alt="AgentGuard logo" width="120">
</p>

# AgentGuard documentation portal

This portal is the trilingual entry point. Trilingual coverage includes the root README, this portal, the `1.0.0-rc.1` release notes, the changelog, privacy disclosures, component READMEs, primary store copy, and the seven technical and five acceptance documents maintained in this update. Other deep technical and audit documents remain in their original languages and are labeled below by purpose and status.

> `1.0.0-rc.1` is a source release candidate. Code signing, notarization, store publication, and real-device end-to-end acceptance evidence are incomplete. The production release decision remains **No-Go**.

## Status labels

- **Core entry point**: a current summary maintained in all three languages.
- **Technical reference**: implementation or threat-model detail, not production-release evidence.
- **Needs reconciliation**: contains historical figures, appended corrections, or fields that still need replacement; verify against code and generated reports before citing it.
- **Draft**: store, privacy, or release-preparation material that is not ready to publish as-is.
- **Historical/internal**: review, plan, or iteration history that does not define the current product promise.
- **Generated report**: must be regenerated on the current commit before it can serve as evidence.

## Core trilingual entry points

- [Project README (Simplified Chinese)](../README.md) · [繁體](../README.zh-TW.md) · [English](../README.en.md)
- [1.0.0-rc.1 release notes (Simplified Chinese)](RELEASE-1.0.0-rc.1.md) · [繁體](RELEASE-1.0.0-rc.1.zh-TW.md) · [English](RELEASE-1.0.0-rc.1.en.md)
- [2026-09-01 real-device acceptance report (Simplified Chinese)](acceptance-report-2026-09-01.md) · [繁體](acceptance-report-2026-09-01.zh-TW.md) · [English](acceptance-report-2026-09-01.en.md) — Historical snapshot separating `bd7bb2f` from the integration candidate that was uncommitted at the time. It does not prove real-device acceptance for this commit; the release decision remains No-Go.
- [Changelog (Simplified Chinese)](../CHANGELOG.md) · [繁體](../CHANGELOG.zh-TW.md) · [English](../CHANGELOG.en.md)
- [Privacy disclosure (Simplified Chinese)](privacy-policy.md) · [繁體](privacy-policy.zh-TW.md) · [English](privacy-policy.en.md)

## Trilingual technical and acceptance documents maintained in this update

- [Inbound trust (Simplified Chinese)](入站信任.md) · [繁體](入站信任.zh-TW.md) · [English](入站信任.en.md) — Shared trust principles, vocabulary, and an inventory test for six inbound surfaces.
- [Capability claim-to-test mapping (Simplified Chinese)](主张与测试映射.md) · [繁體](主张与测试映射.zh-TW.md) · [English](主张与测试映射.en.md) — Initial capability claims, proof tests, and a generated status dashboard; not a substitute for real-device evidence.
- [Browser pre-execution gates (Simplified Chinese)](浏览器执行前阻断.md) · [繁體](浏览器执行前阻断.zh-TW.md) · [English](浏览器执行前阻断.en.md) — Page gates, DNR, blocklist management and provenance, plus asynchronous Native Host and fail-open boundaries.
- [Cross-browser support (Simplified Chinese)](跨浏览器.md) · [繁體](跨浏览器.zh-TW.md) · [English](跨浏览器.en.md) — The Firefox port, Edge compatibility, and Safari design boundary.
- [Consumerized interface (Simplified Chinese)](消费者化界面.md) · [繁體](消费者化界面.zh-TW.md) · [English](消费者化界面.en.md) — Plain-language trilingual UI, first-run onboarding, accessibility, keyboard use, and dark mode.
- [macOS real-time observation (Simplified Chinese)](macos实时观测.md) · [繁體](macos实时观测.zh-TW.md) · [English](macos实时观测.en.md) — AXObserver push and coalescing, with pixel-sampling, fallback-polling, and real-device-unverified boundaries.
- [Structured release evidence (Simplified Chinese)](release-evidence.md) · [繁體](release-evidence.zh-TW.md) · [English](release-evidence.en.md) — Commit and artifact binding for eight evidence kinds, template and verification commands, and the unsigned-attestation boundary.
- [Real-device acceptance runbook (Simplified Chinese)](acceptance-runbook.md) · [繁體](acceptance-runbook.zh-TW.md) · [English](acceptance-runbook.en.md) — Executable steps and evidence rules, not completed acceptance.
- [Real-device acceptance report template (Simplified Chinese)](acceptance-report-template.md) · [繁體](acceptance-report-template.zh-TW.md) · [English](acceptance-report-template.en.md) — Per-platform PASS, FAIL, and BLOCKED recording.
- [Firefox acceptance checklist (Simplified Chinese)](acceptance-firefox.md) · [繁體](acceptance-firefox.zh-TW.md) · [English](acceptance-firefox.en.md) — Firefox 128+, DNR quota, and gecko-id Native Messaging real-device checks.
- [Windows acceptance checklist (Simplified Chinese)](acceptance-windows.md) · [繁體](acceptance-windows.zh-TW.md) · [English](acceptance-windows.en.md) — UIA, GDI, OCR, capability-probe, and Native Messaging real-device checks.
- [macOS acceptance checklist (Simplified Chinese)](acceptance-macos.md) · [繁體](acceptance-macos.zh-TW.md) · [English](acceptance-macos.en.md) — Strict PASS/BLOCKED boundaries for SCK, AX, TCC, and native cases.

## Release, platform, and operations

- [release-security.md](release-security.md) — Original language: mixed Chinese and English; status: historical gate-design note; use the trilingual Structured Release Evidence document for the current format.
- [platform-matrix.md](platform-matrix.md) — Original language: primarily English; status: platform reference whose real-device state must be read with the release notes.
- [status-dashboard.html](status-dashboard.html) — A generated Simplified-Chinese machine view of capability claims and gate data; this English portal carries the translated conclusion. Regenerate it on the current commit, and do not treat it as real-device evidence.
- [macos-release.md](macos-release.md) — Original language: Simplified Chinese; status: signing, notarization, and packaging guide, not proof of execution.
- [roadmap-status.md](roadmap-status.md) — Original language: primarily English; status: needs reconciliation because some metrics and completed boxes are historical snapshots.
- [privacy-policy.md](privacy-policy.md) — Trilingual technical-disclosure draft; legal review and real contact details are still required before publication.
- [store-listing-cws.md](store-listing-cws.md) — Trilingual compatibility entry point for the Chromium store-copy drafts.
- [store-listing-macos.md](store-listing-macos.md) — Trilingual compatibility entry point for the macOS store-copy drafts.
- [i18n.md](i18n.md) — Original language: English; status: client internationalization reference.
- [intro.html](intro.html) — Original languages: Simplified Chinese and English; status: needs reconciliation, historical figures require revalidation, and no Traditional Chinese body is present.

## Architecture, adapters, and runtime interfaces

- [architecture.md](architecture.md) — Original language: mixed Chinese and English; status: technical reference.
- [android-completeness.md](android-completeness.md) — Original language: primarily English; status: Android capability and gap reference.
- [android-env-survey.md](android-env-survey.md) — Original language: English; status: Android environment-survey reference.
- [windows-observation.md](windows-observation.md) — Original language: English; status: Windows implementation reference with no real-device end-to-end acceptance.
- [ios-limited-sku.md](ios-limited-sku.md) — Original language: primarily English; status: limited scaffold description, not a complete product.
- [local-api.md](local-api.md) — Original language: mixed Chinese and English; status: local API reference.
- [billing.md](billing.md) — Original language: mixed Chinese and English; status: billing and entitlement reference.
- [sck-bridge.md](sck-bridge.md) — Original language: primarily English; status: ScreenCaptureKit integration reference.
- [safe-shell.md](safe-shell.md) — Original language: mixed Chinese and English; status: cooperative command-decision reference, not a general sandbox.
- [interception-design.md](interception-design.md) — Original language: mixed Chinese and English; status: needs reconciliation because pre-implementation prose and later implemented status coexist.
- [scope-and-non-goals.md](scope-and-non-goals.md) — Original language: mixed Chinese and English; status: current capability-boundary and non-goals reference.

## Audit, identity, and information flow

- [audit-signing.md](audit-signing.md) — Original language: mixed Chinese and English; status: signed-audit technical reference.
- [audit-encryption.md](audit-encryption.md) — Original language: mixed Chinese and English; status: SQLCipher technical reference.
- [agent-identity.md](agent-identity.md) — Original language: English; status: session-level agent identity and limitation reference.
- [app-identity.md](app-identity.md) — Original language: English; status: application signing-identity reference.
- [app-lookalike.md](app-lookalike.md) — Original language: primarily English; status: application-lookalike detection reference.
- [information-flow.md](information-flow.md) — Original language: English; status: information-flow labeling and declassification reference.
- [semantic-firewall.md](semantic-firewall.md) — Original language: English; status: structured-entity and context-isolation reference.
- [session-scope.md](session-scope.md) — Original language: English; status: session least-privilege reference.
- [trajectory-alignment.md](trajectory-alignment.md) — Original language: English; status: plan-trajectory alignment reference.
- [log-hygiene.md](log-hygiene.md) — Original language: primarily English; status: log-redaction and boundary reference.

## Vision, text, and evaluation methodology

- [frame-integrity.md](frame-integrity.md) — Original language: mixed Chinese and English; status: frame-digest and tampering reference.
- [text-anomalies.md](text-anomalies.md) — Original language: English; status: text-anomaly heuristic reference.
- [eval-methodology.md](eval-methodology.md) — Original language: English; status: evaluation-method reference.
- [leaderboard-comparability.md](leaderboard-comparability.md) — Original language: English; status: leaderboard-comparability reference.
- [myphonebench-mapping.md](myphonebench-mapping.md) — Original language: primarily English; status: research mapping reference.
- [paper-gap-improvements.md](paper-gap-improvements.md) — Original language: English; status: historical research-gap and improvement record.
- [paper-gap-iter6-review.md](paper-gap-iter6-review.md) — Original language: English; status: historical review record.
- [Attack-surface coverage matrix](../eval/coverage-matrix.md) — Original language: English; status: generated report that must be regenerated on the current commit before release.

## Simplified-Chinese implementation notes

- [路径模型.md](路径模型.md) — Status: filesystem path-decision reference.
- [工具网关.md](工具网关.md) — Status: cooperative MCP gateway reference.
- [内核约束.md](内核约束.md) — Status: Linux `guard-jail` and backend-boundary reference.
- [适配器断言签名.md](适配器断言签名.md) — Status: adapter-signing and asymmetric-trust reference.

## Historical and internal material

The following files preserve the audit trail but do not replace the current README, release notes, or strict release gate:

- [上线评估.md](上线评估.md), [发布阻塞项.md](发布阻塞项.md)
- [第五轮复核.md](第五轮复核.md), [第六轮复核.md](第六轮复核.md), [第七轮复核-文档与实现差距.md](第七轮复核-文档与实现差距.md)
- [开发计划-文档实现差距修复.md](开发计划-文档实现差距修复.md), [第二类全做.md](第二类全做.md)

## Entry points outside docs

- [Threat Intel README (Simplified Chinese)](../intel/README.md) · [繁體](../intel/README.zh-TW.md) · [English](../intel/README.en.md)
- Component READMEs: [macOS](../apps/desktop-macos/README.en.md), [Windows](../apps/desktop-windows/README.en.md), [Android](../apps/android-companion/README.en.md), [Chromium](../apps/extension-chromium/README.en.md), and [iOS WebShield](../apps/ios-webshield/README.en.md). Each entry point links to Simplified Chinese, Traditional Chinese, and English.

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

<p align="center">
  <img src="../assets/brand/agentguard-logo.png" alt="AgentGuard 標誌" width="120">
</p>

# AgentGuard 文件入口

本入口提供三語導覽。目前三語覆蓋根 README、本入口、`1.0.0-rc.1` 發佈說明、CHANGELOG、隱私說明、各元件 README 與主要商店文案；深層技術與稽核文件保留原始語言，並在下方標明用途與狀態。

> `1.0.0-rc.1` 是原始碼候選版。程式碼簽署、公證、商店發佈與真實裝置端對端驗收證據尚未完成，正式環境發佈判斷仍為 **No-Go**。

## 狀態說明

- **核心入口**：本次維護的目前三語摘要。
- **技術參考**：描述實作或威脅模型，不等於正式環境發佈證據。
- **需對齊**：含歷史數字、追加式更正或待替換欄位，引用前應核對程式碼與產生報告。
- **草稿**：用於商店、隱私或發佈準備，不能直接視為已發佈材料。
- **歷史/內部**：複核、計畫或迭代記錄，不代表目前產品承諾。
- **產生報告**：必須在目前提交上重新產生後才能作為證據。

## 核心三語入口

- [專案 README（簡體）](../README.md) · [繁體](../README.zh-TW.md) · [English](../README.en.md)
- [1.0.0-rc.1 發佈說明（簡體）](RELEASE-1.0.0-rc.1.md) · [繁體](RELEASE-1.0.0-rc.1.zh-TW.md) · [English](RELEASE-1.0.0-rc.1.en.md)
- [CHANGELOG（簡體）](../CHANGELOG.md) · [繁體](../CHANGELOG.zh-TW.md) · [English](../CHANGELOG.en.md)
- [隱私說明（簡體）](privacy-policy.md) · [繁體](privacy-policy.zh-TW.md) · [English](privacy-policy.en.md)

## 發佈、平台與維運

- [release-security.md](release-security.md) — 原始語言：中英混合；狀態：發佈證據閘門參考。
- [platform-matrix.md](platform-matrix.md) — 原始語言：英文為主；狀態：平台能力參考，真實裝置狀態須結合發佈說明。
- [acceptance-macos.md](acceptance-macos.md) — 原始語言：簡體中文；狀態：驗收清單，不是已完成證據。
- [macos-release.md](macos-release.md) — 原始語言：簡體中文；狀態：簽署、公證與封裝指南，不是已執行證明。
- [roadmap-status.md](roadmap-status.md) — 原始語言：英文為主；狀態：需對齊，部分指標與完成勾選是歷史快照。
- [privacy-policy.md](privacy-policy.md) — 三語技術揭露草稿；公開前仍需法務複核並補真實聯絡資訊。
- [store-listing-cws.md](store-listing-cws.md) — 三語相容入口，指向 Chromium 商店文案草稿。
- [store-listing-macos.md](store-listing-macos.md) — 三語相容入口，指向 macOS 商店文案草稿。
- [i18n.md](i18n.md) — 原始語言：英文；狀態：客戶端國際化技術參考。
- [intro.html](intro.html) — 原始語言：簡體中文與英文；狀態：需對齊，歷史指標必須重新驗證，尚無繁體正文。

## 架構、介接器與執行介面

- [architecture.md](architecture.md) — 原始語言：中英混合；狀態：技術參考。
- [android-completeness.md](android-completeness.md) — 原始語言：英文為主；狀態：Android 能力與缺口參考。
- [android-env-survey.md](android-env-survey.md) — 原始語言：英文；狀態：Android 環境調查技術參考。
- [windows-observation.md](windows-observation.md) — 原始語言：英文；狀態：Windows 實作參考，尚無真實裝置端對端驗收。
- [ios-limited-sku.md](ios-limited-sku.md) — 原始語言：英文為主；狀態：有限骨架說明，不是完整產品。
- [local-api.md](local-api.md) — 原始語言：中英混合；狀態：本機 API 技術參考。
- [billing.md](billing.md) — 原始語言：中英混合；狀態：計費與授權技術參考。
- [sck-bridge.md](sck-bridge.md) — 原始語言：英文為主；狀態：ScreenCaptureKit 接線參考。
- [safe-shell.md](safe-shell.md) — 原始語言：中英混合；狀態：協作式命令判決參考，不是通用沙箱。
- [interception-design.md](interception-design.md) — 原始語言：中英混合；狀態：需對齊，正文同時保留設計前敘述與後續已實作狀態。
- [scope-and-non-goals.md](scope-and-non-goals.md) — 原始語言：中英混合；狀態：目前能力邊界與非目標參考。

## 稽核、身分與資訊流

- [audit-signing.md](audit-signing.md) — 原始語言：中英混合；狀態：簽署稽核技術參考。
- [audit-encryption.md](audit-encryption.md) — 原始語言：中英混合；狀態：SQLCipher 技術參考。
- [agent-identity.md](agent-identity.md) — 原始語言：英文；狀態：工作階段層級 Agent 身分與限制參考。
- [app-identity.md](app-identity.md) — 原始語言：英文；狀態：應用程式簽章身分參考。
- [app-lookalike.md](app-lookalike.md) — 原始語言：英文為主；狀態：應用程式外觀仿冒偵測參考。
- [information-flow.md](information-flow.md) — 原始語言：英文；狀態：資訊流標籤與降級參考。
- [semantic-firewall.md](semantic-firewall.md) — 原始語言：英文；狀態：結構化實體與上下文隔離參考。
- [session-scope.md](session-scope.md) — 原始語言：英文；狀態：工作階段最小權限參考。
- [trajectory-alignment.md](trajectory-alignment.md) — 原始語言：英文；狀態：計畫與軌跡對齊參考。
- [log-hygiene.md](log-hygiene.md) — 原始語言：英文為主；狀態：記錄脫敏與邊界參考。

## 視覺、文字與評測方法

- [frame-integrity.md](frame-integrity.md) — 原始語言：中英混合；狀態：畫面摘要與竄改偵測參考。
- [text-anomalies.md](text-anomalies.md) — 原始語言：英文；狀態：文字異常啟發式參考。
- [eval-methodology.md](eval-methodology.md) — 原始語言：英文；狀態：評測方法參考。
- [leaderboard-comparability.md](leaderboard-comparability.md) — 原始語言：英文；狀態：排行榜可比性參考。
- [myphonebench-mapping.md](myphonebench-mapping.md) — 原始語言：英文為主；狀態：研究對應參考。
- [paper-gap-improvements.md](paper-gap-improvements.md) — 原始語言：英文；狀態：歷史研究差距與改進記錄。
- [paper-gap-iter6-review.md](paper-gap-iter6-review.md) — 原始語言：英文；狀態：歷史複核記錄。
- [攻擊面覆蓋矩陣](../eval/coverage-matrix.md) — 原始語言：英文；狀態：產生報告，發佈前必須在目前提交上重新產生。

## 簡體中文實作說明

- [路径模型.md](路径模型.md) — 狀態：檔案系統路徑判決技術參考。
- [工具网关.md](工具网关.md) — 狀態：協作式 MCP 閘道技術參考。
- [内核约束.md](内核约束.md) — 狀態：Linux `guard-jail` 與後端邊界參考。
- [适配器断言签名.md](适配器断言签名.md) — 狀態：介接器簽章與不對稱信任參考。

## 歷史與內部材料

以下文件保留稽核軌跡，但不能替代目前 README、發佈說明或嚴格發佈閘門：

- [上线评估.md](上线评估.md)、[发布阻塞项.md](发布阻塞项.md)
- [第五轮复核.md](第五轮复核.md)、[第六轮复核.md](第六轮复核.md)、[第七轮复核-文档与实现差距.md](第七轮复核-文档与实现差距.md)
- [开发计划-文档实现差距修复.md](开发计划-文档实现差距修复.md)、[第二类全做.md](第二类全做.md)

## 儲存庫外層入口

- [Threat Intel README（簡體）](../intel/README.md) · [繁體](../intel/README.zh-TW.md) · [English](../intel/README.en.md)
- 元件 README：[macOS](../apps/desktop-macos/README.zh-TW.md)、[Windows](../apps/desktop-windows/README.zh-TW.md)、[Android](../apps/android-companion/README.zh-TW.md)、[Chromium](../apps/extension-chromium/README.zh-TW.md)、[iOS WebShield](../apps/ios-webshield/README.zh-TW.md)；每個入口均可切換簡體、繁體與英文。

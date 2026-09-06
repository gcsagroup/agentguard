[简体中文](remediation-publication-2026-09-06.md) | [繁體中文](remediation-publication-2026-09-06.zh-TW.md) | [English](remediation-publication-2026-09-06.en.md)

# 跨平台整改原始碼提交說明（2026-09-06）

本次整理先前跨平台整改、macOS 新工作區與經驗證的閘道確認接線。**這是原始碼審查候選，不是安裝套件發佈；正式環境仍為 No-Go。** 本機原始報告、截圖、裝置識別碼、憑證、建置產物與測試資料不隨原始碼上傳。

## 主要變化與使用

- 共用引擎、路徑判定、待確認生命週期、加密／簽署稽核恢復與結構化發佈門禁。
- macOS 五頁工作區、四標籤設定與接入引導；輔助使用必需，錄影選用。閘道批准與桌面事後提醒分開，綁定程序及目前請求，過期、重複、錯號或斷連不自動批准。
- Windows 觀察與資源接線、Android 工作階段／隱私狀態、受限 iOS Safari WebShield 工程，以及各平台測試與發佈界線。
- Chrome/Edge 獨立 block-only 擴充功能與靜態 DNR，沒有網頁內允許一次、重播或 GA Native Messaging；Firefox 僅保留原始碼原型。

操作見[桌面說明](desktop-guide.zh-TW.md)。App 可檢查隨附閘道並產生設定，不改寫既有 MCP 用戶端。取得執行中閘道的本機連接埠和本次權杖後，在 App 連接並核對、拒絕或僅批准目前請求。權杖不儲存、不自動重連。批准回執不是執行成功，結果須在呼叫端確認。

寫入請求顯示目標與位元組數，不展示完整檔案正文；尚未提供經驗證的呼叫端身分或統一閘道歷史頁。這是協作式保護，不是不可繞過的系統邊界。

## 驗證

提交整合前，最終本機 arm64／SQLCipher／ad-hoc App 已實際操作：拒絕不產生檔案、批准後才寫入、逾時與中斷未產生檔案。發起端是專用真實 stdio 測試用戶端，不代表使用者的 MCP 用戶端已接入；權限與簽署證據不能轉移到重新建置的身分。

獨立提交工作區重新執行 Rust workspace、macOS 後端、62 項介面渲染、桌面彈層、擴充功能、Android Debug/Release 單測與 lint、iOS 模擬器及無簽署建置。實際結果以 PR 和該提交 CI 為準，靜態測試數不等於通過數。

```bash
./scripts/bootstrap-rust.sh -- cargo test --workspace --locked
make check-shells check-extension-gate
node eval/ui-preview/workspace.test.mjs
make shell-a11y
make check-android
make check-ios
```

使用倉庫要求的 Rust、Node 22、JDK 21 和平台 SDK。Playwright 渲染明確使用後端替身；真實閘道副作用測試需先建置 `agentguard-mcp`，設定 `AGENTGUARD_GATEWAY_TEST_BIN`，再執行 macOS 後端 `gateway_confirm` 的 `--include-ignored` 測試。CI 已接入兩者。

指定 MCP 用戶端、最終簽署身分的連續桌面觀察、正式簽署／公證、真機 Safari／TestFlight、安裝升級回復及渠道驗收仍待完成。無簽署裝置建置不等於裝置執行；Windows 歷史互動不等於目前候選驗收。見[發佈證據](release-evidence.zh-TW.md)。

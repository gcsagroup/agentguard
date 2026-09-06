# AgentGuard macOS

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

這是 AgentGuard 的 Tauri 2 選單列用戶端。它透過 AXUIElement、ScreenCaptureKit 與本機規則引擎觀察受保護工作階段，並提供狀態、稽核和合作式 Critical Confirm。

## 本機執行

```bash
cd apps/desktop-macos
npm ci
npm run tauri dev
```

桌面觀察需要使用者自行授予「輔助使用」；「螢幕錄製」為選用補充。加密記錄或必要權限未就緒時不能開始，不能把模擬或部分觀測描述為完整保護。

五頁工作區與四標籤設定的操作見[桌面說明](../../docs/desktop-guide.zh-TW.md)。主動防護頁提供瀏覽器設定、MCP 設定產生與經驗證的本機閘道確認，不自動修改用戶端設定。見[本輪整改說明](../../docs/remediation-publication-2026-09-06.zh-TW.md)。

## 能力邊界

- AXUIElement 樹變化採用 AXObserver 推送並保留 3 秒備援；ScreenCaptureKit 像素仍按 1.5 秒取樣，因此不是零間隙即時攔截。
- 只有經過合作式閘道的操作可以在執行前等待確認；直接執行可繞過閘道。
- 除錯建置、自動化測試或成功啟動不代表已完成 Developer ID 簽章、公證與真實裝置端對端驗收。
- 預設設定不啟用 updater；啟用前必須替換公鑰與更新端點預留值。

## 驗證與發布

```bash
../../scripts/bootstrap-rust.sh --install
../../scripts/bootstrap-rust.sh -- cargo test --manifest-path src-tauri/Cargo.toml --locked
node --check src/main.js
AGENTGUARD_ALLOW_ADHOC=1 ./scripts/build-release.sh  # 僅本機 smoke
```

Release 必須明確啟用 `audit-sqlcipher`；缺少該 feature 會在編譯期失敗。發布腳本固定使用
`--no-default-features --features audit-sqlcipher --locked`，不再提供明文 Release override。
正式腳本預設產生 Apple Silicon + Intel universal `.app`，從套件內載入安全資源，並將稽核加密密語與簽章種子
分別存入 Keychain。可散布建置必須提供 Developer ID、預期 Team ID 與 `notarytool` Keychain profile；
ad-hoc 僅供本機 smoke，不代表 TCC 身分穩定、Gatekeeper 或公證通過。

發布步驟與未完成證據見 [`../../docs/macos-release.md`](../../docs/macos-release.md) 和 [`../../docs/RELEASE-1.0.0-rc.1.zh-TW.md`](../../docs/RELEASE-1.0.0-rc.1.zh-TW.md)。

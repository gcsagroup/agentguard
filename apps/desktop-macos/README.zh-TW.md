# AgentGuard macOS

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

這是 AgentGuard 的 Tauri 2 選單列用戶端。它透過 AXUIElement、ScreenCaptureKit 與本機規則引擎觀察受保護工作階段，並提供狀態、稽核和合作式 Critical Confirm。

## 本機執行

```bash
cd apps/desktop-macos
npm ci
npm run tauri dev
```

首次執行需要使用者自行授予「輔助使用」與「螢幕錄製」權限。缺少權限時用戶端必須顯示降級狀態，不能把模擬或部分觀測描述為完整保護。

## 能力邊界

- AXUIElement 與 ScreenCaptureKit 原生橋接已實作；觀測採用輪詢，不是即時攔截。
- 只有經過合作式閘道的操作可以在執行前等待確認；直接執行可繞過閘道。
- 除錯建置、自動化測試或成功啟動不代表已完成 Developer ID 簽章、公證與真實裝置端對端驗收。
- 預設設定不啟用 updater；啟用前必須替換公鑰與更新端點預留值。

## 驗證與發布

```bash
cargo test --manifest-path src-tauri/Cargo.toml
node --check src/main.js
```

發布步驟與未完成證據見 [`../../docs/macos-release.md`](../../docs/macos-release.md) 和 [`../../docs/RELEASE-1.0.0-rc.1.zh-TW.md`](../../docs/RELEASE-1.0.0-rc.1.zh-TW.md)。

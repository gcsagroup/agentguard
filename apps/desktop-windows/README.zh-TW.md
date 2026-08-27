# AgentGuard Windows

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

這是 AgentGuard 的 Tauri 2 Windows 用戶端。它接入 Windows UI Automation、GDI 視窗擷取和 `Windows.Media.Ocr`，把觀測事件交給本機規則引擎與稽核層。

## 本機執行

```powershell
cd apps/desktop-windows
npm ci
npm run tauri dev
```

## 目前狀態

- 原生 UIA、視窗擷取與 OCR 程式碼已實作，並在 Windows CI 中編譯與測試。
- 尚未完成代表性 Windows 真機、RDP、權限變化與程式碼簽章驗收，因此不能把 CI 建置稱為正式發布證明。
- 觀測採用約 2.5 秒輪詢，不是即時監控；Critical Confirm 只約束經過合作式入口的操作。
- 目前沒有完整的系統匣、開機恢復與通知生命週期閉環。

## 驗證

```powershell
cargo test --manifest-path src-tauri/Cargo.toml
node --check src/main.js
```

平台能力與限制見 [`../../docs/windows-observation.md`](../../docs/windows-observation.md) 和 [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md)。

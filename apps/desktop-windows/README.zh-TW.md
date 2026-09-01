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

- 候選版 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在 Windows 11 build 26200 上完成 RDP 互動驗證：閒置執行超過 30 秒，兩輪會話各超過 30 秒；UIA、GDI 和 OCR 可用，並實際觸發 `OVL-010` 阻擋。
- 桌面測試 5/5、Clippy、Release 建置和 CI 視窗啟動 smoke 均通過。
- 候選產物仍未簽章，預設 Release 未包含 SQLCipher；安裝/升級/卸載、權限失敗分支、Native Messaging 和完整 W1–W7 仍未驗證，生產發布結論仍為 **No-Go**。
- 觀測採用約 2.5 秒輪詢，不是即時監控；Critical Confirm 只約束經過合作式入口的操作。
- 目前沒有完整的系統匣、開機恢復與通知生命週期閉環。

## 驗證

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path src-tauri/Cargo.toml --release --locked
node --check src/main.js
```

完整的 Windows 真機補充報告：[簡體中文](../../docs/acceptance-report-windows-2026-09-02.md) | [繁體中文](../../docs/acceptance-report-windows-2026-09-02.zh-TW.md) | [English](../../docs/acceptance-report-windows-2026-09-02.en.md)。平台能力與限制見 [`../../docs/windows-observation.md`](../../docs/windows-observation.md) 和 [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md)。

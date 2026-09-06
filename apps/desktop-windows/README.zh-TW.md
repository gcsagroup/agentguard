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

- 歷史候選 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 曾在 Windows 11 build 26200 上完成 RDP 互動 smoke：閒置執行超過 30 秒，兩輪工作階段各超過 30 秒；UIA、GDI 和 OCR 可用，並顯示 `OVL-010` 事後風險確認。該紀錄只證明 `effect=observed_only`、`external_action_blocked=false` 的觀察路徑，不是目前候選驗收，也不證明外部動作被阻擋。
- 桌面測試 5/5、Clippy、Release 建置和 CI 視窗啟動 smoke 均通過。
- 歷史候選產物仍未簽章且未包含 SQLCipher。目前原始碼已改為「Release 缺 `audit-sqlcipher` 就編譯失敗」，但新的安全 Release、簽章、安裝/升級/解除安裝、權限失敗分支和 `first-ga-v1` 的 W1–W6/W8–W11 仍待 Windows 真機驗證，生產發布結論仍為 **No-Go**。W7 Native Messaging 是非 GA／舊版可選項，不得為它向首個 GA 瀏覽器套件加回權限。
- Windows Release 的稽核現在必須同時具備 SQLCipher 與預檢可用的簽章器。自動產生的資料庫口令與 Ed25519 簽章種子分別只以目前使用者 `agentguard-dpapi-v1` / `agentguard-signing-dpapi-v1` envelope 落盤；這不是 TPM。舊明文資料庫、WAL/SHM、`audit.key` 與 `audit-signing.key` 都不會自動改寫；應用會保留原檔並阻擋，等待明確選擇清除或遷移。
- 首個 GA 不發布 Windows gateway 的 `run_shell` / 檔案副作用工具：工具清單不宣告，偽造呼叫也會在任何副作用前失敗關閉。這是避免 junction/reparse/hard-link TOCTOU 的功能收窄，不是主機層級保護；繞過合作式 gateway 的直接執行仍不受它約束。
- 觀測採用約 2.5 秒輪詢，不是即時監控；Critical Confirm 只約束經過合作式入口的操作。
- 目前沒有完整的系統匣、開機恢復與通知生命週期閉環。

## 驗證

```powershell
bash ../../scripts/bootstrap-rust.sh --install
bash ../../scripts/bootstrap-rust.sh -- cargo test --manifest-path src-tauri/Cargo.toml --locked
bash ../../scripts/bootstrap-rust.sh -- cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
node --check src/main.js
bash scripts/build-release.sh
```

`scripts/build-release.sh` 透過儲存庫釘住的 Rust 1.95.0 執行 `npm ci` 與 Tauri 建置，並固定
`--no-default-features --features audit-sqlcipher --locked`。直接執行未帶該 feature 的
`cargo build --release` 會依設計在編譯期失敗；腳本產物仍需正式程式碼簽章與真機驗收。
真機驗收還必須涵蓋兩種 envelope 的 DPAPI 目前使用者綁定、正確/錯誤密鑰、舊明文簽章種子原樣阻擋、
DB/WAL/SHM canary、
中斷復原與升級/回滾；macOS 上的交叉編譯和 SQLCipher 單元測試不能取代這些證據。

完整的 Windows 真機補充報告：[簡體中文](../../docs/acceptance-report-windows-2026-09-02.md) | [繁體中文](../../docs/acceptance-report-windows-2026-09-02.zh-TW.md) | [English](../../docs/acceptance-report-windows-2026-09-02.en.md)。平台能力與限制見 [`../../docs/windows-observation.md`](../../docs/windows-observation.md) 和 [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md)。

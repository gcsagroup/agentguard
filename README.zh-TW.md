[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

# AgentGuard

AgentGuard 是面向第三方 GUI Agent 的本機優先安全觀測與稽核系統。它分析畫面、輔助使用樹、表單、深層連結、工具呼叫與外傳中繼資料，並給出可稽核的風險判決。

> **目前狀態：`1.0.0-rc.1` 是原始碼候選版，不是正式環境安裝套件。**
> 儲存庫尚未提供本次發佈所需的程式碼簽署、公證、商店發佈與真實裝置端對端驗收證據，正式環境發佈判斷仍為 **No-Go**。

## 能做什麼

- 在 macOS、Windows、Android 與 Chromium 路徑上擷取可用的介面或事件訊號。
- 偵測提示注入、透明或不可見內容、介面樹與畫面不一致、隱私過度揭露、可疑深層連結與關鍵操作。
- 透過雜湊鏈與選用簽章保存本機稽核記錄；支援簽署的威脅情報與選用 SQLCipher。
- 當 Agent 主動經過 MCP 工具閘道時，依判決執行、拒絕或等待人工確認。
- 在 Linux 上，透過 `guard-jail` 為其自行啟動的程序提供窄範圍核心檔案系統邊界。

## 必須理解的邊界

- **不是即時監控。** 桌面觀測包含輪詢，輪詢間隙內的動作可能看不到。
- **大部分控制是協作式的。** Agent 若繞過閘道直接執行命令，閘道無法阻止。
- **不是通用沙箱、EDR、防火牆或 DLP。** Linux `guard-jail` 是唯一不依賴受約束方配合的窄邊界。
- **Android 與 Chromium 的高風險提示發生在事件之後，不是執行前阻擋。**
- Windows 原生觀測程式碼已實作並進入 CI，但尚無真實裝置端對端驗收；iOS 仍是未接入引擎的有限骨架。

適用對象是研究與評測、開發或預備環境，以及知情維運控制下的內部試點；不應把目前 RC 當作面向消費者或受監管環境的強制安全控制。

## 快速開始

~~~bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- coverage
make acceptance
make check
~~~

macOS 開發殼層：

~~~bash
cd apps/desktop-macos
npm install
npm run tauri dev
~~~

## 文件

- [文件入口](docs/README.zh-TW.md)
- [1.0.0-rc.1 發佈說明](docs/RELEASE-1.0.0-rc.1.zh-TW.md)
- [變更記錄](CHANGELOG.zh-TW.md)
- [範圍與非目標](docs/scope-and-non-goals.md)
- [平台能力矩陣](docs/platform-matrix.md)
- [發佈安全與證據閘門](docs/release-security.md)
- [產生的攻擊面覆蓋矩陣](eval/coverage-matrix.md)

深層技術文件仍保留其原始語言；入口會標明語言、用途與狀態，避免把歷史複核記錄當作目前發佈結論。

## 儲存庫結構

~~~text
crates/    Rust 引擎、規則、稽核、評測與工具
adapters/  macOS、Windows、Android 與瀏覽器介接器
apps/      桌面端、Chromium 擴充功能、Android 伴生應用程式與 iOS 骨架
docs/      產品邊界、架構、發佈、安全與研究文件
eval/      情境、測試資料、覆蓋聲明與產生報告
~~~

## 授權條款

[Apache License 2.0](LICENSE)

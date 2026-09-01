[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

<p align="center">
  <img src="assets/brand/agentguard-logo.png" alt="AgentGuard 標誌" width="160">
</p>

# AgentGuard

AgentGuard 是面向第三方 GUI Agent 的本機優先安全觀測與稽核系統。它分析畫面、輔助使用樹、表單、深層連結、工具呼叫與外傳中繼資料，並給出可稽核的風險判決。

> **目前狀態：`1.0.0-rc.1` 是原始碼候選版，不是正式環境安裝套件。**
> 儲存庫尚未提供本次發佈所需的程式碼簽署、公證、商店發佈與真實裝置端對端驗收證據，正式環境發佈判斷仍為 **No-Go**。

## 能做什麼

- 在 macOS、Windows、Android 與 Chromium 路徑上擷取可用的介面或事件訊號。
- 偵測提示注入、透明或不可見內容、介面樹與畫面不一致、隱私過度揭露、可疑深層連結與關鍵操作。
- 透過雜湊鏈與選用簽章保存本機稽核記錄；支援簽署的威脅情報與選用 SQLCipher。
- 當 Agent 主動經過 MCP 工具閘道時，依判決執行、拒絕或等待人工確認。
- 在支援的瀏覽器頁面內，對付款按鈕、陷阱表單與付款形狀的 fetch/XHR 提供有限的執行前確認閘門；對已知惡意或超出工作階段範圍的主機安裝 DNR 網路規則，並提供名單管理與規則溯源。
- 在 Linux 上，透過 `guard-jail` 為其自行啟動的程序提供窄範圍核心檔案系統邊界；工作明確宣告 `scope.net` 時，還可在 Landlock 支援下限制 TCP 連線與監聽連接埠。
- 使用 `guard-trust` 統一六類入站面的 fail-closed 信任詞彙，並將目前 20 條使用者能力聲明映射至具體測試與產生的狀態儀表板。

## 必須理解的邊界

- **不是零間隙即時監控。** macOS AX 樹狀結構變化已有 AXObserver 推送、合併與兜底輪詢；像素擷取及其他桌面路徑仍包含取樣或輪詢，間隙內的動作可能看不到。
- **大部分控制是協作式的。** Agent 若繞過閘道直接執行命令，閘道無法阻止。
- **不是通用沙箱、EDR、防火牆或 DLP。** Linux `guard-jail` 只約束它啟動的程序；網路連接埠天花板是選用能力，宣告後若所選後端無法強制，便會拒絕啟動。
- **瀏覽器控制有明確範圍。** 頁面閘門與 DNR 可在其覆蓋的向量上於執行前攔截，但頁面閘門可被惡意頁面繞過，DNR 安裝失敗時會 fail-open；Native Messaging 判決仍為非同步，不能回溯阻止觸發它的動作。Android 高風險提示仍發生在事件之後。
- Firefox 移植與 Edge 相容路徑已具備，但尚無真實瀏覽器端對端驗收；Safari 目前只有設計。目前 macOS ad-hoc 候選已在本機通過啟動、TCC 探測與 AXObserver 推送流程檢查，但尚未完成簽署/公證後的全新安裝與升級驗收；Windows 仍缺候選版真機 E2E，iOS 仍是未接入引擎的有限骨架。

適用對象是研究與評測、開發或預備環境，以及知情維運控制下的內部試點；不應把目前 RC 當作面向消費者或受監管環境的強制安全控制。

## 快速開始

~~~bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- coverage
make capability-claims
make check-extension-gate
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
- [入站信任](docs/入站信任.zh-TW.md)
- [主張與測試映射](docs/主张与测试映射.zh-TW.md)
- [瀏覽器執行前阻擋](docs/浏览器执行前阻断.zh-TW.md)
- [真實裝置驗收執行手冊](docs/acceptance-runbook.zh-TW.md)
- [發佈安全與證據閘門](docs/release-security.md)
- [產生的攻擊面覆蓋矩陣](eval/coverage-matrix.md)

本輪新增的關鍵技術與驗收文件提供簡體中文、繁體中文與英文版本；其餘深層文件仍保留原始語言。入口會標明語言、用途與狀態，避免把設計、離線測試或歷史複核記錄當作目前真實裝置與發佈結論。

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

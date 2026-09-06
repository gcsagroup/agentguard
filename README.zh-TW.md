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
- 在首個 GA 支援的 Chrome / Edge 頁面內，對符合條件的付款按鈕與陷阱表單執行 block-only 的執行前阻斷；對已聲明付款關鍵詞、HTTP(S)、非 GET/HEAD 與指定資源類型的請求啟用靜態 DNR 硬擋。
- 在 Linux 上，透過 `guard-jail` 為其自行啟動的程序提供窄範圍核心檔案系統邊界；工作明確宣告 `scope.net` 時，還可在 Landlock 支援下限制 TCP 連線與監聽連接埠。
- 使用 `guard-trust` 統一六類入站面的 fail-closed 信任詞彙，並將目前 36 條使用者能力聲明映射至具體測試與產生的狀態儀表板。

## 必須理解的邊界

- **不是零間隙即時監控。** macOS AX 樹狀結構變化已有 AXObserver 推送、合併與兜底輪詢；像素擷取及其他桌面路徑仍包含取樣或輪詢，間隙內的動作可能看不到。
- **大部分控制是協作式的。** Agent 若繞過閘道直接執行命令，閘道無法阻止。
- **不是通用沙箱、EDR、防火牆或 DLP。** Linux `guard-jail` 只約束它啟動的程序；網路連接埠天花板是選用能力，宣告後若所選後端無法強制，便會拒絕啟動。
- **瀏覽器控制有明確範圍。** DOM 風險動作只阻斷，網頁內沒有放行；頁面提示只是可被頁面影響的資訊層，使用者若堅持繼續，只能從瀏覽器擴充功能管理頁停用或移除保護後自行重做。靜態 DNR 不檢查 body，也不涵蓋自訂別名或其他未聲明表面；GA manifest 停用 Native Messaging。Android 高風險提示仍發生在事件之後。
- 首個 GA 的瀏覽器套件只支援共用 Chromium 套件的 Chrome / Edge；Firefox 僅保留原始碼原型，不封裝、不作為驗收門。iOS WebShield/Safari Extension 是首發正式產品範圍內的獨立 Xcode/Swift 受限 SKU，不是未來選項。舊 ad-hoc macOS 候選曾在本機通過啟動、TCC 探測與 AXObserver 推送流程檢查，但本輪最新 universal `.app` 尚未完成全量複驗，簽署／公證後的全新安裝與升級驗收也仍缺失。Windows 歷史候選 `89dadf9` 已取得真實 Windows 11 上的啟動、連續觀測與風險確認介面部分證據，但目前安全建置、簽署安裝套件及全新安裝/升級/解除安裝仍待重新驗收。iOS 已有可建置的受限 Safari WebShield App/延伸功能/Core 工程並通過無簽署模擬器測試，但未接 Rust 引擎，正式簽署、真機 Safari 與 TestFlight 仍未完成。
- **各端真正觀察什麼，以原始碼產生的 [docs/capability-matrix.zh-TW.md](docs/capability-matrix.zh-TW.md) 為準。** 上面「分析深層連結」說的是引擎能力（離線語料與適配器格式帶 `deeplink` 事件）；目前沒有任何一端的觀察器在真機上發出深層連結事件——Android 只回報介面文字裡的深層連結字樣。

適用對象是研究與評測、開發或預備環境，以及知情維運控制下的內部試點；不應把目前 RC 當作面向消費者或受監管環境的強制安全控制。

## 快速開始

~~~bash
make bootstrap-rust
./scripts/bootstrap-rust.sh -- cargo test --workspace
./scripts/bootstrap-rust.sh -- cargo run -p guard-cli -- eval --scenarios eval/scenarios
./scripts/bootstrap-rust.sh -- cargo run -p guard-cli -- coverage
./scripts/bootstrap-rust.sh -- make capability-claims
./scripts/bootstrap-rust.sh -- make check-extension-gate
./scripts/bootstrap-rust.sh -- make acceptance
./scripts/bootstrap-rust.sh -- make check
~~~

macOS 開發殼層：

~~~bash
cd apps/desktop-macos
npm install
npm run tauri dev
~~~

**裝好之後怎麼用**：見[桌面端使用說明](docs/desktop-guide.zh-TW.md)。macOS 提供五頁工作區、四標籤設定、瀏覽器設定與閘道確認入口；輔助使用必需，錄影選用。自我檢查只驗證模擬風險提醒，不證明阻斷了外部動作。

連接目前閘道的連接埠與權杖，即可核對、拒絕或僅批准目前請求；過期與斷連不自動放行，也不代表特定 MCP 用戶端已接入。見[本輪整改與驗證說明](docs/remediation-publication-2026-09-06.zh-TW.md)。

## 文件

- [文件入口](docs/README.zh-TW.md)
- [桌面端使用說明](docs/desktop-guide.zh-TW.md)
- [郵件防護：實驗性網頁擴充功能與後續代理設計](docs/mail-protection-design.zh-TW.md)
- [1.0.0-rc.1 發佈說明](docs/RELEASE-1.0.0-rc.1.zh-TW.md)
- [變更記錄](CHANGELOG.zh-TW.md)
- [範圍與非目標](docs/scope-and-non-goals.md)
- [平台能力矩陣](docs/platform-matrix.md)
- [入站信任](docs/入站信任.zh-TW.md)
- [主張與測試映射](docs/主张与测试映射.zh-TW.md)
- [瀏覽器執行前阻擋](docs/浏览器执行前阻断.zh-TW.md)
- [真實裝置驗收執行手冊](docs/acceptance-runbook.zh-TW.md)
- [結構化發佈證據](docs/release-evidence.zh-TW.md)
- [GA 發佈閉環閘門](docs/ga-release-gate.zh-TW.md)
- [歷史發佈閘門設計說明](docs/release-security.md)
- [產生的攻擊面覆蓋矩陣](eval/coverage-matrix.md)

本輪新增的關鍵技術與驗收文件提供簡體中文、繁體中文與英文版本；其餘深層文件仍保留原始語言。入口會標明語言、用途與狀態，避免把設計、離線測試或歷史複核記錄當作目前真實裝置與發佈結論。

## 儲存庫結構

~~~text
crates/    Rust 引擎、規則、稽核、評測與工具
adapters/  macOS、Windows、Android 與瀏覽器介接器
apps/      桌面端、Chromium 擴充功能、Android 伴生應用程式與受限 iOS Safari WebShield
docs/      產品邊界、架構、發佈、安全與研究文件
eval/      情境、測試資料、覆蓋聲明與產生報告
~~~

## 授權條款

[Apache License 2.0](LICENSE)

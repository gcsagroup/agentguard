[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# 變更記錄

本文件記錄 AgentGuard 的重要變更。版本號遵循語意化版本。

## [未發佈]

### 郵件聯合防護設計（2026-09-06）

- 新增三語[設計方案](docs/mail-protection-design.zh-TW.md)，涵蓋企業收發閘道、網頁與用戶端接入、權限與隱私邊界、寄送批准綁定及郵件專用驗收集。
- 本輪只完成設計與本機互動預覽檢查；尚未實作信箱代理、連接真實帳號或變更郵件路由，不將既有通用測試計為郵件防護通過。

### CI 跨平台回歸修復（2026-09-06）

- 能力矩陣腳本固定 UTF-8 輸出，並在儲存庫測試中重現 Windows 的 cp1252 管線環境；macOS 配接器的非原生分支正確限定平台專屬程式碼，保留嚴格編譯警告檢查。
- webhook 冒煙改用執行時產生的暫存事件，真實 CLI 驗證有效、重試、過期、未來、亂序、缺欄位及退款情境；不修改歷史夾具，不放寬十分鐘時間窗。
- 簽署流水線先驗證缺少身分時預設發佈路徑拒絕，再明確啟用 ad-hoc 模式驗證暫存替身；不降低正式簽署、公證或發佈門檻。
- Windows 封裝測試相容簽出後的 CRLF 換行，仍要求正式金鑰使用 DPAPI，不允許明文簽署退回路徑。

### 跨平台整改原始碼整合（2026-09-06）

- 整合共用核心、加密稽核與確認生命週期，以及桌面、行動端、瀏覽器擴充功能的既有整改；新增三語[提交說明](docs/remediation-publication-2026-09-06.zh-TW.md)，列明驗證範圍與未完成門檻。
- CI 加入工作區介面回歸及真實 MCP 閘道檔案副作用測試；同步權限聲明、證明測試對應與產生的能力矩陣。
- 原始碼審查候選隨後依維護者要求透過儲存庫 SSH 身分合入 `main`，收斂遠端與本機分支；排除本機憑據、原始報告與建置產物。不發佈安裝包，正式環境仍為 No-Go。

### macOS 工作區與主動防護入口（2026-09-06）

- 補齊經驗證的本機閘道待確認列表、目前請求拒絕／勾選後批准、倒數與斷連保護；權杖僅暫存，不儲存或自動重連。首次回答生效，過期與重複回答被拒絕；真實暫存檔驗證拒絕無副作用、批准後才寫入。
- 新增總覽、主動防護、活動記錄、四標籤防護設定及說明與診斷；語言、外觀與下一會話任務儲存在本機。
- 分開必需輔助使用與可選螢幕錄製，提供目前 App 身分、權限偵測與錯誤回饋，後端也拒絕未授權啟動。
- 隨附 Chrome/Edge 測試擴充功能、無害驗收頁和目前平台 MCP 閘道；可實際握手並產生不含權杖、不預設擴大目錄權限的設定。
- 驗收 App 使用獨立固定名稱與識別碼；ad-hoc 重新編譯仍須核對權限。實際用戶端接入、正式簽署與發佈驗收尚未完成；不宣稱跨平台改版或可上線。
- 同步三語桌面說明，修正桌面提醒等於事前攔截的誤述與無驗證確認範例。

### 真機報告（2026-08-31，含 2026-09-02 Windows 補充）整改

按報告的 P0 / P1 / P2 編號逐項處理，每項帶紅-綠-突變測試；只能在真機、憑證或商店帳號上發生的部分仍標為未驗證，見 [docs/release-evidence.zh-TW.md](docs/release-evidence.zh-TW.md)。

- **P0-1 閘門偽證**：發佈證據改為十二類結構化校驗（綁定完整提交號、真實命令、退出碼、判據輸出與產物身分）；新增 iOS Apple Distribution、iOS 真實裝置、TestFlight、Chrome 與 Edge 獨立 fail-closed 閘門，只含關鍵字的檔案一律拒絕。
- **RC / GA 分層閘門**：`--strict` 固定為 12 類 RC 技術證據；`--ga` 再要求 SBOM／授權、隱私／商店聲明、14 天 Beta、雙 RC、五方簽核、六渠道 smoke 與 5%→25%→100% 擴量，共 19 類。首個 GA 排除 Firefox；目前真實 GA 閉環材料缺失，結論仍為 No-Go。
- **P0-2 CI 兩處根因**：Windows 擴充功能路徑降級、Landlock `prctl` 尾參數殘值。
- **P0-3 / P0-5 工作階段與確認**：確認佇列按 `request_id` 排隊消競態；工作階段結束觀察器真的停；防護狀態由狀態機從「工作階段 + 觀察器 + 心跳 + 稽核可寫」推出（active / degraded）；Windows 觀察器綁工作階段並帶代際號、失敗退避進 degraded。
- **P0-4 真機判據機器化**：殼子在 `AGENTGUARD_ACCEPTANCE_TRACE` 下寫 JSONL，`guard-cli acceptance-trace-check` 對照稽核庫做六項檢查；macOS 15–17、Windows W8–W10 用例與證據必填清單三語同步。
- **P1-1 / P1-2 / P1-3 擴充功能**：Native Messaging 轉送預設關閉且設定載入前 fail-closed 排隊；外送與本機 URL 最小化；宿主長連線、退避重連、暫停狀態持久化；連線級 nonce + 單調 seq 拒重放/亂序。
- **P1-4 背景 Critical**：確認到達拉前視窗、選單列 / 標題計數；兩分鐘未拍板按拒絕寫 Timeout 回執；待確認落盤並在重啟後逐條寫回執。未接系統級通知。
- **P1-6 Android**：守護 / 中繼狀態由狀態機推出；處理程序重啟後失敗關閉並要求使用者重新開始工作階段，不自動恢復觀測；普通常駐通知只反映目前綁定工作階段；權杖進 Keystore、不回顯；事件 JSONL 14 天 / 20 檔 / 50 MiB / 5 MiB 輪轉 + 清除按鈕。
- **P1-7 Local API / webhook**：稽核庫預設私有目錄並拒符號連結與共享可寫目錄；請求體 256 KiB、`limit` 1000；權杖脫敏；webhook 必帶 `event_id / created_ms / version`，冪等、±10 分鐘、版本單調。
- **P1-8 / P1-9**：CI 簽名步驟在替身產物上真跑 ad-hoc 簽名並驗；裝置策略只裝驗過簽的且只收緊不放寬，未驗證的只顯示。
- **Windows 補充報告**：觀察器按 pid 跳過 AgentGuard 自己的視窗；OVL-010 加「未渲染文字須像一段指令」判據；W6 能力強制不可用開關；W7 `install-host.ps1`（未在真機執行）。
- **P2-1 覆蓋面**：iMy `ask_user` 以 `user_query` 事件進引擎（USER-QUERY / PRIV-GUESS），最後一個 uncovered surface 關閉；圖示語料的重複字形修正，通道度量重算。
- **P2-3 告警風暴**：桌面觀察去重（`event_dedup`，同內容 30 s 一次，改一字即放行）並修 UI-REVALIDATE 跨來源誤判根因；擴充功能 finding 去重、增量掃描、1.5 s 節流，真瀏覽器 E2E 加變異風暴回歸 M1–M4。
- **P2-4 無障礙與在地化**：桌面彈層 `alertdialog` + 焦點圈 + Esc + 焦點還原 + live region；Android TalkBack 等系統服務不再算「輸入被觀察」；繁中資源修正；launcher 標籤在地化。
- **P2-5 文件漂移**：新增原始碼產生的三語 [docs/capability-matrix.zh-TW.md](docs/capability-matrix.zh-TW.md)（各端真正發出的事件、靜態測試數、版本字串），`cargo test` 逐字核對；Android 文案不再說「觀察深層連結」（只回報介面文字裡的深層連結字樣，程式碼從未發出 `deeplink`）；iOS 頁面從「我們交付」改為「今天有什麼 / 目標是什麼」；發佈說明與本檔不再自寫聲明條數。
- **P2-6 重現與供應鏈**：`rust-toolchain.toml`、`.nvmrc`、Actions 釘 commit SHA；兩個桌面殼子的 lockfile 用 `deny.shells.toml` 單獨過 cargo-deny（MPL-2.0 逐 crate 例外待法務確認）。
- **P2-7 商業邊界**：企業功能只對廠商 Ed25519 簽名的授權解鎖（到期必填、7 天離線寬限、簽名撤銷名單）；HMAC / webhook / 夾具簽名的授權顯示為示範、不解鎖。
- **階段 D 雲端準備**：Chromium 真瀏覽器 E2E（39 條機器判據）與三語 `acceptance-chrome.zh-TW.md`；Windows W3–W5 確定性固件與渲染契約測試；Android adb 驗收腳本；Local API 對每份簽名 body 的驗簽結論可讀。

**仍未驗證（需你側）**：Developer ID 簽章與公證、Authenticode、Android release key、iOS Apple Distribution，以及 macOS / Windows / Android / iOS / TestFlight / Chrome / Edge 目前候選逐項完成並封存 strict 證據。Chrome 與 Edge 各自要求 B1–B5；Firefox 不屬於首個 GA，不能產生發佈 PASS。


### Added

- 接入 D 亮色品牌方案：新增共用 Logo 與 App 圖示母版；更新 macOS、Windows、Android 與 Chromium 圖示（含選單列、Adaptive/主題及通知小圖示）；並在三語 README、文件入口、符合性說明與各前端頁首顯示統一品牌標誌。
- 新增 `guard-trust`，以統一的常數時間比較、`InboundOutcome` 詞彙與入站面清冊測試約束六類入站信任邊界；各協定仍保留適合自身的密碼學原語與信任錨。
- 新增「使用者能力聲明 ↔ 證明測試」機器可核對映射（目前條數見原始碼產生的 [docs/capability-matrix.zh-TW.md](docs/capability-matrix.zh-TW.md)），以及從能力聲明、發佈閘門與狀態資料產生的儀表板；它們證明聲明錨點與測試存在，不取代真實裝置驗收。
- `guard-jail` 新增選用 `scope.net` 網路天花板：在 Landlock ABI v4（Linux 核心 6.7+）上只允許明確列出的 TCP connect/bind 連接埠；未宣告時不約束網路，已宣告但無法強制時拒絕啟動。
- 瀏覽器擴充功能新增付款 CTA、陷阱表單及付款形狀 fetch/XHR 的有限執行前確認閘門；新增對已知惡意與超出工作階段範圍主機的 DNR 阻擋、持久化/到期語意、名單管理與規則溯源。
- Firefox 僅保留獨立原始碼原型 manifest 與 Native Messaging host 接入骨架，並補 Edge 安裝相容；首個 GA 不封裝、提交或驗收 Firefox。iOS Safari 已有可編譯的有限 Swift 工程／SKU，但 Apple Distribution 簽章、真實裝置 Safari Extension、TestFlight 與 Rust 引擎接入仍待完成。
- macOS AX 樹狀結構觀測新增 AXObserver 推送、150ms 去抖、800ms 延遲上限與 3s 兜底輪詢；像素擷取仍為取樣路徑。
- macOS、Windows 與 Chromium 介面完成三語消費者化改造，包括首次引導、易懂風險文案、無障礙確認層、鍵盤焦點、深色模式、通知及詞表完整性檢查。
- 新增 Chrome／Edge、Windows、macOS、Android 與 iOS 驗收清單、可執行手冊、瀏覽器測試資料與報告範本；文件與測試資料是待執行流程，不表示已取得真實裝置證據。
- 記錄 Windows 候選 `89dadf9` 的歷史部分真機驗收：Windows 11 build 26200 上桌面測試 5/5、Clippy `-D warnings` 與 Release 建置通過；未簽署 EXE 的 SHA-256 為 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`。獨立 RDP 互動證據涵蓋兩輪各超過 30 秒的啟動與連續觀測、UIA/GDI/OCR 可用狀態、真實 `OVL-010` 事後風險確認及拒絕後第二輪穩定性，且未出現新的 Event 1000；它不證明外部動作被阻止，也不是目前 `first-ga-v1` W1–W6/W8–W11 全量驗收。
- 首個 GA 嚴格閘門目前有十二類結構化發佈證據範本與校驗：證據綁定目前完整提交號、實際命令、結束碼、時間、判據輸出與產物身分。普通發佈檔案使用標準 SHA-256；macOS/iOS `.app` 的 tree-v2 綁定整個 bundle 的路徑、類型、長度、內容及 Unix `0111` 可執行位元遮罩；驗收 closure-v1 則綁定報告 bytes 與每個唯一逐項引用的路徑、長度和內容。五類簽署證據把 `signer` 綁定至閘門外部提供的 Apple Team ID 或發佈憑證 SHA-256，七類驗收證據固定為 `null`；Firefox kind 僅保留舊版／未來格式相容，不進入首個 GA strict。路徑採用可攜式 ASCII 元件且逐項引用不得重複使用；未填寫範本、空產物、缺失檔案、自我引用、符號連結與摘要不符均不能通過。tree-v2 不綁定其他 mode、xattr／ACL，也不取代隔離機上的 quarantine、Gatekeeper 與首次啟動驗收；驗收 closure 仍是不能證明螢幕截圖來源的未簽署自證。

### Security

- 網路天花板一經宣告便涵蓋 TCP connect 與 bind；空連接埠表表示全部拒絕，非 Landlock 後端不得靜默降級為網路開放。
- 惡意主機 DNR 名單跨 service worker 重啟保留，越界主機隨工作階段到期；popup 可檢視、解除並追溯至 `INTEL-DOMAIN` 或 `SCOPE-HOST`。
- 嚴格閘門不再接受僅含關鍵字的任意檔案；簽署與驗收命令必須採用校驗器認可的完整 fail-closed 成功鏈，任何子命令失敗都不能被後續輸出掩蓋。五類簽署證據還須出現工具輸出與外部預期的 Team ID／憑證 SHA-256，並在執行前後核對同一個 clean 候選提交。結構化 JSON 仍是未簽署自證，只防誤綁定、誤操作與部分機械偽造，不防控制工作區的攻擊者偽造全部欄位。

### Changed

- Chromium 不再籠統描述為「只能事後通知」：頁面閘門與 DNR 對其涵蓋的向量提供執行前控制；Native Messaging 判決仍為非同步，不能回溯阻止觸發事件，且頁面閘門/DNR 都有明確繞過與 fail-open 邊界。Android 仍為事件後提示。
- 桌面觀測不再籠統描述為「僅輪詢」：macOS AX 樹狀結構變化已有推送；像素擷取、其他桌面路徑與兜底仍包含取樣或輪詢，因此不是零間隙即時監控。
- Windows CI 在既有工作區測試、介接器建置/Clippy 與桌面測試之後新增真實視窗啟動 smoke；候選對應的 GitHub Actions run `33551495621` 全綠。該 smoke 只防止視窗啟動後立即退出，不能取代 `first-ga-v1` W1–W6/W8–W11 的人工互動證據。

### Fixed

- 修正 Landlock 將目錄專屬權限附加到 `/dev/null` 等單一檔案規則，導致整份規則集回傳 `EINVAL`、子行程未啟動的問題；Linux 整合測試現在從已授權目錄啟動，並直接驗證授權讀寫與真實越界拒絕，不再因未授權的 `/dev/null` 重新導向而假綠。
- 修正 Landlock 呼叫 `prctl(PR_SET_NO_NEW_PRIVS)` 時未明確傳入三個必須為零的尾端參數而可能收到 `EINVAL` 的問題；現在統一使用完整五參數系統呼叫，並依 Linux x86_64／aarch64 選擇正確的 `prctl` 系統呼叫號，同時保留現有單一檔案權限過濾。
- 修正 aarch64 的 mount-namespace 降級路徑誤用 x86_64 `getuid`／`getgid` 系統呼叫號的問題；現在依架構選擇正確編號，並以真實系統呼叫回歸測試固定回退身分。
- 修正 Windows 預設主執行緒堆疊不足時 `guard-cli` 會在進入子命令前溢出的問題；Windows 入口現在以明確的 8 MiB 堆疊執行同一 CLI 調度。發佈閘門參數測試在 Windows 上解析 GitHub Runner 的 `C:\shells\gitbash.exe` 絕對路徑，並為一般 Windows 回退到預設 Git 安裝路徑；測試再由原生 `current_dir` 進入儲存庫並綁定腳本自己的結束碼 2 與拒絕文字，WSL、路徑或 CLI 啟動失敗都不能再冒充安全拒絕。
- 修正 Windows `canonicalize` 產生的 `\\?\` verbatim 磁碟機／UNC 前綴與一般前綴不等價的問題；真實 `C:\Windows`、`C:\ProgramData` 路徑會重新命中敏感目標，固定的 `\\?\` 命名空間標記也不再被誤判為萬用字元。
- 保留 Windows 元件層級路徑歸約與現有 home、`ProgramData`、`Program Files (x86)` 敏感路徑保護；未採用會把不同路徑形狀全域折疊並造成保護降級的方案。
- 修正 Windows 工作區測試仍把 `/bin/*`、`/srv`、`/tmp` 與 `/etc` 當作跨平台測試資料的問題；閘道改用可控 Rust 子行程驗證並行管道、UTF-8 截斷與結束碼，路徑、Shell 與 jail 測試使用目標平台真實的絕對路徑，同時保留敏感目錄與參數注入覆蓋。
- 修正 Windows 桌面啟動時先在主執行緒以 MTA 初始化 UI Automation，隨後 `OleInitialize` 需要 STA 而觸發 `RPC_E_CHANGED_MODE` 並退出的問題；啟動能力探測現在使用專用執行緒並快取結果，視窗主執行緒不再被預先改為 MTA。
- 修正短命能力探測執行緒結束後重用 WinRT OCR `FactoryCache` 可能觸發 `0xC0000005` 的問題；處理程序期 `CoIncrementMTAUsage` cookie 維持 COM MTA 可用，並新增 COM/OCR 跨執行緒回歸測試。
- Firefox MV3 原始碼原型 manifest 改用其支援的模組化 `background.scripts` 事件頁；結構測試釘住該原型與 Chromium service worker 的同一個 `background.js` 入口，但首個 GA 不產生 Firefox 套件。
- 修正讀取阻擋名單時遺失規則溯源，以及「允許一次」使用 `form.submit()` 繞過表單驗證並遺失 submitter 語意的問題；付款按鈕的 click→submit 鏈現在共用一次性批准，不會重複顯示確認。
- 把 macOS AXObserver 真正接入桌面驅動，繫結持續運作的主 RunLoop，並隨最上層應用程式切換重新繫結；新增產品路徑接線測試。
- macOS／Windows Release 殼程式把 SQLCipher 與可用稽核簽章器合併為失敗關閉的啟動合約；macOS 兩個 secret 存入 Keychain，Windows 存入不同類型的 DPAPI envelope。舊明文 DB/WAL/SHM/key 保持不變並阻斷，禁止靜默切換同層新庫造成歷史消失。
- macOS `.app` 現內建規則、工作計畫、授權政策、簽署威脅情報與公鑰；Release 只從簽署 bundle 載入。移除無依據的 JIT、無簽章可執行記憶體與停用 Library Validation entitlement；正式簽章固定 Team ID，公證只接受 Keychain profile。
- 擴充功能封裝改為先產生全新 ZIP 再原子取代，避免 `zip` 更新模式因來源檔案時間戳而保留舊程式碼。

### Known limitations

- 最新 universal macOS `.app` 仍需本輪完整清單以及 Developer ID／公證後全新安裝、升級與 TCC 驗收；Chrome／Edge 候選 ZIP 仍需分別做乾淨 profile 真機驗收，Firefox 不在首個 GA。iOS 已有可編譯的有限 SKU 與模擬器證據，但無簽章真機證據。Windows 仍需目前候選 `first-ga-v1` W1–W6/W8–W11 全量證據。
- 頁面閘門能涵蓋的只是在已安裝擴充功能可觸及的頁面向量；DNR 規則安裝失敗時 fail-open，Native Host 與 Android 通知不能提供不可繞過的執行前控制。
- 目前尚未設定正式 macOS/iOS Apple Team ID、Windows／Android 發佈憑證 SHA-256，五類簽署檢查維持 `UNVERIFIED`；桌面 Release 已強制 SQLCipher，但 Windows EXE 仍為 `NotSigned`，且沒有正式安裝套件及全新安裝、升級、解除安裝證據。公證、真實裝置與回復證據仍不完整；正式環境發佈結論維持 **No-Go**。

## [1.0.0-rc.1] - 2026-08-28

> 原始碼候選版，不代表正式環境安裝套件已具備發佈條件。目前尚未完成程式碼簽署、公證、商店發佈或真實裝置端對端驗收，正式環境發佈判斷仍為 **No-Go**。

### Added

- 跨平台 Rust 規則引擎、OP/TR/FM 隱私評分、工作階段計畫與能力範圍判決。
- macOS AXUIElement、ScreenCaptureKit 與 Vision OCR 觀測路徑。
- Windows UI Automation、GDI 擷取與 Windows.Media.Ocr 實作。
- Android AccessibilityService 伴生應用程式、環境調查與 Android Keystore P-256 介接器簽章。
- Chromium MV3 擴充功能、Native Messaging host、高風險判決通知，以及對有限頁面向量與名單主機的執行前控制。
- 協作式 MCP 工具閘道，以及 Linux 上由核心執行的 `guard-jail` 檔案系統邊界。
- Ed25519 威脅情報、雜湊鏈稽核、選用逐筆簽章與 SQLCipher。
- Bearer 保護的本機 API、簽署策略同步與已驗證計費 webhook。
- 離線評測、覆蓋矩陣、預檢與發佈證據閘門。
- 簡體中文、繁體中文與英文的核心 README、文件入口、發佈說明和變更記錄。

### Security

- 發佈路徑拒絕以 `sha256:` 完整性摘要冒充威脅情報真實性簽章。
- Native Messaging 呼叫者身分預設 fail-closed。
- 敏感檔案系統目標改為不可確認放行；閘道檔案操作進入引擎獨立判決，宿主接入稽核儲存與簽章器後才寫入可驗證稽核。
- 修正路徑歸約、符號連結、macOS 磁碟區別名、root mount namespace 與讀取範圍問題。
- 強化稽核見證包含性、工作階段計數、金鑰檔案權限、前端 DOM 寫入與 CSP。
- 讓策略同步與計費 webhook 在跨越信任邊界時驗證簽章。

### Changed

- 明確區分旁路觀測、協作式控制與 Linux 核心執行邊界。
- Android 的確認仍是事件後通知；Chromium 的頁面閘門與 DNR 則在其有限涵蓋面內提供執行前控制，Native Messaging 判決仍為非同步。
- Windows 狀態從模擬骨架更新為真實 UIA/GDI/OCR 實作，同時保留“尚未真實裝置驗收”的限制。
- `guard-ffi` 明確標記為儲存庫內沒有使用者的實驗元件。
- 發佈文件不再把原始碼、測試、建置與正式安裝套件證據混為同一狀態。

### Known limitations

- 除 Linux `guard-jail` 外，大部分控制依賴 Agent 主動經過 AgentGuard，可以繞過。
- macOS AX 樹狀結構變化已有推送，但像素擷取、其他桌面觀測與兜底仍包含取樣或輪詢，不是零間隙即時監控。
- Android 無法在動作發生前阻擋；Chromium 只能在頁面閘門與 DNR 涵蓋的向量上執行前控制，不能據此聲稱通用或不可繞過。
- Windows 尚無真實裝置端對端驗收；iOS 只有有限骨架，沒有完整工程或引擎接線。
- 儲存庫測試金鑰不得用於正式環境，部署前必須替換。
- 尚無簽署、公證安裝套件與真實裝置驗收證據，嚴格發佈閘門不能通過。

完整範圍與複驗要求見 [1.0.0-rc.1 發佈說明](docs/RELEASE-1.0.0-rc.1.zh-TW.md)。

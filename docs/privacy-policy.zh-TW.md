# AgentGuard 隱私說明草案

[简体中文](privacy-policy.md) | [繁體中文](privacy-policy.zh-TW.md) | [English](privacy-policy.en.md)

新增預設關閉的實驗性網頁信箱模組：開啟後僅在候選 Gmail/Outlook 頁面本機讀取可識別的主旨、正文、收件人欄位及附件存在狀態。郵件專項記錄只保留固定風險類別、阻斷狀態、時間、網站來源與 Gmail/Outlook 固定名稱；不存正文、主旨、地址、附件名或完整連結，不讀取附件內容，不呼叫信箱 API 或轉送到桌面端。模組無法阻止信箱本身草稿同步、直接 API 或未覆蓋路徑；關閉只停止郵件專項，既有付款規則保持啟用。

- **最後更新：** 2026-09-07
- **產品版本：** 1.0.0-rc.1
- **適用範圍：** macOS、Windows、Android 伴生應用程式、iOS WebShield/Safari Extension、首個 GA 的 Chrome/Edge Chromium 擴充功能、CLI 與本機 API

> 這是隨原始碼提供的技術揭露草案，不是已完成法律審閱的正式隱私權政策。公開散布前必須補充有效的營運主體、聯絡方式、適用地區與資料保留條款。

Firefox manifest 與 Native Messaging host 僅作為儲存庫原始碼原型保留，不在首個 GA 瀏覽器套件、商店提交或本隱私聲明的發佈能力範圍內。iOS WebShield 是首發產品範圍內的獨立 Xcode/Swift Safari Extension，不是 Chromium 擴充功能的 Safari 打包。

## 摘要

AgentGuard 預設在本機處理觀測資料，不提供預設雲端帳號、遙測或廠商上傳服務。使用者或企業可主動設定威脅情報、政策同步、Android 中繼或本機 API；這些連線的目標、傳輸安全與資料保留由實際部署設定決定。

| 資料 | 預設是否離開裝置 | 說明 |
|---|---|---|
| UI / AX / UIA / Accessibility 文字 | 否 | 僅在記憶體中用於本機規則判斷；預設不把原文寫入持久化稽核記錄 |
| ScreenCaptureKit / GDI 畫面 | 否 | 在本機擷取摘要或視覺特徵；預設不上傳原始像素 |
| 瀏覽器 DOM 訊號 | 否 | 在擴充功能內掃描；有限的發現摘要與最小化 URL 可保存在擴充功能本機，不傳送給 Native Host 或廠商服務 |
| iOS Safari 頁面事件 | 否 | 內容規則與原生合同在本機執行；僅保留規則/動作枚舉、時間和縮減到 origin 的 HTTP(S) URL，預設無上傳 |
| 稽核資料庫 | 否 | 桌面 Release 建置強制 SQLCipher；CLI／開發建置可明確使用普通 SQLite |
| 威脅情報與企業政策 | 可選下載 | 僅在部署方設定端點後存取；發布路徑要求簽章驗證 |
| Android 中繼 | 可選 | 使用者可設定 loopback、ADB reverse 或 LAN 位址 |
| 當機遙測與廣告追蹤 | 否 | 目前原始碼候選未整合預設遙測或廣告 SDK |

## 本機處理的資料

1. 無障礙樹、視窗與表單文字，用於辨識付款、隱私過度揭露、注入與可疑介面。
2. 瀏覽器 DOM 訊號，用於本機偵測隱藏文字、隱私陷阱，並在涵蓋的付款／提交動作執行前進行 block-only 阻擋。
3. 畫面或畫面摘要，用於透明覆蓋、低對比內容、隱寫與畫面變化偵測。
4. 網路流量中繼資料，例如主機名稱與概略大小；AgentGuard 不是完整封包擷取工具。
5. 稽核記錄，例如事件類型、規則編號、判決、固定安全摘要與人工確認結果。持久化事件採用 `persistable_event_v1`：布林值、數值、標準枚舉、受限識別碼及經格式驗證的摘要；URL 僅保留 scheme 與標準化 host，非 HTTP(S) URI 僅保留 scheme，環境清單僅保留數量。原始 UI/OCR/剪貼簿文字、路徑、命令操作數、URL userinfo/path/query/fragment、自由文字理由與未知欄位不落庫。
6. Android 環境調查結果，例如其他可讀取輸入的廣播接收器或無障礙服務。
7. iOS Safari Extension 的合同版本、隨機 request ID、規則 ID、固定 finding/action 枚舉、時間與當前 URL。Swift 落盤前再次驗證並將 URL 縮減為 HTTP(S) origin；原始 DOM、輸入值、頁面標題與 URL path/query/fragment 不落盤。

## 典型儲存位置

- macOS：`~/Library/Application Support/agentguard/`
- Windows：應用程式資料目錄中的本機稽核與設定檔
- Android：應用程式私有目錄中的 JSONL 信封、偏好與 Android Keystore 金鑰
- iOS：App Group `group.com.agentguard.webshield` 中的原子 JSONL 稽核與同意/開關；最多保留 7 天或 500 筆，使用者可清除，讀取時也會物理刪除過期列
- Chrome/Edge Chromium 擴充功能：擴充功能本機儲存；最近記錄中的 URL 會移除 userinfo、query 與 fragment，並遮蔽形似權杖的路徑段

Core／桌面稽核中，沒有經格式驗證的套件識別碼之應用來源會儲存為穩定 SHA-256 假名；外部工作階段 ID 也只儲存穩定假名，以支援同一資料庫內關聯而不保留原始 ID。雜湊不代表匿名化保證；低熵識別碼仍可能被猜測，因此匯出的稽核檔案仍應視為敏感本機資料保護。

此最小化僅適用於新寫入。舊版本已寫入的歷史列不會自動改寫（否則會破壞既有雜湊鏈與簽章），在完成經核准的清空或遷移前，仍須視為可能包含原始觀測內容。

Android Keystore 中的適配器私鑰依設計不可匯出。macOS Release 將稽核加密密語與 Ed25519 種子分開存入目前使用者 Keychain；Windows Release 使用兩個目前使用者 DPAPI envelope。CLI／開發路徑仍可明確使用 `0600` 檔案型簽章金鑰，能讀取該檔案的帳戶或 root 可匯出。Keychain／DPAPI 也是本機靜態保護，不等同 Secure Enclave／TPM 不可匯出。倉庫中的公開測試金鑰只供測試夾具與評測，不能用於正式環境。

## 網路行為

- 核心規則判斷預設不需要網際網路。
- 威脅情報與企業政策只在使用者或組織設定端點後下載。
- 本機 API 預設綁定 loopback 並要求 Bearer token；只有明確使用 `--allow-lan` 才允許 LAN 綁定。LAN 例外可能是明文 HTTP，部署方必須自行提供受信網路或額外傳輸保護。
- Android 中繼由使用者主動設定；傳送內容與目標取決於該設定。
- 首個 GA 的 Chrome/Edge 擴充功能不申請 Native Messaging 權限，也不連接 AgentGuard 雲端服務。靜態 DNR 由瀏覽器本機依 URL、方法與資源類型比對；它不會讀取 HTTPS 請求 body。
- iOS WebShield 沒有上傳端點、`connectNative` 長連線或遠端 DNR 情報；App 與 Safari Extension 透過本機 App Group/原生訊息交換最小化事件。

## 權限與控制

- macOS：輔助使用與螢幕錄製；拒絕權限會降低涵蓋範圍，應用程式不得把此狀態描述為完整保護。
- Windows：UI Automation、視窗與螢幕觀測能力取決於系統權限和目標應用程式。
- Android：無障礙服務與可見的普通常駐工作階段通知；風險通知通常發生在動作之後，不是阻擋式確認。
- Chrome/Edge：需要在 HTTP(S) 頁面執行內容腳本、使用本機儲存／通知，並由靜態 DNR 阻擋宣告範圍內的請求；頁面內提示只有「關閉」，不能授權或重播動作。
- iOS：使用者必須在 Safari 啟用擴充並授予網站權限；未授權 frame、closed Shadow DOM 與指令碼直接網路呼叫不在已宣告範圍。可在容器 App 關閉保護或清除稽核，也可在 Safari 設定撤銷網站權限。
- 使用者可以結束工作階段、停用可選觀測、關閉中繼，並刪除本機資料庫與報告。

## 目前發布狀態

本倉庫是原始碼發布候選。正式簽章安裝包、商店資料安全表單、法律審閱、真實裝置驗收與公開支援管道尚未完成。

## 聯絡方式

目前原始碼候選未提供可對外承諾的隱私聯絡地址。公開散布前必須在此填入真實、可用且由營運主體維護的聯絡方式。

# Chrome Web Store 商店頁面草稿

[简体中文](STORE.md) · 繁體中文 · [English](STORE.en.md)

> **草稿，尚未提交或通過 Chrome Web Store 審核。** 商店文案不能作為已發布、已審核或已完成真實瀏覽器驗收的證據。

## 名稱

AgentGuard Web Shield

## 摘要

在 AI Agent 使用的網頁中，於付款、隱私陷阱提交與高風險網路請求發生前提醒並等待確認，同時發現隱藏提示詞注入；本機優先。

## 說明

AgentGuard Web Shield 為 AI Agent 代替使用者操作的頁面提供三層有限防護：

- **頁面內確認閘門**：付款/轉帳點擊、向隱私陷阱提交個資，以及付款形狀的 `fetch`/XHR 會先被暫停；只有使用者選擇「允許這一次」才重放。
- **網路層名單阻斷**：瀏覽器 DNR 會在請求送出前攔截威脅情報判定的惡意主機，以及目前工作明確允許表以外的主機；名單、原因與解除入口均可見。
- **頁面偵測**：發現隱藏/潛意識提示詞注入文字、非必要個資欄位、隱私陷阱和高風險按鈕文字。

發現結果預設保存在擴充功能本機。使用者安裝並啟用選用的 `guard-nm-host` 後，符合條件的事件會交給本機引擎判決，並可進入已簽章、可察覺竄改的稽核鏈；桌面 App 不必同時執行。host 判決是**非同步路徑**：Critical 結果只能在事件發生後發出通知，不能撤銷已發生的操作；執行前控制來自頁面閘門與成功安裝的 DNR 規則。

**如實限制**：頁面閘門只涵蓋主框架中擴充功能能接觸到的 DOM 動作，以及頁面未提前保存原始參照的 `fetch`/XHR，可能被乾淨 iframe 或更早取得的 API 參照繞過。DNR 安裝失敗時 fail-open。目前機制不能監控瀏覽器以外的原生 App。

## 隱私

- 預設不向 AgentGuard 伺服器上傳瀏覽歷程。
- 未安裝或關閉 Native Messaging host 時，發現保存在擴充功能本機緩衝區。
- 啟用 host 後，符合條件的事件傳送到使用者本機的 `guard-nm-host`。
- host 的稽核資料庫預設是本機資料；稽核簽章與加密必須由使用者明確設定，不能假定預設存在。
- 威脅情報更新使用 Ed25519 簽章且為選用功能；正式環境部署必須替換儲存庫測試金鑰。
- 詳見 [隱私權政策](../../docs/privacy-policy.zh-TW.md)。

## 權限說明

- `storage`：保存開關與最近發現的本機緩衝區。
- `nativeMessaging`：選擇性連線使用者安裝的本機 `guard-nm-host`。
- `declarativeNetRequest`：在請求送出前阻斷名單中的惡意或越界主機。
- `notifications`：顯示引擎回傳的非同步高風險通知。
- `activeTab`：支援與目前分頁相關的擴充功能互動。
- `http://*/*`、`https://*/*`：在使用者造訪的網頁中執行內容腳本並檢查 DOM。

## 本機 host 安全邊界

host 除了依賴 Chrome manifest 的 `allowed_origins`，還會驗證 Chrome 經由 `argv[1]` 提供的 origin。沒有設定期望 origin 或值不相符時拒絕啟動；安裝腳本會把擴充功能 origin 寫到二進位檔旁的 `allowed-origin` 檔案。

## 封裝

```bash
./apps/extension-chromium/scripts/package-store.sh
```

產生的 ZIP 不包含 Native Messaging host。擴充功能套件、host 安裝方式與本機稽核設定必須分別說明。

## 目前發布狀態

- 未提交 Chrome Web Store 審核。
- 沒有商店安裝、升級或權限提示的真實瀏覽器驗收記錄。
- Native Messaging 自動安裝腳本目前只支援 macOS 與 Linux；Windows 需手動安裝 manifest。
- Chrome、Edge 與 Firefox 的真實商店安裝及端到端執行前阻斷仍需分別留證；Safari 僅有設計說明。

技術說明請參閱 [Chromium Extension README](README.zh-TW.md)。

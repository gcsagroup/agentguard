# Chrome Web Store 商店頁面草稿

[简体中文](STORE.md) · 繁體中文 · [English](STORE.en.md)

> **草稿，尚未提交或通過 Chrome Web Store 審核。** 商店文案不能作為已發布、已審核或已完成真實瀏覽器驗收的證據。

## 名稱

AgentGuard Web Shield

## 摘要

在 AI Agent 使用的網頁中發現提示詞注入、隱私陷阱、非必要個資與付款提示，並在本機記錄與提醒。

## 說明

AgentGuard Web Shield 在使用者造訪的 HTTP/HTTPS 頁面中檢查：

- 隱藏文字與提示詞注入標記；
- 非必要個資欄位與隱私陷阱元件；
- 付款、轉帳與其他高風險按鈕文字。

發現結果預設保存在擴充功能本機。使用者安裝並啟用選用的 `guard-nm-host` 後，擴充功能會把符合條件的事件傳送給這個獨立本機程序。host 自行載入 AgentGuard 規則、執行判決並寫入稽核資料庫，不要求桌面 App 正在執行。

host 回傳 High/Critical、Block 或需要確認的結果時，擴充功能會顯示瀏覽器通知並更新徽章。這是**非同步通知**：通知可能在使用者操作前或後出現，但判決不與特定操作同步綁定，擴充功能不能暫停、撤銷或阻止網頁操作。引擎的暫停狀態只影響後續事件判決。

## 隱私

- 預設不向 AgentGuard 伺服器上傳瀏覽歷程。
- 未安裝或關閉 Native Messaging host 時，發現保存在擴充功能本機緩衝區。
- 啟用 host 後，符合條件的事件傳送到使用者本機的 `guard-nm-host`。
- host 的稽核資料庫預設是本機資料；稽核簽章與加密必須由使用者明確設定，不能假定預設存在。
- 詳見 [隱私權政策](../../docs/privacy-policy.zh-TW.md)。

## 權限說明

- `storage`：保存開關與最近發現的本機緩衝區。
- `nativeMessaging`：選擇性連線使用者安裝的本機 `guard-nm-host`。
- `notifications`：顯示引擎回傳的高風險事後通知。
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
- Critical 通知不是執行前確認或網頁操作攔截。

技術說明請參閱 [Chromium Extension README](README.zh-TW.md)。

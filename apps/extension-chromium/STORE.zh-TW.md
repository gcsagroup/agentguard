# Chrome Web Store 商店頁面草稿

[简体中文](STORE.md) · 繁體中文 · [English](STORE.en.md)

> **草稿，尚未提交或通過 Chrome Web Store 審核。** 商店文案不能作為已發布、已審核或已完成真實瀏覽器驗收的證據。首個 GA 僅面向 Chrome / Edge；Firefox 原始碼原型不封裝，也不作為驗收門。

## 名稱

AgentGuard Web Shield

## 摘要

在 AI Agent 使用的網頁中，於執行前阻擋符合條件的付款或隱私陷阱 DOM 動作，並硬擋已聲明付款路徑上的非唯讀網路請求；同時提示隱藏提示詞注入，本機優先。

## 說明

AgentGuard Web Shield 為 Chrome / Edge 頁面提供三項邊界明確的有限防護：

- **DOM 動作阻斷**：瀏覽器從 `document_start` 向允許擴充功能進入的各個 HTTP(S) frame 注入內容腳本；其中的付款／轉帳點擊和隱私陷阱個資提交會在執行前被同步阻擋。頁面內沒有「允許一次」、繼續或重播控制項。
- **付款路徑網路硬擋**：預設靜態 DNR 在瀏覽器網路層阻擋符合聲明範圍的 HTTP(S) 非 GET/HEAD 請求，涵蓋瀏覽器歸類為 `xmlhttprequest`、`ping`、`main_frame` 或 `sub_frame` 的請求。
- **頁面偵測**：發現隱藏或潛意識提示詞注入文字、非必要個資欄位、隱私陷阱和高風險按鈕文字，並把結果留在擴充功能本機最近列表。

頁面內警告只是資訊層。網頁可以刪除、遮蔽、仿冒或影響它，因此它不是授權 UI，頁面裡的任何點擊都不能放行。若使用者理解風險後仍要繼續，只能先在瀏覽器自己的受信擴充功能管理介面（`chrome://extensions` 或 `edge://extensions`）停用或移除 AgentGuard，再自行重新發起操作；首個 GA 不提供暫時例外。

靜態 DNR 僅在以下條件同時成立時硬擋：URL 為 HTTP(S)；方法不是 GET/HEAD；路徑元件以 `pay`、`payment`、`checkout`、`charge`、`transfer`、`remit`、`purchase`、`orderconfirm` / `order-confirm` / `order_confirm` 或 `confirmorder` / `confirm-order` / `confirm_order` 開頭並符合字元邊界，或查詢鍵 `op`、`action`、`operation` 的值明確等於這些標記；資源類型為上述四類。路徑規則亦明確涵蓋核心標記逐位元組百分號編碼與 `%2F` 分隔符。它不檢查請求 body，也不涵蓋 body-only 付款意圖、自訂別名、未明確列出的編碼／混淆形式、任意查詢鍵或值、WebSocket/WebTransport、GET/HEAD 或其他資源類型。

**如實限制**：DOM 阻斷只涵蓋瀏覽器實際注入內容腳本，且會產生可觀察 click/submit 事件的 HTTP(S) frame；直接 `form.submit()`、未注入的頁面／協定與不產生被監聽事件的腳本路徑不在該保證內。網頁可影響資訊提示的可見性或真實性，但不能藉此產生放行狀態。靜態 DNR 與 DOM 阻斷都是 block-only，沒有網頁內批准、scope 例外或一次性放行。擴充功能不監控瀏覽器之外的原生 App。

## 隱私

- 預設不向 AgentGuard 伺服器上傳瀏覽歷程或發現結果。
- 符合條件的結果保存在擴充功能本機最近列表。
- 本機記錄的 URL 會被最小化：移除 userinfo、fragment 與全部 query，並把形似權杖的路徑段替換為 `…`。這是啟發式保護，短權杖或嵌在一般文字裡的秘密可能無法辨識。
- GA manifest 不申請 `nativeMessaging`，擴充功能不連線本機 host。儲存庫中保留的 Native host 原始碼與範本不是首個 GA 能力，也不隨商店 ZIP 發布。
- 詳見[隱私權政策](../../docs/privacy-policy.zh-TW.md)。

## 權限說明

- `storage`：儲存設定與最近發現的本機緩衝區。
- `declarativeNetRequest`：預設啟用已聲明付款路徑的靜態網路硬阻斷。
- `notifications`：在 DOM 動作已被阻擋後顯示瀏覽器擁有的資訊通知，不作為授權入口。
- `activeTab`：支援與目前分頁相關的擴充功能互動。
- `http://*/*`、`https://*/*`：在使用者造訪的 HTTP(S) 頁面中執行內容腳本並檢查 DOM。

`nativeMessaging` 明確不在 GA manifest 權限中；首個 GA 不聲明 Native host 判決、動態主機名單或本機稽核鏈能力。

## 封裝

```bash
./apps/extension-chromium/scripts/package-store.sh
```

此命令產生 Chrome / Edge 共用 ZIP。發布腳本拒絕 `--firefox`，ZIP 不包含 Firefox manifest 或 Native Messaging host。

## 目前發布狀態

- 未提交 Chrome Web Store 或 Microsoft Edge Add-ons 審核。
- Chrome / Edge 尚需分別完成商店候選的安裝、升級、權限提示與執行前阻斷真實瀏覽器留證。
- Firefox 僅保留原始碼原型，不封裝、不提交、不作為首個 GA 驗收門。
- Native Messaging 在 GA manifest 中徹底停用；相關原型不構成發布能力。
- Safari 是獨立產品線，不屬於此擴充功能首個 GA。

技術說明見 [Chrome / Edge 擴充功能 README](README.zh-TW.md)。

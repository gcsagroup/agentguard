# AgentGuard Chrome / Edge 擴充功能

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

這是首個 GA 的瀏覽器擴充功能實作，用於在 Chrome 與 Edge 頁面中偵測隱藏提示詞注入、非必要個人資料欄位、隱私陷阱，以及付款／轉帳動作。符合條件的高風險 DOM 點擊或提交會在執行前被阻擋；符合付款路徑的非 GET/HEAD 網路請求則由預設啟用的靜態 DNR 在網路層硬擋。

> 首個 GA 只支援 Chrome 與 Edge。Firefox 僅保留原始碼原型，不產生發布套件，也不是首個 GA 的驗收門；Safari 屬於獨立 Xcode/Swift 產品線。GA manifest 不包含 `nativeMessaging`，發布套件不連線或攜帶 Native Messaging host。

## 載入未封裝擴充功能

Chrome：

1. 開啟 `chrome://extensions`。
2. 啟用「開發人員模式」。
3. 點擊「載入未封裝項目」，選擇 `apps/extension-chromium`。

Edge 使用同一目錄與同一套件，在 `edge://extensions` 中載入。擴充功能包含 `en`、`zh_CN`、`zh_TW` 三套介面資源，也支援在彈出頁面覆寫系統語言。

Firefox 的 `manifest.firefox.json` 僅作為後續研發起點保留。首個 GA 不應把它暫時載入、封裝、提交商店或納入驗收結論。

## 封裝

從儲存庫根目錄執行：

```bash
./apps/extension-chromium/scripts/package-store.sh
```

輸出 `apps/extension-chromium/dist/agentguard-extension.zip`，供 Chrome / Edge 共用。發布腳本拒絕 `--firefox`；ZIP 不包含 Native Messaging host，GA manifest 也不申請 `nativeMessaging` 權限。

## 執行前阻斷

### 頁面 DOM 動作

瀏覽器從 `document_start` 向它允許擴充功能進入的各個 HTTP(S) frame 注入 isolated content script；其中的付款／轉帳 CTA 與隱私陷阱個資提交會在擷取階段同步阻擋。擴充功能**不會在網頁內提供「允許一次」、繼續或重播動作的授權控制項**。

頁面內提示只是資訊層：網頁可以刪除、遮蔽、仿冒或影響它，所以它不是可信授權 UI，點擊頁面裡的任何內容都不能改變阻斷決定。若使用者理解風險後仍要繼續，只能先進入瀏覽器自己的受信擴充功能管理介面（Chrome 的 `chrome://extensions` 或 Edge 的 `edge://extensions`），停用或移除 AgentGuard，再由使用者自行重新發起原操作。首個 GA 不提供暫時例外。

DOM 保護只涵蓋瀏覽器實際注入內容腳本，且會產生可觀察 click/submit 事件的 HTTP(S) frame；直接 `form.submit()`、未注入的頁面／協定，以及不產生被監聽事件的腳本路徑不在該保證內。網頁能破壞的是資訊提示的可見性或真實性，不能藉此產生放行狀態。

### 靜態 DNR 網路硬阻斷

靜態規則集 `payment_shape_block` 僅在以下條件**同時**成立時阻擋：

- URL 為 HTTP(S)；
- 方法不是 GET 或 HEAD；
- URL 路徑元件以明確列出的付款標記開頭並符合字元邊界，或查詢鍵 `op`、`action`、`operation` 的值明確等於這些標記：`pay`、`payment`、`checkout`、`charge`、`transfer`、`remit`、`purchase`、`orderconfirm` / `order-confirm` / `order_confirm`、`confirmorder` / `confirm-order` / `confirm_order`；路徑規則亦明確涵蓋核心標記逐位元組百分號編碼與 `%2F` 分隔符；
- 瀏覽器把請求分類為 `xmlhttprequest`、`ping`、`main_frame` 或 `sub_frame`。

因此它涵蓋聲明範圍內的 fetch/XHR、sendBeacon，以及頂層／子框架 form 導覽。它不檢查請求 body，也不涵蓋只有 body 表示付款、網站自訂別名、未明確列出的編碼／混淆形式、任意查詢鍵或值、WebSocket/WebTransport、GET/HEAD 或未列出的資源類型。規則是 block-only：沒有網頁內批准、scope 例外或一次性網路放行。

完整邊界見[瀏覽器執行前阻斷](../../docs/浏览器执行前阻断.zh-TW.md)。

## 本機資料與權限

- 發現結果保存在擴充功能本機最近列表，不預設上傳至 AgentGuard 伺服器。
- URL 在進入最近列表前會移除 userinfo、fragment 與全部 query，並把形似權杖的路徑段替換為 `…`；此處理是啟發式，不能保證辨識所有秘密。
- 同一頁裡同一條發現只上報一次，頁面持續變化不會刷屏；內容變化會形成新發現，掃描仍有節流與有界指紋集。
- `storage` 儲存設定與最近發現；`declarativeNetRequest` 啟用靜態網路規則；`notifications` 在 DOM 動作已被阻擋後提供瀏覽器擁有的資訊提示；`activeTab` 支援目前分頁相關互動；HTTP(S) host 權限用於在使用者造訪的頁面執行內容腳本。
- GA manifest 中沒有 `nativeMessaging`；儲存庫裡的 Native host 原始碼與範本不是首個 GA 能力，也不得作為商店文案或驗收依據。

## 驗證

```bash
make check-extension-gate
make e2e-extension
```

`check-extension-gate` 檢查阻斷邏輯、manifest、三語詞條與 Chrome/Edge 封裝邊界。`e2e-extension` 把擴充功能裝入 Chromium 測試環境，驗證 DOM 動作不執行、舊 decision/scope 訊息不能放行、靜態 DNR 在請求到達伺服器前阻擋，以及 GET 和一般 POST 不被誤擋。離線與自動化通過仍不取代 Chrome / Edge 商店候選的真實瀏覽器安裝、升級、權限提示與行為留證。

## 目前發布邊界

- 首個 GA：Chrome / Edge，同一 Chromium ZIP，分別完成商店與真實瀏覽器驗收。
- Firefox：原始碼原型保留；不封裝、不提交、不作為首個 GA 驗收門。
- Native Messaging：在 GA manifest 中徹底停用；host 不隨 ZIP 發布，相關原型不構成 GA 能力。
- Safari：獨立產品線，不屬於此擴充功能的首個 GA。

另請參閱[隱私權政策](../../docs/privacy-policy.zh-TW.md)、[商店文案草稿](STORE.zh-TW.md)與[跨瀏覽器範圍](../../docs/跨浏览器.zh-TW.md)。

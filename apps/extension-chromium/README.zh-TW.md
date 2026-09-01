# AgentGuard Chromium Extension

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

這是一個 Manifest V3 擴充功能，用於檢查隱藏/提示詞注入文字、非必要個資欄位、隱私陷阱與付款/轉帳動作。它會在頁面內同步攔住符合條件的點擊、提交及付款形狀 `fetch`/XHR，等待使用者選擇；也可透過 DNR 在請求送出前阻止已判定的惡意或越界主機。發現結果預設保存在擴充功能本機緩衝區；安裝選用的 Native Messaging host 後，可增加引擎判決與稽核記錄。

> 能力邊界：頁面閘門只涵蓋擴充功能能接觸到的主框架 DOM 動作，以及頁面未提前保存原始參照的 `fetch`/XHR；它不是不可繞過的瀏覽器沙箱。Native Messaging 判決仍是非同步路徑，只能通知或影響後續狀態；執行前控制來自頁面閘門與成功安裝的 DNR 規則。

## 載入未封裝擴充功能

1. 開啟 `chrome://extensions`。
2. 啟用「開發人員模式」。
3. 點選「載入未封裝項目」，選擇 `apps/extension-chromium`。
4. 記下 Chrome 分配的擴充功能 ID；安裝 Native Messaging host 時需要它。

Edge 透過 `edge://extensions` 使用相同目錄與套件。Firefox 128+ 可在 `about:debugging#/runtime/this-firefox` 選擇「暫時載入附加元件」，並開啟 `manifest.firefox.json`；Firefox 移植仍需真實瀏覽器驗收。

擴充功能包含 `en`、`zh_CN`、`zh_TW` 三套介面資源，也支援在彈出頁面覆寫系統語言。

## 封裝

從儲存庫根目錄執行：

```bash
./apps/extension-chromium/scripts/package-store.sh
./apps/extension-chromium/scripts/package-store.sh --firefox
```

預設輸出 Chrome/Edge 套件 `agentguard-extension.zip`；`--firefox` 輸出 `agentguard-extension-firefox.zip`。套件不包含 Native Messaging host；上傳商店前仍需完成對應商店審核、隱私揭露與真實瀏覽器驗收。

## 選用的獨立 Native Messaging host

`guard-nm-host` 是獨立本機程序：它自行載入規則、執行判決並寫入稽核資料庫，不要求 AgentGuard 桌面 App 正在執行。若明確把 `AGENTGUARD_AUDIT_DB` 指向同一個資料庫，host 與桌面端可以使用同一稽核位置；稽核簽章與加密仍需分別設定 `AGENTGUARD_AUDIT_SIGNING_KEY` 與 `AGENTGUARD_AUDIT_KEY`，不能假定預設已啟用。

macOS / Linux 開發安裝：

```bash
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
# Edge
./apps/extension-chromium/native-host/install-host.sh --browser edge <EXTENSION_ID>
# Firefox
./apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev
```

安裝腳本會：

- 建置 `guard-nm-host`；
- 寫入 Chrome Native Messaging manifest；
- 把 `chrome-extension://<EXTENSION_ID>/` 寫到 host 二進位檔旁的 `allowed-origin`。

這個輔助腳本目前只支援 macOS 與 Linux，並會依目標瀏覽器寫入正確的允許呼叫方格式。Windows 需要手動安裝 Native Messaging manifest，儲存庫沒有自動安裝器。

### 呼叫方身分預設拒絕

Chrome manifest 的 `allowed_origins` 只約束 Chrome 本身。host 還會讀取 Chrome 經由 `argv[1]` 傳入的實際 origin，並與下列期望值逐字比較：

1. `AGENTGUARD_ALLOWED_ORIGIN`；或
2. 二進位檔旁的 `allowed-origin` 檔案。

兩者都沒有、Chrome 未提供 origin 或值不相符時，host 以結束碼 2 拒絕啟動。這可防止任意本機程序直接執行 host，並把偽造的 `source_app` 寫入稽核。

## 執行前閘門、網路規則與非同步判決

頁面閘門會在捕獲階段判斷付款 CTA、隱私陷阱表單與付款形狀 `fetch`/XHR：先攔住動作，只有使用者選擇「允許這一次」才重放。DNR 依引擎回傳的惡意主機與工作階段允許表產生規則，在符合條件的請求送出前阻斷，並在 popup 提供原因與解除入口。

擴充功能也會把發現非同步傳送給 host。host 回傳 High/Critical、Block 或 `require_confirm` 時會顯示通知、更新徽章並寫入最近結果；「暫停」只表示引擎拒絕後續事件。這條 host 路徑不能撤銷已經發生的網頁動作，也不能冒充頁面閘門的 approve-then-proceed。

host 未安裝、未註冊或被關閉時，發現仍保存在擴充功能的本機緩衝區，但不會取得引擎判決。彈出頁面中的「轉送到本機守護」開關可以關閉 Native Messaging。

## 離線載荷檢查

從儲存庫根目錄執行：

```bash
cargo run -p guard-cli -- ingest-browser \
  --payload eval/fixtures/browser_extension_payload.json
```

## 隱私與限制

- 預設不把瀏覽歷程上傳到 AgentGuard 伺服器。
- 啟用 Native Messaging 後，符合條件的頁面發現會傳給本機 host；host 的稽核儲存位置與保護方式由本機設定決定。
- 擴充功能具有 `http://*/*` 與 `https://*/*` host 權限，用於在使用者造訪的頁面執行內容腳本。
- 頁面閘門是盡力而為的客戶端控制：提前保存的原始 `fetch`、乾淨 iframe、跨框架動作或原生 App 行為可能繞過它。
- DNR 規則安裝失敗時會如實 fail-open；Chrome、Edge、Firefox 仍需分別完成真實瀏覽器驗收，Safari 目前只有設計說明。

請參閱 [隱私權政策](../../docs/privacy-policy.zh-TW.md) 與 [商店文案草稿](STORE.zh-TW.md)。

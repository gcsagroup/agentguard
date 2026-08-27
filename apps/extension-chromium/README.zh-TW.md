# AgentGuard Chromium Extension

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

這是一個 Manifest V3 擴充功能，用於在瀏覽器頁面中檢查隱藏/提示詞注入文字、非必要個資欄位、隱私陷阱元件與付款/轉帳按鈕文字。發現結果預設保存在擴充功能本機緩衝區；安裝選用的 Native Messaging host 後，可把事件交給本機 AgentGuard 引擎判決。

> 能力邊界：擴充功能非同步觀察 DOM 變更與頁面內容。Critical/Block 結果會觸發瀏覽器通知與徽章；通知可能在使用者操作前或後出現，但判決不與特定操作同步綁定，不能暫停、撤銷或阻止網頁操作。

## 載入未封裝擴充功能

1. 開啟 `chrome://extensions`。
2. 啟用「開發人員模式」。
3. 點選「載入未封裝項目」，選擇 `apps/extension-chromium`。
4. 記下 Chrome 分配的擴充功能 ID；安裝 Native Messaging host 時需要它。

擴充功能包含 `en`、`zh_CN`、`zh_TW` 三套介面資源，也支援在彈出頁面覆寫系統語言。

## 封裝

從儲存庫根目錄執行：

```bash
./apps/extension-chromium/scripts/package-store.sh
```

預設輸出為 `apps/extension-chromium/dist/agentguard-extension.zip`。腳本只封裝擴充功能檔案，不包含 Native Messaging host；上傳商店前仍需完成商店審核、隱私揭露與實際瀏覽器驗收。

## 選用的獨立 Native Messaging host

`guard-nm-host` 是獨立本機程序：它自行載入規則、執行判決並寫入稽核資料庫，不要求 AgentGuard 桌面 App 正在執行。若明確把 `AGENTGUARD_AUDIT_DB` 指向同一個資料庫，host 與桌面端可以使用同一稽核位置；稽核簽章與加密仍需分別設定 `AGENTGUARD_AUDIT_SIGNING_KEY` 與 `AGENTGUARD_AUDIT_KEY`，不能假定預設已啟用。

macOS / Linux 開發安裝：

```bash
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
```

安裝腳本會：

- 建置 `guard-nm-host`；
- 寫入 Chrome Native Messaging manifest；
- 把 `chrome-extension://<EXTENSION_ID>/` 寫到 host 二進位檔旁的 `allowed-origin`。

這個輔助腳本目前只支援 macOS 與 Linux。Windows 需要手動安裝 Native Messaging manifest，儲存庫沒有自動安裝器。

### 呼叫方身分預設拒絕

Chrome manifest 的 `allowed_origins` 只約束 Chrome 本身。host 還會讀取 Chrome 經由 `argv[1]` 傳入的實際 origin，並與下列期望值逐字比較：

1. `AGENTGUARD_ALLOWED_ORIGIN`；或
2. 二進位檔旁的 `allowed-origin` 檔案。

兩者都沒有、Chrome 未提供 origin 或值不相符時，host 以結束碼 2 拒絕啟動。這可防止任意本機程序直接執行 host，並把偽造的 `source_app` 寫入稽核。

## 判決與通知語意

擴充功能把本機發現轉換為瀏覽器事件，並非同步傳送給 host。host 回傳 High/Critical、Block 或 `require_confirm` 判決時，擴充功能顯示通知、更新徽章並記錄最近結果。

「暫停」只表示 AgentGuard 引擎內部會拒絕後續事件；host 判決非同步到達且不綁定某一次網頁操作。此路徑沒有 approve-then-proceed 對話框，不應描述為瀏覽器操作攔截。

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
- 這是 DOM 啟發式觀察器，不是網路過濾器、瀏覽器沙箱或不可繞過的防護。

請參閱 [隱私權政策](../../docs/privacy-policy.zh-TW.md) 與 [商店文案草稿](STORE.zh-TW.md)。

[简体中文](acceptance-chrome.md) | [繁體中文](acceptance-chrome.zh-TW.md) | [English](acceptance-chrome.en.md)

# Chromium 擴充功能驗收清單（首個 GA：Chrome / Edge）

首個 GA 的瀏覽器產品只有一份 Chrome / Edge 共用的 Chromium MV3 ZIP。它是 **block-only**：符合條件的 DOM 動作與付款形狀網路請求會被阻擋，網頁內沒有「允許一次」、暫時例外或動作重播。GA manifest 不申請 `nativeMessaging`，發佈 ZIP 不攜帶 Native host。Firefox 僅保留原始碼原型，不進入本清單、發佈套件或首個 GA 閘門。

本清單分成兩層：

- `make e2e-extension` 在測試 Chromium 中執行 39 條機器判據，證明原始碼與封裝內容的阻擋行為；
- Chrome 與 Edge 正式版仍須分別使用候選 ZIP 完成安裝、升級、權限與代表性行為留證。

自動化通過不能取代商店簽署、正式瀏覽器、候選 ZIP 身分或其他平台證據。嚴格閘門要求 Chrome 與 Edge 各自提交結構化驗收證據；一份 Chromium 測試報告不能取代兩個正式瀏覽器的獨立結果。

## 自動化驗收

`make e2e-extension` 把擴充功能裝入真 Chromium 持久化情境，輸出 `eval/e2e-extension/out/report.json` 與唯一結論標記 `AGENTGUARD_E2E_EXTENSION=PASS|FAIL`。目前 39 條案例分組如下：

| 組別 | 機器判據 |
|---|---|
| D0 / D0b / D0c | 預設靜態規則集啟用；每條 DNR 正規表示式被瀏覽器接受；代表性 `POST /pay/checkout` 命中 block |
| U1 | 升級到無 Native 的 GA 後清除舊暫停、舊 host blocklist、動態 DNR 與徽章 |
| F1 / F1b | 隱藏注入進入最近清單；URL 最小化、標題截斷，不保存原始敏感 URL |
| F2a–F2f / H0 / H1 / H5 | 一般、早期捕獲與開放 Shadow DOM 付款 CTA 均在頁面處理器前阻擋；提示只有關閉鍵；頁面竄改不能授權或重播；每次點擊仍重新阻擋並留痕 |
| F3a–F3d | 隱私陷阱表單與一般子 frame 付款動作在導覽/POST 前阻擋；關閉提示後仍不送出 |
| F4a–F4e / H2–H4 | fetch、XHR、sendBeacon、form、明確編碼與操作查詢由 DNR 在伺服器前阻擋；舊 decision/scope 訊息與舊 15 秒逾時不能放行 |
| F5a–F5d | GET、一般 POST、僅 body 付款語意、付款前綴一般詞與巢狀查詢文字不誤擋 |
| M1–M4 | DOM 變異風暴去重、節流，且不同的新 finding 不漏報 |
| P1–P4 | GA 無 Native 權限且隱藏不可用控制；計數、最近清單與三語可見文案正確 |

執行：

```bash
make check-extension-gate
make e2e-extension
```

成功必須同時滿足：程序退出 0、最後一行為 `AGENTGUARD_E2E_EXTENSION=PASS`、`report.json` 的 `all_pass` 為 `true`，且報告恰好記錄目前清單預期的 39 條 PASS。必須保留報告中的 Chromium 版本；不得改稱 Chrome 或 Edge 正式版證據。

## Chrome / Edge 候選 ZIP 人工驗收

兩種正式瀏覽器分別執行，且必須使用同一份待提交 ZIP。不要安裝 Native host，也不要開啟任何「桌面轉送」原型。

| ID | 操作 | PASS 判據 | 必留證據 |
|---|---|---|---|
| B1 | 記錄 ZIP SHA-256、manifest 版本、瀏覽器正式版版本；解壓並載入 | Chrome 與 Edge 載入相同 SHA-256；manifest 權限不含 `nativeMessaging`；沒有意外權限提示 | 雜湊、版本與擴充功能詳情頁 |
| B2 | 全新 profile 安裝並開啟引導頁、popup | 圖示、三語文案與權限說明正常；Native 控制不可見；靜態 `payment_shape_block` 已啟用 | 引導頁、popup、規則集狀態 |
| B3 | 在本機固件重做 F2、H5、F3、F4a/F4c/F4d、F5a/F5b/F5d | 付款/陷阱動作沒有副作用；網路正例伺服器零請求；負例到達；提示只有關閉鍵，關閉後仍不執行 | 頁面結果、Network 與伺服器計數 |
| B4 | 從上一公開版本原地升級到同一候選 ZIP | 不新增 Native 權限；舊暫停、舊動態 host 規則與舊徽章不殘留；39 條自動化涵蓋的代表性阻擋仍成立 | 升級前後權限、storage/規則、popup |
| B5 | 停用、重新啟用、解除安裝；依發佈回滾方案恢復上一候選 | 瀏覽器狀態可預期，沒有殘留頁面授權狀態；回滾不得記為目前候選 PASS | 操作記錄與最終擴充功能狀態 |

任一瀏覽器缺失、任一列無法判定或證據未綁定候選 ZIP 時，記錄 `BLOCKED`，不得合併成「Chromium 已通過」。

分別從中央範本複製一份報告，Chrome 放在 `evidence/chrome/`，Edge 放在 `evidence/edge/`。B1–B5 必須逐項為 `PASS (native)` 且引用不同的非空證據檔案；B1 證據必須記錄兩端共用的候選 ZIP SHA-256。完成後執行：

```bash
guard-cli manual-acceptance chrome docs/acceptance-chrome.md evidence/chrome/report.md --repo-root .
guard-cli manual-acceptance edge docs/acceptance-chrome.md evidence/edge/report.md --repo-root .
```

Chrome 報告須包含整列 `AGENTGUARD_ACCEPTANCE_CHROME=PASS`，Edge 報告須包含整列 `AGENTGUARD_ACCEPTANCE_EDGE=PASS`。結構校驗通過仍是未簽署本機自證，不能取代商店審核與正式環境下載 smoke。

## 明確邊界

- DOM 保證只涵蓋擴充功能實際注入、能產生被監聽 `click` / `submit` 事件且標籤可辨識的 HTTP(S) frame；直接 `form.submit()`、未注入的特殊 frame、pointer/keyboard 自訂前置邏輯與瀏覽器外原生動作不在保證內。
- 靜態 DNR 只涵蓋文件聲明的 HTTP(S)、非 GET/HEAD、付款關鍵詞/編碼、查詢鍵與資源類型；不檢查 body，不涵蓋未列別名、雙重編碼、WebSocket/WebTransport 或未列資源類型。
- 頁面提示是網頁可影響的資訊層，不是授權面。使用者若堅持繼續，只能在擴充功能管理頁停用或移除保護後自行重新操作。
- Firefox 與 Safari 的任何原型、歷史截圖或舊驗收報告都不能作為 Chrome / Edge 首個 GA 證據。

## 封裝

```bash
apps/extension-chromium/scripts/package-store.sh
unzip -t apps/extension-chromium/dist/agentguard-extension.zip
shasum -a 256 apps/extension-chromium/dist/agentguard-extension.zip
```

`package-store.sh --firefox` 必須失敗且不產生 Firefox ZIP；這是範圍保護，不是 Firefox 驗收。

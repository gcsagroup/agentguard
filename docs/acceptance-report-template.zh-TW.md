[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# 真機驗收報告（範本）

> 由執行者填寫。每個案例一列：`PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` + 證據路徑 + 備註。
> 判據以 `acceptance-runbook.zh-TW.md` 第 7 節小抄為準。**無法判斷就填 `BLOCKED` 並寫明原因，不要猜 PASS。**
> `PASS (sim)` 只證明模擬判決鏈路，不能取代 `PASS (native)`、真機觀測證據或發佈證明。
> 作為嚴格閘門 artifact 時，每個必要 ID 必須在 Markdown 表中恰好出現一列；第二欄必須精確為
> `PASS (native)`，第三欄必須指向對應 `evidence/<平台>/` 下真實存在的儲存庫相對非空普通檔案，且每個案例的路徑必須唯一；不能引用報告本身或
> 目前 evidence JSON 來源檔案，也不能經過符號連結或超出儲存庫。路徑只使用 `/`，每個元件須符合可攜式 ASCII `[A-Za-z0-9._-]+`，不能包含空白或 shell glob／展開字元。
> 缺失、重複、重複使用路徑、`PASS (sim)`、FAIL、BLOCKED、N/A 或引用檔案不存在都不會通過。

## 環境資訊

| 項目 | 值 |
|---|---|
| 執行日期 |  |
| 執行者（agent / 人） |  |
| 作業系統 + 版本 |  |
| 儲存庫 commit（`git rev-parse HEAD`） |  |
| 提交時間（`git show -s --format=%ct HEAD`） |  |
| Rust 版本（`cargo --version`） |  |
| Node 版本（`node --version`） |  |
| 離線門禁是否全綠（`make capability-claims check-extension-gate coverage`） | ☐ 是 ☐ 否 |

## 瀏覽器擴充功能（Firefox / Chrome / Edge）

瀏覽器 + 版本：__________　擴充功能 ID：__________　原生 host 已安裝：☐ 是 ☐ 否

| 案例 | 結果 | 證據（路徑） | 備註 |
|---|---|---|---|
| F1 隱藏注入 |  |  |  |
| F2 付款 CTA 執行前攔截 |  |  |  |
| F3 陷阱+PII 送出攔截 |  |  |  |
| F4 付款形狀 fetch 攔截 |  |  |  |
| F5 唯讀方法不攔截 |  |  |  |
| F6 惡意網域網路層硬攔截 |  |  |  |
| F7 原生訊息握手 |  |  |  |
| F8 DNR 配額 |  |  |  |

## Windows 桌面殼程式

Windows 版本：__________　殼程式模式：☐ 模擬 ☐ 原生可用 ☐ 原生已接線但權限 / capability 不可用

| 案例 | 結果 | 證據（路徑） | 備註 |
|---|---|---|---|
| W1 阻斷模態（判決鏈路） |  |  |  |
| W2 UIA 取樹 |  |  |  |
| W3 GDI 擷取影格 + 隱寫 |  |  |  |
| W4 Windows.Media.Ocr 讀屏 |  |  |  |
| W5 overlay |  |  |  |
| W6 能力探針（含原因字串） |  |  |  |
| W7 原生訊息 |  |  |  |

## macOS 桌面殼程式

macOS 版本：__________　殼程式模式：☐ 模擬 ☐ 原生可用 ☐ 原生已接線但權限 / capability 不可用

| 案例 | 結果 | 證據（路徑） | 備註 |
|---|---|---|---|
| 1 支付確認 |  |  |  |
| 2 轉帳確認 |  |  |  |
| 3 選用 PII |  |  |  |
| 4 Trap 表單 |  |  |  |
| 5 透明 overlay |  |  |  |
| 5b 圓角不可見區 |  |  |  |
| 5c 執行前 UI 變化 |  |  |  |
| 6 Intel 注入 |  |  |  |
| 7 惡意網域 |  |  |  |
| 8 Netmon 外洩 |  |  |  |
| 9 瀏覽器惡意 URL |  |  |  |
| 10 工作階段暫停 |  |  |  |
| 11 SCK 探針 |  |  |  |
| 12 AX 探針 |  |  |  |
| 13 真實裝置 AX |  |  |  |
| 14 UI revalidate |  |  |  |

## Android 伴生應用程式

Android 裝置 + 版本：__________　候選版本：__________　AccessibilityService：☐ 已啟用 ☐ 不可用

| 案例 | 結果 | 證據（路徑） | 備註 |
|---|---|---|---|
| A1 真實裝置安裝、通知與無障礙權限生命週期 |  |  |  |
| A2 裝置 P-256 公鑰已登錄，桌面端成功驗證真實 HTTP body 簽章 |  |  |  |
| A3 真實無障礙事件送達引擎，判決符合預期 |  |  |  |
| A4 判決回傳裝置並顯示對應風險結果 |  |  |  |

## 彙總

| 面向 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| 瀏覽器 |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |
| Android |  |  |  |  |  |

**整體結論（一句話）**：

**FAIL 的案例（若有）逐項填寫：現象 / 預期 / 證據 / 初步判斷原因**：

**BLOCKED 的案例逐項填寫原因**（例如 `permission-denied` / `capability-unavailable` / `no host verdict` / 缺語言套件 / 環境未接 host）：

**結構化證據平台標記**（只在該平台全部必要原生案例 PASS 後，把 `<PLATFORM>` 替換為平台名稱並把結果改為 `PASS`；否則保留預留值）：

```text
AGENTGUARD_ACCEPTANCE_<PLATFORM>=<RESULT>
```

> 本報告記錄本次驗收結果，不單獨構成發佈證明；簽章、公證/商店審核、發佈套件身分、嚴格門禁與平台覆蓋須另行核驗。
> 作為結構化證據 artifact 時，報告必須儲存為 `evidence/<平台>/` 下的 `.md` 普通檔案。`artifact.sha256` 是
> `agentguard-acceptance-closure-sha256-v1`，綁定報告 bytes 以及每個唯一逐項引用的路徑、長度與內容；不要提交進由它綁定的候選 commit。
> 該閉包仍是未簽署自證，不能證明螢幕截圖、記錄或裝置資料的真實來源。

[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# 真機驗收報告（範本）

> 由執行者填寫。每個案例一列：`PASS` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` + 證據路徑 + 備註。
> 判據以 `acceptance-runbook.md` 第 6 節小抄為準。**無法判斷就填 `BLOCKED` 並寫明原因，不要猜 PASS。**
> `PASS (sim)` 只證明模擬判決鏈路，不能取代 `PASS (native)`、真機觀測證據或發佈證明。

## 環境資訊

| 項目 | 值 |
|---|---|
| 執行日期 |  |
| 執行者（agent / 人） |  |
| 作業系統 + 版本 |  |
| 儲存庫 commit（`git rev-parse HEAD`） |  |
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
| （逐項抄錄 `acceptance-macos.md` 案例表） |  |  |  |

## 彙總

| 面向 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| 瀏覽器 |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |

**整體結論（一句話）**：

**FAIL 的案例（若有）逐項填寫：現象 / 預期 / 證據 / 初步判斷原因**：

**BLOCKED 的案例逐項填寫原因**（例如 `permission-denied` / `capability-unavailable` / `no host verdict` / 缺語言套件 / 環境未接 host）：

> 本報告記錄本次驗收結果，不單獨構成發佈證明；簽章、公證/商店審核、發佈套件身分、嚴格門禁與平台覆蓋須另行核驗。

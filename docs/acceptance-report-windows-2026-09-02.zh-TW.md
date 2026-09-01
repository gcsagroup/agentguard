[簡體中文](acceptance-report-windows-2026-09-02.md) | [繁體中文](acceptance-report-windows-2026-09-02.zh-TW.md) | [English](acceptance-report-windows-2026-09-02.en.md)

# AgentGuard Windows 真機補充驗收報告（2026-09-02）

> 結論：最終候選 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在真實 Windows 11 上通過自動化、Release 建置、啟動、閒置、兩輪觀察與真實阻斷模態 smoke；測試期間沒有新增應用程式崩潰事件。但 W1–W7 的完整發佈級情境、Authenticode 簽章與安裝／升級／解除安裝仍未完成，生產發佈仍為 **No-Go**。

本報告是 [2026-09-01 整體驗收報告](acceptance-report-2026-09-01.zh-TW.md) 的 Windows 補充紀錄，執行依據為 [Windows 真機驗收清單](acceptance-windows.zh-TW.md)、[真機驗收執行手冊](acceptance-runbook.zh-TW.md) 與 [報告範本](acceptance-report-template.zh-TW.md)。它不是 `evidence/windows/` 下的 strict artifact；沒有逐項證據檔案的案例不會猜測為 `PASS (native)`。

## 1. 候選與證據邊界

本輪連續複測了四個程式碼身分，結果不能互相替代：

| 候選 | 結果 | 邊界 |
|---|---|---|
| `e9648eb86a8e82d83cd3c144de874565712e2c5f` | 自動化與 Release 建置通過；互動啟動在主視窗出現前以退出碼 101 失敗，stderr 為 `OleInitialize failed! Result was: RPC_E_CHANGED_MODE` | 證明舊候選存在主執行緒 COM apartment 衝突；自動化全綠不等於桌面程式可啟動 |
| `f9bcecd` | COM 啟動衝突關閉後進入程式，但出現 `0xC0000005`；Windows Event 1000 的 RVA `0x4b4a7c` 符號化至 `OcrEngine TryCreate`／`FactoryCache` 路徑 | 該候選失敗，不繼承為最終候選 PASS |
| `ea9cb1a` | 閒置啟動穩定；第一輪觀察到第 8 幀時再次出現 `0xC0000005` | 證明僅閒置存活不足以關閉 OCR／觀察鏈崩潰 |
| `89dadf960a558d35dc3c6c557eadbc19d3a162d0` | 自動化、Clippy、Release 建置、互動啟動與兩輪觀察 smoke 均完成；本輪新增 Event 1000 為 0 | 本報告的最終程式碼候選；發佈邊界仍見第 6、7 節 |

`e9648eb` 上的 5/5 門禁測試只驗證結構化發佈證據校驗器的測試集合，不等於 strict 發佈門禁已經通過，也不等於 W1–W7 真機驗收通過。

## 2. 環境與遠端連線

| 項目 | 值 |
|---|---|
| 執行日期 | 2026-09-02（Asia/Shanghai） |
| 作業系統 | Windows 11 Pro，build 26200 |
| Rust | `rustc 1.98.0`、`cargo 1.98.0`，目標 `x86_64-pc-windows-msvc` |
| 最終程式碼候選 | `89dadf960a558d35dc3c6c557eadbc19d3a162d0` |
| 自動化通道 | WinRM over HTTPS 5986，NTLM |
| 互動通道 | Windows 圖形桌面工作階段，用於真實視窗、按鈕、模態與生命週期檢查 |
| CI | GitHub Actions run [33551495621](https://github.com/gcsagroup/agentguard/actions/runs/33551495621)，針對 `89dadf9` 全綠 |

5986 的服務憑證為自我簽署，且 SAN 與連線目標不符；用戶端只在這次受控測試中關閉憑證驗證。5985 無法連線。該設定可用於本次診斷，**不構成生產可信 TLS**，報告也不記錄主機位址、帳號或密碼。

## 3. 自動化與建置結果

### 3.1 舊候選 `e9648eb`

| 範圍 | 結果 | 備註 |
|---|---|---|
| 結構化發佈證據門禁測試 | 5/5 PASS | 測試集合通過；不是 strict release gate PASS |
| 根工作區 | 901 passed / 2 ignored | `cargo +stable test --workspace --locked` |
| `win-adapter` 全目標建置 | PASS | Windows 原生工具鏈 |
| `win-adapter` Clippy `-D warnings` | PASS | 無 warning 放行 |
| Windows desktop tests | 2/2 PASS | 當時的自動測試沒有涵蓋真實視窗啟動 |
| Release EXE | 建置 PASS | 14,341,632 bytes；SHA-256 `11389F7F6CBA1815C836CC14A93FC5B03A2B2B064E86E220829625153888F20E`；Authenticode `NotSigned` |
| 互動啟動 | **FAIL** | 退出碼 101；`RPC_E_CHANGED_MODE`；未顯示主視窗 |

### 3.2 最終候選 `89dadf960a558d35dc3c6c557eadbc19d3a162d0`

| 範圍 | 結果 | 備註 |
|---|---|---|
| Windows desktop tests | 5/5 PASS | 包含啟動執行緒／觀察鏈相關迴歸涵蓋 |
| Windows desktop Clippy `-D warnings` | PASS | 目前 Windows 工具鏈實跑 |
| Release build | PASS | Windows MSVC Release 產物 |
| GitHub Actions | 全綠 | run `33551495621`，綁定 `89dadf9` |

最終 Release 可執行檔：

| 項目 | 值 |
|---|---|
| 檔案 | `desktop-windows.exe` |
| 大小 | 14,343,168 bytes |
| SHA-256 | `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119` |
| Authenticode | `NotSigned` |

雜湊只綁定本輪本機產物；由於 Authenticode 為 `NotSigned`，它不是可對外發佈的已簽章 Windows 安裝產物。

## 4. 最終候選互動 smoke

| 步驟 | 觀察結果 | 判定邊界 |
|---|---|---|
| 啟動後閒置 | 主視窗穩定存活超過 30 秒 | 支援 W0 啟動 smoke，不等於 W1–W7 |
| 更新能力兩次 | 兩次更新均保持穩定，能力狀態可顯示 | 證明正向顯示路徑可執行；能力失敗分支未執行 |
| 第一輪 `Start` | 觀察超過 30 秒；出現真實阻斷模態，內容為 `Accessibility-tree text not rendered on screen`，規則 `OVL-010`；選擇拒絕 | 證明目前產品鏈能產生真實阻斷模態；不是清單 W1 的付款 CTA 情境 |
| 生命週期切換 | `End` → `Resume` → `Start` 進入第二輪，介面與行程保持穩定 | 支援兩輪工作階段生命週期 smoke |
| 第二輪 `Start` | 再觀察超過 30 秒；再次出現同類 `OVL-010` 阻斷模態；選擇拒絕 | 第二輪 UIA／GDI／OCR／判決鏈沒有重現早期崩潰 |
| 關閉 | 最終透過正常介面關閉；測試視窗內新增 Windows Event 1000 數量為 0 | 沒有觀察到應用程式崩潰事件 |

stderr 只有「Release 未啟用 SQLCipher」的警告。批次 helper 的退出碼檔案為空，原因是 `echo 0>` 的重新導向解析歧義；因此本報告只記錄「正常介面關閉」和「新增 Event 1000 為 0」，**不宣稱行程退出碼為 0**。

本輪支援的範圍為：W0 啟動、正向能力顯示、UIA／GDI／OCR 產品鏈、阻斷模態，以及兩輪工作階段生命週期。它沒有取代下列 W1–W7 的精確情境。

## 5. W1–W7 正式清單結果

| 案例 | 結果 | 本輪已有觀察 | 仍缺的發佈級證據 |
|---|---|---|---|
| W1 阻斷模態（付款 CTA） | `BLOCKED (payment-CTA-not-executed)` | 兩輪均出現真實 `OVL-010` 阻斷模態並選擇拒絕 | 未在一般第三方應用程式中執行「Confirm Payment／確認支付」，也未證明取消後付款副作用為零 |
| W2 UIA 取樹 | `BLOCKED (form-FM-TR-case-not-executed)` | 觀察鏈與基於 Accessibility tree 的判決路徑執行穩定 | 未在真實第三方表單中歸檔 `UiTreeDelta` 及非必要 PII 的 FM/TR 判決 |
| W3 GDI 擷取影格 + 隱寫 | `BLOCKED (third-party-steganography-not-executed)` | 兩輪觀察沒有重現第 8 幀崩潰 | 未在第三方應用程式中執行 chroma／luma 隱寫樣本並歸檔影格與規則命中 |
| W4 Windows.Media.Ocr 讀屏 | `BLOCKED (third-party-pixel-OCR-not-executed)` | 最終候選的 UIA／GDI／OCR 鏈連續執行，兩輪均無新增 Event 1000 | 未執行只存在於第三方應用程式像素中的付款文字，也未歸檔語言套件、辨識輸出與對應判決 |
| W5 overlay 邊界 | `BLOCKED (overlay-boundary-not-executed)` | 無 | 未對比目標視窗自繪覆蓋與另一行程覆蓋的 Windows 窄邊界 |
| W6 能力探針 | `BLOCKED (capability-failure-branch-not-executed)` | 兩次更新可顯示正向能力狀態 | 未逐項觸發 UIA／擷取／OCR 不可用狀態並驗證原因字串與 fail-closed 行為 |
| W7 原生訊息 | `BLOCKED (native-messaging-not-installed)` | 無 | 未安裝登錄檔 manifest，未執行 Chrome／Edge origin 握手、host 判決與簽章稽核 |

| 面向 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---:|---:|---:|---:|---:|
| Windows 正式清單（W1–W7） | 0 | 0 | 0 | 7 | 0 |

這裡的 0 FAIL 只表示最終候選沒有在已執行到可判定狀態的 W1–W7 案例上記錄失敗；七項仍是 `BLOCKED`，不能解釋為 Windows 驗收通過。

## 6. 未完成的發佈門禁

以下項目仍未執行或沒有發佈級證據：

1. W1 付款 CTA 的執行前阻斷與拒絕後零副作用；
2. W2 的真實第三方表單、`UiTreeDelta` 與 FM/TR 證據；
3. W3／W4 的第三方應用程式像素隱寫與 OCR 情境；
4. W5 的 Windows overlay 擷取邊界；
5. W6 的能力不可用／失敗原因分支；
6. W7 Native Messaging 註冊、origin 握手、判決和簽章稽核；
7. Authenticode 簽章的安裝套件，以及安裝、升級、回復與解除安裝；
8. 依 strict 範本為 W1–W7 逐項歸檔唯一、非空、綁定目前提交的 `evidence/windows/` 證據。

## 7. 總體結論

`89dadf960a558d35dc3c6c557eadbc19d3a162d0` 在本輪相同啟動與觀察路徑中沒有重現早期的 COM／OCR 崩潰，兩輪生命週期 smoke 保持穩定，CI 也針對該候選全綠。這使 Windows 狀態從「程式無法啟動」推進到「真實產品 smoke 可執行」。但由於 W1–W7 仍為 0/7 正式 PASS，Release EXE 未簽章，安裝／升級／解除安裝未驗收，**生產發佈結論仍為 No-Go**。

下一次驗收應使用同一個不可變提交產生已簽章安裝套件，在一般第三方應用程式與真實 Chrome／Edge 上逐項執行 W1–W7，並把每條獨立證據歸檔至 `evidence/windows/` 後再執行 strict 門禁。

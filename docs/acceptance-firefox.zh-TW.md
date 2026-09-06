[简体中文](acceptance-firefox.md) | [繁體中文](acceptance-firefox.zh-TW.md) | [English](acceptance-firefox.en.md)

# Firefox 排除說明（首個 GA）

> **這不是首個 GA 的驗收清單，也不能產生 Firefox PASS。**

首個 GA 只發佈 Chrome / Edge 共用的 Chromium ZIP。Firefox 目前僅保留 `manifest.firefox.json` 與相關原始碼，作為未來研發起點：不封裝、不暫時載入作發佈驗收、不提交 Firefox 商店，也不進入 `scripts/release-gate.sh --strict`。

## 目前必須成立的範圍保護

- `apps/extension-chromium/scripts/package-store.sh --firefox` 回傳非零且不產生 Firefox ZIP；
- Chrome / Edge ZIP 不包含 `manifest.firefox.json`、Native host 或 Firefox 專屬中繼資料；
- 首個 GA 的 README、商店文案、權限說明、驗收報告與發佈結論都不得聲稱支援 Firefox；
- 歷史 F1–F8 報告、Firefox 截圖、`AGENTGUARD_ACCEPTANCE_FIREFOX=PASS` 或 `acceptance_firefox` JSON 都不能授權首個 GA 發佈。

目前唯一可執行的是負向範圍檢查：

```bash
make check-extension-gate
apps/extension-chromium/scripts/package-store.sh --firefox
# 預期：退出 64，且不產生 Firefox 套件。
```

第二條指令失敗是預期的範圍保護行為；它不產生任何 Firefox 產品 PASS。

## 遺留 CLI 能力

`guard-cli manual-acceptance firefox`、`evidence-template --kind acceptance_firefox` 與對應驗證程式碼暫時保留，屬於舊版/未來格式相容能力。嚴格閘門不讀取 `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`，也不接受該 kind 作為首個 GA 證據。直接呼叫得到的成功標記只表示遺留格式本身通過，不能改變產品範圍。

## Firefox 未來重新進入發佈範圍的前置條件

只有在單獨產品決策後，才可建立新的 Firefox 發佈清單。至少需要：

1. 重新審查 Firefox manifest、權限與商店隱私聲明；
2. 建立獨立且可重現的 Firefox 封裝路徑，不得沿用 Chromium ZIP 結論；
3. 在真實 Firefox 驗證 DOM、Shadow DOM、frame、DNR 方法/編碼/資源類型與誤報邊界；
4. 單獨完成全新安裝、升級、解除安裝、回滾與商店候選身分綁定；
5. 若未來考慮 Native Messaging，必須另做權限、身分、隱私與升級遷移設計，不得繼承首個 GA 的舊原型；
6. 新增明確的 Firefox evidence kind、嚴格閘門接線與三語發佈文件後，才可改變支援矩陣。

在所有條件完成前，Firefox 狀態固定為：**原始碼原型 / 非首個 GA / 無發佈 PASS**。

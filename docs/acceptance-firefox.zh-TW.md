[简体中文](acceptance-firefox.md) | [繁體中文](acceptance-firefox.zh-TW.md) | [English](acceptance-firefox.en.md)

# Firefox 擴充功能真機驗收清單（Launch Readiness）

本文件用於在**真實 Firefox（≥128）**上對擴充功能進行發佈前人工驗收。它對應 `docs/跨浏览器.md` 中
Firefox 那幾項「骨架已完成、真機未驗證」的項目——**這些只有在真 Firefox 上跑過一次才算數**，離線自動化
和 `node --check` 都無法驗證。

> 本清單全綠只是發佈的必要非充分條件；它不能取代商店簽章、發佈套件身分、其餘平台證據或完整發佈門禁。

> **前置的離線門禁**：先在儲存庫根目錄執行 `make check-extension-gate`（guard-gate 邏輯 + 兩份 manifest
> 結構一致）。它全綠是必要非充分條件——它證明「Chrome 與 Firefox 安裝同一套內容指令碼、判決邏輯正確」，
> 不證明「在真 Firefox 裡確實攔得住」。

## 前置條件

- [ ] Firefox 版本 ≥ 128（`world: "MAIN"` 內容指令碼從 128 起支援——低於它 fetch 門不會載入）
- [ ] 使用 `about:debugging` →「此 Firefox」→「暫時載入附加元件」載入 `manifest.firefox.json`
      （或 `package-store.sh --firefox` 產生的 zip）
- [ ] 記下暫時載入分配的 **gecko id**（應為 `agentguard@agentguard.dev`）
- [ ] `install-host.sh --browser firefox agentguard@agentguard.dev` 安裝原生訊息 host
- [ ] 規則集為 `crates/guard-schema/rules/p0_rules.yaml`；情報 bundle 已載入（預設基線即包含 `evil.example`）

## 驗收案例

每一項都要在**真 Firefox** 上手動走一遍，保留證據（螢幕截圖 / about:debugging 主控台日誌）。

| # | 步驟 | 預期 | 實測 | 證據 |
|---|------|------|------|------|
| F1 | 開啟含隱藏注入文字（`[AG_INVISIBLE_TEXT]` / "ignore previous instructions"）的測試頁 | 擴充功能回報 finding（popup 最近清單出現） | | |
| F2 | 頁面上放一個文案含「確認支付/Confirm Payment」的按鈕並點擊 | **執行前**彈出 AgentGuard 確認層（「允許這一次/先不要」）；點「先不要」→ 動作不發生 | | |
| F3 | 一個把非必要 PII（手機號碼）填入陷阱控制項的表單並送出 | 送出被 `preventDefault` 攔住並彈出確認；取消 → 不送出 | | |
| F4 | 頁面指令碼 `fetch("/api/checkout",{method:"POST"})`（在頁面主控台執行） | fetch 門彈出確認；拒絕 → Promise reject、請求**未送出**（Network 面板沒有該請求） | | |
| F5 | 同 F4 但使用 `GET` | **不**攔截（唯讀方法不應有副作用） | | |
| F6 | 導覽至 `https://evil.example/`（內建情報的惡意網域） | 引擎判 `INTEL-DOMAIN` Block → host 回傳 `block_hosts` → DNR 規則裝上 → 該主機後續請求在網路層被攔（Network 面板顯示 blocked） | | |
| F7 | 觀察 F6 的原生訊息往返 | host 接受呼叫端（gecko id 與 origin 對上，`guard-nm-host` 未因 origin 拒絕啟動），判決進入簽章稽核 | | |
| F8 | DNR 動態規則數量 | 未超過 Firefox 的動態規則配額（安裝規則不報錯；必要時依配額上限截斷清單） | | |

## 這些案例分別驗證 docs/跨浏览器.md 的哪一項「未驗證」

- F2/F3 → DOM 門在 Firefox 成立
- **F4/F5 → `world:"MAIN"` 的 fetch 門在 FF≥128 確實載入並攔截**（跨浏览器.md 明確標為待驗）
- F6 → E5 引擎→DNR 橋接 + F8 DNR 配額（跨浏览器.md 標為「配額待校準」）
- F7 → **native host 收到的呼叫端識別是 gecko id 而非 chrome-extension:// origin**（跨浏览器.md 標為
  「依 MDN 編寫、真機未驗」）——這一項是 fail-closed 的 origin 驗證，驗不過 host 會拒絕啟動，因此必須真機走通

## 快速命令

```bash
# 離線門禁（必須先 PASS）
make check-extension-gate

# 產生 Firefox 套件
apps/extension-chromium/scripts/package-store.sh --firefox

# 安裝 Firefox 原生訊息 host（gecko id 見 manifest.firefox.json）
apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev
```

## 簽署

- 驗收人：____________  版本 / commit：____________  日期：____________
- 全部案例 PASS 後，把證據目錄路徑匯出至 `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`，再執行
  `scripts/release-gate.sh --strict`，讓這一項從「未驗證」轉為已驗證。

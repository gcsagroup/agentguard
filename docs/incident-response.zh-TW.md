[简体中文](incident-response.md) | [繁體中文](incident-response.zh-TW.md) | [English](incident-response.en.md)

# 生產事故回應手冊

Sev-0 是大規模安全／隱私損害、供應鏈／簽署破壞或無法停止的錯誤高風險動作；Sev-1 是多用戶核心保護／審計不可用、更新／回滾斷裂或可擴大的繞過；Sev-2 是有安全替代路徑的局部退化；Sev-3 是不影響保護語義的輕微問題。Sev-0/1 立即停止擴量。

流程：記錄 UTC、來源、commit/artifact-set、渠道及影響（不放憑證或未脫敏 PII）；指定 Incident Commander 與技術、運維、安全、隱私／法務、溝通負責人；暫停渠道及功能開關並保留現場；以雙人複核的已驗證產物緩解／回滾；重跑受影響 RC、smoke 與回歸；完成時間線、根因、通知和跟進後才關單。

恢復需 Incident Commander、Release、Security、Operations 同意；涉及個資或商店聲明時也需 Privacy/Legal。事故中斷的 Beta／擴量時鐘不能繼承，舊 `--ga` 日誌也不能為新候選背書。

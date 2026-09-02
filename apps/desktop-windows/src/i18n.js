/* E16 消费者化:所有用户第一眼看到的词都是人话;内部术语(UI Automation / GDI / OCR)
 * 只作为括号补充留给想深究的人。演示与诊断词条(threats/syncPolicy/…)只出现在
 * 默认折叠的开发者面板里。新增 key 时三语一起补。 */
const dictionaries = {
  en: {
    subtitle: "Guards what AI agents do on this PC",
    "action.block": "Blocked", "action.alert": "Alert", "action.allow": "Allowed", "action.logonly": "Logged",
    observing: "Watching", notObserving: "Not watching",
    observation: "Live observation", pollNow: "Observe once now",
    capUiTree: "Read window contents (UI Automation)", capFrame: "Capture the screen (GDI)", capOcr: "Read text on screen (OCR)",
    capAvailable: "available", capUnavailable: "unavailable",
    threatsNote: "Replays fixtures through the engine. Not observation — these buttons prove the rules fire, not that this machine is being watched.",
    language_label: "Language", system: "System", en: "English", zhHans: "Simplified Chinese", zhHant: "Traditional Chinese",
    idle: "Idle", pending: "Confirmation required", paused: "Paused", simulating: "Simulation", protecting: "Protected",
    guard: "Protection", start: "Start session", end: "End session", resume: "Resume",
    taskLabel: "Task", taskNone: "(any task)",
    taskBookHotel: "Book a hotel", taskOrderFood: "Order food", taskNavigate: "Navigate pages", taskPrefSave: "Save preferences",
    autoApprove: "Auto-approve high-risk confirmations (testing only)", reloadIntel: "Update threat intelligence",
    devPanel: "Developer panel (demos & diagnostics)",
    threats: "Simulate threats", payment: "Payment confirmation", fm: "Optional PII", trap: "Privacy trap",
    overlay: "Transparent overlay", inject: "Intel injection", domain: "Malicious domain", netmon: "Exfiltration monitor",
    syncPolicy: "Sync enterprise policy", audit: "Activity timeline", export: "Export summary", refresh: "Refresh",
    confirm: "AgentGuard paused a high-risk action", deny: "Not now", approve: "Allow once",
    rules: "rules", plan: "plan", policy: "policy", privacy: "privacy score", initError: "Initialization failed: {error}",
    "state.stopped": "Not protecting", "state.confirmation_pending": "Waiting for your decision", "state.paused": "Paused",
    "state.permission_required": "Permission needed", "state.observer_starting": "Starting to watch…",
    "state.degraded": "Protection incomplete", "state.active": "Protecting",
    "reason.no_session": "No protection session is running. Press Start to begin.",
    "reason.confirm_pending": "A high-risk action is waiting for you to allow or stop it.",
    "reason.engine_paused": "Protection is paused after a critical block. Press Resume to continue.",
    "reason.no_observer_available": "This PC cannot read window contents or capture the screen — only simulation is active.",
    "reason.observer_warming_up": "The watcher just started and has not reported yet.",
    "reason.observer_not_running": "No watcher is running.",
    "reason.observer_error": "The watcher stopped with an error: {detail}",
    "reason.heartbeat_never": "The watcher has not reported anything since the session began.",
    "reason.heartbeat_stale": "The watcher has not reported for {age}s — it may be stuck.",
    "reason.audit_disabled": "The activity log is not open, so nothing is being recorded.",
    "reason.audit_unwritable": "The activity log cannot be written: {detail}",
    folded: "{n} repeated observations folded"
  },
  "zh-Hans": {
    subtitle: "实时守护 AI 智能体在这台电脑上的操作",
    "action.block": "已拦截", "action.alert": "提醒", "action.allow": "已放行", "action.logonly": "已记录",
    observing: "观察中", notObserving: "未在观察",
    observation: "实时观察", pollNow: "立即观察一次",
    capUiTree: "读取窗口内容（UI Automation）", capFrame: "捕获屏幕画面（GDI）", capOcr: "识别屏幕文字（OCR）",
    capAvailable: "可用", capUnavailable: "不可用",
    threatsNote: "这些按钮把语料回放进引擎，不是观察。它们证明规则会触发，不证明这台机器正在被守护。",
    language_label: "语言", system: "跟随系统", en: "English", zhHans: "简体中文", zhHant: "繁體中文",
    idle: "待命", pending: "待确认", paused: "已暂停", simulating: "仿真中", protecting: "守护中",
    guard: "守护", start: "开始会话", end: "结束会话", resume: "恢复暂停",
    taskLabel: "本次任务", taskNone: "（不限定任务）",
    taskBookHotel: "订酒店", taskOrderFood: "点外卖", taskNavigate: "页面跳转", taskPrefSave: "保存偏好",
    autoApprove: "自动批准高危确认（仅测试用）", reloadIntel: "更新威胁情报",
    devPanel: "开发者面板（演示与诊断）",
    threats: "注入演示威胁", payment: "支付确认", fm: "非必要个人信息", trap: "隐私陷阱",
    overlay: "透明浮层", inject: "提示词注入", domain: "恶意域名", netmon: "数据外传监测",
    syncPolicy: "同步企业策略", audit: "活动时间线", export: "导出摘要", refresh: "刷新",
    confirm: "AgentGuard 拦下了一个高危操作", deny: "先不要", approve: "允许这一次",
    rules: "规则", plan: "计划", policy: "策略", privacy: "隐私分", initError: "初始化失败：{error}",
    "state.stopped": "未在守护", "state.confirmation_pending": "等你决定", "state.paused": "已暂停",
    "state.permission_required": "需要授权", "state.observer_starting": "正在启动观察…",
    "state.degraded": "守护不完整", "state.active": "守护中",
    "reason.no_session": "没有正在进行的守护会话。点「开始会话」。",
    "reason.confirm_pending": "有一个高风险操作在等你放行或阻止。",
    "reason.engine_paused": "关键拦截后守护已暂停。点「恢复」继续。",
    "reason.no_observer_available": "这台电脑读不到窗口内容也抓不到屏幕——现在只有仿真在起作用。",
    "reason.observer_warming_up": "观察刚启动，还没有汇报。",
    "reason.observer_not_running": "没有任何观察在运行。",
    "reason.observer_error": "观察因错误停止：{detail}",
    "reason.heartbeat_never": "会话开始以来观察还没有汇报过任何内容。",
    "reason.heartbeat_stale": "观察已 {age} 秒没有汇报——可能卡住了。",
    "reason.audit_disabled": "活动记录没有打开，任何事都没被记下来。",
    "reason.audit_unwritable": "活动记录写不进去：{detail}",
    folded: "已折叠 {n} 条重复观察"
  },
  "zh-Hant": {
    subtitle: "即時守護 AI 代理在這台電腦上的操作",
    "action.block": "已攔截", "action.alert": "提醒", "action.allow": "已放行", "action.logonly": "已記錄",
    observing: "觀察中", notObserving: "未在觀察",
    observation: "即時觀察", pollNow: "立即觀察一次",
    capUiTree: "讀取視窗內容（UI Automation）", capFrame: "擷取螢幕畫面（GDI）", capOcr: "辨識螢幕文字（OCR）",
    capAvailable: "可用", capUnavailable: "不可用",
    threatsNote: "這些按鈕把語料回放進引擎，不是觀察。它們證明規則會觸發，不證明這台機器正在被守護。",
    language_label: "語言", system: "跟隨系統", en: "English", zhHans: "简体中文", zhHant: "繁體中文",
    idle: "待命", pending: "待確認", paused: "已暫停", simulating: "模擬中", protecting: "守護中",
    guard: "守護", start: "開始工作階段", end: "結束工作階段", resume: "恢復",
    taskLabel: "本次任務", taskNone: "（不限定任務）",
    taskBookHotel: "訂飯店", taskOrderFood: "點外送", taskNavigate: "頁面跳轉", taskPrefSave: "儲存偏好",
    autoApprove: "自動批准高風險確認（僅測試用）", reloadIntel: "更新威脅情資",
    devPanel: "開發者面板（示範與診斷）",
    threats: "模擬威脅", payment: "付款確認", fm: "非必要個資", trap: "隱私陷阱",
    overlay: "透明浮層", inject: "提示詞注入", domain: "惡意網域", netmon: "資料外洩監測",
    syncPolicy: "同步企業原則", audit: "活動時間軸", export: "匯出摘要", refresh: "重新整理",
    confirm: "AgentGuard 攔下了一個高風險操作", deny: "先不要", approve: "允許這一次",
    rules: "規則", plan: "方案", policy: "原則", privacy: "隱私分數", initError: "初始化失敗：{error}",
    "state.stopped": "未在守護", "state.confirmation_pending": "等你決定", "state.paused": "已暫停",
    "state.permission_required": "需要授權", "state.observer_starting": "正在啟動觀察…",
    "state.degraded": "守護不完整", "state.active": "守護中",
    "reason.no_session": "沒有正在進行的守護工作階段。點「開始工作階段」。",
    "reason.confirm_pending": "有一個高風險操作在等你放行或阻止。",
    "reason.engine_paused": "關鍵攔截後守護已暫停。點「恢復」繼續。",
    "reason.no_observer_available": "這台電腦讀不到視窗內容也抓不到螢幕——現在只有模擬在起作用。",
    "reason.observer_warming_up": "觀察剛啟動，還沒有回報。",
    "reason.observer_not_running": "沒有任何觀察在執行。",
    "reason.observer_error": "觀察因錯誤停止：{detail}",
    "reason.heartbeat_never": "工作階段開始以來觀察還沒有回報過任何內容。",
    "reason.heartbeat_stale": "觀察已 {age} 秒沒有回報——可能卡住了。",
    "reason.audit_disabled": "活動記錄沒有開啟，任何事都沒被記下來。",
    "reason.audit_unwritable": "活動記錄寫不進去：{detail}",
    folded: "已折疊 {n} 條重複觀察"
  }
};

const KEY = "agentguard.locale";
let locale = "en";
const systemLocale = () => {
  const lang = (navigator.languages?.[0] || navigator.language || "en").toLowerCase();
  if (/zh-(tw|hk|mo)|hant/.test(lang)) return "zh-Hant";
  return lang.startsWith("zh") ? "zh-Hans" : "en";
};

export function t(key, vars = {}) {
  const template = dictionaries[locale]?.[key] ?? dictionaries.en[key] ?? key;
  return Object.entries(vars).reduce((s, [k, v]) => s.replaceAll(`{${k}}`, String(v)), template);
}

export function applyTranslations() {
  document.documentElement.lang = locale === "zh-Hans" ? "zh-CN" : locale === "zh-Hant" ? "zh-TW" : "en";
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  const select = document.getElementById("locale-select");
  if (select) select.value = localStorage.getItem(KEY) || "system";
}

export function initializeI18n() {
  const mode = localStorage.getItem(KEY) || "system";
  locale = mode === "system" ? systemLocale() : mode;
  applyTranslations();
  document.getElementById("locale-select")?.addEventListener("change", (event) => {
    const value = event.target.value;
    localStorage.setItem(KEY, value);
    locale = value === "system" ? systemLocale() : value;
    applyTranslations();
    window.dispatchEvent(new CustomEvent("agentguard-locale-change"));
  });
}

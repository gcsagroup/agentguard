const dictionaries = {
  en: {
    observing: "Observing", notObserving: "Not observing",
    observation: "Live observation", pollNow: "Observe once now",
    capUiTree: "UI tree (UI Automation)", capFrame: "Window capture (GDI)", capOcr: "Screen text (Windows OCR)",
    capAvailable: "available", capUnavailable: "unavailable",
    threatsNote: "Replays fixtures through the engine. Not observation \u2014 these buttons prove the rules fire, not that this machine is being watched.",
    language_label: "Language", system: "System", en: "English", zhHans: "Simplified Chinese", zhHant: "Traditional Chinese",
    idle: "Idle", pending: "Confirmation required", paused: "Paused", simulating: "Simulation", protecting: "Protected",
    guard: "Guard controls", start: "Start session", end: "End session", resume: "Resume",
    autoApprove: "Auto-approve critical confirmations (test only)", reloadIntel: "Reload threat intel",
    threats: "Simulate threats", payment: "Payment confirmation", fm: "Optional PII", trap: "Privacy trap",
    overlay: "Transparent overlay", inject: "Intel injection", domain: "Malicious domain", netmon: "Exfiltration monitor",
    syncPolicy: "Sync enterprise policy", audit: "Audit timeline", export: "Export summary", refresh: "Refresh",
    confirm: "High-risk action confirmation", deny: "Deny and pause", approve: "Allow once",
    rules: "rules", plan: "plan", policy: "policy", privacy: "privacy", initError: "Initialization failed: {error}"
  },
  "zh-Hans": {
    observing: "观察中", notObserving: "未在观察",
    observation: "实时观察", pollNow: "立即观察一次",
    capUiTree: "UI 树（UI Automation）", capFrame: "窗口捕获（GDI）", capOcr: "屏幕文字（Windows OCR）",
    capAvailable: "可用", capUnavailable: "不可用",
    threatsNote: "这些按钮把语料回放进引擎，不是观察。它们证明规则会触发，不证明这台机器正在被守护。",
    language_label: "语言", system: "跟随系统", en: "English", zhHans: "简体中文", zhHant: "繁體中文",
    idle: "待命", pending: "待确认", paused: "已暂停", simulating: "仿真中", protecting: "守护中",
    guard: "守护控制", start: "开始会话", end: "结束会话", resume: "恢复暂停",
    autoApprove: "Critical Confirm 自动批准（测试用）", reloadIntel: "重载 Threat Intel",
    threats: "注入演示威胁", payment: "支付确认", fm: "Optional PII", trap: "隐私陷阱",
    overlay: "透明浮层", inject: "Intel 注入", domain: "恶意域名", netmon: "外传监测",
    syncPolicy: "同步企业策略", audit: "审计时间线", export: "导出摘要", refresh: "刷新",
    confirm: "高危操作确认", deny: "拒绝并暂停", approve: "允许一次",
    rules: "规则", plan: "计划", policy: "策略", privacy: "隐私分", initError: "初始化失败：{error}"
  },
  "zh-Hant": {
    observing: "觀察中", notObserving: "未在觀察",
    observation: "即時觀察", pollNow: "立即觀察一次",
    capUiTree: "UI 樹（UI Automation）", capFrame: "視窗擷取（GDI）", capOcr: "螢幕文字（Windows OCR）",
    capAvailable: "可用", capUnavailable: "不可用",
    threatsNote: "這些按鈕把語料回放進引擎，不是觀察。它們證明規則會觸發，不證明這台機器正在被守護。",
    language_label: "語言", system: "跟隨系統", en: "English", zhHans: "简体中文", zhHant: "繁體中文",
    idle: "待命", pending: "待確認", paused: "已暫停", simulating: "模擬中", protecting: "守護中",
    guard: "守護控制", start: "開始工作階段", end: "結束工作階段", resume: "恢復",
    autoApprove: "自動批准 Critical Confirm（僅測試）", reloadIntel: "重新載入 Threat Intel",
    threats: "模擬威脅", payment: "付款確認", fm: "選填個資", trap: "隱私陷阱",
    overlay: "透明浮層", inject: "Intel 注入", domain: "惡意網域", netmon: "外洩監測",
    syncPolicy: "同步企業原則", audit: "稽核時間軸", export: "匯出摘要", refresh: "重新整理",
    confirm: "高風險操作確認", deny: "拒絕並暫停", approve: "允許一次",
    rules: "規則", plan: "方案", policy: "原則", privacy: "隱私分數", initError: "初始化失敗：{error}"
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

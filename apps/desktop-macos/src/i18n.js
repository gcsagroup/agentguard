const messages = {
  en: {
    "language.label": "Language",
    "language.system": "System",
    "language.en": "English",
    "language.zhHans": "Simplified Chinese",
    "language.zhHant": "Traditional Chinese",
    "status.idle": "Idle",
    "status.pending": "Confirmation required",
    "status.paused": "Paused",
    "status.simulating": "Simulation",
    "status.protecting": "Protected",
    "coverage.checking": "Protection coverage: checking…",
    "coverage.full": "Protection coverage: Full",
    "coverage.partial": "Protection coverage: Partial",
    "coverage.sim": "Protection coverage: Simulation",
    "coverage.ax": "Accessibility UI-tree monitoring",
    "coverage.capture": "ScreenCaptureKit pixel and overlay monitoring",
    "coverage.unavailable": "Unavailable until permission is granted",
    "tcc.title": "Permission setup (TCC)",
    "tcc.description": "Without permission, only simulation and extension protection are active. AgentGuard will not claim full protection.",
    "tcc.probe": "Check permissions",
    "tcc.axGranted": "Accessibility: granted",
    "tcc.axMissing": "System Settings → Privacy & Security → Accessibility → enable AgentGuard",
    "tcc.captureGranted": "Screen Recording: granted",
    "tcc.captureMissing": "System Settings → Privacy & Security → Screen Recording → enable AgentGuard",
    "intel.reload": "Reload threat intel",
    "guard.title": "Guard controls",
    "guard.start": "Start session",
    "guard.end": "End session",
    "guard.resume": "Resume",
    "guard.autoApprove": "Auto-approve critical confirmations (debug builds only)",
    "ax.title": "Accessibility (live AX)",
    "ax.description": "Requires Accessibility permission; captures the frontmost UI tree for FormFill classification and UI revalidation.",
    "ax.probe": "Probe AX",
    "ax.poll": "Capture frontmost AX",
    "ax.auto": "Auto-poll AX",
    "sck.description": "Requires Screen Recording permission; polls frames every 1.5s. Without TCC permission it fails safely and simulation remains available.",
    "sck.probe": "Probe SCK",
    "sck.start": "Start capture",
    "sck.stop": "Stop",
    "sck.poll": "Poll frames",
    "threat.title": "Simulate threats",
    "threat.payment": "Payment confirmation",
    "threat.fm": "Optional PII",
    "threat.trap": "Privacy trap",
    "threat.overlay": "Transparent overlay",
    "threat.inject": "Intel injection",
    "threat.domain": "Malicious domain",
    "threat.capture": "Overlay frame",
    "threat.netmon": "Exfiltration monitor",
    "policy.sync": "Sync enterprise policy",
    "audit.title": "Audit timeline",
    "audit.export": "Export summary",
    "common.refresh": "Refresh",
    "confirm.title": "High-risk action confirmation",
    "confirm.deny": "Deny and pause",
    "confirm.approve": "Allow once",
    "status.rules": "rules",
    "status.plan": "plan",
    "status.policy": "policy",
    "status.privacy": "privacy",
    "sck.autoOn": "1.5s auto-poll enabled",
    "sck.permissionMissing": "Screen Recording permission is missing; continuous capture was not started",
    "sck.noFrames": "No new frames. Start capture and grant Screen Recording permission first.",
    "error.init": "Initialization failed: {error}"
  },
  "zh-Hans": {
    "language.label": "语言",
    "language.system": "跟随系统",
    "language.en": "English",
    "language.zhHans": "简体中文",
    "language.zhHant": "繁體中文",
    "status.idle": "待命",
    "status.pending": "待确认",
    "status.paused": "已暂停",
    "status.simulating": "仿真中",
    "status.protecting": "守护中",
    "coverage.checking": "防护范围：检测中…",
    "coverage.full": "防护范围：完整",
    "coverage.partial": "防护范围：部分",
    "coverage.sim": "防护范围：仿真",
    "coverage.ax": "辅助功能界面树监控",
    "coverage.capture": "ScreenCaptureKit 像素与浮层监控",
    "coverage.unavailable": "授权后启用",
    "tcc.title": "权限引导（TCC）",
    "tcc.description": "未授权时仅仿真/扩展有效，不会静默声称“已在完整守护”。",
    "tcc.probe": "重新探测权限",
    "tcc.axGranted": "辅助功能：已授权",
    "tcc.axMissing": "系统设置 → 隐私与安全性 → 辅助功能 → 允许 AgentGuard",
    "tcc.captureGranted": "屏幕录制：已授权",
    "tcc.captureMissing": "系统设置 → 隐私与安全性 → 屏幕录制 → 允许 AgentGuard",
    "intel.reload": "重载 Threat Intel",
    "guard.title": "守护控制",
    "guard.start": "开始会话",
    "guard.end": "结束会话",
    "guard.resume": "恢复暂停",
    "guard.autoApprove": "Critical Confirm 自动批准（仅调试构建）",
    "ax.title": "Accessibility（真机 AX）",
    "ax.description": "需辅助功能授权；抓取前台窗口树 → FormFill 分类 + UI revalidate。",
    "ax.probe": "AX 探测",
    "ax.poll": "抓取前台 AX",
    "ax.auto": "AX 自动轮询",
    "sck.description": "需屏幕录制授权；开始后后台每 1.5s 自动拉取帧。无 TCC 时安全失败，仍可使用仿真。",
    "sck.probe": "SCK 探测",
    "sck.start": "开始捕获",
    "sck.stop": "停止",
    "sck.poll": "拉取帧",
    "threat.title": "注入演示威胁",
    "threat.payment": "支付确认",
    "threat.fm": "Optional PII",
    "threat.trap": "隐私陷阱",
    "threat.overlay": "透明浮层",
    "threat.inject": "Intel 注入",
    "threat.domain": "恶意域名",
    "threat.capture": "屏幕浮层帧",
    "threat.netmon": "外传监测",
    "policy.sync": "同步企业策略",
    "audit.title": "审计时间线",
    "audit.export": "导出摘要",
    "common.refresh": "刷新",
    "confirm.title": "高危操作确认",
    "confirm.deny": "拒绝并暂停",
    "confirm.approve": "允许一次",
    "status.rules": "规则",
    "status.plan": "计划",
    "status.policy": "策略",
    "status.privacy": "隐私分",
    "sck.autoOn": "已开启 1.5s 自动轮询",
    "sck.permissionMissing": "未获得屏幕录制权限，不会持续捕获",
    "sck.noFrames": "无新帧（需先开始捕获且已授权）",
    "error.init": "初始化失败：{error}"
  },
  "zh-Hant": {
    "language.label": "語言",
    "language.system": "跟隨系統",
    "language.en": "English",
    "language.zhHans": "简体中文",
    "language.zhHant": "繁體中文",
    "status.idle": "待命",
    "status.pending": "待確認",
    "status.paused": "已暫停",
    "status.simulating": "模擬中",
    "status.protecting": "守護中",
    "coverage.checking": "防護範圍：檢測中…",
    "coverage.full": "防護範圍：完整",
    "coverage.partial": "防護範圍：部分",
    "coverage.sim": "防護範圍：模擬",
    "coverage.ax": "輔助使用介面樹監控",
    "coverage.capture": "ScreenCaptureKit 像素與浮層監控",
    "coverage.unavailable": "授權後啟用",
    "tcc.title": "權限引導（TCC）",
    "tcc.description": "未授權時僅模擬/擴充功能有效，不會聲稱已啟用完整守護。",
    "tcc.probe": "重新檢查權限",
    "tcc.axGranted": "輔助使用：已授權",
    "tcc.axMissing": "系統設定 → 隱私權與安全性 → 輔助使用 → 允許 AgentGuard",
    "tcc.captureGranted": "螢幕錄製：已授權",
    "tcc.captureMissing": "系統設定 → 隱私權與安全性 → 螢幕錄製 → 允許 AgentGuard",
    "intel.reload": "重新載入 Threat Intel",
    "guard.title": "守護控制",
    "guard.start": "開始工作階段",
    "guard.end": "結束工作階段",
    "guard.resume": "恢復",
    "guard.autoApprove": "自動批准 Critical Confirm（僅偵錯版本）",
    "ax.title": "輔助使用（即時 AX）",
    "ax.description": "需要輔助使用權限；擷取最上層視窗樹以進行 FormFill 分類與 UI 重新驗證。",
    "ax.probe": "檢查 AX",
    "ax.poll": "擷取最上層 AX",
    "ax.auto": "自動輪詢 AX",
    "sck.description": "需要螢幕錄製權限；啟動後每 1.5 秒自動擷取畫面。沒有 TCC 權限時會安全失敗，仍可使用模擬。",
    "sck.probe": "檢查 SCK",
    "sck.start": "開始擷取",
    "sck.stop": "停止",
    "sck.poll": "擷取畫面",
    "threat.title": "模擬威脅",
    "threat.payment": "付款確認",
    "threat.fm": "選填個資",
    "threat.trap": "隱私陷阱",
    "threat.overlay": "透明浮層",
    "threat.inject": "Intel 注入",
    "threat.domain": "惡意網域",
    "threat.capture": "螢幕浮層畫面",
    "threat.netmon": "外洩監測",
    "policy.sync": "同步企業原則",
    "audit.title": "稽核時間軸",
    "audit.export": "匯出摘要",
    "common.refresh": "重新整理",
    "confirm.title": "高風險操作確認",
    "confirm.deny": "拒絕並暫停",
    "confirm.approve": "允許一次",
    "status.rules": "規則",
    "status.plan": "方案",
    "status.policy": "原則",
    "status.privacy": "隱私分數",
    "sck.autoOn": "已啟用 1.5 秒自動輪詢",
    "sck.permissionMissing": "未取得螢幕錄製權限，不會持續擷取",
    "sck.noFrames": "沒有新畫面（請先開始擷取並授權）",
    "error.init": "初始化失敗：{error}"
  }
};

const STORAGE_KEY = "agentguard.locale";
let locale = "en";

function systemLocale() {
  const lang = (navigator.languages?.[0] || navigator.language || "en").toLowerCase();
  if (lang.startsWith("zh-tw") || lang.startsWith("zh-hk") || lang.startsWith("zh-mo") || lang.includes("hant")) {
    return "zh-Hant";
  }
  if (lang.startsWith("zh")) return "zh-Hans";
  return "en";
}

export function t(key, vars = {}) {
  const template = messages[locale]?.[key] ?? messages.en[key] ?? key;
  return Object.entries(vars).reduce(
    (text, [name, value]) => text.replaceAll(`{${name}}`, String(value)),
    template,
  );
}

export function currentLocale() {
  return locale;
}

export function applyTranslations() {
  document.documentElement.lang = locale === "zh-Hans" ? "zh-CN" : locale === "zh-Hant" ? "zh-TW" : "en";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  const select = document.getElementById("locale-select");
  if (select) select.value = localStorage.getItem(STORAGE_KEY) || "system";
}

export function initializeI18n() {
  const mode = localStorage.getItem(STORAGE_KEY) || "system";
  locale = mode === "system" ? systemLocale() : mode;
  applyTranslations();
  const select = document.getElementById("locale-select");
  select?.addEventListener("change", () => {
    localStorage.setItem(STORAGE_KEY, select.value);
    locale = select.value === "system" ? systemLocale() : select.value;
    applyTranslations();
    window.dispatchEvent(new CustomEvent("agentguard-locale-change"));
  });
}

import { uiText, translateWorkspace } from "./workspace-i18n.js";
import { initializeGatewayConfirmation } from "./gateway-confirmation.js";

const byId = (id) => document.getElementById(id);
const ROUTES = new Set(["overview", "active", "activity", "settings", "help"]);
const TABS = ["observation", "risk", "privacy", "general"];
let route = "overview";
let status = null;
let installation = null;
let setupKind = null;
let setupGeneration = 0;
let setupOpener = null;
let invoke;

export function showFeedback(message, error = false) {
  const el = byId("workspace-feedback");
  el.textContent = message;
  el.dataset.error = String(error);
  el.hidden = !message;
}

export function showPage(next, focus = true) {
  if (!ROUTES.has(next)) return;
  if (route !== next) {
    showFeedback("");
    closeGuide(false);
  }
  route = next;
  document.querySelectorAll("[data-page]").forEach((el) => { el.hidden = el.dataset.page !== route; });
  document.querySelectorAll("[data-route]").forEach((el) => {
    el.ariaCurrent = el.dataset.route === route ? "page" : null;
  });
  byId("page-label").textContent = uiText(route);
  if (focus) byId(`${route}-title`)?.focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "instant" });
}

function setTab(next, focus = false) {
  if (!TABS.includes(next)) return;
  for (const tab of TABS) {
    const selected = tab === next;
    const panel = byId(`settings-${tab}`);
    panel.hidden = false;
    panel.ariaHidden = String(!selected);
    panel.tabIndex = selected ? 0 : -1;
    byId(selected ? "settings-content" : "settings-parking").append(panel);
    byId(`tab-${tab}`).ariaSelected = String(selected);
    byId(`tab-${tab}`).tabIndex = selected ? 0 : -1;
  }
  if (focus) byId(`tab-${next}`).focus();
}

function move(selector, slot) {
  const el = document.querySelector(selector);
  if (el) byId(slot).append(el);
}

function readPreference(key, fallback) {
  try { return localStorage.getItem(key) || fallback; } catch { return fallback; }
}

function savePreference(key, value) {
  try {
    localStorage.setItem(key, value);
    byId("preferences-feedback").textContent = uiText("saved");
    return true;
  } catch {
    showFeedback(uiText("saveFailed"), true);
    return false;
  }
}

const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");
function applyTheme(mode) {
  document.documentElement.dataset.theme = mode === "system" ? (themeMedia.matches ? "dark" : "light") : mode;
}

function renderInstallation() {
  byId("current-app-name").textContent = installation?.app_name || "AgentGuard.app";
  byId("installation-path").textContent = installation?.app_path || "";
  byId("channel-label").textContent = uiText(status?.build_profile ? "localTest" : "productionBuild");
}

export function renderWorkspace(st) {
  status = st;
  const readiness = {
    ax: [!!st.accessibility, st.accessibility ? "granted" : "missing"],
    screen: [!!st.screen_capture, st.screen_capture ? "granted" : "optionalOff"],
    audit: [!!st.audit_ready, st.audit_ready ? "ready" : "unavailable"],
  };
  document.querySelectorAll("[data-readiness]").forEach((el) => {
    const [ready, key] = readiness[el.dataset.readiness];
    el.textContent = uiText(key);
    el.dataset.state = ready ? "ready" : el.dataset.readiness === "screen" ? "optional" : "missing";
  });
  const state = st.protection_state;
  byId("overview-title").textContent = uiText(state === "active" ? "activeDesktopTitle" : !st.audit_ready || st.session_active ? "checkTitle" : st.accessibility ? "readyTitle" : "welcome");
  byId("overview-summary").textContent = !st.accessibility ? uiText("permissionSummary") : st.session_active || !st.audit_ready ? byId("watching").textContent : uiText("readySummary");
  byId("desktop-state").textContent = byId("status-pill").textContent;
  byId("intel-version").textContent = st.intel_version || uiText("unavailable");
  byId("btn-start").disabled = !st.audit_ready || !st.accessibility || !!st.session_active;
  byId("btn-end").disabled = !st.session_active;
  byId("btn-resume").disabled = !st.audit_ready || !st.accessibility || state !== "paused";
  byId("btn-selftest").disabled = !st.audit_ready;
  byId("btn-export-report").disabled = !st.audit_ready;
  document.querySelectorAll('[data-forward="btn-export-report"]').forEach((el) => { el.disabled = !st.audit_ready; });
  renderInstallation();
}

export function renderRecent(rows, unavailable = false) {
  const box = byId("recent-activity");
  box.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = uiText(!status ? "checking" : unavailable || !status.audit_ready ? "recordsUnavailable" : "emptyActivity");
    box.append(empty);
    return;
  }
  for (const row of rows.slice(0, 3)) {
    const el = document.createElement("div");
    el.className = "recent-row";
    const title = document.createElement("strong");
    // 总览只展示标识与来源；外部正文留在活动页，绝不作为 HTML 解释。
    title.textContent = row.rule_id || uiText("activity");
    const source = document.createElement("span");
    source.textContent = sourceLabel(row.source_app);
    el.append(title, source);
    box.append(el);
  }
}

export function sourceLabel(source) {
  const value = source || "";
  return /^app:sha256:[0-9a-f]{8,64}$/.test(value) ? `${uiText("privateSource")} ${value.slice(-8)}` : value;
}

export function permissionFeedback(tcc) {
  const text = uiText(tcc.accessibility ? "recheckReady" : "recheckMissing");
  byId("permission-feedback").textContent = text;
  showFeedback(text, !tcc.accessibility);
}

function openGuide(kind) {
  if (!["browser", "gateway"].includes(kind)) return;
  const opener = document.activeElement;
  showPage("active", false);
  setupOpener = opener;
  setupKind = kind;
  setupGeneration += 1;
  byId("setup-title").textContent = uiText(kind === "browser" ? "browserProtection" : "gateway");
  byId("browser-guide").hidden = kind !== "browser";
  byId("gateway-guide").hidden = kind !== "gateway";
  byId("setup-feedback").textContent = "";
  byId("setup-error").textContent = "";
  byId("setup-dialog").hidden = false;
  byId("setup-title").focus();
  byId("setup-dialog").scrollIntoView({ block: "start" });
}

function closeGuide(restoreFocus = true) {
  if (!setupKind) return;
  byId("setup-dialog").hidden = true;
  setupGeneration += 1;
  setupKind = null;
  if (restoreFocus) {
    const target = setupOpener?.offsetParent ? setupOpener : byId("active-title");
    target.focus();
  }
  setupOpener = null;
}

export function initializeWorkspace(backendInvoke) {
  invoke = backendInvoke;
  // 移动既有控件，不复制安全按钮或创建第二份状态源；保留其真实后端接线。
  move("#status-pill", "status-slot");
  move("#btn-refresh", "toolbar-actions");
  move(".locale-picker", "language-slot");
  move("#audit-recovery-panel", "recovery-slot");
  move(".task-profile", "task-slot");
  move("#btn-reload-intel", "intel-slot");
  const sessionCard = byId("btn-start").closest(".card");
  byId("session-slot").append(sessionCard);
  const activityCard = byId("timeline").closest("section.card");
  byId("activity-slot").append(activityCard);
  move("#btn-open-ax", "ax-settings-slot");
  move("#btn-open-screen", "screen-settings-slot");
  move("#btn-tcc", "permission-recheck-slot");
  move("#howto", "howto-slot");
  move("#coverage-banner", "coverage-slot");
  move("details.dev", "developer-slot");
  byId("legacy-layout").remove();
  // 活动面板与收纳区采用不同父节点，避免当前 macOS WebView 保留隐藏面板的旧无障碍状态。
  const settingsContent = document.createElement("div");
  settingsContent.id = "settings-content";
  const settingsParking = document.createElement("div");
  settingsParking.id = "settings-parking";
  settingsParking.hidden = true;
  byId("settings-observation").before(settingsContent, settingsParking);
  byId("active-title").closest(".hero").after(byId("setup-dialog"));
  translateWorkspace();
  initializeGatewayConfirmation(invoke);
  setTab("observation");
  renderRecent([]);
  document.querySelectorAll("[data-route]").forEach((btn) => { btn.onclick = () => showPage(btn.dataset.route); });
  document.querySelectorAll("[data-setting-tab]").forEach((btn) => {
    btn.onclick = () => setTab(btn.dataset.settingTab);
    btn.onkeydown = (event) => {
      const at = TABS.indexOf(btn.dataset.settingTab);
      const offset = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
      if (offset || ["Home", "End"].includes(event.key)) {
        event.preventDefault();
        setTab(event.key === "Home" ? TABS[0] : event.key === "End" ? TABS.at(-1) : TABS[(at + offset + TABS.length) % TABS.length], true);
      }
    };
  });
  document.querySelectorAll("[data-forward]").forEach((btn) => {
    btn.onclick = () => { const target = byId(btn.dataset.forward); if (target && !target.disabled) target.click(); };
  });
  const appearance = byId("appearance");
  const savedTheme = readPreference("agentguard.appearance", "system");
  appearance.value = ["system", "light", "dark"].includes(savedTheme) ? savedTheme : "system";
  applyTheme(appearance.value);
  appearance.onchange = () => {
    if (savePreference("agentguard.appearance", appearance.value)) applyTheme(appearance.value);
  };
  themeMedia.addEventListener("change", () => applyTheme(appearance.value));
  const task = byId("task-profile");
  const savedTask = readPreference("agentguard.nextTask", "");
  if ([...task.options].some((option) => option.value === savedTask)) task.value = savedTask;
  task.onchange = () => { savePreference("agentguard.nextTask", task.value); };
  document.querySelectorAll("[data-open-guide]").forEach((btn) => { btn.onclick = () => openGuide(btn.dataset.openGuide); });
  byId("setup-close").onclick = () => closeGuide();
  document.addEventListener("keydown", (event) => {
    // 异步按钮暂时禁用时焦点可能回到 body；不干扰另一个安全确认层的 Escape。
    if (setupKind && event.key === "Escape" && !event.defaultPrevented
      && (event.target === document.body || byId("setup-dialog").contains(event.target))) {
      event.preventDefault(); closeGuide();
    }
  });
  document.querySelectorAll("[data-setup-action]").forEach((btn) => {
    btn.onclick = async () => {
      try {
        await invoke("open_setup_resource", { which: btn.dataset.setupAction });
        byId("setup-feedback").textContent = "";
      } catch (error) {
        byId("setup-feedback").textContent = uiText("actionFailed");
        byId("setup-error").textContent = String(error);
      }
    };
  });
  byId("gateway-check").onclick = async () => {
    const generation = setupGeneration;
    byId("gateway-check").disabled = true;
    byId("gateway-copy").disabled = true;
    byId("gateway-config").value = "";
    byId("gateway-result").hidden = true;
    byId("setup-error").textContent = "";
    byId("setup-feedback").textContent = uiText("checking");
    try {
      const result = await invoke("check_gateway_setup");
      if (generation !== setupGeneration || setupKind !== "gateway") return;
      byId("gateway-config").value = JSON.stringify(result.config, null, 2);
      byId("gateway-result").textContent = result.tools.join("\n");
      byId("gateway-result").hidden = false;
      byId("gateway-copy").disabled = false;
      byId("setup-feedback").textContent = uiText("gatewayChecked");
    } catch (error) {
      if (generation === setupGeneration) {
        byId("setup-feedback").textContent = uiText("actionFailed");
        byId("setup-error").textContent = String(error);
      }
    } finally { byId("gateway-check").disabled = false; }
  };
  byId("gateway-copy").onclick = async () => {
    try {
      await navigator.clipboard.writeText(byId("gateway-config").value);
      byId("setup-feedback").textContent = uiText("copied");
    } catch { byId("setup-feedback").textContent = uiText("copyFailed"); }
  };
  window.addEventListener("agentguard-locale-change", () => {
    translateWorkspace();
    showPage(route, false);
    if (setupKind) byId("setup-title").textContent = uiText(setupKind === "browser" ? "browserProtection" : "gateway");
    if (status) renderWorkspace(status);
  });
  invoke("get_installation_info").then((info) => { installation = info; renderInstallation(); }).catch(() => {});
  showPage("overview", false);
}

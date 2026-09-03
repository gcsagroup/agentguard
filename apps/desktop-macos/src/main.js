import { currentLocale, initializeI18n, t } from "./i18n.js";

const { invoke } = window.__TAURI__.core;

const pill = () => document.getElementById("status-pill");
const caps = () => document.getElementById("caps");
const decisions = () => document.getElementById("decisions");
const timeline = () => document.getElementById("timeline");
const modal = () => document.getElementById("confirm-modal");
const tccPanel = () => document.getElementById("tcc-panel");

let lastStatus = null;

function actionClass(action) {
  const a = (action || "").toLowerCase();
  if (a.includes("block")) return "block";
  if (a.includes("alert")) return "alert";
  if (a.includes("allow")) return "allow";
  return "logonly";
}

// P0-5:记住当前弹层展示的确切 request_id。resolve 时原样回传,后端据此 compare-and-swap
// ——用户拒绝的是他看到的那一条,不是"此刻队首碰巧是哪条"。
let shownRequestId = null;

// ---------------------------------------------------------------------------
// P2-4:弹层的读屏与键盘可达性。
//
// 真机报告:桌面弹层缺 aria-labelledby、焦点转入/回退、focus trap 和 Escape;键盘用户要穿过
// 11–12 个背景控件才到确认按钮;审计列表不是 live region。现在:
//   * 打开:记住开启前的焦点元素,<main> 置 inert(背景控件既不可点也不可 Tab 到),焦点落在
//     「先不要」(安全的默认),读屏播报一条「有一个高危操作等你决定:…」;
//   * 开着:Tab / Shift+Tab 只在弹层内的可聚焦元素之间循环;Esc = 先不要;
//   * 关闭:撤 inert、卸载键盘监听、焦点还原到开启前的元素(不在了就回状态灯),播报结果。
// 全部走 DOM 属性与 textContent,不用 setAttribute / innerHTML(仓库不变量禁 sink)。
// ---------------------------------------------------------------------------
let modalOpener = null;
let modalKeyHandler = null;
let lastAnnouncedState = null;

function announce(text) {
  const el = document.getElementById("sr-announce");
  if (!el) return;
  // 同一句连播两次读屏会吞掉;先清空再写,确保每次都播。
  el.textContent = "";
  setTimeout(() => {
    el.textContent = text;
  }, 30);
}

function modalFocusables() {
  return Array.from(modal().querySelectorAll("button, [href], input, select, textarea, [tabindex]"))
    .filter((el) => !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null);
}

function openModalA11y(message) {
  const main = document.getElementById("app-main");
  const wasOpen = !modal().classList.contains("hidden");
  if (!wasOpen) {
    modalOpener = document.activeElement && document.activeElement !== document.body ? document.activeElement : null;
    if (main) main.inert = true;
  }
  modal().classList.remove("hidden");
  if (!wasOpen) {
    const deny = document.getElementById("confirm-deny");
    if (deny) deny.focus();
    announce(t("a11y.confirmPending", { msg: message || "" }));
  }
  if (!modalKeyHandler) {
    modalKeyHandler = (e) => {
      if (modal().classList.contains("hidden")) return;
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopImmediatePropagation();
        document.getElementById("confirm-deny")?.click();
        return;
      }
      if (e.key !== "Tab") return;
      const items = modalFocusables();
      if (items.length === 0) return;
      const i = items.indexOf(document.activeElement);
      const next = e.shiftKey
        ? (i <= 0 ? items.length - 1 : i - 1)
        : (i === -1 || i === items.length - 1 ? 0 : i + 1);
      e.preventDefault();
      items[next].focus();
    };
    document.addEventListener("keydown", modalKeyHandler, true);
  }
}

function closeModalA11y(outcomeKey) {
  const wasOpen = !modal().classList.contains("hidden");
  modal().classList.add("hidden");
  const main = document.getElementById("app-main");
  if (main) main.inert = false;
  if (modalKeyHandler) {
    document.removeEventListener("keydown", modalKeyHandler, true);
    modalKeyHandler = null;
  }
  if (wasOpen) {
    const target = modalOpener && document.contains(modalOpener) ? modalOpener : pill();
    try {
      if (target && typeof target.focus === "function") {
        if (target === pill() && target.tabIndex < 0) target.tabIndex = -1;
        target.focus();
      }
    } catch (_) {}
    if (outcomeKey) announce(t("a11y.confirmClosed", { outcome: t(outcomeKey) }));
  }
  modalOpener = null;
}

function announceStateChange(state) {
  if (state === lastAnnouncedState) return;
  const first = lastAnnouncedState === null;
  lastAnnouncedState = state;
  if (first) return; // 首屏不播,只播转换。
  announce(t("a11y.stateChanged", { state: t(`state.${state}`) }));
}

async function maybeShowConfirm() {
  const pending = await invoke("get_pending_confirm");
  if (!pending) {
    shownRequestId = null;
    closeModalA11y(null);
    return;
  }
  shownRequestId = pending.request_id;
  document.getElementById("confirm-msg").textContent = pending.human_message;
  document.getElementById("confirm-meta").textContent =
    `${pending.rule_id} · ${pending.severity} · ${pending.source_app}` +
    (pending.ui_excerpt ? ` · ${pending.ui_excerpt}` : "");
  openModalA11y(pending.human_message);
}

async function refreshCoverage(st, tcc) {
  const banner = document.getElementById("coverage-banner");
  const title = document.getElementById("coverage-title");
  const lines = document.getElementById("coverage-lines");
  if (!banner || !title || !lines) return;
  const mode = (st && st.protection_mode) || (tcc && tcc.protection_mode) || "sim";
  banner.className = `card coverage ${mode}`;
  title.textContent = t(
    mode === "full" ? "coverage.full" : mode === "partial" ? "coverage.partial" : "coverage.sim",
  );
  lines.replaceChildren();
  const source = st || tcc || {};
  const coverage = [
    `${t("coverage.ax")}: ${source.accessibility ? "✓" : t("coverage.unavailable")}`,
    `${t("coverage.capture")}: ${source.screen_capture ? "✓" : t("coverage.unavailable")}`,
  ];
  for (const tip of coverage) {
    const li = document.createElement("li");
    li.textContent = tip;
    lines.appendChild(li);
  }
}

async function refreshTcc() {
  const tcc = await invoke("get_tcc_status");
  const list = document.getElementById("tcc-hints");
  list.replaceChildren();
  for (const tip of [
    t(tcc.accessibility ? "tcc.axGranted" : "tcc.axMissing"),
    t(tcc.screen_capture ? "tcc.captureGranted" : "tcc.captureMissing"),
  ]) {
    const li = document.createElement("li");
    li.textContent = tip;
    list.appendChild(li);
  }
  // 「权限设置」独立卡片已合进「怎么用」第一步(见 index.html),这里对它的存在不作假设。
  const panel = tccPanel();
  if (panel) {
    panel.classList.toggle("done", !!tcc.acknowledged);
  }
  await refreshCoverage(null, tcc);
  return tcc;
}

// P0-3:状态灯只信后端状态机的 `protection_state`,不再自己用 session_active 拼「守护中」。
// 七个状态里只有 active 是绿的;degraded 是橙的——会话开着但没人在看,不能显示成绿。
const PILL_CLASS = {
  stopped: "idle",
  confirmation_pending: "paused",
  paused: "paused",
  permission_required: "idle",
  observer_starting: "idle",
  degraded: "paused",
  active: "active",
};

function renderStateReasons(st) {
  const box = document.getElementById("state-why");
  if (!box) return;
  box.replaceChildren();
  const reasons = st.state_reasons || [];
  if (reasons.length === 0) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  for (const code of reasons) {
    // 原因文本里的 {detail} 是操作系统/数据库的错误原文,可能含被观察窗口的标题 —— 走 textContent。
    const li = document.createElement("li");
    li.textContent = t(`reason.${code}`, {
      detail: code === "observer_error" ? st.observer_error : st.audit_error,
      age: Math.round((st.heartbeat_age_ms || 0) / 1000),
    });
    box.appendChild(li);
  }
}

/** 一句话说清"现在在看什么"。真机反馈:主界面原来只有 `AX=false · Capture=false · SCK=idle`。
 *
 * 说的是**观察器此刻的实况**,不是授权矩阵:授权了但观察器没跑(会话没开、或武装失败)
 * 就不能说"正在看"。所以先看 session_active,再看两个 auto_poll 标志。 */
function renderWatching(st) {
  const el = document.getElementById("watching");
  if (!el) return;
  const suffix = ` ${t("watching.rules", { rules: st.rules_loaded, intel: st.intel_version })}`;
  if (!st.session_active) {
    el.textContent = t("watching.none") + suffix;
  } else {
    const ax = !!st.ax_auto_poll;
    const cap = !!(st.sck_streaming && st.sck_auto_poll);
    const key = ax && cap ? "watching.full" : ax ? "watching.axOnly" : cap ? "watching.captureOnly" : "watching.simOnly";
    el.textContent = t(key) + suffix;
  }
  setChip("chip-session", st.session_active ? "on" : "off");
  setChip(
    "chip-perm",
    st.accessibility && st.screen_capture ? "done" : st.accessibility || st.screen_capture ? "partial" : "todo",
  );
}

/** 步骤徽章:done / partial / todo / on / off。文案走词典,颜色走 class。 */
function setChip(id, kind) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = t(`chip.${kind}`);
  el.className = `chip ${kind}`;
}

function policyLine(p) {
  if (!p || !p.policy_id) return t("policy.none");
  if (p.enforced) {
    return t("policy.enforced", { id: p.policy_id, ver: p.version, signer: p.signer || "?" });
  }
  return t("policy.notEnforced", { id: p.policy_id, ver: p.version, why: p.last_error || "" });
}

async function refreshStatus() {
  const st = await invoke("get_status");
  lastStatus = st;
  const state = st.protection_state || "stopped";
  pill().textContent = t(`state.${state}`);
  pill().className = `pill ${PILL_CLASS[state] || "idle"}`;
  announceStateChange(state);
  renderStateReasons(st);
  const sckPart = st.sck_streaming
    ? `SCK=streaming(native=${st.sck_native_ok}${st.sck_auto_poll ? ",auto" : ""})`
    : "SCK=idle";
  const sckMsg = st.sck_message ? ` · ${st.sck_message}` : "";
  const axMsg = st.ax_message ? ` · AX: ${st.ax_message}` : "";
  const folded = st.suppressed_events > 0 ? ` · ${t("status.folded", { n: st.suppressed_events })}` : "";
  // P1-4:超时/遗留的确认不是悄悄消失的——状态行说出来。
  const pendingN = st.pending_count > 0 ? ` · ${t("status.pendingCount", { n: st.pending_count })}` : "";
  const timedOut = st.confirms_timed_out > 0 ? ` · ${t("status.timedOut", { n: st.confirms_timed_out })}` : "";
  const orphaned = st.orphaned_confirms > 0 ? ` · ${t("status.orphaned", { n: st.orphaned_confirms })}` : "";
  // P1-9:策略是"验过并生效"还是"只下载了":两种情况必须说出来,不能都显示成一个 ID。
  // 这一整行是**原始状态行**,只出现在开发者面板里。主界面看 #watching(人话)。
  caps().textContent =
    `${t("status.rules")} ${st.rules_loaded} · intel ${st.intel_version} · AX=${st.accessibility} · Capture=${st.screen_capture} · ${sckPart}${sckMsg}${axMsg}${folded}${pendingN}${timedOut}${orphaned} · ${policyLine(st.policy)}`;
  renderWatching(st);
  const tcc = await invoke("get_tcc_status");
  await refreshCoverage(st, tcc);
  await maybeShowConfirm();
}

// 审计行用 DOM 拼,不用字符串拼。
//
// 这里的文本有一部分是**受监控方能影响**的:`human_message` 里带窗口标题、URL、
// 表单标签,`source_app` 是被观察应用报上来的名字。以前这一行是模板字符串塞进
// innerHTML —— 于是一个把窗口标题改成 `<img src=x onerror=...>` 的 agent,
// 能在守卫自己的界面里执行脚本。一个安全产品的 UI 是最不该有这个洞的地方。
//
// `textContent` 从根上关掉这条路:它赋的是文本节点,永远不会被当作标签解析。
// 配合 tauri.conf.json 里的限制性 CSP —— 两道,因为任何一道都可能被将来的
// 某次改动绕过。
// P2-3:一段重复观察结束时,开发者日志里留一行;折叠本身不逐条刷屏(计数在状态行)。
function pushObserveSummaries(list) {
  for (const detail of list || []) {
    pushDecisions([{
      action: "LogOnly",
      rule_id: "OBSERVE-FOLD",
      human_message: t("observe.summary", { detail }),
    }]);
  }
}

function auditRow(r) {
  const el = document.createElement("div");
  el.className = `item ${actionClass(r.action)}`;

  const head = document.createElement("div");
  const strong = document.createElement("strong");
  // E18:第一眼是人话动作词(已拦截/提醒/放行/记录),不是引擎枚举;
  // rule_id 挪到下面的 meta 行(和 popup 的"技术标识收进详情"同一原则)。
  strong.textContent = t(`action.${actionClass(r.action)}`);
  head.appendChild(strong);

  const msg = document.createElement("div");
  msg.textContent = r.human_message ?? "";

  const meta = document.createElement("div");
  meta.className = "meta";
  let metaText = `${r.rule_id ?? ""} · ${r.source_app ?? ""} · ${r.event_type ?? ""}`;
  if (r.user_decision) {
    metaText += ` · user=${r.user_decision}`;
  }
  meta.textContent = metaText;

  el.append(head, msg, meta);
  return el;
}

async function refreshAudit() {
  const rows = await invoke("list_audit", { limit: 40 });
  timeline().replaceChildren();
  for (const r of rows) {
    timeline().appendChild(auditRow(r));
  }
}

function pushDecisions(list) {
  for (const d of list || []) {
    const li = document.createElement("li");
    li.textContent = `${d.action} [${d.rule_id}] ${d.human_message}`;
    decisions().prepend(li);
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  initializeI18n();
  await invoke("set_tray_locale", { locale: currentLocale() });
  window.addEventListener("agentguard-locale-change", async () => {
    await invoke("set_tray_locale", { locale: currentLocale() });
    await refreshStatus();
    await refreshTcc();
  });
  document.getElementById("btn-tcc").onclick = async () => {
    await invoke("acknowledge_tcc");
    const caps = await invoke("probe_permissions");
    pushDecisions([{
      action: "LogOnly",
      rule_id: "TCC-PROBE",
      human_message: `AX=${caps.accessibility} Capture=${caps.screen_capture}`,
    }]);
    await refreshTcc();
    await refreshStatus();
  };

  // 「打开系统设置」:直接跳到该点的那一页,而不是让用户按着一行四层路径自己找。
  for (const [id, pane] of [["btn-open-ax", "accessibility"], ["btn-open-screen", "screen"]]) {
    const btn = document.getElementById(id);
    if (!btn) continue;
    btn.onclick = async () => {
      try {
        await invoke("open_privacy_settings", { which: pane });
      } catch (err) {
        // 打不开(非 macOS / 系统拒绝)不是静默失败:界面上说出来,用户还能照文字路径自己走。
        pushDecisions([{ action: "LogOnly", rule_id: "TCC-OPEN", human_message: String(err) }]);
      }
    };
  }

  // 自检:喂一条本机构造的付款事件,让确认层真的弹出来。以前这个按钮只在开发者面板里,
  // 于是"我怎么知道它真的会拦"没有答案。
  const selftest = document.getElementById("btn-selftest");
  if (selftest) {
    selftest.onclick = async () => {
      const out = await invoke("inject_demo_threat", { kind: "payment" });
      pushDecisions(out);
      await refreshStatus();
      await refreshAudit();
    };
  }

  document.getElementById("btn-reload-intel").onclick = async () => {
    const ver = await invoke("reload_intel");
    pushDecisions([{ action: "LogOnly", rule_id: "INTEL-RELOAD", human_message: `intel ${ver}` }]);
    await refreshStatus();
  };

  document.getElementById("btn-sync-policy").onclick = async () => {
    const id = await invoke("sync_device_policy", { source: null });
    pushDecisions([{ action: "LogOnly", rule_id: "POLICY-SYNC", human_message: id }]);
    await refreshStatus();
  };

  document.getElementById("btn-start").onclick = async () => {
    // An empty selection sends `null`, which opens an unscoped session — the pre-existing
    // behaviour. A named profile selects its plan and its Aura §4.4 resource ceiling.
    const profile = document.getElementById("task-profile")?.value || null;
    const sid = await invoke("start_guard_session", {
      taskProfile: profile,
      taskApps: null,
    });
    pushDecisions([{ action: "LogOnly", rule_id: "SESSION-START", human_message: `session ${sid}` }]);
    await refreshStatus();
    await refreshAudit();
  };

  document.getElementById("btn-end").onclick = async () => {
    await invoke("end_guard_session");
    await refreshStatus();
    await refreshAudit();
  };

  document.getElementById("btn-resume").onclick = async () => {
    await invoke("resume_session");
    await refreshStatus();
  };

  document.getElementById("btn-sck-probe").onclick = async () => {
    const probe = await invoke("sck_probe_cmd");
    pushDecisions([{
      action: probe.ok ? "LogOnly" : "Alert",
      rule_id: "SCK-PROBE",
      human_message: probe.ok
        ? `SCK OK · screen_capture=${probe.screen_capture}`
        : `SCK failed: ${probe.error} · screen_capture=${probe.screen_capture}`,
    }]);
    await refreshStatus();
  };

  document.getElementById("btn-ax-probe").onclick = async () => {
    const probe = await invoke("ax_probe_cmd");
    pushDecisions([{
      action: probe.ok ? "LogOnly" : "Alert",
      rule_id: "AX-PROBE",
      human_message: probe.ok
        ? `AX OK · accessibility=${probe.accessibility}`
        : `AX failed: ${probe.error} · accessibility=${probe.accessibility}`,
    }]);
    await refreshStatus();
  };

  document.getElementById("btn-ax-poll").onclick = async () => {
    try {
      const out = await invoke("ax_poll_cmd");
      pushDecisions(out.decisions.length ? out.decisions : [{
        action: "LogOnly",
        rule_id: "AX-POLL",
        human_message: out.message,
      }]);
    } catch (err) {
      pushDecisions([{
        action: "Alert",
        rule_id: "AX-POLL",
        human_message: String(err),
      }]);
    }
    await refreshStatus();
    await refreshAudit();
    await maybeShowConfirm();
  };

  document.getElementById("btn-ax-auto").onclick = async () => {
    const on = !lastStatus?.ax_auto_poll;
    try {
      const out = await invoke("ax_auto_cmd", { enable: on });
      pushDecisions([{
        action: "LogOnly",
        rule_id: "AX-AUTO",
        human_message: out.message,
      }]);
    } catch (err) {
      pushDecisions([{
        action: "Alert",
        rule_id: "AX-AUTO",
        human_message: String(err),
      }]);
    }
    await refreshStatus();
  };

  document.getElementById("btn-sck-start").onclick = async () => {
    const info = await invoke("sck_start_cmd");
    pushDecisions([{
      action: info.native ? "LogOnly" : "Alert",
      rule_id: "SCK-START",
      human_message: info.native
        ? `${info.message} (${t("sck.autoOn")})`
        : `${info.message} (${t("sck.permissionMissing")})`,
    }]);
    await refreshStatus();
  };

  document.getElementById("btn-sck-stop").onclick = async () => {
    const info = await invoke("sck_stop_cmd");
    pushDecisions([{
      action: "LogOnly",
      rule_id: "SCK-STOP",
      human_message: info.message,
    }]);
    await refreshStatus();
  };

  document.getElementById("btn-sck-poll").onclick = async () => {
    const out = await invoke("sck_poll_cmd");
    if (out.frames_drained > 0 || out.decisions.length > 0) {
      pushDecisions(out.decisions);
    } else {
      pushDecisions([{
        action: "LogOnly",
        rule_id: "SCK-POLL",
        human_message: t("sck.noFrames"),
      }]);
    }
    await refreshStatus();
    await refreshAudit();
    await maybeShowConfirm();
  };

  // The backend AXObserver driver emits coalesced events even when the Menu Bar window is in background.
  try {
    const { listen } = window.__TAURI__.event;
    await listen("sck-poll", async (ev) => {
      const out = ev.payload || {};
      pushObserveSummaries(out.summaries);
      if ((out.frames_drained || 0) > 0 || (out.decisions || []).length > 0) {
        pushDecisions(out.decisions);
        await refreshStatus();
        await refreshAudit();
        await maybeShowConfirm();
      }
    });
    await listen("sck-confirm-needed", async () => {
      await maybeShowConfirm();
      await refreshStatus();
    });
    await listen("ax-poll", async (ev) => {
      const out = ev.payload || {};
      pushObserveSummaries(out.summaries);
      if ((out.decisions || []).length > 0) {
        pushDecisions(out.decisions);
        await refreshStatus();
        await refreshAudit();
        await maybeShowConfirm();
      }
    });
    await listen("ax-poll-error", async (ev) => {
      const err = (ev.payload && ev.payload.error) || "AX poll failed";
      pushDecisions([{ action: "Alert", rule_id: "AX-POLL", human_message: String(err) }]);
      await refreshStatus();
    });
  } catch (_) {
    /* event API unavailable in non-tauri preview */
  }

  document.getElementById("btn-refresh").onclick = async () => {
    await refreshStatus();
    await refreshAudit();
    await refreshTcc();
  };

  document.getElementById("btn-export-report").onclick = async () => {
    const msg = await invoke("export_session_report", { limit: 500 });
    pushDecisions([{ action: "LogOnly", rule_id: "AUDIT-REPORT", human_message: msg }]);
  };

  document.getElementById("auto-approve").onchange = async (e) => {
    try {
      await invoke("set_auto_approve", { enabled: e.target.checked });
    } catch (err) {
      e.target.checked = false;
      pushDecisions([{ action: "Alert", rule_id: "SEC", human_message: String(err) }]);
    }
  };

  try {
    const sec = await invoke("security_status");
    if (!sec.auto_approve_allowed) {
      const row = document.getElementById("auto-approve-row");
      if (row) row.style.display = "none";
    }
  } catch (_) {}

  // P0-5:两个按钮都回传 shownRequestId(用户看到的那条)。后端若返回 resolved:false,
  // 说明这条已过期(新会话清了 / 被挤出)——不当作成功,重新拉 pending 让用户看当前那条。
  const resolvePending = async (approve) => {
    if (shownRequestId == null) {
      closeModalA11y(null);
      return;
    }
    const res = await invoke("resolve_confirm", { requestId: shownRequestId, approve });
    closeModalA11y(approve ? "a11y.allowed" : "a11y.denied");
    await refreshStatus();
    await refreshAudit();
    // 队列里还有下一条(或这条已过期需要重看),再弹一次。
    if (res && (res.has_next || !res.resolved)) {
      await maybeShowConfirm();
    }
  };
  document.getElementById("confirm-deny").onclick = () => resolvePending(false);
  document.getElementById("confirm-approve").onclick = () => resolvePending(true);

  // P1-4:弹层开着时每 15 秒复查一次——超时的确认由后端按「先不要」处理并写 Timeout 回执,
  // 弹层要跟着收起、状态行要说出来,不能停在一个已经不存在的请求上。
  setInterval(() => {
    if (!modal().classList.contains("hidden")) {
      maybeShowConfirm().catch(() => {});
      refreshStatus().catch(() => {});
    }
  }, 15000);

  document.querySelectorAll("[data-threat]").forEach((btn) => {
    btn.onclick = async () => {
      const kind = btn.getAttribute("data-threat");
      const out = await invoke("inject_demo_threat", { kind });
      pushDecisions(out);
      await refreshStatus();
      await refreshAudit();
    };
  });

  try {
    await refreshTcc();
    await refreshStatus();
    await refreshAudit();
  } catch (err) {
    caps().textContent = t("error.init", { error: err });
  }
});

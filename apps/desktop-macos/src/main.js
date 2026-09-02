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

async function maybeShowConfirm() {
  const pending = await invoke("get_pending_confirm");
  if (!pending) {
    shownRequestId = null;
    modal().classList.add("hidden");
    return;
  }
  shownRequestId = pending.request_id;
  document.getElementById("confirm-msg").textContent = pending.human_message;
  document.getElementById("confirm-meta").textContent =
    `${pending.rule_id} · ${pending.severity} · ${pending.source_app}` +
    (pending.ui_excerpt ? ` · ${pending.ui_excerpt}` : "");
  modal().classList.remove("hidden");
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
  if (tcc.acknowledged) {
    tccPanel().classList.add("done");
  } else {
    tccPanel().classList.remove("done");
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

async function refreshStatus() {
  const st = await invoke("get_status");
  lastStatus = st;
  const state = st.protection_state || "stopped";
  pill().textContent = t(`state.${state}`);
  pill().className = `pill ${PILL_CLASS[state] || "idle"}`;
  renderStateReasons(st);
  const sckPart = st.sck_streaming
    ? `SCK=streaming(native=${st.sck_native_ok}${st.sck_auto_poll ? ",auto" : ""})`
    : "SCK=idle";
  const sckMsg = st.sck_message ? ` · ${st.sck_message}` : "";
  const axMsg = st.ax_message ? ` · AX: ${st.ax_message}` : "";
  const folded = st.suppressed_events > 0 ? ` · ${t("status.folded", { n: st.suppressed_events })}` : "";
  caps().textContent =
    `${t("status.rules")} ${st.rules_loaded} · intel ${st.intel_version} · AX=${st.accessibility} · Capture=${st.screen_capture} · ${sckPart}${sckMsg}${axMsg}${folded}`;
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

  // Backend auto-poll emits events even when Menu Bar window is in background.
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
      modal().classList.add("hidden");
      return;
    }
    const res = await invoke("resolve_confirm", { requestId: shownRequestId, approve });
    modal().classList.add("hidden");
    await refreshStatus();
    await refreshAudit();
    // 队列里还有下一条(或这条已过期需要重看),再弹一次。
    if (res && (res.has_next || !res.resolved)) {
      await maybeShowConfirm();
    }
  };
  document.getElementById("confirm-deny").onclick = () => resolvePending(false);
  document.getElementById("confirm-approve").onclick = () => resolvePending(true);

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

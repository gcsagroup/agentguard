import { initializeI18n, t } from "./i18n.js";

const { invoke } = window.__TAURI__.core;

const pill = () => document.getElementById("status-pill");
const caps = () => document.getElementById("caps");
const decisions = () => document.getElementById("decisions");
const timeline = () => document.getElementById("timeline");
const modal = () => document.getElementById("confirm-modal");
const observeBox = () => document.getElementById("observe-status");

const { listen } = window.__TAURI__.event;

function actionClass(action) {
  const a = (action || "").toLowerCase();
  if (a.includes("block")) return "block";
  if (a.includes("alert")) return "alert";
  if (a.includes("allow")) return "allow";
  return "logonly";
}

// P0-5:记住当前弹层展示的确切 request_id,resolve 时原样回传做 compare-and-swap。
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

// P0-3:状态灯只信后端状态机的 `protection_state`(guard_core::observe_state)。
// 以前这里用 session_active / observing 两个布尔自己拼——会话开着、观察器停了、审计写不进去,
// 三种情况都能显示成绿。现在七个状态里只有 active 是绿的。
const PILL_CLASS = {
  stopped: "idle",
  confirmation_pending: "paused",
  paused: "paused",
  permission_required: "idle",
  observer_starting: "idle",
  degraded: "paused",
  active: "active",
};

function renderStateReasons(st, span) {
  const box = document.getElementById("state-why");
  if (!box) return;
  box.replaceChildren();
  const reasons = st.state_reasons || [];
  box.hidden = reasons.length === 0;
  for (const code of reasons) {
    // {detail} 是操作系统/数据库的错误原文,可能含被观察窗口的标题 —— 走 textContent。
    box.appendChild(
      span(
        "state-why-item",
        t(`reason.${code}`, {
          detail: code === "observer_error" ? st.observe_error : st.audit_error,
          age: Math.round((st.heartbeat_age_ms || 0) / 1000),
        })
      )
    );
  }
}

/** 一句话说清"现在在看什么"。真机反馈:主界面原来只有 `规则 27 · intel … · plan … · privacy 1.00`。
 *
 * 说的是**此刻的实况**:没开会话就不能说在看。Windows 的观察随会话启动
 * (start_guard_session 里 "Observation begins with the session and ends with it"),
 * 所以 session_active 就是"在看",但能看到多少受三样能力限制,由下面那张卡逐项说明。 */
function renderWatching(st) {
  const el = document.getElementById("watching");
  if (!el) return;
  const anyCap = !!(st.uia_native || st.frame_capture || st.ocr);
  const suffix = ` ${t("watchingRules", { rules: st.rules_loaded, intel: st.intel_version })}`;
  if (!st.session_active) {
    el.textContent = t("watchingNone") + suffix;
  } else {
    el.textContent = t(anyCap ? "watchingOn" : "watchingNoCaps") + suffix;
  }
  setChip("chip-session", st.session_active ? "On" : "Off");
  const nCaps = [st.uia_native, st.frame_capture, st.ocr].filter(Boolean).length;
  setChip("chip-caps", nCaps === 3 ? "Done" : nCaps > 0 ? "Partial" : "Todo");
}

/** 步骤徽章:Done / Partial / Todo / On / Off。文案走词典,颜色走 class。 */
function setChip(id, kind) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = t(`chip${kind}`);
  el.className = `chip ${kind.toLowerCase()}`;
}

function policyLine(p) {
  if (!p || !p.policy_id) return t("policyNone");
  if (p.enforced) {
    return t("policyEnforced", { id: p.policy_id, ver: p.version, signer: p.signer || "?" });
  }
  return t("policyNotEnforced", { id: p.policy_id, ver: p.version, why: p.last_error || "" });
}

async function refreshStatus() {
  const st = await invoke("get_status");
  const state = st.protection_state || "stopped";
  pill().textContent = t(`state.${state}`);
  pill().className = `pill ${PILL_CLASS[state] || "idle"}`;
  announceStateChange(state);
  const folded = st.suppressed_events > 0 ? ` · ${t("folded", { n: st.suppressed_events })}` : "";
  // P1-4:超时/遗留的确认不是悄悄消失的——状态行说出来。
  const pendingN = st.pending_count > 0 ? ` · ${t("pendingCount", { n: st.pending_count })}` : "";
  const timedOut = st.confirms_timed_out > 0 ? ` · ${t("timedOut", { n: st.confirms_timed_out })}` : "";
  const orphaned = st.orphaned_confirms > 0 ? ` · ${t("orphaned", { n: st.orphaned_confirms })}` : "";
  // P1-9:策略是"验过并生效"还是"只下载了":两种情况必须说出来,不能都显示成一个 ID。
  // 这一整行是**原始状态行**,只出现在开发者面板里。主界面看 #watching(人话)。
  caps().textContent =
    `${t("rules")} ${st.rules_loaded} · intel ${st.intel_version} · ${t("plan")} ${st.plan}${st.pro_active ? "✓" : ""} · ${policyLine(st.policy)} · ${t("privacy")} ${st.privacy_composite.toFixed(2)}${folded}${pendingN}${timedOut}${orphaned}`;
  renderWatching(st);

  // Every capability renders with its reason. A bare cross told the user nothing and let a
  // compile flag pass for a probe.
  const rows = [
    [t("capUiTree"), st.uia_native, st.uia_detail],
    [t("capFrame"), st.frame_capture, st.frame_capture_detail],
    [t("capOcr"), st.ocr, st.ocr_detail],
  ];
  // 同样不走 innerHTML。`*_detail` 和 `observe_error` 里会带操作系统的错误文本,
  // 而那段文本可以含被观察窗口的标题 —— 也就是受监控方能影响的内容。
  const span = (cls, text) => {
    const e = document.createElement("span");
    e.className = cls;
    e.textContent = text ?? "";
    return e;
  };
  renderStateReasons(st, span);
  const box = observeBox();
  box.replaceChildren();
  for (const [label, ok, detail] of rows) {
    const row = document.createElement("div");
    row.className = `cap ${ok ? "cap-ok" : "cap-no"}`;
    row.append(
      span("cap-name", label),
      span("cap-val", ok ? t("capAvailable") : t("capUnavailable"))
    );
    if (detail) {
      row.appendChild(span("cap-why", detail));
    }
    box.appendChild(row);
  }
  const mode = document.createElement("div");
  mode.className = "cap-mode";
  mode.textContent = st.protection_summary ?? "";
  box.appendChild(mode);
  if (st.observe_error) {
    const err = document.createElement("div");
    err.className = "cap cap-no";
    err.appendChild(span("cap-why", st.observe_error));
    box.appendChild(err);
  }
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

  // The observation loop pushes from the backend; nothing here polls it.
  await listen("native-poll", async (e) => {
    pushDecisions(e.payload?.decisions);
    for (const w of e.payload?.warnings || []) {
      // Warnings are shown, not swallowed: a poll that read nothing has to look different
      // from a poll that found nothing.
      pushDecisions([{ action: "LogOnly", rule_id: "ADAPTER", human_message: w }]);
    }
    await refreshAudit();
  });
  await listen("native-poll-error", async (e) => {
    pushDecisions([{ action: "Alert", rule_id: "ADAPTER-ERROR", human_message: e.payload?.error || "poll failed" }]);
    await refreshStatus();
  });
  await listen("confirm-needed", maybeShowConfirm);

  document.getElementById("btn-poll-now").onclick = async () => {
    const res = await invoke("poll_native");
    pushDecisions(res.decisions);
    for (const w of res.warnings || []) {
      pushDecisions([{ action: "LogOnly", rule_id: "ADAPTER", human_message: w }]);
    }
    await refreshAudit();
    await refreshStatus();
  };

  window.addEventListener("agentguard-locale-change", refreshStatus);
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
    // Blank selection → unscoped session, the pre-existing behaviour. A named profile selects its
    // plan and its Aura §4.4 resource ceiling.
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

  document.getElementById("btn-refresh").onclick = async () => {
    await refreshStatus();
    await refreshAudit();
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

  // P0-5:回传 shownRequestId;resolved:false = 已过期,重看当前那条。
  const resolvePending = async (approve) => {
    if (shownRequestId == null) {
      closeModalA11y(null);
      return;
    }
    const res = await invoke("resolve_confirm", { requestId: shownRequestId, approve });
    closeModalA11y(approve ? "a11y.allowed" : "a11y.denied");
    await refreshStatus();
    await refreshAudit();
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

  // 自检:喂一条本机构造的付款固件,让确认层真的弹出来。以前这个按钮只在开发者面板里,
  // 于是"我怎么知道它真的会拦"在主界面上没有答案。
  const selftest = document.getElementById("btn-selftest");
  if (selftest) {
    selftest.onclick = async () => {
      const out = await invoke("inject_demo_threat", { kind: "payment" });
      pushDecisions(out);
      await refreshStatus();
      await refreshAudit();
    };
  }

  try {
    await refreshStatus();
    await refreshAudit();
  } catch (err) {
    caps().textContent = t("initError", { error: err });
  }
});

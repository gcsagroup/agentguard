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

async function maybeShowConfirm() {
  const pending = await invoke("get_pending_confirm");
  if (!pending) {
    modal().classList.add("hidden");
    return;
  }
  document.getElementById("confirm-msg").textContent = pending.human_message;
  document.getElementById("confirm-meta").textContent =
    `${pending.rule_id} · ${pending.severity} · ${pending.source_app}` +
    (pending.ui_excerpt ? ` · ${pending.ui_excerpt}` : "");
  modal().classList.remove("hidden");
}

async function refreshStatus() {
  const st = await invoke("get_status");
  if (st.pending_confirm) {
    pill().textContent = t("pending");
    pill().className = "pill paused";
  } else if (st.paused) {
    pill().textContent = t("paused");
    pill().className = "pill paused";
  } else if (st.session_active) {
    // "observing" and "able to observe" are different states, and the pill has to say which.
    // The old version printed "protecting" whenever a session was open, including on a host
    // where no tree could be read and no frame captured.
    if (st.observing) {
      pill().textContent = t("observing");
      pill().className = "pill active";
    } else {
      pill().textContent = t(st.protection_mode === "sim" ? "simulating" : "notObserving");
      pill().className = st.protection_mode === "sim" ? "pill paused" : "pill idle";
    }
  } else {
    pill().textContent = t("idle");
    pill().className = "pill idle";
  }
  caps().textContent =
    `${t("rules")} ${st.rules_loaded} · intel ${st.intel_version} · ${t("plan")} ${st.plan}${st.pro_active ? "✓" : ""} · ${t("policy")} ${st.device_policy_id} · ${t("privacy")} ${st.privacy_composite.toFixed(2)}`;

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
  strong.textContent = r.action ?? "";
  head.appendChild(strong);
  head.appendChild(document.createTextNode(` · ${r.rule_id ?? ""}`));

  const msg = document.createElement("div");
  msg.textContent = r.human_message ?? "";

  const meta = document.createElement("div");
  meta.className = "meta";
  let metaText = `${r.source_app ?? ""} · ${r.event_type ?? ""}`;
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

  document.getElementById("confirm-deny").onclick = async () => {
    await invoke("resolve_confirm", { approve: false });
    modal().classList.add("hidden");
    await refreshStatus();
    await refreshAudit();
  };

  document.getElementById("confirm-approve").onclick = async () => {
    await invoke("resolve_confirm", { approve: true });
    modal().classList.add("hidden");
    await refreshStatus();
    await refreshAudit();
  };

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
    await refreshStatus();
    await refreshAudit();
  } catch (err) {
    caps().textContent = t("initError", { error: err });
  }
});

import { initializeGatewayGovernance } from "./gateway-governance.js";
import { uiText } from "./workspace-i18n.js";
import { renderPendingMemory } from "./memory-content.js";
const el = (id) => document.getElementById(id);
const setText = (id, value) => { if (el(id).textContent !== value) el(id).textContent = value; };

// 正文、目标与参数以文本展示；批准随机值与连接凭据不在此视图中。
export function formatGatewayAction(request) {
  const action = request.action;
  if (!action || !/^[a-f0-9]{64}$/.test(request.action_sha256 || "")) return uiText("gatewayBindingMissing");
  return [request.what, "", `${uiText("gatewayBoundSession")}: ${action.session_id}`, `${uiText("gatewayBoundTool")}: ${action.tool_service} / ${action.tool_name} @ ${action.tool_version}`,
    `${uiText("gatewayBoundTarget")}: ${action.target}`, `${uiText("gatewayBoundPolicy")}: ${action.policy_version}`, `${uiText("gatewayBoundDigest")}: ${request.action_sha256}`,
    "", `${uiText("gatewayBoundParameters")}:`, JSON.stringify(action.parameters, null, 2)].join("\n");
}

// 与桌面事后提醒完全分开；不持久化凭据，不把外部命令解释为 HTML。
export function initializeGatewayConfirmation(invoke) {
  let connection = null;
  let managed = false;
  const governance = initializeGatewayGovernance(invoke, () => connection);
  const workspace = initializeGatewayWorkspace(invoke, () => connection, governance);
  let pending = null;
  let deadline = 0;
  let checkedAt = 0;
  let generation = 0;
  let busy = false;
  let polling = false;
  let statusKey = "gatewayDisconnected";
  let feedbackKey = "";
  function connectionError(error) {
    const code = String(error);
    if (code.includes("GATEWAY_TOO_LARGE")) return "gatewayTooLarge";
    if (code.includes("GATEWAY_FILE_PATH")) return "gatewayFilePathError";
    if (code.includes("GATEWAY_FILE_FORMAT") || code.includes("GATEWAY_FILE_TOO_LARGE")) return "gatewayFileFormatError";
    if (code.includes("GATEWAY_INSTANCE_CHANGED")) return "gatewayInstanceChanged";
    if (code.includes("GATEWAY_FILE_")) return "gatewayFileSecurityError";
    return "gatewayConnectFailed";
  }
  function clearPending() {
    pending = null;
    deadline = 0;
    el("gateway-reviewed").checked = false;
    el("gateway-request-what").textContent = "";
    el("gateway-memory-preview").replaceChildren();
    el("gateway-action-details").open = true;
    el("gateway-findings").replaceChildren();
  }
  function render() {
    el("gateway-connect-form").hidden = !!connection;
    el("gateway-connect").disabled = busy;
    el("gateway-import").disabled = busy;
    el("gateway-pick-file").disabled = busy;
    el("gateway-control-path").disabled = busy;
    el("gateway-disconnect").hidden = !connection;
    el("gateway-disconnect").disabled = busy;
    el("gateway-disconnect").dataset.ui = managed ? "gatewayManagedDisconnect" : "gatewayDisconnect";
    setText("gateway-disconnect", uiText(managed ? "gatewayManagedDisconnect" : "gatewayDisconnect"));
    el("gateway-confirmation-description").dataset.ui = managed ? "gatewayManagedBoundary" : "gatewayPendingBoundary";
    setText("gateway-confirmation-description", uiText(managed ? "gatewayManagedBoundary" : "gatewayPendingBoundary"));
    // 倒计时刷新不能反复重建相同的状态文本，避免原生读屏重复播报。
    setText("gateway-connection-status", uiText(statusKey));
    setText("gateway-answer-feedback", feedbackKey ? uiText(feedbackKey) : "");
    setText("gateway-connection-detail", connection ? `127.0.0.1:${connection.port} · ${connection.instance_id}` : "");
    el("gateway-pending").hidden = !pending;
    const remaining = Math.max(0, deadline - performance.now());
    const bound = !!pending?.action && /^[a-f0-9]{64}$/.test(pending?.action_sha256 || "");
    const fresh = !!pending && bound && remaining > 0 && performance.now() - checkedAt < 2500 && !busy;
    el("gateway-deny").disabled = !fresh;
    el("gateway-approve").disabled = !fresh || !el("gateway-reviewed").checked;
    el("gateway-reviewed").disabled = !fresh;
    setText("gateway-countdown", pending ? `${uiText(remaining > 0 ? "gatewayRemaining" : "gatewayExpired")} ${remaining > 0 ? Math.ceil(remaining / 1000) : ""}` : "");
  }
  function apply(view, started, adoptedManaged = null) {
    managed = adoptedManaged ?? (connection?.connection_id === view.connection_id ? managed : !!view.managed);
    connection = { ...view, managed };
    workspace.connectionChanged();
    governance.connectionChanged();
    const next = view.pending;
    if (JSON.stringify(next) !== JSON.stringify(pending)) {
      clearPending();
      pending = next;
      if (pending) {
        feedbackKey = ""; // 上一条回执不能出现在新请求上方，造成处置归属混淆。
        el("gateway-request-id").textContent = pending.id;
        el("gateway-request-what").textContent = formatGatewayAction(pending);
        showMemory();
        for (const finding of pending.findings) {
          const li = document.createElement("li");
          li.textContent = `${finding.rule_id} · ${finding.severity} · ${finding.message}`;
          el("gateway-findings").append(li);
        }
      }
    }
    checkedAt = performance.now();
    deadline = started + view.remaining_ms;
    statusKey = pending ? "gatewayWaiting" : "gatewayConnected";
    render();
  }
  function showMemory() {
    const preview = renderPendingMemory(pending?.action);
    el("gateway-memory-preview").replaceChildren(...(preview ? [preview] : []));
    el("gateway-action-details").open = !preview;
  }
  async function drop(key) {
    const previous = connection;
    generation++;
    connection = null;
    managed = false;
    workspace.reset(); governance.reset();
    clearPending();
    statusKey = key;
    render();
    if (previous) {
      try { await invoke("disconnect_gateway_confirmation", { connectionId: previous.connection_id }); } catch { /* 不自动批准或重新连接。 */ }
    }
  }
  el("gateway-pick-file").onclick = async () => {
    if (busy || connection) return;
    busy = true; render();
    try {
      const path = await invoke("pick_gateway_control_file");
      if (path) { el("gateway-control-path").value = path; statusKey = "gatewayDisconnected"; }
    } catch { statusKey = "gatewayFilePickerUnavailable"; }
    finally { busy = false; render(); }
  };
  el("gateway-import-form").onsubmit = async (event) => {
    event.preventDefault();
    if (busy || connection) return;
    const path = el("gateway-control-path").value.trim();
    if (!path.startsWith("/")) { statusKey = "gatewayFilePathError"; render(); return; }
    busy = true;
    const current = ++generation;
    statusKey = "checking"; feedbackKey = ""; render();
    const started = performance.now();
    try {
      const view = await invoke("import_gateway_confirmation", { path });
      if (current === generation) apply(view, started);
    } catch (error) { if (current === generation) await drop(connectionError(error)); }
    finally { busy = false; render(); }
  };
  el("gateway-legacy-form").onsubmit = async (event) => {
    event.preventDefault();
    if (busy || connection) return;
    busy = true;
    const current = ++generation;
    let token = el("gateway-token").value.trim();
    const port = Number(el("gateway-port").value);
    el("gateway-token").value = "";
    statusKey = "checking";
    feedbackKey = "";
    render();
    const started = performance.now();
    try {
      const promise = invoke("connect_gateway_confirmation", { port, token });
      token = "";
      const view = await promise;
      if (current === generation) apply(view, started);
    } catch (error) { if (current === generation) await drop(connectionError(error)); }
    finally { busy = false; render(); }
  };
  async function poll() {
    if (!connection || busy || polling) return;
    const current = generation;
    const started = performance.now();
    polling = true;
    try {
      const view = await invoke("poll_gateway_confirmation", { connectionId: connection.connection_id });
      if (current === generation) apply(view, started);
    } catch (error) { if (current === generation) await drop(String(error).includes("GATEWAY_TOO_LARGE") ? "gatewayTooLarge" : "gatewayLost"); }
    finally { polling = false; render(); }
  }
  el("gateway-disconnect").onclick = () => drop("gatewayDisconnected");
  el("gateway-reviewed").onchange = render;
  async function answer(approve) {
    render();
    if (!connection || !pending || el(approve ? "gateway-approve" : "gateway-deny").disabled) return;
    const args = { connectionId: connection.connection_id, requestId: pending.id, approve };
    busy = true;
    generation++; // 使已经在途的只读刷新失效，不能重新画出已回答的请求。
    feedbackKey = "";
    render();
    try {
      await invoke("answer_gateway_confirmation", args);
      feedbackKey = approve ? "gatewayApproved" : "gatewayDenied";
    } catch (error) {
      feedbackKey = String(error).includes("GATEWAY_STALE") ? "gatewayStale" : "gatewayUnknownAnswer";
      await drop("gatewayLost");
    } finally {
      clearPending();
      busy = false;
      render();
      await poll();
    }
  }
  el("gateway-deny").onclick = () => answer(false);
  el("gateway-approve").onclick = () => answer(true);
  window.addEventListener("focus", poll);
  window.addEventListener("agentguard-locale-change", () => {
    if (pending) { el("gateway-request-what").textContent = formatGatewayAction(pending); showMemory(); }
    render();
  });
  window.setInterval(poll, 1000);
  window.setInterval(render, 200);
  try {
    const { listen } = window.__TAURI__.event;
    listen("cooperative-halted", async () => {
      feedbackKey = "cooperativeHalted";
      render();
      await poll();
    });
  } catch (_) {}
  render();
  return {
    current: () => connection ? { connectionId: connection.connection_id, managed } : null,
    isConnecting: () => busy,
    forgetManaged(connectionId) {
      if (!managed || connection?.connection_id !== connectionId) return;
      generation++; connection = null; managed = false; clearPending(); workspace.reset(); governance.reset();
      statusKey = "gatewayDisconnected"; feedbackKey = ""; render();
    },
    // 宿主只提供安全视图。相同连接由自身轮询刷新，不能用 Agent 状态覆盖已核对的预览。
    adopt(view, { replaceConnectionId = null } = {}) {
      if (!view?.connection_id || busy) return false;
      if (connection?.connection_id === view.connection_id) { managed = true; render(); return true; }
      if (connection && connection.connection_id !== replaceConnectionId) return false;
      generation++;
      clearPending(); feedbackKey = "";
      apply(view, performance.now(), true);
      return true;
    },
    hasWorkspaceReview: () => workspace.hasReview(),
    hasPending: () => !!pending,
    async showResults() { if (!connection) return; await workspace.showPreview(); },
    showPending() {
      el("gateway-confirmation").scrollIntoView({ block: "start" });
      el(pending ? "gateway-pending-title" : "gateway-confirmation").focus({ preventScroll: true });
    },
  };
}

function initializeGatewayWorkspace(invoke, getConnection, governance) {
  let owner = "";
  let state = null;
  let review = null;
  let result = null;
  let submitted = null;
  let selected = "";
  let feedback = "";
  let revision = 0;
  let working = false;
  let controlling = false;
  let polling = false;
  let unknown = false;
  let checkedAt = 0;
  let reviewSignature = "";
  let resultSignature = "";
  const stateKeys = { active: "workspaceActive", paused: "workspacePaused", stopped: "workspaceStopped", failed: "workspaceFailed" };
  const outcomeKeys = { applied: "workspaceApplied", conflict: "workspaceConflict", partial: "workspacePartial", unknown: "workspaceOutcomeUnknown", not_applied: "workspaceNotApplied" };
  const kindKeys = { create: "workspaceCreate", modify: "workspaceModify", delete: "workspaceDelete" };
  function clearReview() {
    review = null; reviewSignature = "";
    el("gateway-workspace-reviewed").checked = false;
    el("gateway-workspace-changes").replaceChildren();
  }
  function errorKey(error) {
    const code = String(error);
    if (code.includes("REPLY_UNKNOWN")) return "workspaceUnknown";
    if (code.includes("TOO_LARGE")) return "workspaceTooLarge";
    if (code.includes("BINDING") || code.includes("PROTOCOL")) return "workspaceInvalidBinding";
    if (code.includes("STALE")) return "workspaceStale";
    if (code.includes("BUSY")) return "workspaceBusy";
    if (code.includes("UNAVAILABLE")) return "workspaceUnavailable";
    if (code.includes("WORKSPACE_DENIED")) return "workspaceDenied";
    return "workspaceOperationFailed";
  }
  function textNode(tag, text, className) {
    const node = document.createElement(tag); node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function showVersion(parent, version, key) {
    const details = document.createElement("details");
    details.append(textNode("summary", uiText(key)));
    if (!version) details.append(textNode("p", uiText("workspaceAbsent")));
    else {
      details.append(textNode("p", `${version.bytes} ${uiText("workspaceBytes")} · ${uiText("workspaceMode")}: ${version.mode.toString(8)} · SHA-256: ${version.sha256}`, "gateway-location"));
      details.append(textNode("pre", version.text === null ? uiText("workspaceBinary") : version.text));
    }
    parent.append(details);
  }
  function paintReview(force = false) {
    const signature = JSON.stringify(review);
    if (!force && signature === reviewSignature) return;
    reviewSignature = signature;
    el("gateway-workspace-changes").replaceChildren();
    el("gateway-workspace-limitations").replaceChildren();
    if (!review) return;
    const preview = review.preview;
    setText("gateway-workspace-review-detail", `${uiText("workspaceSessionId")}: ${review.session_id}\n${uiText("workspaceOriginal")}: ${preview.workspace_root}\n${uiText("workspaceRecovery")}: ${preview.recovery_directory}\n${uiText("gatewayBoundDigest")}: ${review.review_sha256}\n${uiText("workspaceExpires")}: ${new Date(review.expires_at_ms).toLocaleString()}`);
    for (const limitation of preview.limitations) el("gateway-workspace-limitations").append(textNode("li", limitation));
    for (const change of preview.changes) {
      const section = document.createElement("section"); section.className = "gateway-file-change";
      section.append(textNode("h5", `${uiText(kindKeys[change.kind] || "workspaceOutcomeUnknown")} · ${change.path}`));
      showVersion(section, change.before, "workspaceBefore"); showVersion(section, change.after, "workspaceAfter");
      el("gateway-workspace-changes").append(section);
    }
  }
  function paintResult(force = false) {
    const signature = JSON.stringify(result);
    if (!force && signature === resultSignature) return;
    resultSignature = signature;
    el("gateway-workspace-result-files").replaceChildren();
    el("gateway-workspace-result").hidden = !result;
    if (!result) return;
    setText("gateway-workspace-result-summary", `${uiText(outcomeKeys[result.outcome] || "workspaceOutcomeUnknown")} · ${result.detail}`);
    setText("gateway-workspace-result-recovery", result.recovery_directory ? `${uiText("workspaceRecovery")}: ${result.recovery_directory}` : uiText("workspaceNoRecovery"));
    for (const file of result.files) el("gateway-workspace-result-files").append(textNode("li", `${file.path} · ${uiText(outcomeKeys[file.state] || "workspaceOutcomeUnknown")}\n${file.detail}${file.recovery_file ? `\n${uiText("workspaceRecovery")}: ${file.recovery_file}` : ""}`));
  }
  function render() {
    const connection = getConnection();
    el("gateway-workspace").hidden = !connection?.supports_workspace;
    if (!connection?.supports_workspace) return;
    const fresh = !!state && performance.now() - checkedAt < 3000;
    const active = fresh && state.session_state === "active";
    const entry = state?.workspaces.find(w => w.workspace_id === selected);
    const ready = active && !state.busy && !working && !controlling && !unknown;
    setText("gateway-workspace-state", state ? `${uiText(stateKeys[state.session_state] || "workspaceFailed")}${state.busy ? ` · ${uiText("workspaceBusy")}` : ""}` : uiText("workspaceUnavailable"));
    setText("gateway-workspace-detail", state ? `${uiText("workspaceSessionId")}: ${state.session_id} · ${uiText("workspaceProfile")}: ${state.task_profile}\n${uiText("workspaceLastClient")}: ${state.last_client_message_ms ? new Date(state.last_client_message_ms).toLocaleString() : uiText("workspaceNoClient")}` : "");
    setText("gateway-workspace-feedback", feedback ? uiText(feedback) : "");
    el("gateway-workspace-submitted").hidden = !submitted;
    setText("gateway-workspace-submitted", submitted ? `${uiText("workspaceSubmitted")}: ${submitted.review_id}\n${uiText("workspaceSessionId")}: ${submitted.session_id}\n${uiText("workspaceOriginal")}: ${submitted.preview.workspace_root}\n${uiText("workspaceRecovery")}: ${submitted.preview.recovery_directory}\n${uiText("gatewayBoundDigest")}: ${submitted.review_sha256}` : "");
    el("gateway-workspace-pause").disabled = !active || controlling;
    el("gateway-workspace-resume").disabled = !fresh || state.session_state !== "paused" || state.busy || controlling || working;
    el("gateway-workspace-stop").disabled = !fresh || ["stopped", "failed"].includes(state.session_state) || controlling;
    el("gateway-workspace-refresh").disabled = polling;
    el("gateway-workspace-select").disabled = working || controlling || !state?.workspaces.length;
    el("gateway-workspace-preview").disabled = !ready || !entry?.writable || !entry?.writeback_available;
    setText("gateway-workspace-location", entry ? `${uiText("workspaceOriginal")}: ${entry.target}\n${uiText("workspaceSnapshot")}: ${entry.snapshot}` : "");
    setText("gateway-workspace-reason", !entry ? uiText("workspaceNoWorkspaces") : !entry.writable || !entry.writeback_available ? entry.writeback_reason || uiText("workspaceReadOnly") : "");
    el("gateway-workspace-reason").hidden = !el("gateway-workspace-reason").textContent;
    el("gateway-workspace-review").hidden = !review;
    const pending = state?.pending_review;
    const bound = !!review && review.workspace_id === selected && review.session_id === state?.session_id
      && pending?.review_id === review.review_id && pending?.review_sha256 === review.review_sha256
      && pending?.expires_at_ms === review.expires_at_ms && pending?.workspace_id === review.workspace_id
      && /^[a-f0-9]{64}$/i.test(review.review_sha256 || "") && review.expires_at_ms > Date.now();
    el("gateway-workspace-discard").disabled = !ready || !bound;
    el("gateway-workspace-reviewed").disabled = !ready || !bound || !review?.preview.changes.length;
    el("gateway-workspace-apply").disabled = el("gateway-workspace-reviewed").disabled || !el("gateway-workspace-reviewed").checked;
    if (review && review.expires_at_ms <= Date.now()) { el("gateway-workspace-reviewed").checked = false; setText("gateway-workspace-feedback", uiText("workspaceExpired")); }
    paintReview(); paintResult();
  }
  function applyState(next) {
    const changedSession = !!state && state.session_id !== next.session_id;
    const nextReview = next.pending_review;
    if (changedSession) { clearReview(); unknown = false; submitted = null; }
    if (review && (next.session_id !== review.session_id || next.session_state !== "active" || nextReview?.review_id !== review.review_id
      || nextReview?.review_sha256 !== review.review_sha256 || nextReview?.expires_at_ms !== review.expires_at_ms || nextReview?.workspace_id !== review.workspace_id)) clearReview();
    const optionsChanged = JSON.stringify(state?.workspaces) !== JSON.stringify(next.workspaces);
    state = next; checkedAt = performance.now();
    if (!state.workspaces.some(w => w.workspace_id === selected)) { selected = state.workspaces[0]?.workspace_id || ""; clearReview(); }
    if (optionsChanged) {
      el("gateway-workspace-select").replaceChildren(...state.workspaces.map(w => { const option = textNode("option", w.target); option.value = w.workspace_id; return option; }));
      el("gateway-workspace-select").value = selected;
    }
    result = state.last_result;
    render();
  }
  async function poll() {
    const connection = getConnection();
    if (!connection?.supports_workspace || polling) return;
    const current = revision; const id = connection.connection_id;
    polling = true; render();
    try {
      const next = await invoke("poll_gateway_workspace", { connectionId: id });
      if (current === revision && getConnection()?.connection_id === id) applyState(next);
    } catch (error) { if (current === revision) { state = null; clearReview(); if (!unknown) feedback = errorKey(error); } }
    finally { polling = false; render(); }
  }
  async function preview() {
    render(); if (el("gateway-workspace-preview").disabled) return;
    const id = getConnection().connection_id; const current = ++revision;
    working = true; feedback = "workspaceWorking"; submitted = null; clearReview(); render();
    try {
      const next = await invoke("preview_gateway_workspace", { connectionId: id, workspaceId: selected });
      if (current === revision && getConnection()?.connection_id === id) {
        review = next; feedback = next.preview.changes.length ? "workspacePreviewReady" : "workspaceNoChanges";
      }
    } catch (error) { if (current === revision) { clearReview(); feedback = errorKey(error); } }
    finally { if (current === revision) working = false; render(); await poll(); }
  }
  async function writeback() {
    render(); if (el("gateway-workspace-apply").disabled) return;
    const args = { connectionId: getConnection().connection_id, reviewId: review.review_id, reviewSha256: review.review_sha256 };
    const current = ++revision; working = true; feedback = "workspaceWorking"; submitted = review; clearReview(); render();
    try {
      const report = await invoke("apply_gateway_workspace", args);
      if (current === revision) { result = report; feedback = outcomeKeys[report.outcome] || "workspaceOutcomeUnknown"; if (report.outcome === "unknown") { unknown = true; feedback = "workspaceUnknown"; } }
    } catch (error) {
      if (current === revision) { feedback = errorKey(error); if (feedback === "workspaceUnknown") unknown = true; }
    } finally { if (current === revision) working = false; render(); await poll(); }
  }
  async function discard() {
    render(); if (el("gateway-workspace-discard").disabled) return;
    const args = { connectionId: getConnection().connection_id, reviewId: review.review_id, reviewSha256: review.review_sha256 };
    const current = ++revision; working = true; feedback = "workspaceWorking"; clearReview(); render();
    try {
      const next = await invoke("discard_gateway_workspace", args);
      if (current === revision) { applyState(next); feedback = "workspaceDiscarded"; }
    } catch (error) { if (current === revision) feedback = errorKey(error) === "workspaceUnknown" ? "workspaceOperationFailed" : errorKey(error); }
    finally { if (current === revision) working = false; render(); await poll(); }
  }
  async function control(action) {
    render(); if (el(`gateway-workspace-${action}`).disabled) return;
    const id = getConnection().connection_id; const current = ++revision;
    controlling = true; working = false; clearReview(); feedback = "workspaceWorking"; render();
    try {
      governance.invalidate();
      const next = await invoke("control_gateway_workspace", { connectionId: id, action });
      if (current === revision) { applyState(next); feedback = "workspaceControlDone"; }
    } catch (error) { if (current === revision) feedback = errorKey(error); }
    finally { if (current === revision) controlling = false; render(); await poll(); }
  }
  function reset() {
    owner = ""; revision++; state = null; result = null; submitted = null; selected = ""; feedback = "";
    working = false; controlling = false; unknown = false; clearReview(); resultSignature = ""; render();
  }
  function connectionChanged() {
    const connection = getConnection();
    const help = connection?.managed ? "workspaceManagedControlHelp" : "workspaceControlHelp";
    el("gateway-workspace-control-help").dataset.ui = help;
    setText("gateway-workspace-control-help", uiText(help));
    if (connection?.connection_id !== owner) { reset(); owner = connection?.connection_id || ""; if (connection?.supports_workspace) poll(); }
    render();
  }
  el("gateway-workspace-select").onchange = () => { selected = el("gateway-workspace-select").value; clearReview(); feedback = ""; render(); };
  el("gateway-workspace-reviewed").onchange = render;
  el("gateway-workspace-preview").onclick = preview;
  el("gateway-workspace-apply").onclick = writeback;
  el("gateway-workspace-discard").onclick = discard;
  el("gateway-workspace-refresh").onclick = poll;
  for (const action of ["pause", "resume", "stop"]) el(`gateway-workspace-${action}`).onclick = () => control(action);
  window.addEventListener("agentguard-locale-change", () => { paintReview(true); paintResult(true); render(); });
  window.addEventListener("focus", poll);
  window.setInterval(poll, 1000);
  window.setInterval(render, 200);
  return {
    reset, connectionChanged,
    hasReview: () => !!review || !!state?.pending_review,
    async showPreview() {
      await poll();
      if (!review && !el("gateway-workspace-preview").disabled) await preview();
      el("gateway-workspace").scrollIntoView({ block: "start" });
      el("gateway-workspace-title").focus({ preventScroll: true });
    },
  };
}

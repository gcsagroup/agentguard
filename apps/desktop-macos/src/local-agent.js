import { uiText } from "./workspace-i18n.js";
const el = (id) => document.getElementById(id);
const text = (id, value) => { if (el(id).textContent !== value) el(id).textContent = value; };
const phases = {
  starting: "localAgentStarting", running: "localAgentRunning", awaiting_review: "localAgentAwaitingReview",
  paused: "localAgentPaused", ready: "localAgentReady", failed: "localAgentFailed", stopped: "localAgentStopped",
};
const stepStates = { running: "localAgentStepRunning", succeeded: "localAgentStepSucceeded", failed: "localAgentStepFailed", cancelled: "localAgentStepCancelled", unknown: "localAgentStepUnknown" };
const tools = { read_file: "localAgentToolRead", write_file: "localAgentToolWrite", delete_file: "localAgentToolDelete", list_dir: "localAgentToolList", search: "localAgentToolSearch", search_file: "localAgentToolSearch", search_files: "localAgentToolSearch", run_shell: "localAgentToolShell", browser_status: "localAgentBrowserStatus", browser_navigate: "localAgentBrowserNavigate", browser_read: "localAgentBrowserRead", browser_click: "localAgentBrowserClick", browser_fill: "localAgentBrowserFill" };

// 本地任务只采用宿主给出的安全视图，任务正文和模型回答不解释为 HTML。
export function initializeLocalAgent(invoke, gateway, showActive) {
  let run = null;
  let working = false;
  let controlling = false;
  let polling = false;
  let generation = 0;
  let feedback = "";
  let detail = "";
  let browserAvailable = false;
  let browserChecking = false;
  let browserFeedback = "localAgentBrowserUnchecked";
  let browserError = "";
  let modelLoading = false;
  let modelGeneration = 0;
  let modelPort = 0;
  let modelNames = [];
  let lastManagedId = null;
  let replaceableId = null;
  let adoptionAttempt = "";
  let stepsSignature = "";
  let preparingNew = false;

  const port = () => Number(el("local-agent-port").value);
  const browserEnabled = () => el("local-agent-browser-enabled").checked;
  const browserOrigins = () => el("local-agent-browser-origins").value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  const validBrowser = () => {
    const origins = browserOrigins();
    return origins.length > 0 && origins.length <= 8 && new Set(origins).size === origins.length && origins.every(origin => {
      const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(origin);
      return match && Number(match[1]) <= 65535 && Number(match[1]) !== port();
    });
  };
  const validPort = () => Number.isInteger(port()) && port() >= 1 && port() <= 65535;
  const matchingConnection = () => !!run?.connection && gateway.current()?.connectionId === run.connection.connection_id;
  const unresolvedReview = () => matchingConnection() && gateway.hasWorkspaceReview();
  function setFeedback(key = "", error = "") { feedback = key; detail = error; }
  function renderModels() {
    const selected = el("local-agent-model").value;
    el("local-agent-model").replaceChildren();
    if (!modelNames.length) {
      const option = document.createElement("option"); option.value = ""; option.textContent = uiText("localAgentNoModel"); el("local-agent-model").append(option);
    }
    for (const name of modelNames) {
      const option = document.createElement("option"); option.value = name; option.textContent = name; el("local-agent-model").append(option);
    }
    if (modelNames.includes(selected)) el("local-agent-model").value = selected;
  }
  function renderSteps(force = false) {
    const signature = JSON.stringify(run?.steps || []);
    if (!force && signature === stepsSignature) return;
    stepsSignature = signature;
    el("local-agent-steps").replaceChildren();
    for (const step of run?.steps || []) {
      const item = document.createElement("li");
      item.value = step.number;
      const label = document.createElement("span"); label.textContent = tools[step.tool] ? uiText(tools[step.tool]) : String(step.tool);
      const state = document.createElement("span"); state.className = "badge"; state.textContent = uiText(stepStates[step.state] || "localAgentStepUnknown");
      item.append(label, state); el("local-agent-steps").append(item);
    }
  }
  function render() {
    const phase = run?.phase;
    const hasRun = !!run && !preparingNew;
    el("local-agent-form").hidden = hasRun;
    el("local-agent-run").hidden = !hasRun;
    for (const id of ["local-agent-pick", "local-agent-mode", "local-agent-port", "local-agent-task", "local-agent-model-data"]) el(id).disabled = working;
    el("local-agent-browser-enabled").disabled = working;
    el("local-agent-browser-origins").disabled = working || !browserEnabled();
    el("local-agent-browser-check").disabled = working || browserChecking;
    text("local-agent-browser-status", `${uiText(browserFeedback)}${browserError ? ` ${browserError}` : ""}${browserEnabled() && !validBrowser() ? ` ${uiText("localAgentBrowserScopeInvalid")}` : ""}`);
    el("local-agent-models").disabled = working || modelLoading || !validPort();
    el("local-agent-model").disabled = working || modelLoading || !modelNames.length;
    el("local-agent-start").disabled = working || modelLoading || !validPort() || modelPort !== port() || !modelNames.includes(el("local-agent-model").value) || !el("local-agent-workspace").value.trim() || !el("local-agent-task").value.trim() || !el("local-agent-model-data").checked || (browserEnabled() && (!browserAvailable || browserChecking || !validBrowser()));
    text("local-agent-model-recipient", `${uiText("localAgentModelRecipient")}: http://127.0.0.1:${port()}/v1/chat/completions`);
    text("local-agent-scope", uiText(el("local-agent-mode").value === "write" ? "localAgentWriteScope" : "localAgentReadScope"));
    text("local-agent-feedback", [feedback ? uiText(feedback) : "", detail].filter(Boolean).join(" "));
    text("local-agent-phase", uiText(phases[phase] || "localAgentReady"));
    text("local-agent-run-scope", run ? `${uiText("localAgentProject")}: ${run.workspace}\n${uiText(run.write_enabled ? "localAgentWrite" : "localAgentRead")}` : "");
    text("local-agent-run-model", run ? `${uiText("localAgentModel")}: ${run.model} · 127.0.0.1:${run.model_port}
${uiText("localAgentModelDataGranted")}` : "");
    text("local-agent-run-browser", run?.browser_origins?.length ? `${uiText("localAgentBrowserActive")}: ${run.browser_origins.join(", ")}` : uiText("localAgentBrowserDisabled"));
    el("local-agent-pause").disabled = !["running", "awaiting_review", "ready"].includes(phase) || controlling;
    el("local-agent-resume").disabled = phase !== "paused" || controlling;
    el("local-agent-stop").disabled = !hasRun || phase === "stopped" || controlling;
    el("local-agent-refresh").disabled = polling || controlling;
    el("local-agent-new").hidden = phase !== "stopped";
    el("local-agent-new").disabled = working || controlling;
    el("local-agent-run-error").hidden = !run?.error;
    text("local-agent-run-error", run?.error || "");
    el("local-agent-empty-steps").hidden = !!run?.steps?.length;
    el("local-agent-answer-section").hidden = !run?.answer;
    text("local-agent-answer", run?.answer || "");
    el("local-agent-confirm").hidden = !matchingConnection() || !gateway.hasPending();
    el("local-agent-confirm").disabled = controlling || !matchingConnection();
    el("local-agent-results").disabled = !hasRun || !run.write_enabled || !run.connection || ["starting", "running", "paused", "stopped"].includes(phase) || working || controlling;
    el("local-agent-return").hidden = !hasRun || !matchingConnection();
    el("local-agent-followup-form").hidden = !hasRun || ["failed", "stopped"].includes(phase);
    el("local-agent-followup").disabled = working || controlling || !["ready", "awaiting_review"].includes(phase);
    el("local-agent-continue").disabled = working || controlling || !["ready", "awaiting_review"].includes(phase) || unresolvedReview() || !el("local-agent-followup").value.trim();
    text("local-agent-followup-help", uiText(unresolvedReview() ? "localAgentReviewFirst" : phase === "paused" ? "localAgentResumeFirst" : "localAgentFollowupHelp"));
    renderSteps();
  }
  function apply(next) {
    if (!next || !phases[next.phase] || typeof next.run_id !== "string" || !Array.isArray(next.steps)) throw new Error(uiText("localAgentInvalidReply"));
    if (next.phase !== "ready" && feedback === "localAgentResumed") setFeedback();
    run = next;
    if (next.phase === "stopped" && !next.connection && lastManagedId) gateway.forgetManaged(lastManagedId);
    if (next.connection) {
      const identity = `${next.run_id}:${next.connection.connection_id}`;
      if (identity !== adoptionAttempt) {
        adoptionAttempt = identity;
        if (gateway.adopt(next.connection, { replaceConnectionId: replaceableId })) {
          lastManagedId = next.connection.connection_id; replaceableId = null;
        } else setFeedback("localAgentOtherConnection");
      }
    }
    render();
  }
  async function poll() {
    if (polling || working || controlling) return;
    const current = generation;
    polling = true;
    try {
      const next = await invoke("poll_local_agent");
      if (current !== generation || preparingNew) return;
      if (next) { if (["localAgentPollFailed", "localAgentStartFailed"].includes(feedback)) setFeedback(); apply(next); }
      else if (run) { run = null; render(); }
    } catch (error) { if (current === generation) setFeedback("localAgentPollFailed", String(error)); }
    finally { polling = false; render(); }
  }
  async function loadModels() {
    if (modelLoading || working || !validPort()) return;
    const requestedPort = port(); const current = ++modelGeneration;
    modelLoading = true; setFeedback("localAgentLoadingModels"); render();
    try {
      const result = await invoke("list_local_agent_models", { port: requestedPort });
      if (current !== modelGeneration || requestedPort !== port()) return;
      if (!Array.isArray(result.models) || result.models.some(name => typeof name !== "string" || !name.trim())) throw new Error(uiText("localAgentInvalidReply"));
      modelNames = [...new Set(result.models)]; modelPort = requestedPort;
      renderModels(); setFeedback(modelNames.length ? "localAgentModelsReady" : "localAgentModelsEmpty");
    } catch (error) {
      if (current === modelGeneration) { modelNames = []; modelPort = 0; renderModels(); setFeedback("localAgentModelsFailed", String(error)); }
    } finally { if (current === modelGeneration) modelLoading = false; render(); }
  }
  el("local-agent-pick").onclick = async () => {
    if (working) return;
    working = true; setFeedback(); render();
    try {
      const path = await invoke("pick_local_agent_workspace");
      if (path) { el("local-agent-workspace").value = path; el("local-agent-model-data").checked = false; }
    } catch (error) { setFeedback("localAgentPickFailed", String(error)); }
    finally { working = false; render(); }
  };
  el("local-agent-models").onclick = loadModels;
  el("local-agent-browser-check").onclick = async () => {
    if (working || browserChecking) return;
    browserChecking = true; browserAvailable = false; browserFeedback = "localAgentBrowserChecking"; browserError = ""; render();
    try {
      const result = await invoke("check_local_agent_browser");
      if (result?.available !== true || result.scope !== "exact_loopback_http") throw new Error(uiText("localAgentInvalidReply"));
      browserAvailable = true; browserFeedback = "localAgentBrowserReady";
    } catch (error) { browserFeedback = "localAgentBrowserMissing"; browserError = String(error); }
    finally { browserChecking = false; render(); }
  };
  for (const id of ["local-agent-browser-enabled", "local-agent-browser-origins"]) el(id).addEventListener("input", () => { el("local-agent-model-data").checked = false; render(); });
  el("local-agent-port").oninput = () => { el("local-agent-model-data").checked = false; modelGeneration++; modelLoading = false; modelNames = []; modelPort = 0; renderModels(); setFeedback("localAgentModelsChanged"); render(); };
  for (const id of ["local-agent-mode", "local-agent-model", "local-agent-task", "local-agent-followup", "local-agent-model-data"]) el(id).addEventListener("input", render);
  el("local-agent-form").onsubmit = async (event) => {
    event.preventDefault(); render(); if (el("local-agent-start").disabled) return;
    const previous = gateway.current();
    if (gateway.isConnecting() || (previous && !(previous.managed && previous.connectionId === lastManagedId && (!run || run.phase === "stopped")))) { setFeedback("localAgentOtherConnection"); render(); return; }
    replaceableId = previous?.connectionId || null;
    const current = ++generation;
    working = true; preparingNew = false; setFeedback("localAgentStarting"); render();
    try {
      const next = await invoke("start_local_agent", {
        workspace: el("local-agent-workspace").value, writeEnabled: el("local-agent-mode").value === "write",
        browserOrigins: browserEnabled() ? browserOrigins() : [],
        modelDataAuthorized: el("local-agent-model-data").checked,
        port: port(), model: el("local-agent-model").value, task: el("local-agent-task").value.trim(),
      });
      if (current === generation) { setFeedback(); apply(next); }
    } catch (error) { if (current === generation) setFeedback("localAgentStartFailed", String(error)); }
    finally { if (current === generation) working = false; render(); await poll(); }
  };
  el("local-agent-followup-form").onsubmit = async (event) => {
    event.preventDefault(); render(); if (el("local-agent-continue").disabled) return;
    const current = ++generation; const id = run.run_id; const task = el("local-agent-followup").value.trim();
    working = true; setFeedback(); render();
    try {
      const next = await invoke("continue_local_agent", { runId: id, task });
      if (current === generation) { el("local-agent-followup").value = ""; apply(next); }
    } catch (error) { if (current === generation) setFeedback("localAgentContinueFailed", String(error)); }
    finally { if (current === generation) working = false; render(); await poll(); }
  };
  async function control(action) {
    render(); if (el(`local-agent-${action}`).disabled || !run) return;
    const id = run.run_id; const current = ++generation;
    controlling = true; working = false; setFeedback(); render();
    try {
      const next = await invoke("control_local_agent", { runId: id, action });
      if (current === generation) { apply(next); if (action === "resume") setFeedback("localAgentResumed"); }
    } catch (error) { if (current === generation) setFeedback("localAgentControlFailed", String(error)); }
    finally { if (current === generation) controlling = false; render(); await poll(); }
  }
  for (const action of ["pause", "resume", "stop"]) el(`local-agent-${action}`).onclick = () => control(action);
  el("local-agent-refresh").onclick = poll;
  el("local-agent-results").onclick = async () => {
    render(); if (el("local-agent-results").disabled) return;
    if (!matchingConnection()) { setFeedback("localAgentOtherConnection"); render(); return; }
    await gateway.showResults(); render();
  };
  el("local-agent-confirm").onclick = () => gateway.showPending();
  el("local-agent-return").onclick = () => {
    el("local-agent").scrollIntoView({ block: "start" });
    el("local-agent-title").focus({ preventScroll: true });
  };
  el("local-agent-new").onclick = () => {
    if (run?.phase !== "stopped") return;
    generation++; preparingNew = true; setFeedback(); render();
    el("local-agent-workspace").value = run.workspace;
    el("local-agent-mode").value = run.write_enabled ? "write" : "read";
    el("local-agent-task").value = "";
    el("local-agent-model-data").checked = false;
    el("local-agent-browser-enabled").checked = !!run.browser_origins?.length;
    el("local-agent-browser-origins").value = (run.browser_origins || []).join("\n");
    render();
    el("local-agent-task").focus();
  };
  document.querySelectorAll("[data-open-local-agent]").forEach(button => {
    button.onclick = () => { showActive(); el("local-agent").scrollIntoView({ block: "start" }); el("local-agent-title").focus({ preventScroll: true }); };
  });
  window.addEventListener("agentguard-locale-change", () => { renderModels(); renderSteps(true); render(); });
  window.addEventListener("focus", poll);
  window.setInterval(poll, 1000);
  render(); poll();
}

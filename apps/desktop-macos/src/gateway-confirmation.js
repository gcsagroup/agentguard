import { uiText } from "./workspace-i18n.js";
const el = (id) => document.getElementById(id);
const setText = (id, value) => { if (el(id).textContent !== value) el(id).textContent = value; };

// 与桌面事后提醒完全分开；不持久化凭据，不把外部命令解释为 HTML。
export function initializeGatewayConfirmation(invoke) {
  let connection = null;
  let pending = null;
  let deadline = 0;
  let checkedAt = 0;
  let generation = 0;
  let busy = false;
  let polling = false;
  let statusKey = "gatewayDisconnected";
  let feedbackKey = "";
  function clearPending() {
    pending = null;
    deadline = 0;
    el("gateway-reviewed").checked = false;
    el("gateway-request-what").textContent = "";
    el("gateway-findings").replaceChildren();
  }
  function render() {
    el("gateway-connect-form").hidden = !!connection;
    el("gateway-connect").disabled = busy;
    el("gateway-disconnect").hidden = !connection;
    el("gateway-disconnect").disabled = busy;
    // 倒计时刷新不能反复重建相同的状态文本，避免原生读屏重复播报。
    setText("gateway-connection-status", uiText(statusKey));
    setText("gateway-answer-feedback", feedbackKey ? uiText(feedbackKey) : "");
    setText("gateway-connection-detail", connection ? `127.0.0.1:${connection.port} · ${connection.instance_id}` : "");
    el("gateway-pending").hidden = !pending;
    const remaining = Math.max(0, deadline - performance.now());
    const fresh = !!pending && remaining > 0 && performance.now() - checkedAt < 2500 && !busy;
    el("gateway-deny").disabled = !fresh;
    el("gateway-approve").disabled = !fresh || !el("gateway-reviewed").checked;
    el("gateway-reviewed").disabled = !fresh;
    setText("gateway-countdown", pending ? `${uiText(remaining > 0 ? "gatewayRemaining" : "gatewayExpired")} ${remaining > 0 ? Math.ceil(remaining / 1000) : ""}` : "");
  }
  function apply(view, started) {
    connection = view;
    const next = view.pending;
    if (JSON.stringify(next) !== JSON.stringify(pending)) {
      clearPending();
      pending = next;
      if (pending) {
        feedbackKey = ""; // 上一条回执不能出现在新请求上方，造成处置归属混淆。
        el("gateway-request-id").textContent = pending.id;
        el("gateway-request-what").textContent = pending.what;
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
  async function drop(key) {
    const previous = connection;
    generation++;
    connection = null;
    clearPending();
    statusKey = key;
    render();
    if (previous) {
      try { await invoke("disconnect_gateway_confirmation", { connectionId: previous.connection_id }); } catch { /* 不自动批准或重新连接。 */ }
    }
  }
  el("gateway-connect-form").onsubmit = async (event) => {
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
    } catch { if (current === generation) await drop("gatewayConnectFailed"); }
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
    } catch { if (current === generation) await drop("gatewayLost"); }
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
  window.addEventListener("agentguard-locale-change", render);
  window.setInterval(poll, 1000);
  window.setInterval(render, 200);
  render();
}

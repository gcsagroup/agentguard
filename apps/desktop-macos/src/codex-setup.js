import { uiText } from "./workspace-i18n.js";
const el = (id) => document.getElementById(id);

export function initializeCodexSetup(invoke) {
  let generation = 0;
  let feedback = "";
  let prepared = null;
  function render() {
    el("codex-scope").textContent = uiText(el("codex-mode").value === "write" ? "codexWriteScope" : "codexReadScope");
    el("codex-feedback").textContent = feedback ? uiText(feedback) : "";
    if (prepared) el("codex-verified-scope").textContent = `${uiText("codexWorkspace")}: ${prepared.workspace} · ${uiText(prepared.write_enabled ? "codexWrite" : "codexRead")}`;
  }
  function invalidate() {
    generation++;
    prepared = null;
    el("codex-command").value = "";
    el("codex-output").hidden = true;
    feedback = "codexStale";
    render();
  }
  for (const id of ["codex-workspace", "codex-mode", "codex-task"]) el(id).addEventListener("input", invalidate);
  el("codex-setup-form").onsubmit = async (event) => {
    event.preventDefault();
    if (el("codex-generate").disabled) return;
    invalidate();
    const current = generation;
    feedback = "checking";
    el("codex-generate").disabled = true;
    render();
    try {
      const result = await invoke("prepare_codex_setup", {
        workspace: el("codex-workspace").value.trim(),
        writeEnabled: el("codex-mode").value === "write",
        task: el("codex-task").value,
      });
      if (current !== generation) return;
      prepared = result;
      el("codex-command").value = result.command;
      el("codex-plan-path").textContent = result.plan_path;
      el("codex-output").hidden = false;
      feedback = "codexPrepared";
      render();
    } catch (error) {
      if (current === generation) {
        feedback = "actionFailed";
        render();
        el("codex-feedback").append(document.createTextNode(` ${String(error)}`));
      }
    } finally { el("codex-generate").disabled = false; }
  };
  el("codex-copy").onclick = async () => {
    if (!prepared) return;
    const current = generation;
    try {
      await navigator.clipboard.writeText(prepared.command);
      if (current === generation) feedback = "copied";
    } catch { if (current === generation) feedback = "copyFailed"; }
    render();
  };
  el("codex-confirm-link").onclick = () => {
    el("gateway-confirmation").scrollIntoView({ block: "start" });
    el("gateway-control-path").focus();
  };
  window.addEventListener("agentguard-locale-change", render);
  render();
}

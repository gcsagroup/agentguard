import { uiText } from "./workspace-i18n.js";

const el = (id) => document.getElementById(`governance-${id}`);
const node = (tag, text, className = "") => {
  const value = document.createElement(tag); value.textContent = text; value.className = className; return value;
};
const time = (ms) => Number.isFinite(ms) ? new Date(ms).toLocaleString() : uiText("governanceUnknownTime");
const stateText = (state) => uiText(({ active: "governanceActive", quarantined: "governanceQuarantined", revoked: "governanceRevoked" })[state] || "governanceUnknown");
const details = (title, value) => {
  const box = document.createElement("details"); box.append(node("summary", title), node("pre", JSON.stringify(value, null, 2), "gateway-request-text")); return box;
};

// 只从原生层接收安全视图。来源和正文始终作为数据展示，不注入 HTML 或执行指令。
export function initializeGatewayGovernance(invoke, getConnection) {
  let owner = "", generation = 0, busy = false, selected = null, history = null;
  let nextKey = null, review = null, tree = null, treeSession = "", feedback = "", entriesPage = null;
  const clearReview = () => {
    review = null; el("reviewed").checked = false; el("review-body").replaceChildren();
  };
  function reset() {
    generation++; owner = ""; busy = false; selected = null; history = null;
    entriesPage = null; nextKey = null; tree = null; treeSession = ""; feedback = ""; clearReview();
    for (const id of ["entry-count", "entries", "history", "tree", "result"]) el(id).replaceChildren();
    render();
  }
  function render() {
    el("panel").hidden = !getConnection()?.supports_workspace;
    el("feedback").textContent = feedback ? uiText(feedback) : "";
    for (const id of ["load-memory", "load-tree"]) el(id).disabled = busy || !owner;
    el("more-memory").hidden = !nextKey;
    el("more-memory").disabled = busy;
    el("more-history").hidden = !history?.next_version;
    el("more-history").disabled = busy;
    for (const id of ["quarantine", "revoke", "restore", "version", "expiry"]) el(id).disabled = busy || !selected || !history;
    el("restore").disabled ||= !el("version").value || !el("expiry").value;
    el("memory-actions").hidden = !selected || !history;
    el("review").hidden = !review;
    const valid = !!review && review.expires_at_ms > Date.now() && !busy;
    el("reviewed").disabled = !valid;
    el("apply").disabled = !valid || !el("reviewed").checked;
    el("discard").disabled = !valid;
    if (review && !valid && !busy) el("reviewed").checked = false;
    el("review-expiry").textContent = review ? `${uiText(valid || busy ? "governanceReviewUntil" : "governanceExpired")}: ${time(review.expires_at_ms)}` : "";
    for (const button of el("entries").querySelectorAll("button")) button.disabled = busy;
    for (const button of el("tree").querySelectorAll("button")) button.disabled = busy || button.dataset.unavailable === "true";
  }
  async function run(command, accept) {
    if (busy || !owner) return;
    const token = ++generation, id = owner;
    busy = true; feedback = ""; render();
    try {
      const value = await invoke("govern_gateway", { connectionId: id, command });
      if (generation !== token || owner !== id) return;
      accept(value); feedback ||= "governanceLoaded";
    } catch (error) {
      if (generation !== token || owner !== id) return;
      clearReview(); selected = null; history = null; tree = null; el("history").replaceChildren(); el("tree").replaceChildren();
      feedback = String(error).includes("OUTCOME_UNKNOWN") ? "governanceOutcomeUnknown" : "governanceUnavailable";
    } finally {
      if (generation === token && owner === id) { busy = false; render(); }
    }
  }
  function showEntries(data) {
    entriesPage = data;
    el("entries").replaceChildren(); nextKey = data.next_key;
    el("entry-count").textContent = `${uiText("governanceEntryCount")}: ${data.total_keys}`;
    if (!data.entries.length) el("entries").append(node("p", uiText("governanceEmpty")));
    for (const entry of data.entries) {
      const box = node("section", "", "gateway-file-change");
      box.append(node("h4", entry.key), node("p", `${stateText(entry.state)} · ${uiText("governanceVersion")} ${entry.version}${entry.expired ? ` · ${uiText("governanceExpired")}` : ""}`));
      const button = node("button", uiText("governanceHistory"), "secondary");
      button.onclick = () => loadHistory(entry.key);
      box.append(button); el("entries").append(box);
    }
  }
  function loadMemory(after = null) {
    clearReview(); selected = null; history = null; el("history").replaceChildren();
    return run({ operation: "memory_list", after_key: after }, ({ data }) => showEntries(data));
  }
  function showHistory() {
    el("history").replaceChildren(); el("version").replaceChildren(node("option", uiText("governanceChooseVersion")));
    el("version").firstChild.value = "";
    for (const version of history.versions) {
      const box = node("section", "", "gateway-file-change");
      box.append(node("h4", `${selected} · ${uiText("governanceVersion")} ${version.version}`),
        node("p", `${stateText(version.state)} · ${time(version.committed_at_ms)} · ${uiText("governanceValidUntil")}: ${time(version.expires_at_ms)}`),
        node("p", `${uiText("governanceLabel")}: ${version.label.integrity} / ${version.label.confidentiality}`),
        node("pre", JSON.stringify(version.content, null, 2), "gateway-request-text"),
        details(`${uiText("governanceSources")} (${version.sources.length})`, version.sources),
        details(uiText("governanceEvidence"), { entry_sha256: version.entry_sha256, approval: version.approval, instruction_authority: version.instruction_authority }));
      el("history").append(box);
      if (version.state === "active") {
        const option = node("option", `${uiText("governanceVersion")} ${version.version} · ${time(version.committed_at_ms)}`); option.value = version.version; el("version").append(option);
      }
    }
    el("current").textContent = `${selected} · ${uiText("governanceCurrentVersion")} ${history.current_version}`;
  }
  function loadHistory(key, after = 0) {
    clearReview();
    return run({ operation: "memory_history", key, after_version: after }, ({ data }) => {
      if (after && (selected !== key || history?.current_version !== data.current_version)) {
        history = null; selected = null; el("history").replaceChildren(); feedback = "governanceChanged"; return;
      }
      selected = key;
      history = { ...data, versions: after ? [...history.versions, ...data.versions] : data.versions };
      showHistory();
    });
  }
  function preview(change) {
    render(); if (el(change).disabled) return;
    clearReview();
    const restore = change === "restore";
    const command = { operation: "memory_preview", key: selected, expected_version: history.current_version, change,
      source_version: restore ? Number(el("version").value) : null, expires_at_ms: restore ? new Date(el("expiry").value).getTime() : null };
    if (restore && (!Number.isSafeInteger(command.expires_at_ms) || command.expires_at_ms <= Date.now())) { feedback = "governanceChooseExpiry"; render(); return; }
    return run(command, ({ data }) => {
      review = data; showReview();
      feedback = "governanceReviewReady";
    });
  }
  function showReview() {
      const data = review, draft = data.draft;
      el("review-body").replaceChildren();
      el("review-body").append(node("h4", `${draft.key} · ${stateText(draft.state)} · ${uiText("governanceVersion")} ${draft.version}`),
        node("p", `${uiText("governanceLabel")}: ${draft.label.integrity} / ${draft.label.confidentiality}`),
        node("p", `${uiText("governanceValidUntil")}: ${time(draft.expires_at_ms)}`),
        node("pre", draft.content, "gateway-request-text"),
        details(`${uiText("governanceSources")} (${draft.sources.length})`, draft.sources),
        details(uiText("governanceEvidence"), { session_id: data.session_id, target: data.target, review_sha256: data.review_sha256, previous_sha256: draft.previous_sha256, policy_version: data.policy_version }));
  }
  function answer(apply) {
    render(); if (el(apply ? "apply" : "discard").disabled) return;
    const command = { operation: apply ? "memory_apply" : "memory_discard", review_id: review.review_id, review_sha256: review.review_sha256 };
    clearReview();
    return run(command, ({ data }) => {
      const outcome = data.execution?._meta?.agentguard?.outcome;
      feedback = apply ? (outcome === "success" ? "governanceApplied" : "governanceOutcomeUnknown") : "governanceDiscarded";
      el("result").replaceChildren(details(uiText("governanceResult"), data));
      selected = null; history = null; el("history").replaceChildren();
    });
  }
  function showTree(data) {
    tree = data.budget; treeSession = data.host_session_id; el("tree").replaceChildren();
    el("tree").append(node("p", `${uiText("governanceSession")}: ${treeSession}`));
    for (const branch of tree.nodes) {
      const box = node("section", "", "gateway-file-change");
      box.append(node("h4", branch.grant_id), node("p", `${uiText("governanceParent")}: ${branch.parent_grant_id || uiText("governanceRoot")}`),
        node("p", `${uiText(branch.revoked || tree.closed ? "governanceStopped" : "governanceActive")} · ${uiText("governanceCalls")}: ${branch.used_calls} / ${branch.limits.max_calls} · ${uiText("governanceRemainingSeconds")}: ${Math.ceil(branch.remaining_ms / 1000)}`),
        details(uiText("governanceBudget"), branch));
      const button = node("button", uiText("governanceStopBranch"), "secondary");
      button.dataset.unavailable = String(branch.revoked || tree.closed || !branch.remaining_ms);
      button.onclick = () => {
        clearReview();
        run({ operation: "delegation_revoke", host_session_id: treeSession, grant_id: branch.grant_id }, ({ data }) => {
          showTree(data); feedback = "governanceBranchStopped"; el("result").replaceChildren(details(uiText("governanceResult"), data));
        });
      };
      box.append(button); el("tree").append(box);
    }
  }
  el("load-memory").onclick = () => loadMemory();
  el("more-memory").onclick = () => loadMemory(nextKey);
  el("more-history").onclick = () => loadHistory(selected, history.next_version);
  for (const change of ["quarantine", "revoke", "restore"]) el(change).onclick = () => preview(change);
  el("reviewed").onchange = render;
  for (const id of ["version", "expiry"]) el(id).onchange = () => { clearReview(); render(); };
  el("apply").onclick = () => answer(true); el("discard").onclick = () => answer(false);
  el("load-tree").onclick = () => { clearReview(); run({ operation: "delegation_status" }, ({ data }) => showTree(data)); };
  window.setInterval(render, 500);
  window.addEventListener("agentguard-locale-change", () => {
    const version = el("version").value;
    if (entriesPage) showEntries(entriesPage);
    if (history) { showHistory(); el("version").value = version; }
    if (review) showReview();
    if (tree) showTree({ budget: tree, host_session_id: treeSession });
    render();
  });
  render();
  return {
    reset,
    connectionChanged() {
      const id = getConnection()?.connection_id || "";
      if (id !== owner) { reset(); owner = id; }
      render();
    },
    invalidate() { generation++; busy = false; selected = null; history = null; tree = null; clearReview(); el("tree").replaceChildren(); el("history").replaceChildren(); feedback = "governanceChanged"; render(); },
  };
}

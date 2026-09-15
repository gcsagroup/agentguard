import { uiText } from "./workspace-i18n.js";

const byId = (id) => document.getElementById(id);
const node = (tag, text, className) => {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
};

// 本接口只有桌面观察记录。即便原始动作是 Block 或用户点了拒绝，也不证明外部阻断。
export function observedRecordOutcome(row) {
  if (row?.effect !== "observed_only" || row.external_action_blocked !== false) return "unknown";
  if (["Block", "Alert"].includes(row.action)) return "alert";
  if (["Allow", "LogOnly"].includes(row.action)) return "record";
  return "unknown";
}

function facts(parent, pairs) {
  const list = node("dl", undefined, "knowledge-facts");
  for (const [key, value] of pairs) {
    list.append(node("dt", uiText(key)), node("dd", Array.isArray(value) ? value.join("；") : value || uiText("knowledgeNone")));
  }
  parent.append(list);
}

function section(parent, key) {
  const box = node("section", undefined, "card knowledge-section");
  box.append(node("h3", uiText(key)));
  parent.append(box);
  return box;
}

function details(parent, title) {
  const box = node("details");
  box.append(node("summary", title));
  parent.append(box);
  return box;
}

function artifacts(parent, items, key) {
  const box = details(parent, `${uiText(key)} · ${items.length}`);
  if (!items.length) box.append(node("p", uiText("knowledgeNoEvidence"), "muted"));
  for (const item of items) {
    box.append(node("p", item.path), node("code", `SHA-256 ${item.sha256}`), node("p", item.provenance, "muted"));
  }
}

// 来源也只作可复制文字；不动态导航、不加载远程图片、不读取资料中的文件路径。
export function sourceReference(source) {
  const reference = node("span", `${source.title} · ${source.publisher}`);
  let url;
  try { url = new URL(source.url); } catch { return reference; }
  if (url.protocol === "https:" && !url.username && !url.password) {
    reference.append(node("code", url.href, "knowledge-source-url"));
  }
  return reference;
}

export function initializeKnowledge(invoke) {
  let view = null;
  let selected = null;
  let loading = false;
  const search = byId("knowledge-search");
  const list = byId("knowledge-list");
  const body = byId("knowledge-detail");

  function showTechnique(id, focus = false) {
    selected = id;
    render(focus);
  }

  function render(focus = false) {
    if (!view) return;
    const catalog = view.catalog;
    const query = search.value.trim().toLocaleLowerCase();
    const matches = catalog.techniques.filter((t) => {
      const cases = catalog.cases.filter((c) => c.technique_ids.includes(t.id));
      const rules = catalog.rules.filter((r) => r.technique_ids.includes(t.id));
      return [t.id, t.name, t.definition, ...cases.map((c) => `${c.id} ${c.title}`), ...rules.map((r) => r.id)].join(" ").toLocaleLowerCase().includes(query);
    });
    if (!matches.some((t) => t.id === selected)) selected = matches[0]?.id || null;
    list.replaceChildren();
    byId("knowledge-count").textContent = `${matches.length} / ${catalog.techniques.length}`;
    for (const t of matches) {
      const button = node("button", undefined, "knowledge-choice");
      button.type = "button";
      button.ariaPressed = String(selected === t.id);
      button.append(node("small", t.id), node("span", t.name));
      button.onclick = () => showTechnique(t.id, true);
      list.append(button);
    }
    body.replaceChildren();
    if (!selected) { body.append(node("p", uiText("knowledgeNoMatch"), "empty-state")); return; }
    const t = matches.find((item) => item.id === selected);
    const intro = section(body, "knowledgeTechnique");
    const title = node("h2", `${t.id} · ${t.name}`);
    title.tabIndex = -1;
    intro.append(title, node("p", t.definition));
    facts(intro, [["knowledgeEntry", t.entry_points], ["knowledgePrerequisites", t.prerequisites], ["knowledgeImpact", t.impact], ["knowledgeSignals", t.observable_signals], ["knowledgeMitigations", t.mitigations], ["knowledgeUnknown", t.uncovered]]);
    const related = node("div", undefined, "btn-row");
    for (const id of t.related_ids) {
      const button = node("button", id, "secondary");
      button.onclick = () => { search.value = ""; showTechnique(id, true); };
      related.append(button);
    }
    intro.append(related);

    const chain = section(body, "knowledgeChain");
    chain.append(node("p", uiText("knowledgeChainBoundary"), "boundary"));
    const stages = node("ol", undefined, "knowledge-stages");
    for (const stage of catalog.stages) {
      const item = node("li");
      item.dataset.related = String(t.stage_ids.includes(stage.id));
      item.append(node("strong", stage.name), node("span", uiText(t.stage_ids.includes(stage.id) ? "knowledgeRelatedStage" : "knowledgeNoStage")), node("small", uiText("knowledgeNotObserved")));
      item.title = stage.definition;
      stages.append(item);
    }
    chain.append(stages);

    const cases = section(body, "knowledgeCases");
    const matchedCases = catalog.cases.filter((c) => c.technique_ids.includes(t.id));
    if (!matchedCases.length) cases.append(node("p", uiText("knowledgeNone"), "muted"));
    for (const c of matchedCases) {
      const box = details(cases, `${c.id} · ${c.title}`);
      facts(box, [["knowledgeEvidenceType", uiText(`knowledgeStatus_${c.evidence}`)], ["knowledgeCaseSummary", c.summary], ["knowledgeBoundary", c.evidence_boundary], ["knowledgeUnknown", c.unknowns]]);
      for (const source of c.sources) {
        const p = node("p");
        p.append(sourceReference(source), node("small", ` · ${uiText("knowledgeVerifiedOn")} ${source.verified_on}`));
        box.append(p);
      }
    }

    const rules = section(body, "knowledgeRules");
    const matchedRules = catalog.rules.filter((r) => r.technique_ids.includes(t.id));
    if (!matchedRules.length) rules.append(node("p", uiText("knowledgeNoRule"), "muted"));
    for (const r of matchedRules) {
      const box = details(rules, `${r.id} · v${r.version}`);
      facts(box, [["knowledgeRuleAction", r.action], ["knowledgeSignals", r.telemetry], ["knowledgeFalsePositive", r.false_positive_conditions], ["knowledgeBoundary", r.limitation], ["knowledgeSource", `${r.source_path} · ${r.source_anchor}`]]);
    }

    const coverage = section(body, "knowledgeCoverage");
    for (const c of catalog.coverage.filter((c) => c.technique_id === t.id)) {
      const box = details(coverage, `${c.id} · ${uiText(`knowledgeStatus_${c.status}`)}`);
      facts(box, [["knowledgePlatform", c.platform], ["knowledgeEntry", c.entry_point], ["knowledgeMode", c.execution_mode], ["knowledgeVersion", c.product_version], ["knowledgeBoundary", c.reason], ["knowledgeScenarios", c.scenario_ids]]);
      artifacts(box, c.evidence, "knowledgeEvidence");
    }

    const scenarios = section(body, "knowledgeScenarios");
    const matchedScenarios = catalog.scenarios.filter((s) => s.technique_ids.includes(t.id));
    if (!matchedScenarios.length) scenarios.append(node("p", uiText("knowledgeNone"), "muted"));
    for (const s of matchedScenarios) {
      const box = details(scenarios, `${s.id} · ${uiText(`knowledgeStatus_${s.status}`)} · ${s.title}`);
      facts(box, [["knowledgeEnvironment", s.environment], ["knowledgeNormalTask", s.normal_task], ["knowledgeExpected", s.expected_effects], ["knowledgeActual", s.actual_effects], ["knowledgeBoundary", s.status_reason], ["knowledgeCases", s.case_ids], ["knowledgeRules", s.rule_ids], ["knowledgeCandidate", s.candidate_sha256]]);
      artifacts(box, s.evidence, "knowledgeEvidence");
      artifacts(box, s.fixtures, "knowledgeFixtures");
    }
    byId("knowledge-provenance").textContent = `${uiText("knowledgeEmbedded")} · v${catalog.catalog_version} · SHA-256 ${view.sha256}`;
    if (focus) title.focus({ preventScroll: true });
  }

  async function load() {
    if (loading) return;
    loading = true;
    byId("knowledge-reload").disabled = true;
    view = null;
    list.replaceChildren(); body.replaceChildren();
    byId("knowledge-count").textContent = "";
    byId("knowledge-provenance").textContent = "";
    byId("knowledge-status").textContent = uiText("checking");
    try {
      const result = await invoke("get_knowledge_catalog");
      if (result?.source !== "embedded_reference" || result.instruction_authority !== "none"
        || !/^[0-9a-f]{64}$/.test(result.sha256) || result.catalog?.trust?.authorization_effect !== "none"
        || result.catalog.trust.signature_status !== "unsigned_reference_data") throw new Error("KNOWLEDGE_INVALID");
      view = result;
      render();
      byId("knowledge-status").textContent = uiText("knowledgeReady");
    } catch {
      view = null;
      list.replaceChildren(); body.replaceChildren();
      byId("knowledge-count").textContent = "";
      byId("knowledge-provenance").textContent = "";
      byId("knowledge-status").textContent = uiText("knowledgeUnavailable");
    } finally { loading = false; byId("knowledge-reload").disabled = false; }
  }
  search.oninput = () => render();
  byId("knowledge-reload").onclick = load;
  window.addEventListener("agentguard-locale-change", () => {
    if (view) { render(); byId("knowledge-status").textContent = uiText("knowledgeReady"); }
    else byId("knowledge-status").textContent = uiText(loading ? "checking" : "knowledgeUnavailable");
  });
  return { load };
}

import { uiText } from "./workspace-i18n.js";

const node = (tag, text, className = "") => {
  const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
};
const strings = (value) => Array.isArray(value) && value.every((item) => typeof item === "string");
const section = (parent, key, values) => {
  parent.append(node("h5", uiText(key)));
  const list = document.createElement("ul");
  for (const value of values) list.append(node("li", value));
  parent.append(list);
};

// 这只是已绑定资料的展示层，不负责授予权限或替代原生层的摘要／签名校验。
// 未知格式保留完整原值，不能显示成“解析通过”或丢掉没有认识的字段。
export function renderMemoryContent(value) {
  const box = node("div", "", "memory-content");
  let material = value;
  if (typeof value === "string") {
    try { material = JSON.parse(value); } catch { /* 原值仍完整显示。 */ }
  }
  const raw = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const parsed = material?.kind === "parsed_document";
  const document = parsed ? material.document : null;
  const valid = document && typeof material.path === "string" && typeof document.text === "string"
    && ["parsed", "partial"].includes(document.status) && document.instruction_authority === "none"
    && typeof document.format === "string" && strings(document.coverage?.parsed_layers)
    && strings(document.coverage?.uncovered) && strings(document.coverage?.empty_units)
    && Array.isArray(document.segments) && document.segments.every((part) => typeof part.location === "string"
      && Number.isSafeInteger(part.start_byte) && Number.isSafeInteger(part.end_byte)
      && part.start_byte >= 0 && part.end_byte >= part.start_byte);
  if (valid) {
    box.append(node("h4", uiText("materialTitle")),
      node("p", `${document.format.toUpperCase()} · ${uiText(document.status === "partial" ? "materialPartial" : "materialParsed")}`),
      node("p", `${uiText("materialPath")}: ${material.path}`, "gateway-location"),
      node("p", uiText("materialBoundary"), "boundary"));
    section(box, "materialCovered", document.coverage.parsed_layers.length ? document.coverage.parsed_layers : [uiText("materialUnknown")]);
    section(box, "materialUncovered", document.coverage.uncovered.length ? document.coverage.uncovered : [uiText("materialUnknown")]);
    if (document.coverage.empty_units.length) section(box, "materialEmpty", document.coverage.empty_units);
    box.append(node("h5", uiText("materialText")), node("pre", document.text || uiText("materialNoText"), "gateway-request-text"));
    section(box, "materialLocations", document.segments.map((part) => `${part.location} · ${part.start_byte}–${part.end_byte}`));
  } else if (["note", "document"].includes(material?.kind) && typeof material.text === "string") {
    if (typeof material.path === "string") box.append(node("p", `${uiText("materialPath")}: ${material.path}`, "gateway-location"));
    box.append(node("pre", material.text, "gateway-request-text"));
  } else {
    box.append(node("p", uiText("materialUnknown"), "boundary"), node("pre", raw, "gateway-request-text"));
    return box;
  }
  const details = node("details", "");
  details.append(node("summary", uiText("materialRaw")), node("pre", raw, "gateway-request-text"));
  box.append(details);
  return box;
}

export function renderPendingMemory(action) {
  if (action?.tool_service !== "agentguard-memory" || action.tool_name !== "memory_write"
    || typeof action.parameters?.content !== "string") return null;
  const draft = action.parameters, box = node("section", "", "memory-draft");
  box.append(node("p", `${uiText("materialKey")}: ${draft.key} · ${uiText("governanceVersion")} ${draft.version}`),
    node("p", uiText("materialSaveBoundary"), "boundary"), renderMemoryContent(draft.content));
  return box;
}

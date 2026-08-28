let messages = {};

function systemLocale() {
  const lang = chrome.i18n.getUILanguage().toLowerCase();
  if (/zh-(tw|hk|mo)|hant/.test(lang)) return "zh_TW";
  return lang.startsWith("zh") ? "zh_CN" : "en";
}

async function loadMessages(mode) {
  const locale = mode === "system" ? systemLocale() : mode;
  const response = await fetch(chrome.runtime.getURL(`_locales/${locale}/messages.json`));
  messages = await response.json();
  document.documentElement.lang = locale === "zh_CN" ? "zh-CN" : locale === "zh_TW" ? "zh-TW" : "en";
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = messages[element.dataset.i18n]?.message || element.dataset.i18n;
  });
}

const t = (key) => messages[key]?.message || key;

async function initialize() {
  const stored = await chrome.storage.local.get("localeOverride");
  const mode = stored.localeOverride || "system";
  const select = document.getElementById("locale");
  select.value = mode;
  await loadMessages(mode);
  select.onchange = async () => {
    await chrome.storage.local.set({ localeOverride: select.value });
    await loadMessages(select.value);
    renderRecent();
    renderBlocklist();
  };
  renderRecent();
  renderBlocklist();
}

// E10:列出当前拦截名单(恶意域累积 / 越界会话),每条可手动解除。
// 全程 createElement + textContent + addEventListener,不用 innerHTML / onclick=(仓库不变量禁 sink)。
function renderBlocklist() {
  chrome.runtime.sendMessage({ type: "get_blocklist" }, (resp) => {
    const list = document.getElementById("blocklist");
    if (!list) return;
    list.replaceChildren();
    const rows = [];
    for (const h of (resp && resp.malicious) || []) rows.push([h, t("kindMalicious")]);
    for (const h of (resp && resp.out_of_scope) || []) rows.push([h, t("kindOutOfScope")]);
    if (rows.length === 0) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = t("noBlocked");
      list.appendChild(li);
      return;
    }
    for (const [host, kind] of rows) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = `${host} · ${kind}`;
      const btn = document.createElement("button");
      btn.textContent = t("unblock");
      btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "unblock_host", host }, () => renderBlocklist());
      });
      li.appendChild(label);
      li.appendChild(document.createTextNode(" "));
      li.appendChild(btn);
      list.appendChild(li);
    }
  });
}

function renderRecent() {
chrome.runtime.sendMessage({ type: "get_recent" }, (resp) => {
  const list = document.getElementById("list");
  const native = document.getElementById("native");
  if (!resp) {
    list.textContent = "";
    const li = document.createElement("li");
    li.textContent = t("readError");
    list.appendChild(li);
    return;
  }
  native.checked = !!resp.nativeEnabled;
  native.onchange = () => {
    chrome.runtime.sendMessage({ type: "set_native", enabled: native.checked });
  };
  list.replaceChildren();
  for (const r of resp.recent || []) {
    const li = document.createElement("li");
    li.textContent = `${r.kinds?.join(", ") || t("findings")} · ${r.title || r.url || ""}`;
    list.appendChild(li);
  }
  if (!resp.recent?.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = t("noRecords");
    list.appendChild(li);
  }
});
}

initialize();

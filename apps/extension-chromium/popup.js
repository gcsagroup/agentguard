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
  };
  renderRecent();
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

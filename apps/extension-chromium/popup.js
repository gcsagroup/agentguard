let messages = {};
// 人话词典(guard-strings.js,先于本文件加载)。finding 种类 / 规则 ID 的用户可见文案
// 全部从这里取 —— popup 不再出现 invisible_injection、INTEL-DOMAIN 这类裸术语。
const S = self.AgentGuardStrings;
let vocabLocale = "en";

function systemLocale() {
  const lang = chrome.i18n.getUILanguage().toLowerCase();
  if (/zh-(tw|hk|mo)|hant/.test(lang)) return "zh_TW";
  return lang.startsWith("zh") ? "zh_CN" : "en";
}

async function loadMessages(mode) {
  const locale = mode === "system" ? systemLocale() : mode;
  vocabLocale = S ? S.pickLocale(mode, chrome.i18n.getUILanguage()) : locale;
  const response = await fetch(chrome.runtime.getURL(`_locales/${locale}/messages.json`));
  messages = await response.json();
  document.documentElement.lang = locale === "zh_CN" ? "zh-CN" : locale === "zh_TW" ? "zh-TW" : "en";
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = messages[element.dataset.i18n]?.message || element.dataset.i18n;
  });
}

const t = (key) => messages[key]?.message || key;
// _locales 走 chrome.i18n 的 $1/$2 占位太绕,popup 自己做 {name} 替换。
const tf = (key, vars) =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

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
  // 设置收进齿轮:语言/桌面端转发不该占首屏 —— 用户打开 popup 是想知道"我安全吗"。
  const panel = document.getElementById("settings-panel");
  document.getElementById("btn-settings").addEventListener("click", () => {
    panel.hidden = !panel.hidden;
  });
  renderRecent();
  renderBlocklist();
}

/** 一条最近记录的人话标题:拦截类读作"已拦截:这一步要付款了",发现类拼各 kind 的词典标题。 */
function humanEntryTitle(entry) {
  if (entry.kind === "prevented") {
    // 优先用确认层的动作标题(「这一步要付款了」),它比 finding 标题(「页面上有付款按钮」)
    // 更贴近"拦下了一次动作"这件事;词典不认识时退回 finding 标题,再退回 reason 原文。
    const gate = S && S.gateText(entry.prevented_kind, vocabLocale);
    const info = S && S.kindText(entry.prevented_kind, vocabLocale);
    const what = (gate && gate.title) || (info && info.title) || entry.reason || "";
    return `${t("blockedPrefix")}${what}`;
  }
  if (entry.kind === "verdict") {
    // 宿主判决(Critical/Block):第一眼是规则的人话名;认不出就退回「关键操作」。
    const ui = S && S.ui(vocabLocale);
    const names = (entry.notify || [])
      .map((n) => {
        const rule = S && n.rule_id ? S.ruleText(n.rule_id, vocabLocale) : null;
        return rule ? rule.title : null;
      })
      .filter(Boolean);
    const what = names[0] || (ui ? ui.criticalAction : "");
    const extra = (entry.notify || []).length > 1 ? ` ×${entry.notify.length}` : "";
    return `${t("blockedPrefix")}${what}${extra}`;
  }
  const sep = vocabLocale === "en" ? "; " : "、";
  const titles = (entry.kinds || [])
    .map((k) => {
      const info = S && S.kindText(k, vocabLocale);
      return info ? info.title : k;
    })
    .filter(Boolean);
  return titles.join(sep) || t("findings");
}

// E10:列出当前拦截名单(恶意域累积 / 越界会话),每条可手动解除。
// 全程 createElement + textContent + addEventListener,不用 innerHTML / onclick=(仓库不变量禁 sink)。
function renderBlocklist() {
  chrome.runtime.sendMessage({ type: "get_blocklist" }, (resp) => {
    const list = document.getElementById("blocklist");
    if (!list) return;
    list.replaceChildren();
    const prov = (resp && resp.provenance) || {};
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
    for (const [host, fallbackKind] of rows) {
      const li = document.createElement("li");
      const ruleId = prov[host] && prov[host].rule_id;
      const rule = ruleId && S ? S.ruleText(ruleId, vocabLocale) : null;
      const btn = document.createElement("button");
      btn.className = "unblock";
      btn.textContent = t("unblock");
      btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "unblock_host", host }, () => renderBlocklist());
      });
      const label = document.createElement("div");
      label.className = "item-title";
      label.textContent = host;
      const kindLine = document.createElement("div");
      kindLine.className = "muted";
      // 第一眼是人话("已知的恶意网站"),不是规则 ID。
      kindLine.textContent = rule ? rule.title : fallbackKind;
      li.append(btn, label, kindLine);
      // E12 溯源改造:解释和技术标识收进「为什么被拦?」,给排障留门,不吓普通用户。
      if (rule || ruleId) {
        const why = document.createElement("details");
        const sum = document.createElement("summary");
        sum.textContent = t("whyBlocked");
        const body = document.createElement("div");
        if (rule) body.textContent = rule.detail;
        const tech = document.createElement("div");
        tech.className = "tech";
        tech.textContent = `${t("blockedBy")}: ${ruleId}`;
        why.append(sum, body, tech);
        li.appendChild(why);
      }
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
    // 状态卡:今天发现了几件事、拦下了几次 —— 用户打开 popup 最想知道的一行。
    const now = Date.now();
    const dayStart = new Date().setHours(0, 0, 0, 0);
    let found = 0;
    let blocked = 0;
    for (const r of resp.recent || []) {
      if (!r.ts || r.ts < dayStart) continue;
      if (r.kind === "prevented") blocked += 1;
      else found += r.count || (r.kinds ? r.kinds.length : 1);
    }
    const todayLine = document.getElementById("today-line");
    if (todayLine) todayLine.textContent = tf("todaySummary", { f: found, b: blocked });

    list.replaceChildren();
    for (const r of resp.recent || []) {
      const li = document.createElement("li");
      // 标题行用 flex:标题占满、可换行,相对时间钉在右上角(float 会在长标题换行时掉下去)。
      const titleLine = document.createElement("div");
      titleLine.className = "item-title";
      const titleText = document.createElement("span");
      titleText.className = "item-title-text";
      titleText.textContent = humanEntryTitle(r);
      const time = document.createElement("span");
      time.className = "item-time";
      time.textContent = r.ts && S ? S.relativeTime(r.ts, now, vocabLocale) : "";
      titleLine.append(titleText, time);
      const page = document.createElement("div");
      page.className = "item-page";
      page.textContent = r.title || r.url || "";
      li.append(titleLine, page);
      list.appendChild(li);
    }
    if (!resp.recent?.length) {
      const li = document.createElement("li");
      li.className = "muted";
      // 教育性空状态:说清"没有记录 = 一切正常,而且真出事时我会拦"。
      li.textContent = t("allClear");
      list.appendChild(li);
    }
  });
}

initialize();

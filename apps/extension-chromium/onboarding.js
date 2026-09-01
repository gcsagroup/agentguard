/* 安装引导页脚本(E17a)。
 *
 * 交互演示用的是**真渲染器**(guard-modal.js)和**真词典**(guard-strings.js)——
 * 用户在这里看到的弹层,和真被拦时看到的是同一段代码画的,不会学到过时的界面。
 * 演示不发任何请求、不产生任何判决记录;点「允许这一次」只在页面上写一行结果。
 *
 * i18n 走 popup 同款方案:读 localeOverride,fetch 对应 _locales 包,填 data-i18n。
 */
function systemLocale() {
  const lang = chrome.i18n.getUILanguage().toLowerCase();
  if (/zh-(tw|hk|mo)|hant/.test(lang)) return "zh_TW";
  return lang.startsWith("zh") ? "zh_CN" : "en";
}

let messages = {};
const t = (key) => messages[key]?.message || key;

async function applyLocale() {
  const stored = await chrome.storage.local.get("localeOverride");
  const mode = stored.localeOverride || "system";
  const locale = mode === "system" ? systemLocale() : mode;
  const response = await fetch(chrome.runtime.getURL(`_locales/${locale}/messages.json`));
  messages = await response.json();
  document.documentElement.lang =
    locale === "zh_CN" ? "zh-CN" : locale === "zh_TW" ? "zh-TW" : "en";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = messages[el.dataset.i18n]?.message || el.textContent;
  });
}

function wireDemo() {
  const btn = document.getElementById("demo-pay");
  const outcome = document.getElementById("demo-outcome");
  btn.addEventListener("click", () => {
    outcome.textContent = "";
    const Modal = self.AgentGuardModal;
    if (!Modal) {
      outcome.textContent = "demo unavailable";
      return;
    }
    Modal.askAllowOnce(
      { kind: "payment_cta", reason: "" },
      () => {
        outcome.textContent = t("obDemoAllowed");
      },
      () => {
        outcome.textContent = t("obDemoCancelled");
      }
    );
  });
}

applyLocale().then(wireDemo);

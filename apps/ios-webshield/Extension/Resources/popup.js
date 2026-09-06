"use strict";

function localize() {
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    const value = browser.i18n.getMessage(element.dataset.i18n);
    if (value) element.textContent = value;
  });
}

async function refresh() {
  const statusElement = document.querySelector("#status");
  statusElement.textContent = browser.i18n.getMessage("popup_loading");
  try {
    const status = await browser.runtime.sendMessage({ type: "webshield:get-status" });
    const key = !status || status.nativeAvailable === false
      ? "popup_unavailable"
      : status.enabled && status.privacyAccepted
        ? "popup_enabled"
        : "popup_disabled";
    statusElement.textContent = browser.i18n.getMessage(key);
  } catch (_error) {
    statusElement.textContent = browser.i18n.getMessage("popup_unavailable");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  localize();
  document.querySelector("#refresh").addEventListener("click", refresh);
  void refresh();
});

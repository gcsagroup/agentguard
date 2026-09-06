(function installAgentGuardWebShield() {
  "use strict";

  const runtime = globalThis.browser && globalThis.browser.runtime;
  const gate = globalThis.AgentGuardWebShieldGate;
  if (!runtime || !gate) return;

  let protectionState = "unknown";
  let statusGeneration = 0;
  const bypassOnce = new WeakSet();
  const pending = new WeakSet();
  const installedRoots = new WeakSet();

  function i18n(key) {
    return globalThis.browser.i18n.getMessage(key) || key;
  }

  function normalizedState(status) {
    if (!status || typeof status !== "object" || status.nativeAvailable !== true) {
      return "unavailable";
    }
    if (status.state === "enabled" && status.enabled === true && status.privacyAccepted === true) {
      return "enabled";
    }
    if (status.state === "disabled" && status.enabled === false) {
      return "disabled";
    }
    return "unavailable";
  }

  async function refreshStatus() {
    const generation = ++statusGeneration;
    try {
      const response = await runtime.sendMessage({ type: "webshield:get-status" });
      if (generation === statusGeneration) protectionState = normalizedState(response);
    } catch (_error) {
      if (generation === statusGeneration) protectionState = "unavailable";
    }
  }

  function contextFor(element) {
    const form = element instanceof HTMLFormElement ? element : element.closest("form");
    const controlText = [
      element.getAttribute("aria-label"),
      element.getAttribute("title"),
      "value" in element ? element.value : "",
      element.textContent
    ].filter(Boolean).join(" ").slice(0, 512);
    const formText = form ? (form.textContent || "").slice(0, 5_000) : "";
    const documentText = document.body ? (document.body.innerText || "").slice(0, 20_000) : "";
    const hasSensitiveField = Boolean(form && form.querySelector([
      "input[type='password']",
      "input[name*='token' i]",
      "input[name*='secret' i]",
      "input[name*='api-key' i]",
      "input[autocomplete='cc-number']"
    ].join(",")));
    return { controlText, formText, documentText, hasSensitiveField };
  }

  function candidateFromClick(event) {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [event.target];
    for (const target of path) {
      if (!(target instanceof Element)) continue;
      if (target.closest("[data-agentguard-webshield-overlay]")) return null;
      const candidate = target.closest(
        "button, input[type='submit'], input[type='button'], [role='button'], a[href]"
      );
      if (candidate) return candidate;
    }
    return null;
  }

  function isSubmitControl(element) {
    return (element instanceof HTMLButtonElement && element.type === "submit" && element.form)
      || (element instanceof HTMLInputElement && ["submit", "image"].includes(element.type) && element.form);
  }

  function sendAudit(finding, action) {
    const event = {
      ruleId: finding.ruleId,
      kind: finding.kind,
      action,
      timestampMs: Date.now(),
      url: location.href
    };
    runtime.sendMessage({ type: "webshield:record-events", events: [event] }).catch(() => {});
  }

  function showDialog(finding, canAllow) {
    return new Promise((resolve) => {
      const host = document.createElement("div");
      host.dataset.agentguardWebshieldOverlay = "true";
      host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647";
      const shadow = host.attachShadow({ mode: "closed" });
      const backdrop = document.createElement("div");
      backdrop.style.cssText = "position:fixed;inset:0;display:grid;place-items:center;padding:20px;background:rgba(5,12,24,.58);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";
      const dialog = document.createElement("section");
      dialog.setAttribute("role", "dialog");
      dialog.setAttribute("aria-modal", "true");
      dialog.style.cssText = "box-sizing:border-box;width:min(420px,100%);padding:22px;border-radius:18px;background:#fff;color:#101828;box-shadow:0 24px 80px rgba(0,0,0,.3)";
      const title = document.createElement("h2");
      title.textContent = i18n(canAllow ? `modal_title_${finding.kind}` : "modal_title_unavailable");
      title.style.cssText = "margin:0 0 8px;font-size:21px;line-height:1.25";
      const body = document.createElement("p");
      body.textContent = i18n(canAllow ? `modal_body_${finding.kind}` : "modal_body_unavailable");
      body.style.cssText = "margin:0 0 18px;color:#475467;font-size:15px;line-height:1.5";
      const actions = document.createElement("div");
      actions.style.cssText = "display:flex;gap:10px;justify-content:flex-end";
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = i18n(canAllow ? "modal_cancel" : "modal_close");
      cancel.style.cssText = "border:0;border-radius:10px;padding:10px 16px;background:#d92d20;color:#fff;font:600 15px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";
      const allow = document.createElement("button");
      allow.type = "button";
      allow.textContent = i18n("modal_allow_once");
      allow.style.cssText = "border:1px solid #d0d5dd;border-radius:10px;padding:10px 16px;background:#fff;color:#344054;font:600 15px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";

      function finish(decision) {
        document.removeEventListener("keydown", onKeyDown, true);
        host.remove();
        resolve(decision);
      }
      function onKeyDown(event) {
        if (event.key === "Escape") finish("cancelled");
      }
      cancel.addEventListener("click", () => finish("cancelled"));
      allow.addEventListener("click", () => finish("allowed"));
      document.addEventListener("keydown", onKeyDown, true);
      actions.append(cancel);
      if (canAllow) actions.append(allow);
      dialog.append(title, body, actions);
      backdrop.append(dialog);
      shadow.append(backdrop);
      const mount = document.documentElement || document.body;
      if (!mount) {
        finish("cancelled");
        return;
      }
      mount.append(host);
      cancel.focus();
    });
  }

  function showDecision(finding) {
    return showDialog(finding, true);
  }

  async function decideAndMaybeReplay(element, finding, replay) {
    if (pending.has(element)) return;
    pending.add(element);
    try {
      const decision = await showDecision(finding);
      sendAudit(finding, decision);
      if (decision === "allowed" && protectionState === "enabled") {
        bypassOnce.add(element);
        replay();
      }
    } finally {
      pending.delete(element);
    }
  }

  async function explainUnavailable(element, finding) {
    if (pending.has(element)) return;
    pending.add(element);
    try {
      await showDialog(finding, false);
    } finally {
      pending.delete(element);
    }
  }

  function installRootsFromPath(event) {
    if (typeof event.composedPath !== "function") return;
    for (const node of event.composedPath()) {
      if (node && node.mode === "open" && node.host) installEventRoot(node);
    }
  }

  function handleClick(event) {
    installRootsFromPath(event);
    if (event.defaultPrevented || protectionState === "disabled") return;
    const element = candidateFromClick(event);
    if (!element) return;
    // Submit controls are handled by the submit listener so one user action can never show two gates.
    if (isSubmitControl(element)) return;
    if (protectionState === "enabled" && bypassOnce.delete(element)) return;
    const finding = gate.classify(contextFor(element));
    if (!finding) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (protectionState === "enabled") {
      void decideAndMaybeReplay(element, finding, () => element.click());
    } else {
      void explainUnavailable(element, finding);
    }
  }

  function handleSubmit(event) {
    installRootsFromPath(event);
    if (event.defaultPrevented || protectionState === "disabled"
      || !(event.target instanceof HTMLFormElement)) return;
    const form = event.target;
    if (protectionState === "enabled" && bypassOnce.delete(form)) return;
    const nativeSubmitter = event.submitter instanceof HTMLElement ? event.submitter : undefined;
    const finding = gate.classify(contextFor(nativeSubmitter || form));
    if (!finding) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (protectionState === "enabled") {
      void decideAndMaybeReplay(form, finding, () => {
        if (nativeSubmitter) form.requestSubmit(nativeSubmitter);
        else form.requestSubmit();
      });
    } else {
      void explainUnavailable(form, finding);
    }
  }

  function installEventRoot(root) {
    if (!root || installedRoots.has(root)) return;
    installedRoots.add(root);
    root.addEventListener("click", handleClick, true);
    root.addEventListener("submit", handleSubmit, true);
  }

  function scanOpenRoots(container) {
    function inspect(element) {
      if (element.shadowRoot && element.shadowRoot.mode === "open") {
        installEventRoot(element.shadowRoot);
        scanOpenRoots(element.shadowRoot);
      }
    }
    if (container instanceof Element) inspect(container);
    if (container && typeof container.querySelectorAll === "function") {
      for (const element of container.querySelectorAll("*")) inspect(element);
    }
  }

  installEventRoot(document);
  scanOpenRoots(document);
  const shadowObserver = new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) scanOpenRoots(node);
    }
  });
  shadowObserver.observe(document, { childList: true, subtree: true });

  runtime.onMessage.addListener((message) => {
    if (message && message.type === "webshield:status-changed") {
      statusGeneration += 1;
      protectionState = normalizedState(message);
    }
  });

  void refreshStatus();
  addEventListener("pageshow", refreshStatus, { passive: true });
  addEventListener("focus", refreshStatus, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") void refreshStatus();
  });
})();

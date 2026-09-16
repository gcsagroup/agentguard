const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const gate = require("../../Extension/Resources/gate.js");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../Extension/Resources/content.js"),
  "utf8"
);

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}

class EventHub {
  constructor() {
    this.listeners = new Map();
  }

  addEventListener(type, listener, options) {
    const group = this.listeners.get(type) || [];
    group.push({ listener, options });
    this.listeners.set(type, group);
  }

  removeEventListener(type, listener) {
    this.listeners.set(type, (this.listeners.get(type) || []).filter((entry) => entry.listener !== listener));
  }

  dispatch(type, event) {
    for (const entry of this.listeners.get(type) || []) {
      entry.listener(event);
      if (event.immediatePropagationStopped) break;
    }
  }

  listenerCount(type) {
    return (this.listeners.get(type) || []).length;
  }

  hasCaptureListener(type) {
    return (this.listeners.get(type) || []).some(({ options }) => (
      options === true || Boolean(options && options.capture)
    ));
  }
}

function createHarness(statusPromise, options = {}) {
  let document;
  const shadows = [];

  class Element extends EventHub {
    constructor(tagName) {
      super();
      this.tagName = tagName.toUpperCase();
      this.parentElement = null;
      this.children = [];
      this.attributes = new Map();
      this.dataset = {};
      this.style = {};
      this.textContent = "";
      this.innerText = "";
      this.value = "";
      this.type = this.tagName === "BUTTON" ? "submit" : "";
      this.form = null;
      this.activations = 0;
      this._root = null;
      this.shadowRoot = null;
    }

    append(...children) {
      for (const child of children) {
        child.parentElement = this;
        child.setRoot(this._root || document);
        this.children.push(child);
      }
    }

    setRoot(root) {
      this._root = root;
      for (const child of this.children) child.setRoot(root);
    }

    setAttribute(name, value) {
      this.attributes.set(name, String(value));
    }

    getAttribute(name) {
      return this.attributes.get(name) || null;
    }

    matches(selector) {
      if (selector === "form") return this.tagName === "FORM";
      if (selector === "[data-agentguard-webshield-overlay]") {
        return this.dataset.agentguardWebshieldOverlay === "true";
      }
      if (selector.includes("button") && this.tagName === "BUTTON") return true;
      if (selector.includes("input[type='submit']") && this.tagName === "INPUT" && this.type === "submit") return true;
      if (selector.includes("input[type='button']") && this.tagName === "INPUT" && this.type === "button") return true;
      if (selector.includes("[role='button']") && this.getAttribute("role") === "button") return true;
      return selector.includes("a[href]") && this.tagName === "A" && this.getAttribute("href") !== null;
    }

    closest(selector) {
      let current = this;
      while (current) {
        if (current.matches(selector)) return current;
        current = current.parentElement;
      }
      return null;
    }

    querySelector(selector) {
      if (selector.includes("input") && this.sensitiveField) return this.sensitiveField;
      return null;
    }

    querySelectorAll() {
      return this.children.flatMap((child) => [child, ...child.querySelectorAll("*")]);
    }

    attachShadow({ mode }) {
      const root = new ShadowRoot(this, mode);
      shadows.push(root);
      if (mode === "open") this.shadowRoot = root;
      return root;
    }

    getRootNode() {
      return this._root || document;
    }

    remove() {
      if (!this.parentElement) return;
      this.parentElement.children = this.parentElement.children.filter((child) => child !== this);
      this.parentElement = null;
    }

    get isConnected() {
      if (this === document.documentElement) return true;
      if (this.parentElement) return this.parentElement.isConnected;
      return this._root instanceof ShadowRoot && this._root.host.isConnected;
    }

    focus() {
      const root = this.getRootNode();
      if (root instanceof ShadowRoot) {
        root.activeElement = this;
        document.activeElement = root.host;
      } else {
        document.activeElement = this;
      }
      document.focusedElement = this;
    }

    click() { return click(this); }
  }

  class HTMLElement extends Element {}
  class HTMLButtonElement extends HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  class HTMLFormElement extends HTMLElement {
    constructor() {
      super("form");
      this.submissions = 0;
    }

    requestSubmit() {
      this.submissions += 1;
    }
  }

  class ShadowRoot extends EventHub {
    constructor(host, mode) {
      super();
      this.host = host;
      this.mode = mode;
      this.children = [];
      this.textContent = "";
    }

    append(...children) {
      for (const child of children) {
        child.parentElement = null;
        child.setRoot(this);
        this.children.push(child);
      }
    }

    querySelectorAll() {
      return this.children.flatMap((child) => [child, ...child.querySelectorAll("*")]);
    }
  }

  class Document extends EventHub {
    constructor() {
      super();
      this.visibilityState = "visible";
      this.documentElement = new HTMLElement("html");
      this.body = new HTMLElement("body");
      this.documentElement.setRoot(this);
      this.documentElement.append(this.body);
      this.activeElement = this.body;
      this.focusedElement = this.body;
    }

    createElement(tagName) {
      switch (tagName.toLowerCase()) {
      case "button": return new HTMLButtonElement("button");
      case "input": return new HTMLInputElement("input");
      case "form": return new HTMLFormElement();
      default: return new HTMLElement(tagName);
      }
    }

    querySelectorAll() {
      return this.documentElement.querySelectorAll("*");
    }
  }

  document = new Document();
  const runtimeMessages = [];
  const runtimeListeners = [];
  const runtime = {
    sendMessage(message) {
      runtimeMessages.push(message);
      if (message.type === "webshield:get-status") return statusPromise;
      return Promise.resolve({ ok: true });
    },
    onMessage: {
      addListener(listener) {
        runtimeListeners.push(listener);
      }
    }
  };
  const windowEvents = new EventHub();
  const context = {
    AgentGuardWebShieldGate: gate,
    Element,
    HTMLElement,
    HTMLButtonElement,
    HTMLInputElement,
    HTMLFormElement,
    ShadowRoot,
    MutationObserver: class { observe() {} },
    browser: {
      runtime,
      i18n: { getMessage: (key) => key }
    },
    document,
    location: { href: options.url || "https://shop.example/checkout" },
    addEventListener: windowEvents.addEventListener.bind(windowEvents),
    setTimeout,
    clearTimeout,
    console
  };

  let openShadow;
  if (options.openShadow) {
    const host = document.createElement("div");
    document.body.append(host);
    openShadow = host.attachShadow({ mode: "open" });
  }

  vm.runInNewContext(source, context, { filename: "content.js" });

  function button(text = "Confirm payment", root = document.body) {
    const element = document.createElement("button");
    element.type = "button";
    element.textContent = text;
    root.append(element);
    return element;
  }

  function click(element, path = [element, document.body, document.documentElement, document]) {
    const event = eventFor(element, path);
    document.dispatch("click", event);
    if (!event.immediatePropagationStopped) element.dispatch("click", event);
    if (!event.defaultPrevented) element.activations += 1;
    return event;
  }

  function sensitiveForm(root = document.body) {
    const form = document.createElement("form");
    form.sensitiveField = document.createElement("input");
    root.append(form);
    return form;
  }

  function submit(form, root = document, path = [form, document.body, document.documentElement, document]) {
    const event = eventFor(form, path);
    root.dispatch("submit", event);
    if (!event.defaultPrevented) form.submissions += 1;
    return event;
  }

  function eventFor(target, path = [target]) {
    return {
      target,
      submitter: null,
      defaultPrevented: false,
      immediatePropagationStopped: false,
      preventDefault() { this.defaultPrevented = true; },
      stopImmediatePropagation() { this.immediatePropagationStopped = true; },
      composedPath() { return path; }
    };
  }

  function emitStatus(message) {
    for (const listener of runtimeListeners) listener(message);
  }

  return {
    document,
    openShadow,
    button,
    click,
    sensitiveForm,
    submit,
    eventFor,
    emitStatus,
    runtimeMessages,
    // 夹具保留自己创建的封闭根；页面代码本身不能读取它。
    dialogElements: () => shadows.filter((root) => root.mode === "closed" && root.host.parentElement)
      .flatMap((root) => root.querySelectorAll("*")),
    dialogButtons: () => shadows.filter((root) => root.mode === "closed" && root.host.parentElement)
      .flatMap((root) => root.querySelectorAll("*").filter((element) => element.tagName === "BUTTON"))
  };
}

async function settle() {
  await Promise.resolve();
  await Promise.resolve();
}

test("document_start listener is synchronous and unknown blocks only dangerous candidates", () => {
  const status = deferred();
  const harness = createHarness(status.promise);
  assert.equal(harness.document.listenerCount("click"), 1);
  assert.equal(harness.document.listenerCount("submit"), 1);
  assert.equal(harness.document.hasCaptureListener("click"), true);
  assert.equal(harness.document.hasCaptureListener("submit"), true);

  const dangerous = harness.button();
  assert.equal(harness.click(dangerous).defaultPrevented, true);
  assert.equal(harness.submit(harness.sensitiveForm()).defaultPrevented, true);
  const ordinary = harness.button("Open help");
  assert.equal(harness.click(ordinary).defaultPrevented, false);
  assert.equal(ordinary.activations, 1);
});

test("an explicit native disabled status allows a dangerous candidate", async () => {
  const status = deferred();
  const harness = createHarness(status.promise);
  status.resolve({ state: "disabled", enabled: false, privacyAccepted: true, nativeAvailable: true });
  await settle();

  const dangerous = harness.button();
  assert.equal(harness.click(dangerous).defaultPrevented, false);
  assert.equal(dangerous.activations, 1);
  const form = harness.sensitiveForm();
  assert.equal(harness.submit(form).defaultPrevented, false);
  assert.equal(form.submissions, 1);
});

test("native status failure remains fail-closed for a dangerous candidate", async () => {
  const status = deferred();
  const harness = createHarness(status.promise);
  status.reject(new Error("native unavailable"));
  await settle();

  assert.equal(harness.click(harness.button()).defaultPrevented, true);
  assert.equal(harness.submit(harness.sensitiveForm()).defaultPrevented, true);
});

test("an explicit unavailable status remains fail-closed for a dangerous candidate", async () => {
  const status = deferred();
  const harness = createHarness(status.promise);
  status.resolve({ state: "unavailable", enabled: false, privacyAccepted: false, nativeAvailable: false });
  await settle();

  assert.equal(harness.click(harness.button()).defaultPrevented, true);
});

test("an enabled status keeps a dangerous candidate behind the decision gate", async () => {
  const status = deferred();
  const harness = createHarness(status.promise);
  status.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true });
  await settle();

  assert.equal(harness.click(harness.button()).defaultPrevented, true);
});

test("启用时提示只有关闭键，关闭和再次点击均不重放付款", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const button = harness.button();
  assert.equal(harness.click(button).defaultPrevented, true);
  assert.deepEqual(harness.dialogButtons().map((element) => element.textContent), ["modal_close"]);
  harness.click(harness.dialogButtons()[0]);
  await settle();
  assert.equal(button.activations, 0);
  assert.equal(harness.click(button).defaultPrevented, true);
  assert.equal(button.activations, 0);
  const records = harness.runtimeMessages.filter((message) => message.type === "webshield:record-events");
  assert.equal(records.length, 2);
  assert.ok(records.every((message) => message.events[0].action === "blocked"));
  assert.equal(harness.click(harness.button("Open help")).defaultPrevented, false);
});

test("敏感表单在提示关闭前已记录阻断，关闭后不提交且再次提交仍阻断", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const form = harness.sensitiveForm();
  assert.equal(harness.submit(form).defaultPrevented, true);
  const records = harness.runtimeMessages.filter((message) => message.type === "webshield:record-events");
  assert.equal(records.length, 1);
  assert.equal(records[0].events[0].action, "blocked");
  harness.click(harness.dialogButtons()[0]);
  await settle();
  assert.equal(form.submissions, 0);
  assert.equal(harness.submit(form).defaultPrevented, true);
  assert.equal(form.submissions, 0);
});

test("Escape 只关闭提示，后续关闭防护也不会重放此前被拦的动作", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const button = harness.button();
  harness.click(button);
  harness.document.dispatch("keydown", { ...harness.eventFor(button), key: "Escape" });
  await settle();
  assert.equal(harness.dialogButtons().length, 0);
  assert.equal(harness.document.listenerCount("keydown"), 0);
  harness.emitStatus({ type: "webshield:status-changed", state: "disabled", enabled: false, nativeAvailable: true });
  await settle();
  assert.equal(button.activations, 0);
  assert.equal(harness.click(button).defaultPrevented, false);
  assert.equal(button.activations, 1);
  assert.deepEqual(harness.runtimeMessages.filter((message) => message.type === "webshield:record-events")
    .map((message) => message.events[0].action), ["blocked"]);
});

test("网页伪造提示属性不能绕过付款检查", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const button = harness.button();
  button.dataset.agentguardWebshieldOverlay = "true";
  assert.equal(harness.click(button).defaultPrevented, true);
  assert.equal(button.activations, 0);
});

test("a delayed stale status cannot overwrite a newer explicit disabled message", async () => {
  const status = deferred();
  const harness = createHarness(status.promise);
  harness.emitStatus({
    type: "webshield:status-changed",
    state: "disabled",
    enabled: false,
    privacyAccepted: true,
    nativeAvailable: true
  });
  status.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true });
  await settle();

  assert.equal(harness.click(harness.button()).defaultPrevented, false);
});

test("the same early fail-closed listener executes inside an iframe world", () => {
  const status = deferred();
  const frame = createHarness(status.promise, { url: "https://pay.example/frame" });
  assert.equal(frame.document.listenerCount("click"), 1);
  assert.equal(frame.click(frame.button("Place order")).defaultPrevented, true);
});

test("dangerous click and submit inside an open shadow root are gated", () => {
  const status = deferred();
  const harness = createHarness(status.promise, { openShadow: true });
  assert.equal(harness.openShadow.hasCaptureListener("click"), true);
  assert.equal(harness.openShadow.hasCaptureListener("submit"), true);
  const shadowButton = harness.button("Pay now", harness.openShadow);
  const click = harness.click(shadowButton, [shadowButton, harness.openShadow, harness.openShadow.host, harness.document]);
  assert.equal(click.defaultPrevented, true);

  const form = harness.sensitiveForm(harness.openShadow);
  const submit = harness.submit(form, harness.openShadow, [form, harness.openShadow]);
  assert.equal(submit.defaultPrevented, true);
});


test("提示关联可读标题与解释，关闭后焦点回到原控件且不执行", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const button = harness.button();
  button.focus();
  harness.click(button);
  const elements = harness.dialogElements();
  const dialog = elements.find((element) => element.getAttribute("role") === "dialog");
  const title = elements.find((element) => element.id === dialog.getAttribute("aria-labelledby"));
  const body = elements.find((element) => element.id === dialog.getAttribute("aria-describedby"));
  assert.ok(title?.textContent.startsWith("modal_title_"));
  assert.ok(body?.textContent.startsWith("modal_body_"));
  harness.click(harness.dialogButtons()[0]);
  await settle();
  assert.equal(harness.document.focusedElement, button);
  assert.equal(button.activations, 0);
});

test("Tab 与 Shift+Tab 留在提示内，Escape 返回开放阴影根中的原焦点", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }), { openShadow: true });
  await settle();
  const button = harness.button("Pay now", harness.openShadow);
  button.focus();
  harness.click(button, [button, harness.openShadow, harness.openShadow.host, harness.document]);
  const close = harness.dialogButtons()[0];
  for (const shiftKey of [false, true]) {
    const event = { ...harness.eventFor(close), key: "Tab", shiftKey };
    harness.document.dispatch("keydown", event);
    assert.equal(event.defaultPrevented, true);
    assert.equal(event.immediatePropagationStopped, true);
    assert.equal(harness.document.focusedElement, close);
  }
  const escape = { ...harness.eventFor(close), key: "Escape" };
  harness.document.dispatch("keydown", escape);
  await settle();
  assert.equal(escape.defaultPrevented, true);
  assert.equal(escape.immediatePropagationStopped, true);
  assert.equal(harness.document.focusedElement, button);
  assert.equal(button.activations, 0);
  assert.equal(harness.document.listenerCount("keydown"), 0);
});

test("原控件被页面移除后关闭提示，不尝试恢复已断开的焦点", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const button = harness.button();
  button.focus();
  harness.click(button);
  button.remove();
  button.focus = () => assert.fail("不得聚焦已移除的控件");
  const escape = { ...harness.eventFor(button), key: "Escape" };
  harness.document.dispatch("keydown", escape);
  await settle();
  assert.equal(escape.defaultPrevented, true);
  assert.equal(harness.dialogButtons().length, 0);
  assert.equal(button.activations, 0);
});

test("不同风险重叠时只处理最上层提示，依次关闭后返回最初焦点", async () => {
  const harness = createHarness(Promise.resolve({ state: "enabled", enabled: true, privacyAccepted: true, nativeAvailable: true }));
  await settle();
  const first = harness.button();
  const second = harness.button();
  first.focus();
  harness.click(first);
  const firstClose = harness.dialogButtons()[0];
  harness.click(second);
  const secondClose = harness.dialogButtons()[1];
  const tab = { ...harness.eventFor(secondClose), key: "Tab" };
  harness.document.dispatch("keydown", tab);
  assert.equal(tab.defaultPrevented, true);
  assert.equal(harness.document.focusedElement, secondClose);
  harness.document.dispatch("keydown", { ...harness.eventFor(secondClose), key: "Escape" });
  await settle();
  assert.deepEqual(harness.dialogButtons(), [firstClose]);
  assert.equal(harness.document.focusedElement, firstClose);
  harness.document.dispatch("keydown", { ...harness.eventFor(firstClose), key: "Escape" });
  await settle();
  assert.equal(harness.document.focusedElement, first);
  assert.equal(harness.document.listenerCount("keydown"), 0);
  assert.equal(first.activations + second.activations, 0);
});

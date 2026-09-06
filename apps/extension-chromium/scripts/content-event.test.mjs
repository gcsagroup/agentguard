/**
 * content.js 的 click → submit 接线回归测试。
 *
 * 这里用一个最小 DOM 事件模型执行真实 content.js，而不是再做源码正则。它覆盖纯决策
 * 测试看不到的链路：危险 click/submit 在 window capture 被阻断，页面提示没有任何放行回调。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const Gate = require(path.join(here, "..", "guard-gate.js"));
const source = fs.readFileSync(path.join(here, "..", "content.js"), "utf8");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok  ${name}`);
}

function installHarness() {
  const listeners = new Map();
  const prompts = [];

  function addListener(type, handler) {
    const group = listeners.get(type) || [];
    group.push(handler);
    listeners.set(type, group);
  }

  const document = {
    body: { innerText: "" },
    documentElement: {},
    title: "fixture",
    querySelectorAll: () => [],
    querySelector: () => null,
    createTreeWalker: () => ({ nextNode: () => null }),
    addEventListener: addListener,
  };

  const window = {
    postMessage() {},
    addEventListener: addListener,
  };
  window.window = window;

  const context = {
    CSS: { escape: (value) => value },
    MutationObserver: class {
      observe() {}
    },
    NodeFilter: { SHOW_TEXT: 4 },
    chrome: {
      runtime: { sendMessage() {} },
      storage: {
        local: { get(_keys, callback) { callback({}); } },
        onChanged: { addListener() {} },
      },
    },
    clearTimeout,
    console,
    document,
    getComputedStyle: () => ({}),
    location: { href: "https://shop.example/checkout" },
    self: {
      AgentGuardGate: Gate,
      AgentGuardModal: {
        showBlocked(spec) {
          prompts.push(spec);
        },
      },
    },
    setTimeout,
    window,
  };
  vm.runInNewContext(source, context, { filename: "content.js" });

  function dispatch(type, event) {
    for (const handler of listeners.get(type) || []) {
      handler(event);
      if (event.immediatePropagationStopped) break;
    }
  }

  function event(target, submitter, composedPath = null) {
    return {
      target,
      submitter,
      composedPath: () => composedPath || [target],
      defaultPrevented: false,
      immediatePropagationStopped: false,
      preventDefault() { this.defaultPrevented = true; },
      stopImmediatePropagation() { this.immediatePropagationStopped = true; },
    };
  }

  const form = {
    submitted: 0,
    querySelectorAll: () => [],
    requestSubmit(submitter) {
      submit(submitter);
    },
  };

  function submit(submitter) {
    const e = event(form, submitter);
    dispatch("submit", e);
    if (!e.defaultPrevented) form.submitted += 1;
  }

  function button(submitOnClick) {
    const el = {
      form,
      innerText: "Pay now",
      type: "submit",
      value: "",
      closest(selector) {
        if (selector === "form") return form;
        if (selector.includes("button")) return this;
        return null;
      },
      click() {
        const e = event(this);
        dispatch("click", e);
        if (!e.defaultPrevented && submitOnClick) submit(this);
      },
    };
    return el;
  }

  function dispatchClick(target, composedPath) {
    const e = event(target, null, composedPath);
    dispatch("click", e);
    return e;
  }

  return { button, dispatchClick, form, prompts, submit };
}

test("付款按钮每次都阻断且页面提示没有放行路径", () => {
  const h = installHarness();
  const button = h.button(true);
  button.click();
  assert.equal(h.prompts.length, 1);
  assert.equal(h.form.submitted, 0, "危险动作不得提交");
  button.click();
  assert.equal(h.prompts.length, 2, "关闭或篡改上次提示不能产生放行令牌");
  assert.equal(h.form.submitted, 0);
});

test("危险表单提交也没有可泄漏的批准状态", () => {
  const h = installHarness();
  const button = h.button(false);
  button.click();
  assert.equal(h.prompts.length, 1);
  h.submit(button);
  assert.equal(h.prompts.length, 2, "未消费的表单令牌必须在 click 重放结束时清掉");
  assert.equal(h.form.submitted, 0);
});

test("开放 Shadow DOM 的付款按钮按 composedPath 阻断", () => {
  const h = installHarness();
  const button = h.button(false);
  const host = { innerText: "", value: "", closest: () => null };
  const event = h.dispatchClick(host, [button, { closest: () => null }, host]);
  assert.equal(event.defaultPrevented, true, "shadow host 的事件重定向不得隐藏内部付款按钮");
  assert.equal(h.prompts.length, 1);
});

test("源码不包含动作重放或页面内 allow 回调", () => {
  assert.doesNotMatch(source, /requestSubmit|gateApproved|replayApproved|onAllow|isTrusted/);
});

console.log(`\ncontent-event: ${passed} 条测试全部通过`);

/**
 * content.js 的 click → submit 接线回归测试。
 *
 * 这里用一个最小 DOM 事件模型执行真实 content.js，而不是再做源码正则。它覆盖一个纯决策
 * 测试看不到的链路：付款 submit 按钮在「允许一次」后重放 click，浏览器随后同步触发 submit；
 * 整条动作只能确认一次，也不能把未消费的表单批准泄漏到下一次提交。
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

  const document = {
    body: { innerText: "" },
    documentElement: {},
    title: "fixture",
    querySelectorAll: () => [],
    querySelector: () => null,
    createTreeWalker: () => ({ nextNode: () => null }),
    addEventListener(type, handler) {
      const group = listeners.get(type) || [];
      group.push(handler);
      listeners.set(type, group);
    },
  };

  const window = {
    postMessage() {},
    addEventListener() {},
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
        askAllowOnce(spec, onAllow) {
          prompts.push(spec);
          onAllow();
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

  function event(target, submitter) {
    return {
      target,
      submitter,
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

  return { button, form, prompts, submit };
}

test("付款按钮允许一次只产生一次确认并提交一次", () => {
  const h = installHarness();
  h.button(true).click();
  assert.equal(h.prompts.length, 1, "click 重放后的 submit 不应再次询问");
  assert.equal(h.form.submitted, 1, "批准后应只提交一次");
});

test("没有发生提交的点击不会把表单批准泄漏到下一次提交", () => {
  const h = installHarness();
  const button = h.button(false);
  button.click();
  assert.equal(h.prompts.length, 1);
  h.submit(button);
  assert.equal(h.prompts.length, 2, "未消费的表单令牌必须在 click 重放结束时清掉");
  assert.equal(h.form.submitted, 1);
});

console.log(`\ncontent-event: ${passed} 条测试全部通过`);

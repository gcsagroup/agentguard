/**
 * MAIN world 原生 submit 包装：探测被取消则跳过原生方法，普通调用保持原语义。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(path.join(here, "..", "guard-native-submit.js"), "utf8");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok  ${name}`);
}

function install() {
  const nativeCalls = [];
  function nativeSubmit() {
    nativeCalls.push(this.id);
  }
  const proto = { submit: nativeSubmit };
  const HTMLFormElement = function HTMLFormElement() {};
  HTMLFormElement.prototype = proto;
  const listeners = [];
  const window = {
    HTMLFormElement,
    CustomEvent: class CustomEvent {
      constructor(type, init) {
        this.type = type;
        this.bubbles = !!(init && init.bubbles);
        this.cancelable = !!(init && init.cancelable);
        this.defaultPrevented = false;
      }
      preventDefault() {
        this.defaultPrevented = true;
      }
    },
  };
  Object.defineProperty(proto, "submit", {
    configurable: true,
    enumerable: false,
    writable: true,
    value: nativeSubmit,
  });
  const form = {
    id: "f",
    dispatchEvent(event) {
      for (const handler of listeners) handler.call(this, event);
      return !event.defaultPrevented;
    },
  };
  Object.setPrototypeOf(form, proto);
  vm.runInNewContext(source, { window, HTMLFormElement, Object, CustomEvent: window.CustomEvent }, { filename: "guard-native-submit.js" });
  return {
    form,
    nativeCalls,
    listen(handler) { listeners.push(handler); },
    submit() { return form.submit(); },
  };
}

test("包装后普通 form.submit 仍调用原生方法", () => {
  const h = install();
  h.submit();
  assert.deepEqual(h.nativeCalls, ["f"]);
});

test("探测被取消时不调用原生 submit", () => {
  const h = install();
  h.listen((event) => event.preventDefault());
  h.submit();
  assert.deepEqual(h.nativeCalls, []);
});

test("源码不做判决、不发页面消息、不引用 chrome", () => {
  assert.doesNotMatch(source, /postMessage|onAllow|gateApproved|chrome\./);
  assert.match(source, /agentguard-native-submit/);
});

console.log(`\nnative-submit: ${passed} 条测试全部通过`);

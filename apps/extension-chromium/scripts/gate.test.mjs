/**
 * guard-gate.js 纯决策逻辑的单元测试(node,无浏览器)。
 *
 * 跑:`node apps/extension-chromium/scripts/gate.test.mjs`(见 `make check-extension-gate`)。
 * 这是浏览器**执行前阻断**逻辑在本环境唯一能实测的一半;DOM 接线(content.js)只做语法检查,
 * 真 Chrome 端到端未验证——和 jail 的 syscall 路径同一种诚实。
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const Gate = require(path.join(here, "..", "guard-gate.js"));

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok  ${name}`);
}

test("付款 CTA 要执行前拦下", () => {
  const d = Gate.gateForFinding("payment_cta");
  assert.equal(d.block, true);
  assert.ok(d.reason.length > 0, "拦截必须带一个给用户看的理由");
});

test("隐私陷阱 PII 提交要执行前拦下", () => {
  assert.equal(Gate.gateForFinding("privacy_trap").block, true);
});

test("普通发现不拦(避免误拦把门变成噪音)", () => {
  // 反面用例:没有这一条,gateForFinding 可能只是"什么都拦"。
  assert.equal(Gate.gateForFinding("optional_pii").block, false);
  assert.equal(Gate.gateForFinding("prompt_injection").block, false);
  assert.equal(Gate.gateForFinding("unknown").block, false);
});

test("一组发现里有一个要拦就拦,并给出那个理由", () => {
  const d = Gate.gateForFindings([{ kind: "optional_pii" }, { kind: "payment_cta" }]);
  assert.equal(d.block, true);
  assert.equal(d.kind, "payment_cta");
});

test("一组全是非拦截发现则放行", () => {
  const d = Gate.gateForFindings([{ kind: "optional_pii" }, { kind: "prompt_injection" }]);
  assert.equal(d.block, false);
});

test("DNR 规则:去重、排序、id 稳定、动作是 block", () => {
  const rules = Gate.buildBlockRules(["EVIL.example", "evil.example", "bad.test"], 10);
  assert.equal(rules.length, 2, "重复主机应去重");
  assert.deepEqual(
    rules.map((r) => r.id),
    [10, 11],
    "id 应从 startId 起连续、稳定"
  );
  assert.deepEqual(
    rules.map((r) => r.condition.requestDomains[0]),
    ["bad.test", "evil.example"],
    "应小写并排序"
  );
  for (const r of rules) {
    assert.equal(r.action.type, "block");
    assert.ok(r.condition.resourceTypes.includes("main_frame"), "至少拦主框架导航");
  }
});

test("空主机列表得到空规则(不无中生有拦东西)", () => {
  assert.deepEqual(Gate.buildBlockRules([]), []);
});

console.log(`\nguard-gate: ${passed} 条测试全部通过`);

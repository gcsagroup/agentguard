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
import fs from "node:fs";
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

test("付款形状的 POST 请求要在发出前拦", () => {
  assert.equal(Gate.classifyRequest("https://shop.example/api/checkout", "POST").gate, true);
  assert.equal(Gate.classifyRequest("/v1/payment/charge", "POST").gate, true);
  assert.equal(Gate.classifyRequest("https://bank.example/transfer", "PUT").gate, true);
});

test("只读方法不拦(GET/HEAD 不该有副作用)", () => {
  // 反面用例:付款路径 + GET 也不拦——拦它是误伤,而误伤会让人关掉门。
  assert.equal(Gate.classifyRequest("https://shop.example/checkout", "GET").gate, false);
  assert.equal(Gate.classifyRequest("https://shop.example/payment", "HEAD").gate, false);
});

test("普通 POST 不拦(避免把门变成噪音)", () => {
  assert.equal(Gate.classifyRequest("https://api.example/search", "POST").gate, false);
  assert.equal(Gate.classifyRequest("https://api.example/login", "POST").gate, false);
  // 'paypal.com' 作为主机名不该因为含 'pay' 命中——判据看的是**路径**,不是整串里的子串。
  assert.equal(Gate.classifyRequest("https://paypal.com/home", "POST").gate, false);
});

test("拦截时带一个给用户看的理由", () => {
  const d = Gate.classifyRequest("https://x.example/api/pay", "POST");
  assert.ok(d.gate && d.reason.length > 0);
});

test("恶意域累积保留:下一批 benign 判决不会把它清掉", () => {
  // E5 原来的 bug:整体替换 → 一批空判决就把上一批的恶意域撤了。累积语义修掉它。
  const s1 = Gate.mergeBlocklist({}, ["evil.example"], [], 1000);
  assert.deepEqual(s1.persistent, ["evil.example"]);
  assert.ok(s1.active.includes("evil.example"));
  const s2 = Gate.mergeBlocklist(s1, [], [], 2000); // benign 批,无新恶意域
  assert.ok(s2.persistent.includes("evil.example"), "恶意域必须仍在持久名单");
  assert.ok(s2.active.includes("evil.example"), "恶意域必须仍在 active");
});

test("越界目的地随会话过期,不永久拦掉用户对该主机的正常访问", () => {
  const ttl = 1000;
  const s1 = Gate.mergeBlocklist({}, [], ["booking.com"], 1000, ttl);
  assert.ok(s1.active.includes("booking.com"), "刚判越界应在 active");
  // 过了 ttl 且没再判越界 → 撤掉。
  const s2 = Gate.mergeBlocklist(s1, [], [], 1000 + ttl + 1, ttl);
  assert.ok(!s2.active.includes("booking.com"), "过期的越界主机应从 active 撤掉");
});

test("清理过期名单不会丢掉规则溯源", () => {
  const state = {
    persistent: ["evil.example"],
    session: [{ host: "expired.example", exp: 1000 }],
    provenance: {
      "evil.example": { kind: "malicious", rule_id: "INTEL-DOMAIN" },
      "expired.example": { kind: "out_of_scope", rule_id: "SCOPE-HOST" },
    },
  };
  const pruned = Gate.pruneBlocklist(state, 1001);
  assert.deepEqual(pruned.persistent, ["evil.example"]);
  assert.deepEqual(pruned.session, []);
  assert.deepEqual(pruned.provenance, state.provenance, "管理界面仍需显示活跃主机的规则来源");
});

test("再次判越界会刷新过期时间", () => {
  const ttl = 1000;
  const s1 = Gate.mergeBlocklist({}, [], ["x.example"], 1000, ttl);
  const s2 = Gate.mergeBlocklist(s1, [], ["x.example"], 1500, ttl); // 刷新
  const s3 = Gate.mergeBlocklist(s2, [], [], 1000 + ttl + 1, ttl); // 原 exp 已过,但被刷新过
  assert.ok(s3.active.includes("x.example"), "刷新后应延到新 exp,仍在 active");
});

test("既恶意又越界的主机归入持久(malicious 更强)", () => {
  const s = Gate.mergeBlocklist({}, ["dual.example"], ["dual.example"], 1000, 1000);
  assert.ok(s.persistent.includes("dual.example"));
  // 不重复出现在会话集里。
  assert.ok(!s.session.some((e) => e.host === "dual.example"));
});

test("持久名单有上限,超了丢最旧的(尊重 DNR 配额)", () => {
  let state = {};
  for (let i = 0; i < 5; i++) {
    state = Gate.mergeBlocklist(state, [`m${i}.example`], [], 1000 + i, 1000, 3);
  }
  assert.equal(state.persistent.length, 3, "持久名单应被截到上限 3");
  assert.deepEqual(state.persistent, ["m2.example", "m3.example", "m4.example"], "保留最近的");
});

test("host_in_scope向量表_rust与js同源", () => {
  // E11:和 Rust 的 host_scope_向量表是rust与js的单一真相源 跑**同一个** JSON。任一端漂移就红。
  const vpath = path.join(here, "..", "..", "..", "eval", "host-scope-vectors.json");
  const doc = JSON.parse(fs.readFileSync(vpath, "utf8"));
  const vectors = doc.vectors;
  assert.ok(Array.isArray(vectors) && vectors.length >= 10, "向量表太少,证明不了什么");
  for (const v of vectors) {
    assert.equal(
      Gate.hostInScope(v.observed, v.entry),
      v.in_scope,
      `向量 {observed:${JSON.stringify(v.observed)}, entry:${JSON.stringify(v.entry)}} 期望 ${v.in_scope}(${v.note || ""})`
    );
  }
});

test("scopeGateHost:没声明允许表不拦,声明了拦越界,空表全拦", () => {
  // 没声明(null/undefined)→ 不拦(和引擎"没声明不拦"一致)。
  assert.equal(Gate.scopeGateHost("anything.example", null).gate, false);
  assert.equal(Gate.scopeGateHost("anything.example", undefined).gate, false);
  // 声明了:在表内不拦,表外拦。
  assert.equal(Gate.scopeGateHost("checkout.stripe.com", ["stripe.com"]).gate, false);
  const d = Gate.scopeGateHost("collector.evil.example", ["stripe.com"]);
  assert.equal(d.gate, true);
  assert.ok(d.reason.length > 0);
  // 空表 = 明确不许出网 → 全拦。
  assert.equal(Gate.scopeGateHost("stripe.com", []).gate, true);
});

test("表单允许一次用 requestSubmit 保留校验与原 submitter 语义", () => {
  const source = fs.readFileSync(path.join(here, "..", "content.js"), "utf8");
  assert.match(source, /form\.requestSubmit\(e\.submitter \|\| undefined\)/);
  assert.doesNotMatch(
    source,
    /^[ \t]*form\.submit\(\);/m,
    "不能绕过约束校验和 submitter 覆盖属性"
  );
});

console.log(`\nguard-gate: ${passed} 条测试全部通过`);

/**
 * 首个 GA Chromium manifest 的结构门禁(E4)。
 *
 * 首发只支持 Chrome/Edge。Firefox manifest 是研发 scaffold，不进入发布包也不作为 GA parity
 * 门禁；它的拒包由 package-store.test.mjs 验证。这里保证 Chromium 没有页面判决通道、
 * Native Messaging，且 DOM 只阻断逻辑在 document_start 注入所有 frame。
 */
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import assert from "node:assert/strict";

const here = path.dirname(fileURLToPath(import.meta.url));
const ext = path.join(here, "..");
const read = (p) => JSON.parse(fs.readFileSync(path.join(ext, p), "utf8"));

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok  ${name}`);
}

const chrome = read("manifest.json");

const jsFiles = (m) =>
  (m.content_scripts || [])
    .flatMap((cs) => cs.js || [])
    .sort()
    .filter((v, i, a) => a.indexOf(v) === i);

test("Chromium manifest 装入完整内容脚本", () => {
  assert.deepEqual(jsFiles(chrome), ["content.js", "guard-gate.js", "guard-modal.js", "guard-strings.js"]);
});

test("GA 权限没有 Native Messaging，通知权限有 DOM 阻断用途", () => {
  assert.ok(!chrome.permissions.includes("nativeMessaging"), "首个 GA 包必须关闭未相互认证的 Native Messaging");
  assert.ok(chrome.permissions.includes("notifications"));
  const background = fs.readFileSync(path.join(ext, "background.js"), "utf8");
  assert.match(background, /function notifyDomBlocked\(/);
  assert.match(background, /notifyDomBlocked\(msg\.kind\)/);
});

test("Chromium 后台运行模块 service worker", () => {
  assert.equal(chrome.background?.service_worker, "background.js", "Chromium MV3 后台应使用 service worker");
  assert.equal(chrome.background?.type, "module");
});

test("Chromium 不注入 MAIN world 页面判决代码", () => {
  assert.ok(!(chrome.content_scripts || []).some((cs) => cs.world === "MAIN"));
  assert.ok(!jsFiles(chrome).includes("guard-page.js"));
  assert.ok(!fs.existsSync(path.join(ext, "guard-page.js")), "guard-page.js 应从扩展源码中删除");
});

test("Chromium 默认启用付款形状静态 DNR 硬阻断", () => {
  const expected = [{ id: "payment_shape_block", enabled: true, path: "rules/payment-shape-block.json" }];
  assert.deepEqual(chrome.declarative_net_request?.rule_resources, expected);
  const rules = read("rules/payment-shape-block.json");
  assert.equal(rules.length, 20, "付款路径标记与显式操作 query 各自使用低复杂度规则");
  assert.equal(new Set(rules.map((rule) => rule.id)).size, rules.length, "DNR rule id 必须唯一");
  for (const rule of rules) {
    assert.equal(rule.action?.type, "block");
    assert.deepEqual(rule.condition?.excludedRequestMethods, ["get", "head"]);
    assert.deepEqual(rule.condition?.resourceTypes, ["main_frame", "sub_frame", "xmlhttprequest", "ping"]);
  }
  const matches = (url) =>
    rules.filter((rule) =>
      new RegExp(
        rule.condition.regexFilter,
        rule.condition.isUrlFilterCaseSensitive ? "" : "i"
      ).test(url)
    );
  for (const url of [
    "https://shop.example/api/checkout",
    "http://bank.example/transfer/v2",
    "https://shop.example/pay-now",
    "https://shop.example/orderconfirm",
    "https://x.example/order-confirm.json",
    "https://x.example/confirm_order/submit",
    "https://shop.example/%70ay",
    "https://shop.example/p%61y",
    "https://shop.example/api%2Fpay",
    "https://shop.example/%6f%72%64%65%72%2d%63%6f%6e%66%69%72%6d",
    "https://shop.example/api?op=pay",
  ]) assert.equal(matches(url).length, 1, `付款路径未唯一命中:${url}`);
  for (const url of [
    "https://paypal.example/home",
    "https://shop.example/prepay",
    "https://shop.example/pay%72oll",
    "https://shop.example/api/search?next=/pay",
    "https://shop.example/api?next=https://x.invalid/?op=pay",
    "https://shop.example/payment_status",
  ]) assert.equal(matches(url).length, 0, `普通路径被误判:${url}`);
});

test("内容脚本没有公开 request decision scope 消息信任根", () => {
  const content = fs.readFileSync(path.join(ext, "content.js"), "utf8");
  assert.doesNotMatch(content, /__agentguard_(?:req_gate|req_decision|scope)__/);
  assert.doesNotMatch(content, /window\.postMessage/);
  assert.doesNotMatch(content, /addEventListener\(\s*["']message["']/);
});

test("DOM 只阻断脚本在 document_start 覆盖所有 frame", () => {
  assert.ok((chrome.content_scripts || []).length > 0);
  for (const script of chrome.content_scripts) {
    assert.equal(script.run_at, "document_start");
    assert.equal(script.all_frames, true);
  }
  const content = fs.readFileSync(path.join(ext, "content.js"), "utf8");
  assert.match(content, /window\.addEventListener\(\s*["']click["']/);
  assert.match(content, /window\.addEventListener\(\s*["']submit["']/);
  assert.doesNotMatch(content, /requestSubmit|gateApproved|replayApproved|onAllow/);
});

test("引用到的每个内容脚本文件都真的存在", () => {
  for (const f of jsFiles(chrome)) {
    assert.ok(fs.existsSync(path.join(ext, f)), `manifest 引用了不存在的文件 ${f}`);
  }
});

console.log(`\nmanifests: ${passed} 条测试全部通过`);

/**
 * 跨浏览器 manifest 的结构一致性测试(E4)。
 *
 * Chrome/Edge 用 manifest.json,Firefox 用 manifest.firefox.json。它们**必须**装同一套内容脚本和
 * 权限——否则某个浏览器上会悄悄少一层防护(比如 Firefox 漏了 guard-page.js,fetch 门就没了,而
 * 没有任何东西会报错)。这条测试把两份 manifest 钉在一起:内容脚本文件集、权限集必须一致,
 * 引用到的每个 js 必须真的存在,Firefox 必须带 gecko id,两份 native-host 模板必须各用对的允许键。
 *
 * 这不能验证扩展在真浏览器里跑得起来(那需要真 Chrome/Firefox);它保证的是"两个目标不漂移"——
 * 和 X-2 主张↔测试映射、P2 端点表一致性同一种钉子。Safari 不在此列:它是 Xcode 包壳,没有可比的
 * manifest(见 docs/跨浏览器.md)。
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
const firefox = read("manifest.firefox.json");

const jsFiles = (m) =>
  (m.content_scripts || [])
    .flatMap((cs) => cs.js || [])
    .sort()
    .filter((v, i, a) => a.indexOf(v) === i);

test("两份 manifest 装的是同一套内容脚本文件", () => {
  assert.deepEqual(jsFiles(firefox), jsFiles(chrome), "内容脚本文件集漂移了");
});

test("两份 manifest 的权限集一致", () => {
  assert.deepEqual([...(firefox.permissions || [])].sort(), [...(chrome.permissions || [])].sort());
});

test("两份 manifest 的商店版本一致", () => {
  assert.equal(firefox.version, chrome.version, "Firefox 与 Chromium 的商店版本漂移了");
});

test("两种浏览器后台都运行同一模块入口", () => {
  assert.equal(chrome.background?.service_worker, "background.js", "Chromium MV3 后台应使用 service worker");
  assert.deepEqual(firefox.background?.scripts, ["background.js"], "Firefox MV3 后台应使用 event page scripts");
  assert.ok(!firefox.background?.service_worker, "Firefox 不支持扩展 background service worker");
  assert.equal(chrome.background?.type, "module");
  assert.equal(firefox.background?.type, "module");
});

test("两份 manifest 都声明了 MAIN world 的 fetch 门", () => {
  for (const [name, m] of [["chrome", chrome], ["firefox", firefox]]) {
    const hasMain = (m.content_scripts || []).some(
      (cs) => cs.world === "MAIN" && (cs.js || []).includes("guard-page.js")
    );
    assert.ok(hasMain, `${name} 少了 world:MAIN 的 guard-page.js`);
  }
});

test("引用到的每个内容脚本文件都真的存在", () => {
  for (const f of jsFiles(chrome)) {
    assert.ok(fs.existsSync(path.join(ext, f)), `manifest 引用了不存在的文件 ${f}`);
  }
});

test("Firefox manifest 带 gecko id(否则装不上、原生消息对不上)", () => {
  const id = firefox.browser_specific_settings?.gecko?.id;
  assert.ok(id && id.length > 0, "firefox manifest 缺 browser_specific_settings.gecko.id");
});

test("native-host 模板:Chromium 用 allowed_origins,Firefox 用 allowed_extensions", () => {
  const chost = read("native-host/com.agentguard.native.json");
  const fhost = read("native-host/com.agentguard.native.firefox.json");
  assert.ok(Array.isArray(chost.allowed_origins), "Chromium host 应有 allowed_origins");
  assert.ok(!chost.allowed_extensions, "Chromium host 不该用 allowed_extensions");
  assert.ok(Array.isArray(fhost.allowed_extensions), "Firefox host 应有 allowed_extensions");
  assert.ok(!fhost.allowed_origins, "Firefox host 不该用 allowed_origins");
  assert.equal(chost.name, fhost.name, "两个 host 的 name 必须一致(同一个 host 二进制)");
});

console.log(`\nmanifests: ${passed} 条测试全部通过`);

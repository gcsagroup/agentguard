const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const resources = path.resolve(__dirname, "../../Extension/Resources");
const manifest = JSON.parse(fs.readFileSync(path.join(resources, "manifest.json"), "utf8"));
const contentSource = fs.readFileSync(path.join(resources, "content.js"), "utf8");
const source = ["background.js", "content.js", "gate.js"]
  .map((name) => fs.readFileSync(path.join(resources, name), "utf8"))
  .join("\n");

test("manifest is a Safari MV3 isolated-world extension", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.content_scripts.length, 1);
  assert.equal(manifest.content_scripts[0].world, undefined);
  assert.equal(manifest.content_scripts[0].run_at, "document_start");
  assert.equal(manifest.content_scripts[0].all_frames, true);
  assert.deepEqual(manifest.permissions, ["nativeMessaging"]);
});

test("MVP has no MAIN-world, DNR, long-lived native port, or upload path", () => {
  assert.equal(JSON.stringify(manifest).includes("MAIN"), false);
  assert.equal(JSON.stringify(manifest).includes("declarativeNetRequest"), false);
  assert.equal(source.includes("connectNative"), false);
  assert.equal(source.includes("XMLHttpRequest"), false);
  assert.equal(source.includes("window.fetch"), false);
  assert.equal(/https?:\/\//.test(source), false);
});

test("all declared extension resources exist", () => {
  for (const script of manifest.background.scripts) {
    assert.equal(fs.existsSync(path.join(resources, script)), true, script);
  }
  for (const script of manifest.content_scripts[0].js) {
    assert.equal(fs.existsSync(path.join(resources, script)), true, script);
  }
  for (const locale of ["en", "zh_CN", "zh_TW"]) {
    assert.equal(fs.existsSync(path.join(resources, "_locales", locale, "messages.json")), true, locale);
  }
});

test("submit controls are gated only by the submit listener", () => {
  assert.match(contentSource, /if \(isSubmitControl\(element\)\) return;/);
  assert.match(contentSource, /form\.requestSubmit\(/);
});

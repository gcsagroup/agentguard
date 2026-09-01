/* 人话词典(guard-strings.js)的红绿测试。
 *
 * 这组测试守的性质是:**用户界面上不出现没有人话解释的裸术语**。做法不是扫渲染后的
 * DOM(node 里没有),而是把"会到达用户眼前的标识符集合"从各自的真相源提取出来,
 * 对着词典点名:
 *   - finding kind:从 content.js 源码提取 kind: "..." 字面量;
 *   - 规则 ID:从 guard-schema/src/events.rs 提取 *_RULE_ID 常量;
 *   - 执行前门:guard-gate.js 会 block 的每个 kind,词典必须有对应确认文案。
 * 新增一个 kind / 规则而忘了配人话词条,这里会红。
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const S = require(join(here, "..", "guard-strings.js"));
const Gate = require(join(here, "..", "guard-gate.js"));

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ok - ${name}`);
  } catch (e) {
    failures += 1;
    console.error(`  FAIL - ${name}\n    ${e && e.message}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

const LOCALES = ["en", "zh_CN", "zh_TW"];
const CJK = /[一-鿿]/;

test("content.js 上报的每个 finding kind 在词典里都有三语人话词条", () => {
  const src = readFileSync(join(here, "..", "content.js"), "utf8");
  const kinds = new Set();
  for (const m of src.matchAll(/kind:\s*(?:invisible\s*\?\s*)?"([a-z_]+)"(?:\s*:\s*"([a-z_]+)")?/g)) {
    kinds.add(m[1]);
    if (m[2]) kinds.add(m[2]);
  }
  for (const m of src.matchAll(/reportPrevented\([^)]*?,\s*"([a-z_]+)"\)/g)) kinds.add(m[1]);
  assert(kinds.size >= 5, `从 content.js 只提取到 ${kinds.size} 个 kind —— 提取正则可能在空转`);
  for (const kind of kinds) {
    for (const locale of LOCALES) {
      const t = S.kindText(kind, locale);
      assert(t && t.title && t.detail, `kind "${kind}" 缺 ${locale} 词条`);
      assert(!/^[a-z_]+$/.test(t.title), `kind "${kind}" 的 ${locale} 标题还是蛇形术语`);
    }
  }
});

test("guard-schema events.rs 里的每个规则 ID 在词典里都有三语人话词条", () => {
  const src = readFileSync(
    join(here, "..", "..", "..", "crates", "guard-schema", "src", "events.rs"),
    "utf8"
  );
  const rules = new Set();
  for (const m of src.matchAll(/_RULE_ID[^=]*=\s*"([A-Z0-9-]+)"/g)) rules.add(m[1]);
  assert(rules.size >= 2, `从 events.rs 只提取到 ${rules.size} 个规则 ID —— 提取正则可能在空转`);
  for (const rule of rules) {
    for (const locale of LOCALES) {
      const t = S.ruleText(rule, locale);
      assert(t && t.title && t.detail, `规则 "${rule}" 缺 ${locale} 词条`);
      assert(t.title !== rule, `规则 "${rule}" 的 ${locale} 标题还是裸 ID`);
    }
  }
});

test("guard-gate 会执行前阻断的每个 kind,词典都有确认层文案(标题/正文/两种后果)", () => {
  for (const kind of Object.keys(S.KINDS)) {
    const d = Gate.gateForFinding(kind);
    if (!d.block) continue;
    for (const locale of LOCALES) {
      const g = S.gateText(kind, locale);
      assert(g && g.title && g.body && g.allow && g.cancel, `门 "${kind}" 缺 ${locale} 确认文案`);
    }
  }
  // fetch 门与越界门不来自 finding kind,单独点名。
  for (const kind of ["payment_request", "out_of_scope_host", "no_egress"]) {
    for (const locale of LOCALES) {
      const g = S.gateText(kind, locale);
      assert(g && g.title && g.body && g.allow && g.cancel, `门 "${kind}" 缺 ${locale} 确认文案`);
    }
  }
});

test("词典每张表三语齐全,中文词条真的是中文(不许英文残留)", () => {
  for (const [tableName, table] of Object.entries({ KINDS: S.KINDS, RULES: S.RULES, GATES: S.GATES })) {
    for (const [key, entry] of Object.entries(table)) {
      for (const locale of LOCALES) {
        assert(entry[locale], `${tableName}.${key} 缺 ${locale}`);
        if (locale !== "en") {
          for (const v of Object.values(entry[locale])) {
            assert(CJK.test(v), `${tableName}.${key} 的 ${locale} 词条没有中文:${v}`);
          }
        }
      }
    }
  }
  for (const locale of LOCALES) {
    assert(S.UI[locale], `UI 缺 ${locale}`);
    assert(
      Object.keys(S.UI[locale]).join() === Object.keys(S.UI.en).join(),
      `UI.${locale} 的键和 en 不一致`
    );
  }
});

test("gateText 的 {host} 占位真的被替换", () => {
  const g = S.gateText("out_of_scope_host", "zh_CN", { host: "tracker.example" });
  assert(g.body.includes("tracker.example"), `body 没替换 host:${g.body}`);
  assert(!g.body.includes("{host}"), "body 还残留 {host} 占位");
});

test("pickLocale:覆盖优先,否则按浏览器语言归一,兜底 en", () => {
  assert(S.pickLocale("zh_TW", "en-US") === "zh_TW", "显式覆盖没生效");
  assert(S.pickLocale("system", "zh-CN") === "zh_CN", "system 应看浏览器语言");
  assert(S.pickLocale(null, "zh-Hant-TW") === "zh_TW", "繁体归一失败");
  assert(S.pickLocale(null, "fr-FR") === "en", "未知语言应兜底 en");
  assert(S.pickLocale("de", "fr-FR") === "en", "词表外的覆盖值应兜底而不是原样返回");
});

test("relativeTime:刚刚/分钟/小时/天四档", () => {
  const now = 1_000_000_000_000;
  assert(S.relativeTime(now - 10_000, now, "zh_CN") === "刚刚");
  assert(S.relativeTime(now - 5 * 60_000, now, "zh_CN") === "5 分钟前");
  assert(S.relativeTime(now - 3 * 3_600_000, now, "en") === "3 h ago");
  assert(S.relativeTime(now - 2 * 86_400_000, now, "zh_TW") === "2 天前");
});

test("扩展语言包三语键集合一致,中文包无未翻译残留", () => {
  const packs = {};
  for (const locale of LOCALES) {
    packs[locale] = JSON.parse(
      readFileSync(join(here, "..", "_locales", locale === "en" ? "en" : locale, "messages.json"), "utf8")
    );
  }
  const enKeys = Object.keys(packs.en).sort().join();
  for (const locale of ["zh_CN", "zh_TW"]) {
    assert(
      Object.keys(packs[locale]).sort().join() === enKeys,
      `_locales/${locale} 的键集合和 en 不一致`
    );
    const allowed = new Set(["english"]); // 语言自称保留原文
    for (const [key, v] of Object.entries(packs[locale])) {
      if (allowed.has(key.toLowerCase())) continue;
      assert(CJK.test(v.message), `_locales/${locale}/${key} 疑似未翻译:${v.message}`);
    }
  }
});

if (failures > 0) {
  console.error(`\n${failures} 个用例失败`);
  process.exit(1);
}
console.log("\nstrings.test.mjs 全部通过");

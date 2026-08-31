/* 桌面壳子词表完整性测试(E18)。
 *
 * 为什么存在:壳子的 t(key) 在词条缺失时把 **key 本身**渲染到界面上——E16 之前
 * macOS 壳子的任务下拉真的显示过 "guard.taskNone" 这个 key 名,因为 index.html 用了
 * 这个 data-i18n 而词表里没有。这类 bug 不报错、不崩溃,只有肉眼看得见,所以要机器盯:
 *
 *   1. 每个壳子的三语词表键集合完全一致(缺一语就是某语用户看 key 名);
 *   2. index.html 里每个 data-i18n 引用的键在词表里存在;
 *   3. main.js 里每个字面量 t("...") 引用的键存在;
 *   4. 动态构造的 `action.${actionClass(...)}` 四个取值都存在;
 *   5. 中文词表没有未翻译的英文残留(语言自称等白名单除外)。
 *
 * 词表是 i18n.js 里的**纯字面量**、模块私有(没导出),所以从源码把字面量抠出来
 * 用 Function 求值——比正则逐键解析稳。它抠不出非字面量的表;如果哪天词表改成
 * 动态构造,下面的"抠不出来就红"会立刻叫。
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

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

const CJK = /[一-鿿]/;
// 语言自称与在中文语境里约定俗成保留原文的值。
const ZH_VALUE_ALLOWLIST = new Set(["English", "简体中文", "繁體中文"]);

function extractTable(src, varName, file) {
  const anchor = `const ${varName} = {`;
  const start = src.indexOf(anchor);
  assert(start >= 0, `${file} 里找不到 ${anchor} —— 词表改名/改构造方式了,这个测试需要跟着改`);
  const end = src.indexOf("\n};", start);
  assert(end > start, `${file} 的词表没有以 "\\n};" 结束`);
  const literal = src.slice(start + anchor.length - 1, end + 2);
  // 词表是纯字面量;Function 求值仅限这段测试内(node 环境,无 DOM)。
  return new Function(`return (${literal});`)();
}

const SHELLS = [
  { dir: "apps/desktop-windows", table: "dictionaries" },
  { dir: "apps/desktop-macos", table: "messages" },
];

for (const shell of SHELLS) {
  const i18nSrc = readFileSync(join(REPO, shell.dir, "src", "i18n.js"), "utf8");
  const html = readFileSync(join(REPO, shell.dir, "src", "index.html"), "utf8");
  const mainSrc = readFileSync(join(REPO, shell.dir, "src", "main.js"), "utf8");
  const dict = extractTable(i18nSrc, shell.table, shell.dir);
  const locales = Object.keys(dict);

  test(`${shell.dir}:三语齐全且键集合一致`, () => {
    assert(locales.length === 3, `期望 3 个语言,实际 ${locales.join()}`);
    const enKeys = Object.keys(dict.en).sort().join("\n");
    for (const loc of locales) {
      assert(
        Object.keys(dict[loc]).sort().join("\n") === enKeys,
        `${loc} 的键集合和 en 不一致`
      );
    }
  });

  test(`${shell.dir}:index.html 的每个 data-i18n 键都在词表里`, () => {
    const used = [...html.matchAll(/data-i18n="([^"]+)"/g)].map((m) => m[1]);
    assert(used.length > 10, `只提取到 ${used.length} 个 data-i18n —— 提取可能在空转`);
    for (const key of used) {
      assert(key in dict.en, `index.html 用了 "${key}",词表里没有(界面会显示 key 名)`);
    }
  });

  test(`${shell.dir}:main.js 的每个字面量 t("...") 键都在词表里`, () => {
    const used = [...mainSrc.matchAll(/\bt\("([^"]+)"/g)].map((m) => m[1]);
    assert(used.length > 3, `只提取到 ${used.length} 个 t("...") —— 提取可能在空转`);
    for (const key of used) {
      assert(key in dict.en, `main.js 用了 t("${key}"),词表里没有(界面会显示 key 名)`);
    }
  });

  test(`${shell.dir}:动态键 action.* 四个取值都在词表里`, () => {
    // main.js 的时间线用 t(\`action.\${actionClass(...)}\`);actionClass 只会返回这四个。
    assert(/action\.\$\{actionClass\(/.test(mainSrc), "main.js 不再用 action.* 动态键?测试需要跟着改");
    for (const cls of ["block", "alert", "allow", "logonly"]) {
      assert(`action.${cls}` in dict.en, `词表缺 "action.${cls}"`);
    }
  });

  test(`${shell.dir}:中文词表无未翻译的英文残留`, () => {
    for (const loc of locales.filter((l) => l !== "en")) {
      for (const [key, v] of Object.entries(dict[loc])) {
        if (ZH_VALUE_ALLOWLIST.has(v)) continue;
        assert(CJK.test(v), `${loc}/${key} 疑似未翻译:${v}`);
      }
    }
  });
}

if (failures > 0) {
  console.error(`\nshells-i18n:${failures} 个用例失败`);
  process.exit(1);
}
console.log("\nshells-i18n.test.mjs 全部通过");

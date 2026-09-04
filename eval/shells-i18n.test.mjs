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

/** Windows 壳子用 modeSim/modeIdle/… 这套键;macOS 用 coverage.full/partial/sim。 */
function dotted_modes(dict) {
  return "modeSim" in dict.en;
}

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

  test(`${shell.dir}:动态键 state.* / reason.* 覆盖 guard-core 状态机的每个取值`, () => {
    // P0-3:main.js 用 t(\`state.\${st.protection_state}\`) 和 t(\`reason.\${code}\`)。取值集合的
    // 单一事实来源是 crates/guard-core/src/observe_state.rs 里两个 as_str():Rust 端多加一个
    // 状态而词表没跟上,界面就会显示 "state.foo" 这个 key 名——这个测试让那种漏在门禁里红。
    assert(/state\.\$\{/.test(mainSrc), "main.js 不再用 state.* 动态键?测试需要跟着改");
    assert(/reason\.\$\{/.test(mainSrc), "main.js 不再用 reason.* 动态键?测试需要跟着改");
    const rust = readFileSync(join(REPO, "crates/guard-core/src/observe_state.rs"), "utf8");
    const states = [...rust.matchAll(/ProtectionState::\w+ => "([a-z_]+)"/g)].map((m) => m[1]);
    const reasons = [...rust.matchAll(/Reason::\w+ => "([a-z_]+)"/g)].map((m) => m[1]);
    assert(states.length >= 7, `只从 observe_state.rs 抠出 ${states.length} 个状态 —— 提取可能在空转`);
    assert(reasons.length >= 11, `只从 observe_state.rs 抠出 ${reasons.length} 个原因 —— 提取可能在空转`);
    for (const st of states) {
      assert(`state.${st}` in dict.en, `词表缺 "state.${st}"(guard-core 有这个状态)`);
    }
    for (const r of reasons) {
      assert(`reason.${r}` in dict.en, `词表缺 "reason.${r}"(guard-core 有这个原因码)`);
    }
  });

  test(`${shell.dir}:「怎么用」三步与实时徽章/在看什么的动态键都在词表里`, () => {
    // 真机反馈:主界面看不出这是什么、该点什么、点了会发生什么,于是加了三步「怎么用」卡片
    // (每步一个实时徽章)和一行人话的"现在在看什么"。徽章与在看什么都是**动态键**——
    // t(`chip.${kind}`) / t(变量),字面量提取看不见它们,漏一条界面就显示 key 名。
    // 两个壳子的键命名不同(macOS 带点,Windows 驼峰),所以两套都认。
    const dotted = /chip\.\$\{/.test(mainSrc);
    assert(dotted || /chip\$\{/.test(mainSrc), "main.js 不再用 chip 动态键?测试需要跟着改");
    const chipKeys = dotted
      ? ["chip.done", "chip.todo", "chip.partial", "chip.on", "chip.off"]
      : ["chipDone", "chipTodo", "chipPartial", "chipOn", "chipOff"];
    for (const k of chipKeys) {
      assert(k in dict.en, `词表缺 "${k}"(步骤徽章会显示 key 名)`);
    }
    const watchKeys = dotted
      ? ["watching.none", "watching.full", "watching.axOnly", "watching.captureOnly", "watching.simOnly", "watching.rules"]
      : ["watchingNone", "watchingOn", "watchingNoCaps", "watchingRules"];
    for (const k of watchKeys) {
      assert(k in dict.en, `词表缺 "${k}"(主界面"在看什么"那行会显示 key 名)`);
    }
    // 三步文案本身:标题 + 每步的"为什么",少一条卡片上就是空段落。
    const howtoKeys = dotted
      ? ["howto.title", "howto.lede", "howto.s1", "howto.s1why", "howto.s2", "howto.s2why", "howto.s3", "howto.s3why", "howto.selftest", "howto.selftestNote"]
      : ["howtoTitle", "howtoLede", "howtoS1", "howtoS1why", "howtoS2", "howtoS2why", "howtoS3", "howtoS3why", "howtoSelftest", "howtoSelftestNote"];
    for (const k of howtoKeys) {
      assert(k in dict.en, `词表缺 "${k}"`);
    }
    // 每一条都必须三语齐全且非空(键集合一致由上面那条测试保证,这里盯"空字符串占位")。
    for (const loc of locales) {
      for (const k of [...chipKeys, ...watchKeys, ...howtoKeys]) {
        assert((dict[loc][k] || "").trim().length > 0, `${loc} 的 "${k}" 是空的`);
      }
    }
  });

  test(`${shell.dir}:「怎么用」第三步引用的按钮名,必须是这个壳子真有的按钮名`, () => {
    // 真跑起来才发现的漂移:Windows 那一步写着点「拒绝并暂停」,而按钮实际叫「先不要」——
    // 使用说明指了一个不存在的按钮。两个壳子的确认层按钮名也不一样(macOS 的是
    // 「先不要,暂停任务」),所以这条不能写死字面量,得从**同一份词表**里取按钮名再回头
    // 在第三步的文案里找。一边改按钮名不改文案,这里当场红。
    const dotted = "howto.s3why" in dict.en;
    const s3 = dotted ? "howto.s3why" : "howtoS3why";
    const denyKey = dotted ? "confirm.deny" : "deny";
    const allowKey = dotted ? "confirm.approve" : "approve";
    for (const loc of locales) {
      const text = dict[loc][s3];
      const deny = dict[loc][denyKey];
      const allow = dict[loc][allowKey];
      assert(!!text && !!deny && !!allow, `${loc} 缺 ${s3} / ${denyKey} / ${allowKey}`);
      assert(
        text.includes(deny),
        `${loc} 的第三步说明没有逐字引用「先不要」那个按钮的真实名字 "${deny}" —— 文案与按钮漂了`,
      );
      assert(
        text.includes(allow),
        `${loc} 的第三步说明没有逐字引用「允许这一次」那个按钮的真实名字 "${allow}"`,
      );
    }
  });

  test(`${shell.dir}:界面文案不来自后端拼好的字符串(mode 句子要在词表里)`, () => {
    // 真跑起来才看到的:Windows 壳子把 Rust 侧 `protection_coverage()` 拼好的**中文**句子
    // (`st.protection_summary`)直接渲染,界面切成英文那行还是中文。后端不知道界面语言,
    // 所以给用户看的措辞不能由后端拼 —— macOS 壳子一直按 coverage.* 词条渲染,Windows 是例外。
    // 这条盯两件事:main.js 不再渲染 protection_summary;四个 mode 的词条三语齐全。
    // 先去掉注释再匹配:上面那段注释本身就提到了这个字段名。仓库里已经栽过同一个坑
    // (`ci覆盖make_check的每个target` 的注释里写着"注释含 make X 蒙过测试")。
    const code = mainSrc
      .split("\n")
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .map((l) => l.replace(/\/\/.*$/, ""))
      .join("\n");
    assert(
      !/protection_summary/.test(code),
      "main.js 又在渲染后端拼好的 protection_summary —— 那串文字不跟界面语言走",
    );
    if (!dotted_modes(dict)) return; // macOS 用 coverage.* 那套,下面的键名只适用于 Windows
    for (const key of ["modeSim", "modeIdle", "modeDegraded", "modePartial", "modePartialOcrOn", "modePartialOcrOff"]) {
      for (const loc of locales) {
        assert((dict[loc][key] || "").trim().length > 0, `${loc} 缺 "${key}"`);
      }
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

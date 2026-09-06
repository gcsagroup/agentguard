/* 改版界面真实渲染与交互测试。后端使用明确的桩，不作为 TCC 或网关真实接入证明。 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { join, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const UI = join(ROOT, "apps/desktop-macos/src");
const OUT = process.env.AGENTGUARD_UI_TEST_OUTPUT || join(HERE, "out/workspace");
mkdirSync(OUT, { recursive: true });
const require = createRequire(import.meta.url);
const { chromium } = require(join(execSync("npm root -g", { encoding: "utf8" }).trim(), "playwright"));
const legacy = readFileSync(join(HERE, "shell-a11y.mjs"), "utf8");
const stub = legacy.match(/const TAURI_STUB = `([\s\S]*?)`;\n/)[1];
const server = createServer((req, res) => {
  const relative = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  const path = resolve(UI, `.${relative === "/" ? "/index.html" : relative}`);
  if (!path.startsWith(UI + "/")) { res.writeHead(403); res.end(); return; }
  try {
    res.setHeader("Content-Type", ({ ".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".png": "image/png" })[extname(path)] || "application/octet-stream");
    res.end(readFileSync(path));
  } catch { res.writeHead(404); res.end(); }
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const browser = await chromium.launch();
let checks = 0;
const check = (label, value) => { assert.ok(value, label); checks++; console.log(`通过：${label}`); };
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: "zh-CN" });
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.addInitScript(stub);
  await page.addInitScript(() => {
    localStorage.setItem("agentguard.appearance", "light");
    window.__agTest.patchStatus({ protection_state: "permission_required", session_active: false, accessibility: false, screen_capture: false, build_profile: "ui-acceptance", build_version: "1.0.0", build_time: "1", audit_data_path: "/Users/PRIVATE/fixture.db" });
    window.__agTest.patchTcc({ accessibility: false, screen_capture: false });
    const original = window.__TAURI__.core.invoke;
    window.__gatewayCalls = [];
    window.__confirmView = { connection_id: "connection-one", port: 8790, instance_id: "b".repeat(32), pending: null, remaining_ms: 0 };
    window.__TAURI__.core.invoke = async (cmd, args) => {
      if (cmd.endsWith("_gateway_confirmation")) {
        window.__gatewayCalls.push({ cmd, args: { ...args, token: undefined } });
        if (cmd === "disconnect_gateway_confirmation") return;
        if (cmd === "answer_gateway_confirmation") {
          if (window.__confirmAnswerFail) throw new Error("GATEWAY_IO");
          window.__confirmView.pending = null;
          return;
        }
        if (window.__confirmFail) throw new Error("GATEWAY_AUTH");
        return { ...window.__confirmView, remaining_ms: window.__confirmDeadline ? Math.max(0, window.__confirmDeadline - performance.now()) : 0 };
      }
      if (cmd === "get_status" && window.__statusFail) throw new Error("测试连接断开");
      if (cmd === "list_audit" && window.__auditFail) throw new Error("测试记录不可读");
      if (cmd === "list_audit" && window.__privateAudit) return [{ action: "Block", rule_id: "CRIT-001", source_app: "app:sha256:5f0330392292a13a29ae269a1efe6f7c", human_message: "rule=CRIT-001 action=Block severity=Critical detail_omitted=true" }];
      if (cmd === "get_installation_info") return { app_name: "AgentGuard-UI-Test.app", app_path: "/Applications/AgentGuard-UI-Test.app" };
      if (cmd === "check_gateway_setup") {
        if (window.__gatewayFail) throw new Error("测试失败");
        return { tools: ["read_file", "<img src=x onerror=alert(1)>"], config: { mcpServers: { agentguard: { command: "/Applications/Test App/gateway", args: [] } } } };
      }
      return original(cmd, args);
    };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForFunction(() => document.getElementById("current-app-name").textContent.includes("UI-Test"));
  check("初始化没有脚本异常", errors.length === 0);
  check("未授权时禁止开始桌面观察", await page.isDisabled("#btn-start"));
  check("总览不泄漏内部数据路径", !(await page.locator('[data-page="overview"]').innerText()).includes("/Users/PRIVATE"));
  const go = (route) => page.click(`.sidebar [data-route="${route}"]`);
  for (const route of ["overview", "active", "activity", "settings", "help"]) {
    await go(route);
    check(`${route} 只有一个页面可见`, await page.locator("[data-page]:visible").count() === 1);
    check(`${route} 导航焦点到达页面标题`, await page.evaluate((name) => document.activeElement.id === `${name}-title`, route));
    await page.screenshot({ path: join(OUT, `${route}-zh.png`), fullPage: true });
  }
  await go("activity");
  await page.selectOption("#activity-source", "Safari");
  check("活动来源筛选只保留选中来源", await page.locator("#timeline .item").count() === 1 && (await page.locator("#timeline").innerText()).includes("Safari") && !(await page.locator("#timeline").innerText()).includes("Claude"));
  await page.selectOption("#activity-source", "");
  check("恢复全部来源保留原记录", await page.locator("#timeline .item").count() === 2);
  await page.evaluate(() => { window.__auditFail = true; });
  await page.click("#btn-refresh");
  check("读取失败不伪装成没有历史记录", (await page.locator("#timeline").innerText()).includes("不代表没有历史记录"));
  await page.evaluate(() => { window.__auditFail = false; });
  await page.click("#btn-refresh");
  await page.evaluate(() => { window.__privateAudit = true; });
  await page.click("#btn-refresh");
  const privateText = await page.locator("#timeline").innerText();
  check("真实加密摘要显示人话并折叠内部字段", privateText.includes("仅保留风险摘要") && privateText.includes("匿名来源") && !/detail_omitted|app:sha256/.test(privateText));
  check("技术详情保留原始记录供诊断", (await page.locator("#timeline details pre").textContent()).includes("detail_omitted=true"));
  await page.evaluate(() => { window.__privateAudit = false; });
  await page.click("#btn-refresh");
  await go("settings");
  for (const tab of ["observation", "risk", "privacy", "general"]) {
    await page.click(`#tab-${tab}`);
    check(`${tab} 标签正确显示`, await page.locator(`#settings-${tab}`).isVisible());
  }
  await page.focus("#tab-general");
  await page.keyboard.press("Home");
  check("标签键盘 Home 切回第一个", await page.evaluate(() => document.activeElement.id === "tab-observation"));
  await page.click("#btn-tcc");
  check("重新检测给出可见反馈", /仍未检测到/.test(await page.locator("#permission-feedback").innerText()));
  await page.evaluate(() => { window.__agTest.patchStatus({ accessibility: true, screen_capture: false }); window.__agTest.patchTcc({ accessibility: true, screen_capture: false }); });
  await page.click("#btn-refresh");
  check("只有必需权限即可准备开始，不强制可选录屏", await page.isEnabled("#btn-start"));
  await page.evaluate(() => {
    window.__agTest.patchStatus({ accessibility: false });
    window.__agTest.patchTcc({ accessibility: false });
    window.dispatchEvent(new Event("focus"));
  });
  await page.waitForFunction(() => document.getElementById("btn-start").disabled);
  check("返回前台自动核对撤回权限并禁用启动", await page.isDisabled("#btn-start"));
  await page.evaluate(() => { window.__statusFail = true; window.dispatchEvent(new Event("focus")); });
  await page.waitForFunction(() => document.getElementById("workspace-feedback").textContent.includes("无法获取"));
  check("连接失败不保留守护中状态", /尚未就绪/.test(await page.locator("#status-pill").innerText()) && /无法获取/.test(await page.locator("#overview-summary").innerText()));
  await page.evaluate(() => { window.__statusFail = false; });
  await page.click("#btn-refresh");
  await page.waitForFunction(() => document.getElementById("workspace-feedback").hidden);
  check("状态恢复后清除过期故障提示", await page.locator("#workspace-feedback").isHidden());
  await page.selectOption("#task-profile", "book_hotel");
  check("任务选择只保存下次设置，不调用开始会话", await page.evaluate(() => localStorage.getItem("agentguard.nextTask") === "book_hotel" && !window.__agTest.calls.some((call) => call.cmd === "start_guard_session")));
  await page.click("#tab-general");
  await page.selectOption("#appearance", "dark");
  check("外观切换实际作用于页面并保存", await page.evaluate(() => document.documentElement.dataset.theme === "dark" && localStorage.getItem("agentguard.appearance") === "dark"));
  await page.selectOption("#appearance", "light");
  for (const locale of ["en", "zh-Hant", "zh-Hans"]) {
    await page.selectOption("#locale-select", locale);
    check(`${locale} 新旧词条一起更新`, !(await page.locator('[data-page="settings"]').innerText()).includes("settingsLead"));
    await page.screenshot({ path: join(OUT, `general-${locale}.png`), fullPage: true });
  }
  await go("active");
  await page.click('[data-page="active"] [data-open-guide="gateway"]');
  check("接入向导在当前页展开，焦点到达标题", await page.evaluate(() => !document.getElementById("setup-dialog").hidden && document.activeElement.id === "setup-title"));
  await page.click("#gateway-check");
  await page.waitForFunction(() => !document.getElementById("gateway-copy").disabled);
  check("程序检查不伪装客户端接入成功", /尚未验证客户端/.test(await page.locator("#setup-feedback").innerText()));
  check("网关输出中的标签只作文本显示", await page.locator("#gateway-result img").count() === 0);
  check("配置路径保留空格而非拼接 shell", JSON.parse(await page.locator("#gateway-config").inputValue()).mcpServers.agentguard.command.includes("Test App"));
  await page.screenshot({ path: join(OUT, "gateway-setup.png") });
  await page.evaluate(() => { window.__gatewayFail = true; });
  await page.click("#gateway-check");
  await page.waitForFunction(() => !document.getElementById("gateway-check").disabled);
  check("检查失败清除旧配置并禁止复制", await page.isDisabled("#gateway-copy") && (await page.locator("#gateway-config").inputValue()) === "");
  await page.keyboard.press("Escape");
  check("Escape 关闭接入向导", await page.evaluate(() => document.getElementById("setup-dialog").hidden));
  await page.click('[data-page="active"] [data-open-guide="browser"]');
  await page.click('[data-setup-action="extension"]');
  check("安装按钮连接固定后端资源入口", await page.evaluate(() => window.__agTest.calls.some((call) => call.cmd === "open_setup_resource" && call.args.which === "extension")));
  await page.screenshot({ path: join(OUT, "browser-setup.png") });
  await page.keyboard.press("Escape");
  await page.fill("#gateway-token", "a".repeat(32));
  await page.click("#gateway-connect");
  await page.waitForFunction(() => document.getElementById("gateway-connect-form").hidden);
  check("确认通道连接不冒充客户端接入", /暂无待确认请求/.test(await page.locator("#gateway-connection-status").innerText()) && /客户端接入尚未验证/.test(await page.locator('[data-page="active"]').innerText()));
  check("提交后令牌清空且不写本机设置", await page.evaluate(() => document.getElementById("gateway-token").value === "" && !JSON.stringify(localStorage).includes("a".repeat(32))));
  await page.evaluate(() => {
    window.__confirmView.pending = { id: "confirm-1", what: '<img src=x onerror="window.__injected=true"> 写入测试文件', findings: [{ rule_id: "SHELL-ASK", severity: "medium", message: "<script>外部说明</script>" }] };
    window.__confirmDeadline = performance.now() + 10000;
  });
  await page.waitForSelector("#gateway-pending", { state: "visible" });
  check("外部操作只作文本，默认禁止批准", await page.locator("#gateway-request-what img").count() === 0 && await page.isDisabled("#gateway-approve") && !await page.isDisabled("#gateway-deny"));
  await page.check("#gateway-reviewed");
  check("核对后仅解锁当前批准", !await page.isDisabled("#gateway-approve"));
  await page.evaluate(() => { window.__confirmView.pending = { ...window.__confirmView.pending, id: "confirm-2", what: "另一份测试文件" }; });
  await page.waitForFunction(() => document.getElementById("gateway-request-id").textContent === "confirm-2");
  check("新请求不能继承旧勾选", !await page.isChecked("#gateway-reviewed") && await page.isDisabled("#gateway-approve"));
  await page.click("#gateway-deny");
  await page.waitForFunction(() => document.getElementById("gateway-pending").hidden);
  check("拒绝绑定当前连接和编号", await page.evaluate(() => window.__gatewayCalls.some(c => c.cmd === "answer_gateway_confirmation" && c.args.connectionId === "connection-one" && c.args.requestId === "confirm-2" && c.args.approve === false)));
  await page.evaluate(() => {
    window.__confirmView.pending = { id: "confirm-3", what: "批准测试", findings: [] };
    window.__confirmDeadline = performance.now() + 10000;
  });
  await page.waitForSelector("#gateway-pending", { state: "visible" });
  check("新请求清除上一条处置回执", await page.locator("#gateway-answer-feedback").innerText() === "");
  await page.check("#gateway-reviewed");
  await page.click("#gateway-approve");
  await page.waitForFunction(() => document.getElementById("gateway-pending").hidden);
  check("批准只确认回执，不伪称执行成功", /执行结果请在/.test(await page.locator("#gateway-answer-feedback").innerText()));
  await page.evaluate(() => {
    window.__confirmView.pending = { id: "confirm-4", what: "即将过期", findings: [] };
    window.__confirmDeadline = performance.now() + 1300;
  });
  await page.waitForFunction(() => document.getElementById("gateway-request-id").textContent === "confirm-4");
  await page.waitForFunction(() => document.getElementById("gateway-countdown").textContent.includes("已过期"));
  check("过期请求的两种回答都禁用", await page.isDisabled("#gateway-approve") && await page.isDisabled("#gateway-deny"));
  await page.evaluate(() => {
    window.__confirmView.pending = { id: "confirm-5", what: "回执故障测试", findings: [] };
    window.__confirmDeadline = performance.now() + 10000;
    window.__confirmAnswerFail = true;
  });
  await page.waitForFunction(() => document.getElementById("gateway-request-id").textContent === "confirm-5");
  await page.check("#gateway-reviewed");
  await page.click("#gateway-approve");
  await page.waitForFunction(() => !document.getElementById("gateway-connect-form").hidden);
  check("回执不明断连且不自动重试", /结果未知/.test(await page.locator("#gateway-answer-feedback").innerText()) && await page.evaluate(() => window.__gatewayCalls.filter(c => c.cmd === "answer_gateway_confirmation" && c.args.requestId === "confirm-5").length === 1));
  await page.evaluate(() => { window.__confirmFail = true; });
  await page.fill("#gateway-token", "a".repeat(32));
  await page.click("#gateway-connect");
  await page.waitForFunction(() => document.getElementById("gateway-connection-status").textContent.includes("连接失败"));
  check("错误令牌失败后无旧请求或凭据残留", await page.isHidden("#gateway-pending") && await page.inputValue("#gateway-token") === "");
  for (const width of [1180, 860, 680]) {
    await page.setViewportSize({ width, height: 820 });
    for (const route of ["overview", "active", "settings"]) {
      await go(route);
      check(`${width}px ${route} 不横向溢出`, await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    }
    await page.screenshot({ path: join(OUT, `settings-${width}.png`), fullPage: true });
  }
  check("全部交互无页面异常", errors.length === 0);
  const html = readFileSync(join(UI, "index.html"), "utf8");
  const dict = readFileSync(join(UI, "workspace-i18n.js"), "utf8");
  const { workspaceMessages } = await import(join(UI, "workspace-i18n.js"));
  for (const [key, values] of Object.entries(workspaceMessages)) assert.ok(values.length === 3 && values.every((text) => typeof text === "string" && text.trim()), key);
  for (const [, key] of html.matchAll(/data-ui(?:-aria)?="([^"]+)"/g)) assert.ok(key in workspaceMessages, key);
  check("所有新词条三语齐全且没有引用遗漏", dict.length > 1000);
  console.log(`改版界面 ${checks} 项检查通过；截图：${OUT}`);
} finally { await browser.close(); await new Promise((done) => server.close(done)); }

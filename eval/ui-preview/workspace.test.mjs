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
    window.__localCalls = [];
    window.__localView = null;
    window.__gatewayCalls = [];
    window.__boundRequest = (request) => ({ ...request, action_sha256: "f".repeat(64), action: {
      session_id: "fixture-session", target: "/workspace/fixture.txt", tool_service: "gateway", tool_name: "write_file",
      tool_version: "fixture-2", policy_version: "fixture-policy", parameters: { path: "/workspace/fixture.txt", contents: "完整写入正文 <script>仅文字</script>" }, expires_at_ms: Date.now() + 10000,
    } });
    window.__confirmView = { connection_id: "connection-one", port: 8790, instance_id: "b".repeat(32), pending: null, remaining_ms: 0 };
    window.__workspaceState = { service:"agentguard-mcp",workspace_protocol:1,instance_id:"b".repeat(32),session_id:"session-initial",task_profile:"fixture",session_state:"active",busy:false,last_client_message_ms:0,
      workspaces:[{workspace_id:"workspace-0",target:"/fixture/original",snapshot:"/fixture/snapshot",writable:true,writeback_available:true,writeback_reason:null}],pending_review:null,last_result:null };
    window.__workspaceReview = {session_id:"session-initial",workspace_id:"workspace-0",review_id:"review-one",review_sha256:"c".repeat(64),expires_at_ms:Date.now()+60000,
      preview:{digest:"d".repeat(64),workspace_root:"/fixture/original",recovery_directory:"/fixture/recovery",atomic:false,total_body_bytes:40,limitations:["多文件回写不是原子事务"],changes:[
        {path:"report.txt",kind:"modify",before:{sha256:"e".repeat(64),bytes:10,mode:420,text:"旧内容"},after:{sha256:"f".repeat(64),bytes:20,mode:420,text:"新完整正文 <script>只作文字</script>"}},
        {path:"binary.dat",kind:"create",before:null,after:{sha256:"a".repeat(64),bytes:10,mode:384,text:null}}
      ]}};
    window.__TAURI__.core.invoke = async (cmd, args) => {
      if (cmd.includes("local_agent")) {
        window.__localCalls.push({ cmd, args });
        if (cmd === "check_local_agent_browser") { if(window.__browserMissing) throw new Error("BROWSER_DEPENDENCIES_MISSING"); return {available:true,scope:"exact_loopback_http"}; }
        if (cmd === "pick_local_agent_workspace") return window.__localPickCancelled ? null : "/fixture/local-project";
        if (cmd === "list_local_agent_models") {
          if (window.__localModelsDelay) await new Promise(resolve => setTimeout(resolve, window.__localModelsDelay));
          if (window.__localModelsError) throw new Error("本机模型服务未启动");
          return { models: window.__localModelsEmpty ? [] : ["fixture-local-model", "<script>仅模型名</script>"] };
        }
        if (cmd === "poll_local_agent") {
          const snapshot = structuredClone(window.__localView);
          if (window.__localPollDelay) await new Promise(resolve => setTimeout(resolve, window.__localPollDelay));
          return snapshot;
        }
        if (cmd === "start_local_agent") {
          if (window.__localStartError) throw new Error("项目目录不可用");
          window.__localView = {run_id:"local-run-one",phase:"starting",workspace:args.workspace,write_enabled:args.writeEnabled,browser_origins:args.browserOrigins,model_data_authorized:args.modelDataAuthorized,model_port:args.port,model:args.model,session_id:"local-session",answer:"",error:null,steps:[],connection:null};
          return structuredClone(window.__localView);
        }
        if (cmd === "continue_local_agent") {
          if (window.__localContinueDelay) await new Promise(resolve => setTimeout(resolve, window.__localContinueDelay));
          window.__localView.phase = "running";
          window.__localView.answer = "";
          return structuredClone(window.__localView);
        }
        if (cmd === "control_local_agent") {
          window.__localView.phase = {pause:"paused",resume:"ready",stop:"stopped"}[args.action];
          window.__workspaceState.session_state = {pause:"paused",resume:"active",stop:"stopped"}[args.action];
          window.__workspaceState.pending_review = null;
          if (args.action === "resume") { window.__localView.session_id = "local-session-resumed"; window.__workspaceState.session_id = "local-session-resumed"; }
          if (args.action === "stop") window.__localView.connection = null;
          return structuredClone(window.__localView);
        }
      }
      if (cmd === "pick_gateway_control_file") return "/fixture/private/control.json";
      if (cmd.endsWith("_gateway_workspace")) {
        window.__gatewayCalls.push({ cmd, args });
        if (cmd === "poll_gateway_workspace") return structuredClone(window.__workspaceState);
        if (cmd === "preview_gateway_workspace") {
          if (window.__workspacePreviewError) throw new Error(window.__workspacePreviewError);
          const view = structuredClone(window.__workspaceReview);
          view.session_id = window.__workspaceState.session_id;
          view.expires_at_ms = Date.now() + 60000;
          window.__workspaceState.pending_review = { workspace_id: view.workspace_id, review_id: view.review_id, review_sha256: view.review_sha256, expires_at_ms: view.expires_at_ms };
          return view;
        }
        if (cmd === "discard_gateway_workspace") {
          window.__workspaceState.pending_review = null;
          return structuredClone(window.__workspaceState);
        }
        if (cmd === "apply_gateway_workspace") {
          window.__workspaceState.pending_review = null;
          if (window.__workspaceApplyError) throw new Error(window.__workspaceApplyError);
          window.__workspaceState.last_result = { outcome: "partial", detail: "两项文件结果需分别核对", recovery_directory: "/fixture/recovery", files: [
            {path:"report.txt",state:"applied",detail:"已回写",recovery_file:"/fixture/recovery/report.txt"},
            {path:"binary.dat",state:"conflict",detail:"原目录已由外部修改",recovery_file:null}
          ] };
          return structuredClone(window.__workspaceState.last_result);
        }
        if (cmd === "control_gateway_workspace") {
          window.__workspaceState.pending_review = null;
          window.__workspaceState.session_state = {pause:"paused",resume:"active",stop:"stopped"}[args.action];
          if (args.action === "resume") window.__workspaceState.session_id = "session-resumed";
          return structuredClone(window.__workspaceState);
        }
      }
      if (cmd.endsWith("_gateway_confirmation")) {
        window.__gatewayCalls.push({ cmd, args: { ...args, token: undefined } });
        if (cmd === "disconnect_gateway_confirmation") {
          if (window.__localView?.connection?.connection_id === args.connectionId) { window.__localView.phase = "stopped"; window.__localView.connection = null; }
          return;
        }
        if (cmd === "import_gateway_confirmation") {
          if (window.__importError) throw new Error(window.__importError);
          window.__confirmView.supports_workspace = true;
        }
        if (cmd === "connect_gateway_confirmation") window.__confirmView.supports_workspace = false;
        if (cmd === "answer_gateway_confirmation") {
          if (window.__confirmAnswerFail) throw new Error("GATEWAY_IO");
          window.__confirmView.pending = null;
          return;
        }
        if (window.__confirmTooLarge) throw new Error("GATEWAY_TOO_LARGE");
        if (window.__confirmFail) throw new Error("GATEWAY_AUTH");
        return { ...window.__confirmView, remaining_ms: window.__confirmDeadline ? Math.max(0, window.__confirmDeadline - performance.now()) : 0 };
      }
      if (cmd === "prepare_codex_setup") {
        if (window.__codexDelay) await new Promise(resolve => setTimeout(resolve, 400));
        if (window.__codexFail) throw new Error("工作区不存在或无法访问");
        window.__codexArgs = args;
        return { workspace: args.workspace, write_enabled: args.writeEnabled, command: "codex exec '测试命令'", plan_path: "/fixture/private/plans.json" };
      }
      if (cmd === "get_status" && window.__statusFail) throw new Error("测试连接断开");
      if (cmd === "list_audit" && window.__auditFail) throw new Error("测试记录不可读");
      if (cmd === "list_audit" && window.__timelineFixture) return window.__timelineFixture;
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
  await page.evaluate(() => { window.__timelineFixture = [
    { timestamp_ms: 1789507307792, action: "Block", rule_id: "CRIT-005", source_app: "Safari", human_message: "rule=CRIT-005 action=Block severity=Critical detail_omitted=true" },
    { timestamp_ms: 1789507307082, action: "Alert", rule_id: "OVL-007", source_app: "ScreenCapture", human_message: "rule=OVL-007 action=Alert severity=Medium detail_omitted=true" },
    { timestamp_ms: null, action: "LogOnly", rule_id: "OLD", source_app: "Legacy", human_message: "旧记录缺少时间" },
  ]; });
  await page.click("#btn-refresh");
  await page.waitForFunction(() => document.querySelectorAll("#timeline time").length === 3);
  check("时间线使用记录发生时间并保留可核对的 UTC 值", await page.locator("#timeline time").first().getAttribute("datetime") === "2026-09-15T21:21:47.792Z" && /2026/.test(await page.locator("#timeline time").first().innerText()));
  check("缺少时间不伪造为当前时间", !await page.locator("#timeline time").last().getAttribute("datetime") && /时间未知/.test(await page.locator("#timeline time").last().innerText()));
  check("安装文字和低对比线索显示证据边界", /不证明实际发起了安装/.test(await page.locator("#timeline").innerText()) && /不能据此确认隐藏文字或攻击/.test(await page.locator("#timeline").innerText()));
  await page.setViewportSize({ width: 720, height: 900 });
  check("窄窗口时间线无横向溢出", await page.evaluate(() => document.getElementById("timeline").scrollWidth <= document.getElementById("timeline").clientWidth));
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.evaluate(() => { window.__timelineFixture = null; });
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
  check("可选录屏未开启时保留权限帮助", (await page.locator("#permission-card-title").textContent()).includes("授权后仍没生效"));
  await page.evaluate(() => {
    window.__agTest.patchStatus({ screen_capture: true, sck_streaming: false, sck_message: "ScreenCaptureKit stream started" });
    window.__agTest.patchTcc({ screen_capture: true });
  });
  await page.click("#btn-refresh");
  check("两项权限就绪后不再展示授权失败标题", (await page.locator("#permission-card-title").textContent()) === "权限已就绪" && (await page.locator("#permission-card-hint").textContent()).includes("均已检测到"));
  check("采集停止后将旧启动消息标为历史结果", (await page.locator("#caps").textContent()).includes("SCK=idle · 上次采集结果：ScreenCaptureKit stream started"));
  await page.evaluate(() => window.__agTest.patchStatus({ sck_message: "native stop failed: synthetic" }));
  await page.click("#btn-refresh");
  check("采集空闲时仍保留原始失败信息", (await page.locator("#caps").textContent()).includes("native stop failed: synthetic"));
  await page.evaluate(() => {
    window.__agTest.patchStatus({ accessibility: false });
    window.__agTest.patchTcc({ accessibility: false });
    window.dispatchEvent(new Event("focus"));
  });
  await page.waitForFunction(() => document.getElementById("btn-start").disabled);
  check("返回前台自动核对撤回权限并禁用启动", await page.isDisabled("#btn-start"));
  check("撤回辅助功能后恢复权限帮助", (await page.locator("#permission-card-title").textContent()).includes("授权后仍没生效"));
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
  await page.locator('#gateway-guide > details > summary').click();
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
  await page.fill("#codex-workspace", "/fixture/project");
  await page.fill("#codex-task", "读取 README");
  check("默认只读明确拒绝命令执行", await page.inputValue("#codex-mode") === "read" && (await page.locator("#codex-scope").innerText()).includes("命令执行"));
  await page.click("#codex-generate");
  await page.waitForSelector("#codex-output", { state: "visible" });
  check("生成命令绑定输入范围且不冒充启动", await page.evaluate(() => window.__codexArgs.workspace === "/fixture/project" && !window.__codexArgs.writeEnabled) && (await page.locator("#codex-feedback").innerText()).includes("尚未启动"));
  await page.selectOption("#codex-mode", "write");
  check("修改权限立即清除旧命令", await page.isHidden("#codex-output") && await page.inputValue("#codex-command") === "");
  await page.click("#codex-generate");
  await page.waitForSelector("#codex-output", { state: "visible" });
  check("读写模式准确送达后端", await page.evaluate(() => window.__codexArgs.writeEnabled));
  await page.screenshot({ path: join(OUT, "codex-setup.png"), fullPage: true });
  await page.evaluate(() => { window.__codexDelay = true; });
  await page.click("#codex-generate");
  await page.fill("#codex-workspace", "/fixture/changed");
  await page.waitForFunction(() => !document.getElementById("codex-generate").disabled);
  check("在途旧结果不能覆盖新工作区", await page.isHidden("#codex-output"));
  await page.evaluate(() => { window.__codexFail = true; });
  await page.click("#codex-generate");
  await page.waitForFunction(() => !document.getElementById("codex-generate").disabled);
  check("无效目录显示错误且不提供命令", await page.isHidden("#codex-output") && (await page.locator("#codex-feedback").innerText()).includes("工作区不存在"));
  await page.evaluate(() => { window.__codexFail = false; window.__codexDelay = false; });
  await page.click("#codex-generate");
  await page.waitForSelector("#codex-output", { state: "visible" });
  await page.click("#codex-confirm-link");
  check("确认通道入口移动到真实连接表单", await page.evaluate(() => document.activeElement.id === "gateway-control-path" && !document.getElementById("setup-dialog").hidden));
  await page.click('[data-page="active"] [data-open-guide="gateway"]');
  await page.keyboard.press("Escape");
  check("Escape 关闭接入向导", await page.evaluate(() => document.getElementById("setup-dialog").hidden));
  await page.click('[data-page="active"] [data-open-guide="browser"]');
  await page.click('[data-setup-action="extension"]');
  check("安装按钮连接固定后端资源入口", await page.evaluate(() => window.__agTest.calls.some((call) => call.cmd === "open_setup_resource" && call.args.which === "extension")));
  await page.screenshot({ path: join(OUT, "browser-setup.png") });
  await page.keyboard.press("Escape");
  check("默认使用宿主连接文件且兼容入口折叠", await page.isVisible("#gateway-control-path") && !await page.locator("#gateway-legacy-connection").evaluate(e => e.open));
  await page.click("#gateway-pick-file");
  check("选择文件仅把路径交给表单", await page.inputValue("#gateway-control-path") === "/fixture/private/control.json");
  await page.evaluate(() => { window.__importError = "GATEWAY_FILE_PERMISSIONS"; });
  await page.click("#gateway-import");
  await page.waitForFunction(() => document.getElementById("gateway-connection-status").textContent.includes("权限"));
  check("不安全连接文件拒绝导入", !await page.isHidden("#gateway-connect-form") && await page.isHidden("#gateway-workspace"));
  await page.evaluate(() => { window.__importError = null; });
  await page.click("#gateway-import");
  await page.waitForSelector("#gateway-workspace", {state:"visible"});
  await page.waitForFunction(() => !document.getElementById("gateway-workspace-preview").disabled);
  check("导入只传路径且显示真实授权范围", await page.evaluate(() => window.__gatewayCalls.some(c => c.cmd === "import_gateway_confirmation" && c.args.path === "/fixture/private/control.json" && Object.keys(c.args).filter(k => c.args[k] !== undefined).length === 1)) && (await page.locator("#gateway-workspace-location").textContent()).includes("/fixture/original"));
  check("控制连接不冒充客户端存活", (await page.locator("#gateway-workspace-detail").textContent()).includes("不证明客户端存活"));
  await page.evaluate(() => {window.__workspacePreviewError="WORKSPACE_DENIED";});
  await page.click("#gateway-workspace-preview");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-feedback").textContent.includes("安全规则已拒绝"));
  check("预览硬拒绝明确说明原目录未改且无批准", await page.isHidden("#gateway-workspace-review") && !await page.isDisabled("#gateway-workspace-preview") && !(await page.locator("#gateway-workspace-feedback").textContent()).includes("未知"));
  await page.evaluate(() => {window.__workspacePreviewError=null;});
  await page.click("#gateway-workspace-preview");
  await page.waitForSelector("#gateway-workspace-review", {state:"visible"});
  await page.waitForFunction(() => !document.getElementById("gateway-workspace-reviewed").disabled);
  check("预览默认禁回写并显示原件恢复目录", await page.isDisabled("#gateway-workspace-apply") && (await page.locator("#gateway-workspace-review-detail").textContent()).includes("/fixture/recovery"));
  await page.locator("#gateway-workspace-changes details").evaluateAll(nodes => nodes.forEach(node => {node.open = true;}));
  check("前后全文以文字显示且二进制明确边界", (await page.locator("#gateway-workspace-changes").textContent()).includes("新完整正文 <script>只作文字</script>") && await page.locator("#gateway-workspace-changes script").count() === 0 && (await page.locator("#gateway-workspace-changes").textContent()).includes("仅展示大小与摘要"));
  await page.screenshot({path:join(OUT,"workspace-full-preview.png"),fullPage:true});
  await page.check("#gateway-workspace-reviewed");
  await page.evaluate(() => {window.__workspaceState.pending_review.review_sha256 = "9".repeat(64);});
  await page.waitForSelector("#gateway-workspace-review", {state:"hidden"});
  check("摘要变化撤销旧预览和勾选", !await page.isChecked("#gateway-workspace-reviewed") && await page.isDisabled("#gateway-workspace-apply"));
  await page.click("#gateway-workspace-preview");
  await page.waitForFunction(() => !document.getElementById("gateway-workspace-reviewed").disabled);
  await page.click("#gateway-workspace-discard");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-feedback").textContent.includes("已放弃本次差异"));
  check("放弃差异不暂停任务且不请求回写", await page.isHidden("#gateway-workspace-review") && !await page.isDisabled("#gateway-workspace-preview") && await page.evaluate(() => !window.__gatewayCalls.some(c=>c.cmd==="apply_gateway_workspace") && window.__workspaceState.session_state==="active"));
  await page.click("#gateway-workspace-preview");
  await page.waitForFunction(() => !document.getElementById("gateway-workspace-reviewed").disabled);
  await page.check("#gateway-workspace-reviewed");
  await page.click("#gateway-workspace-apply");
  await page.waitForSelector("#gateway-workspace-result", {state:"visible"});
  check("部分回写展示每文件冲突和恢复位置", (await page.locator("#gateway-workspace-result").textContent()).includes("部分应用") && (await page.locator("#gateway-workspace-result-files").textContent()).includes("原目录已由外部修改") && (await page.locator("#gateway-workspace-result-recovery").textContent()).includes("/fixture/recovery"));
  check("回写请求只带连接及预览编号摘要", await page.evaluate(() => {const call=window.__gatewayCalls.find(c=>c.cmd==="apply_gateway_workspace");return Object.keys(call.args).sort().join(",")==="connectionId,reviewId,reviewSha256";}));
  await page.click("#gateway-workspace-pause");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-state").textContent.includes("已暂停"));
  check("暂停禁止回写但可恢复", await page.isDisabled("#gateway-workspace-preview") && !await page.isDisabled("#gateway-workspace-resume"));
  await page.click("#gateway-workspace-resume");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-detail").textContent.includes("session-resumed"));
  check("恢复显示新会话并明确客户端需新标识", (await page.locator("#gateway-workspace").textContent()).includes("客户端需使用新的会话标识继续") && await page.isHidden("#gateway-workspace-review"));
  await page.click("#gateway-workspace-preview");
  await page.waitForFunction(() => !document.getElementById("gateway-workspace-reviewed").disabled);
  await page.check("#gateway-workspace-reviewed");
  await page.evaluate(() => {window.__workspaceApplyError="WORKSPACE_DENIED";});
  await page.click("#gateway-workspace-apply");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-feedback").textContent.includes("安全规则已拒绝"));
  const countDenied = await page.evaluate(() => window.__gatewayCalls.filter(c=>c.cmd==="apply_gateway_workspace").length);
  await page.click("#gateway-workspace-refresh");
  check("回写硬拒绝消费批准不自动重发且允许修正后新预览", await page.isHidden("#gateway-workspace-review") && !await page.isDisabled("#gateway-workspace-preview") && await page.evaluate(n => window.__gatewayCalls.filter(c=>c.cmd==="apply_gateway_workspace").length===n,countDenied) && !(await page.locator("#gateway-workspace-feedback").textContent()).includes("未知"));
  await page.evaluate(() => {window.__workspaceApplyError=null;});
  await page.click("#gateway-workspace-preview");
  await page.waitForFunction(() => !document.getElementById("gateway-workspace-reviewed").disabled);
  await page.check("#gateway-workspace-reviewed");
  await page.evaluate(() => {window.__workspaceApplyError="WORKSPACE_REPLY_UNKNOWN";});
  await page.click("#gateway-workspace-apply");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-feedback").textContent.includes("禁止重复提交"));
  const countUnknown = await page.evaluate(() => window.__gatewayCalls.filter(c=>c.cmd==="apply_gateway_workspace").length);
  await page.click("#gateway-workspace-refresh");
  check("未知回执仅刷新不重试且禁止新回写", await page.isDisabled("#gateway-workspace-preview") && await page.evaluate(n => window.__gatewayCalls.filter(c=>c.cmd==="apply_gateway_workspace").length===n,countUnknown));
  await page.click("#gateway-workspace-stop");
  await page.waitForFunction(() => document.getElementById("gateway-workspace-state").textContent.includes("永久停止"));
  check("永久停止与断开分离且不可恢复", await page.isDisabled("#gateway-workspace-resume") && await page.isVisible("#gateway-disconnect"));
  await page.click("#gateway-disconnect");
  await page.locator("#gateway-legacy-connection summary").click();
  await page.fill("#gateway-token", "a".repeat(32));
  await page.click("#gateway-connect");
  await page.waitForFunction(() => document.getElementById("gateway-connect-form").hidden);
  check("确认通道连接不冒充客户端接入", /暂无待确认请求/.test(await page.locator("#gateway-connection-status").innerText()) && /客户端接入尚未验证/.test(await page.locator('[data-page="active"]').innerText()));
  check("提交后令牌清空且不写本机设置", await page.evaluate(() => document.getElementById("gateway-token").value === "" && !JSON.stringify(localStorage).includes("a".repeat(32))));
  await page.evaluate(() => {
    window.__confirmView.pending = window.__boundRequest({ id: "confirm-1", what: '<img src=x onerror="window.__injected=true"> 写入测试文件', findings: [{ rule_id: "SHELL-ASK", severity: "medium", message: "<script>外部说明</script>" }] });
    window.__confirmDeadline = performance.now() + 10000;
  });
  await page.waitForSelector("#gateway-pending", { state: "visible" });
  check("外部操作只作文本，默认禁止批准", await page.locator("#gateway-request-what img").count() === 0 && await page.isDisabled("#gateway-approve") && !await page.isDisabled("#gateway-deny"));
  await page.check("#gateway-reviewed");
  check("核对后仅解锁当前批准", !await page.isDisabled("#gateway-approve"));
  check("确认面板展示绑定目标完整正文和摘要", (await page.locator("#gateway-request-what").textContent()).includes("完整写入正文") && (await page.locator("#gateway-request-what").textContent()).includes("f".repeat(64)) && (await page.locator("#gateway-request-what").textContent()).includes("/workspace/fixture.txt"));
  await page.screenshot({ path: join(OUT, "gateway-confirm-bound-v2.png"), fullPage: true });
  await go("settings");
  await page.selectOption("#locale-select", "en");
  await go("active");
  check("切换语言同步更新待确认动作标签", (await page.locator("#gateway-request-what").textContent()).includes("Final target") && (await page.locator("#gateway-request-what").textContent()).includes("Complete parameters"));
  await go("settings");
  await page.selectOption("#locale-select", "zh-Hans");
  await go("active");
  await page.evaluate(() => { window.__confirmView.pending = { ...window.__confirmView.pending, action_sha256: "e".repeat(64), action: { ...window.__confirmView.pending.action, target: "/workspace/changed.txt" } }; });
  await page.waitForFunction(() => document.getElementById("gateway-request-what").textContent.includes("/workspace/changed.txt"));
  check("同编号动作变化也清除旧勾选", !await page.isChecked("#gateway-reviewed") && await page.isDisabled("#gateway-approve"));
  await page.evaluate(() => { window.__confirmView.pending = { ...window.__confirmView.pending, id: "confirm-2", what: "另一份测试文件" }; });
  await page.waitForFunction(() => document.getElementById("gateway-request-id").textContent === "confirm-2");
  check("新请求不能继承旧勾选", !await page.isChecked("#gateway-reviewed") && await page.isDisabled("#gateway-approve"));
  await page.click("#gateway-deny");
  await page.waitForFunction(() => document.getElementById("gateway-pending").hidden);
  check("拒绝绑定当前连接和编号", await page.evaluate(() => window.__gatewayCalls.some(c => c.cmd === "answer_gateway_confirmation" && c.args.connectionId === "connection-one" && c.args.requestId === "confirm-2" && c.args.approve === false)));
  await page.evaluate(() => {
    window.__confirmView.pending = window.__boundRequest({ id: "confirm-3", what: "批准测试", findings: [] });
    window.__confirmDeadline = performance.now() + 10000;
  });
  await page.waitForSelector("#gateway-pending", { state: "visible" });
  check("新请求清除上一条处置回执", await page.locator("#gateway-answer-feedback").innerText() === "");
  await page.check("#gateway-reviewed");
  await page.click("#gateway-approve");
  await page.waitForFunction(() => document.getElementById("gateway-pending").hidden);
  check("批准只确认回执，不伪称执行成功", /执行结果请在/.test(await page.locator("#gateway-answer-feedback").innerText()));
  await page.evaluate(() => {
    window.__confirmView.pending = window.__boundRequest({ id: "confirm-4", what: "即将过期", findings: [] });
    window.__confirmDeadline = performance.now() + 1300;
  });
  await page.waitForFunction(() => document.getElementById("gateway-request-id").textContent === "confirm-4");
  await page.waitForFunction(() => document.getElementById("gateway-countdown").textContent.includes("已过期"));
  check("过期请求的两种回答都禁用", await page.isDisabled("#gateway-approve") && await page.isDisabled("#gateway-deny"));
  await page.evaluate(() => {
    window.__confirmView.pending = window.__boundRequest({ id: "confirm-5", what: "回执故障测试", findings: [] });
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
  await page.evaluate(() => { window.__confirmFail = false; window.__confirmTooLarge = true; });
  await page.fill("#gateway-token", "a".repeat(32));
  await page.click("#gateway-connect");
  await page.waitForFunction(() => document.getElementById("gateway-connection-status").textContent.includes("展示上限"));
  check("超大请求拒绝展示和批准且提示拆分", await page.isHidden("#gateway-pending") && await page.isDisabled("#gateway-approve") && (await page.locator("#gateway-connection-status").innerText()).includes("未批准"));
  await page.evaluate(() => {window.__confirmTooLarge=false;window.__confirmAnswerFail=false;window.__confirmView.pending=null;window.__confirmDeadline=0;});
  await go("overview");
  await page.click("[data-open-local-agent]");
  check("本地任务从总览可发现且不要求系统观察权限", await page.isVisible("#local-agent") && await page.isDisabled("#local-agent-start") && (await page.locator("#local-agent").textContent()).includes("断网 Docker"));
  check("常用启动表单不含控制文件或令牌", await page.locator("#local-agent-form input[type=password]").count()===0 && !(await page.locator("#local-agent-form").textContent()).includes("control.json"));
  await page.click("#local-agent-pick");
  await page.fill("#local-agent-task", "整理项目，写一份变更说明并验证文件结果。");
  check("真实目录选择结果进入表单且缺模型仍禁启动", await page.inputValue("#local-agent-workspace")==="/fixture/local-project" && await page.isDisabled("#local-agent-start"));
  await page.evaluate(() => {window.__localModelsError=true;});
  await page.click("#local-agent-models");
  await page.waitForFunction(() => document.getElementById("local-agent-feedback").textContent.includes("无法读取本地模型"));
  check("模型服务失败明确提示且未启动任务", await page.isDisabled("#local-agent-start") && await page.evaluate(() => !window.__localCalls.some(c=>c.cmd==="start_local_agent")));
  await page.evaluate(() => {window.__localModelsError=false;window.__localModelsEmpty=true;});
  await page.click("#local-agent-models");
  await page.waitForFunction(() => document.getElementById("local-agent-feedback").textContent.includes("没有可用模型"));
  check("空模型列表不冒充就绪", await page.isDisabled("#local-agent-start"));
  await page.evaluate(() => {window.__localModelsEmpty=false;window.__localModelsDelay=300;});
  await page.locator(".local-agent-endpoint summary").click();
  await page.click("#local-agent-models");
  await page.fill("#local-agent-port", "8001");
  await page.waitForTimeout(350);
  check("更换端口后丢弃旧服务迟到模型列表", await page.isDisabled("#local-agent-start") && await page.inputValue("#local-agent-model")==="");
  await page.evaluate(() => {window.__localModelsDelay=0;});
  await page.fill("#local-agent-port", "8000");
  await page.click("#local-agent-models");
  await page.waitForFunction(() => !document.getElementById("local-agent-model").disabled);
  check("模型就绪仍需明确授权数据出口", await page.isDisabled("#local-agent-start") && !await page.isChecked("#local-agent-model-data") && (await page.locator("#local-agent-model-recipient").textContent()).includes("127.0.0.1:8000/v1/chat/completions"));
  await page.check("#local-agent-model-data");
  await page.locator(".local-agent-browser summary").click();
  await page.check("#local-agent-browser-enabled");
  check("启用浏览器重置数据授权并要求明确范围", !await page.isChecked("#local-agent-model-data") && await page.isDisabled("#local-agent-start"));
  await page.evaluate(()=>{window.__browserMissing=true;});
  await page.click("#local-agent-browser-check");
  await page.waitForFunction(()=>document.getElementById("local-agent-browser-status").textContent.includes("未就绪"));
  check("浏览器缺组件可见且未启动", await page.isDisabled("#local-agent-start"));
  await page.evaluate(()=>{window.__browserMissing=false;});
  await page.click("#local-agent-browser-check");
  await page.waitForFunction(()=>document.getElementById("local-agent-browser-status").textContent.includes("组件可用"));
  await page.fill("#local-agent-browser-origins","https://example.test");
  await page.check("#local-agent-model-data");
  check("不支持的公网范围不能启动", await page.isDisabled("#local-agent-start"));
  await page.fill("#local-agent-browser-origins","http://127.0.0.1:3000");
  await page.check("#local-agent-model-data");
  check("明确本机浏览器范围与数据授权后可启动", !await page.isDisabled("#local-agent-start"));
  await page.uncheck("#local-agent-browser-enabled");
  await page.check("#local-agent-model-data");
  await page.waitForFunction(() => !document.getElementById("local-agent-start").disabled);
  check("模型名称按文本呈现且只发送本机端口", await page.locator("#local-agent-model script").count()===0 && await page.evaluate(() => window.__localCalls.filter(c=>c.cmd==="list_local_agent_models").every(c=>Object.keys(c.args).join(",")==="port")));
  check("默认只读范围直白说明", await page.inputValue("#local-agent-mode")==="read" && (await page.locator("#local-agent-scope").textContent()).includes("不允许修改文件或执行命令"));
  await page.selectOption("#local-agent-mode", "write");
  await page.screenshot({path:join(OUT,"local-agent-start.png"),fullPage:true});
  await page.click("#local-agent-start");
  await page.waitForSelector("#local-agent-run", {state:"visible"});
  check("启动只传项目权限模型任务且准备阶段可停止", await page.evaluate(() => {const c=window.__localCalls.find(c=>c.cmd==="start_local_agent");return Object.keys(c.args).sort().join(",")==="browserOrigins,model,modelDataAuthorized,port,task,workspace,writeEnabled"&&c.args.writeEnabled===true&&c.args.modelDataAuthorized===true;}) && !await page.isDisabled("#local-agent-stop") && await page.isDisabled("#local-agent-pause"));
  await page.evaluate(() => {
    window.__confirmView={connection_id:"local-connection-one",port:8791,instance_id:"a".repeat(32),supports_workspace:true,pending:null,remaining_ms:0};
    window.__workspaceState={...window.__workspaceState,instance_id:"a".repeat(32),session_id:"local-session",session_state:"active",pending_review:null,last_result:null,workspaces:[{workspace_id:"workspace-0",target:"/fixture/local-project",snapshot:"/fixture/local-snapshot",writable:true,writeback_available:true,writeback_reason:null}]};
    window.__workspaceReview.preview.workspace_root="/fixture/local-project";
    window.__localView={...window.__localView,phase:"running",connection:structuredClone(window.__confirmView),steps:[{number:1,tool:"read_file",state:"succeeded"},{number:2,tool:"run_shell",state:"running"}]};
  });
  await page.waitForFunction(() => document.getElementById("gateway-disconnect").textContent.includes("断开并停止任务"));
  check("宿主连接自动采用且工具运行不冒充任务完成", await page.isHidden("#gateway-connect-form") && (await page.locator("#local-agent-steps").textContent()).includes("处理中或等待确认") && await page.isDisabled("#local-agent-continue"));
  check("自有连接断开与生命周期说明一致", (await page.locator("#gateway-workspace-control-help").textContent()).includes("断开也会停止本地任务") && (await page.locator("#gateway-confirmation-description").textContent()).includes("同时停止本地任务"));
  await page.evaluate(() => {
    window.__confirmView.pending=window.__boundRequest({id:"local-pending-one",what:"本地任务确认夹具",findings:[]});window.__confirmDeadline=performance.now()+15000;
  });
  await page.waitForSelector("#local-agent-confirm",{state:"visible"});
  check("确认入口使用网关实时待批状态而非Agent初始化快照", await page.evaluate(()=>window.__localView.connection.pending===null));
  await page.click("#local-agent-confirm");
  check("工具批准复用既有完整绑定确认区", await page.isVisible("#gateway-pending") && await page.isDisabled("#gateway-approve") && (await page.locator("#gateway-request-what").textContent()).includes("完整写入正文"));
  await page.click("#gateway-deny");
  await page.waitForSelector("#local-agent-confirm",{state:"hidden"});
  check("网关处理请求后本地确认入口同步消失", await page.isHidden("#local-agent-confirm"));
  await page.evaluate(() => {window.__localView.phase="awaiting_review";window.__localView.answer="建议已给出。<script>仅作模型回答</script>";window.__localView.steps[1].state="failed";});
  await page.waitForFunction(() => document.getElementById("local-agent-answer").textContent.includes("仅作模型回答"));
  check("模型回答纯文本且返回不代表成果验证", await page.locator("#local-agent-answer script").count()===0 && (await page.locator("#local-agent-phase").textContent()).includes("请核对回答与成果") && (await page.locator("#local-agent-answer-section").textContent()).includes("不代表任务已经验证"));
  await page.click("#local-agent-results");
  await page.waitForSelector("#gateway-workspace-review",{state:"visible"});
  await page.check("#gateway-workspace-reviewed");
  const localPollsBefore=await page.evaluate(()=>window.__localCalls.filter(c=>c.cmd==="poll_local_agent").length);
  await page.waitForFunction(n=>window.__localCalls.filter(c=>c.cmd==="poll_local_agent").length>=n+2,localPollsBefore);
  check("相同本地连接轮询不清除已核对预览", await page.isChecked("#gateway-workspace-reviewed") && !await page.isDisabled("#gateway-workspace-apply"));
  await page.fill("#local-agent-followup", "继续核对已生成的说明。");
  check("未处理文件预览时禁止追加", await page.isDisabled("#local-agent-continue") && (await page.locator("#local-agent-followup-help").textContent()).includes("先回写或放弃"));
  await page.click("#gateway-workspace-discard");
  await page.waitForFunction(() => !document.getElementById("local-agent-continue").disabled);
  await page.click("#local-agent-return");
  check("成果区可返回同一任务追加指令", await page.evaluate(()=>document.activeElement.id==="local-agent-title") && await page.inputValue("#local-agent-followup")==="继续核对已生成的说明。");
  await page.evaluate(() => {window.__localContinueDelay=200;});
  await page.click("#local-agent-continue");
  check("明确追加后立即锁定提交", await page.isDisabled("#local-agent-continue"));
  await page.waitForFunction(()=>document.getElementById("local-agent-phase").textContent.includes("任务进行中"));
  const continueCount=await page.evaluate(()=>window.__localCalls.filter(c=>c.cmd==="continue_local_agent").length);
  await page.click("#local-agent-pause");
  await page.waitForFunction(()=>document.getElementById("local-agent-phase").textContent.includes("已暂停"));
  check("暂停由本地任务控制命令接宿主", !await page.isDisabled("#local-agent-resume") && await page.isDisabled("#local-agent-continue") && await page.evaluate(()=>window.__localCalls.some(c=>c.cmd==="control_local_agent"&&c.args.runId==="local-run-one"&&c.args.action==="pause")));
  await page.click("#local-agent-resume");
  await page.waitForFunction(()=>document.getElementById("local-agent-phase").textContent.includes("下一条指令"));
  check("恢复仅授权且不自动重放追加", await page.evaluate(n=>window.__localCalls.filter(c=>c.cmd==="continue_local_agent").length===n,continueCount) && (await page.locator("#local-agent-feedback").textContent()).includes("不会自动重放") && await page.isDisabled("#local-agent-continue"));
  await page.evaluate(()=>{window.__localView.phase="failed";window.__localView.error="模型连接中断；请核对此前文件结果";window.__localView.steps[1].state="unknown";});
  await page.click("#local-agent-refresh");
  await page.waitForFunction(()=>document.getElementById("local-agent-phase").textContent.includes("本轮失败"));
  check("失败保留已有结果但禁追加需停止", await page.isHidden("#local-agent-followup-form") && !await page.isDisabled("#local-agent-results") && !await page.isDisabled("#local-agent-stop"));
  check("缺少回执的步骤显示结果待核查而非执行失败", (await page.locator("#local-agent-steps").textContent()).includes("结果待核查") && !(await page.locator("#local-agent-steps").textContent()).includes("工具失败"));
  await page.screenshot({path:join(OUT,"local-agent-results.png"),fullPage:true});
  await page.click("#local-agent-stop");
  await page.waitForFunction(()=>document.getElementById("local-agent-phase").textContent.includes("永久停止"));
  check("永久停止禁恢复且允许明确新建", await page.isDisabled("#local-agent-resume") && await page.isVisible("#local-agent-new"));
  check("永久停止立即撤销自有连接和旧预览展示", await page.isVisible("#gateway-connect-form") && await page.isHidden("#gateway-workspace"));
  await page.evaluate(()=>{window.__confirmView={connection_id:"external-connection",port:8792,instance_id:"c".repeat(32),supports_workspace:true,pending:null,remaining_ms:0};});
  await page.fill("#gateway-control-path", "/fixture/external/control.json");
  await page.click("#gateway-import");
  await page.waitForFunction(()=>document.getElementById("gateway-connect-form").hidden);
  check("外部兼容连接保持仅断开语义", (await page.locator("#gateway-disconnect").textContent())==="断开确认通道");
  await page.click("#local-agent-new");
  check("新建任务清空旧指令避免意外复用", await page.inputValue("#local-agent-task")==="" && await page.isDisabled("#local-agent-start"));
  check("新任务不沿用旧数据出口授权", !await page.isChecked("#local-agent-model-data"));
  await page.fill("#local-agent-task", "新任务检查项目。");
  await page.check("#local-agent-model-data");
  await page.click("#local-agent-start");
  await page.waitForFunction(()=>document.getElementById("local-agent-feedback").textContent.includes("另一会话"));
  check("本地启动不覆盖已连接的外部会话", await page.evaluate(()=>window.__localCalls.filter(c=>c.cmd==="start_local_agent").length===1) && (await page.locator("#gateway-connection-detail").textContent()).includes("8792"));
  await page.click("#gateway-disconnect");
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

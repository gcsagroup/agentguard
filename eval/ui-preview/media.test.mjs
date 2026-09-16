/* 治理页的真实浏览器交互；后端为明确的桩，不替代原生网关验收。 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { join, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
const here = dirname(fileURLToPath(import.meta.url)), ui = resolve(here, "../../apps/desktop-macos/src");
const out = process.env.AGENTGUARD_UI_TEST_OUTPUT || "/tmp/agentguard-media-ui";
mkdirSync(out, { recursive: true });
const require = createRequire(import.meta.url);
const { chromium } = require(join(execSync("npm root -g", { encoding: "utf8" }).trim(), "playwright"));
const stub = readFileSync(join(here, "shell-a11y.mjs"), "utf8").match(/const TAURI_STUB = `([\s\S]*?)`;\n/)[1];
const server = createServer((req, res) => {
  const path = resolve(ui, `.${new URL(req.url, "http://localhost").pathname === "/" ? "/index.html" : new URL(req.url, "http://localhost").pathname}`);
  if (!path.startsWith(ui + "/")) { res.writeHead(403); res.end(); return; }
  try { res.setHeader("Content-Type", ({ ".js":"text/javascript", ".css":"text/css", ".html":"text/html" })[extname(path)] || "application/octet-stream"); res.end(readFileSync(path)); }
  catch { res.writeHead(404); res.end(); }
});
await new Promise(done => server.listen(0, "127.0.0.1", done));
const browser = await chromium.launch(); let checks = 0;
function check(name, value) { assert.ok(value, name); checks++; console.log(`通过：${name}`); }
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: "zh-CN" });
  const errors = []; page.on("pageerror", error => errors.push(String(error)));
  await page.addInitScript(stub);
  await page.addInitScript(() => {
    const original = window.__TAURI__.core.invoke;
    window.__answers = [];
    window.__material = { kind:"parsed_document", path:"/fixture/安装文档.png", document:{
      format:"png", status:"parsed", instruction_authority:"none", text:"安装示例：pip install demo-package\n<img src=x onerror=window.__injected=true>繁體文字",
      segments:[{location:"image:1:ocr",start_byte:0,end_byte:100}], coverage:{parsed_layers:["image OCR"],uncovered:["OCR 可能误识别或漏字"],empty_units:[]},
      parser_version:"agentguard-document/2",source_sha256:"c".repeat(64),future_field:"不可省略的原字段" } };
    window.__setPending = (id="one", material=window.__material) => {
      window.__pending = {id,what:"保存资料",findings:[],action_sha256:"f".repeat(64),action:{session_id:"test-session",tool_service:"agentguard-memory",tool_name:"memory_write",tool_version:"1",target:"memory://test/material",policy_version:"p1",parameters:{key:"material",version:1,content:JSON.stringify(material)}}};
    };
    window.__setPending();
    window.__TAURI__.core.invoke = async (cmd,args) => {
      if (["import_gateway_confirmation","poll_gateway_confirmation"].includes(cmd)) return {connection_id:"fixture",port:8790,instance_id:"b".repeat(32),pending:window.__pending,remaining_ms:window.__expired?0:60000,supports_workspace:true};
      if (cmd === "answer_gateway_confirmation") { window.__answers.push(args);window.__pending=null;return; }
      if (cmd === "disconnect_gateway_confirmation") return;
      if (cmd === "poll_gateway_workspace") return {service:"agentguard-mcp",workspace_protocol:1,instance_id:"b".repeat(32),session_id:"test-session",session_state:"active",busy:false,workspaces:[],pending_review:null,last_result:null};
      if (cmd === "govern_gateway") {
        const version={key:"material",version:1,state:"active",content:window.__material,sources:[{source_id:"fixture-file"}],label:{integrity:"tainted",confidentiality:"high"},committed_at_ms:Date.now(),expires_at_ms:Date.now()+3600000,approval:{},instruction_authority:"none"};
        if(args.command.operation==="memory_list") return {data:{entries:[version],total_keys:1,next_key:null}};
        if(args.command.operation==="memory_history") return {data:{key:"material",current_version:1,versions:[version],next_version:null}};
        if(args.command.operation==="memory_preview") return {data:{draft:{...version,content:JSON.stringify(window.__material)},review_id:"review",review_sha256:"e".repeat(64),expires_at_ms:Date.now()+60000}};
      }
      return original(cmd,args);
    };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.click('.sidebar [data-route="active"]');
  await page.fill("#gateway-control-path","/fixture/control.json");await page.click("#gateway-import");
  await page.waitForSelector("#gateway-memory-preview h4");
  check("保存预览展示正文、出处和覆盖限制",/pip install demo-package/.test(await page.locator("#gateway-memory-preview").innerText()) && /image:1:ocr/.test(await page.locator("#gateway-memory-preview").innerText()) && /OCR 可能误识别/.test(await page.locator("#gateway-memory-preview").innerText()));
  check("未核对不能批准，JSON 仅作附加依据",await page.isDisabled("#gateway-approve") && !await page.locator("#gateway-action-details").getAttribute("open"));
  check("正文不执行 HTML 或脚本",await page.locator("#gateway-memory-preview img").count()===0 && !await page.evaluate(()=>window.__injected));
  await page.locator("#gateway-memory-preview details summary").click();
  check("原始记录保留未知字段和来源摘要",/不可省略的原字段/.test(await page.locator("#gateway-memory-preview").innerText()) && /cccccccc/.test(await page.locator("#gateway-memory-preview").innerText()));
  await page.locator("#gateway-action-details summary").click();
  check("完整动作绑定仍可展开",/test-session/.test(await page.locator("#gateway-request-what").innerText()));
  await page.check("#gateway-reviewed");
  await page.evaluate(()=>{window.__material.document.status="partial";window.__material.document.coverage.empty_units=["page:2"];window.__setPending("two");});
  await page.waitForFunction(()=>document.getElementById("gateway-request-id").textContent==="two");
  check("新请求清除旧勾选并显示部分覆盖",await page.isDisabled("#gateway-approve") && !await page.isChecked("#gateway-reviewed") && /page:2/.test(await page.locator("#gateway-memory-preview").innerText()) && /仅部分/.test(await page.locator("#gateway-memory-preview").innerText()));
  await page.check("#gateway-reviewed");await page.click("#gateway-approve");
  check("批准提交准确的当前请求且清除正文",await page.evaluate(()=>JSON.stringify(window.__answers)==='[{"connectionId":"fixture","requestId":"two","approve":true}]') && await page.locator("#gateway-memory-preview").innerText()==="");
  await page.evaluate(()=>{window.__setPending("invalid",{kind:"parsed_document",document:{status:"success",text:"不可伪造通过"}});});
  await page.waitForFunction(()=>document.getElementById("gateway-request-id").textContent==="invalid");
  check("未知结构保持原值并提示无法判断",/没有可读摘要/.test(await page.locator("#gateway-memory-preview").innerText()) && /不可伪造通过/.test(await page.locator("#gateway-memory-preview").innerText()));
  await page.click("#gateway-deny");
  check("拒绝无需批准勾选",await page.evaluate(()=>window.__answers.at(-1).approve===false));
  await page.evaluate(()=>{window.__setPending("expired");window.__expired=true;});
  await page.waitForFunction(()=>document.getElementById("gateway-countdown").textContent.includes("过期"));
  check("过期预览不能批准",await page.isDisabled("#gateway-approve") && await page.isDisabled("#gateway-reviewed"));
  await page.evaluate(()=>{window.__expired=false;window.__pending=null;});
  await page.click("#governance-load-memory");await page.click("#governance-entries button");
  check("历史版本同样可读且保留覆盖缺口",/完整提取正文/.test(await page.locator("#governance-history").innerText()) && /page:2/.test(await page.locator("#governance-history").innerText()));
  await page.click("#governance-quarantine");
  check("治理预览沿用相同正文与限制",/pip install demo-package/.test(await page.locator("#governance-review-body").innerText()) && /OCR 可能误识别/.test(await page.locator("#governance-review-body").innerText()));
  for(const locale of ["zh-Hant","en","zh-Hans"]) {
    await page.click('.sidebar [data-route="settings"]');await page.click("#tab-general");await page.selectOption("#locale-select",locale);await page.click('.sidebar [data-route="active"]');
    check(`切换 ${locale} 保留正文与翻译标题`,await page.locator("#governance-review-body .memory-content h4").innerText()==={"zh-Hant":"資料預覽",en:"Material preview","zh-Hans":"资料预览"}[locale]);
  }
  await page.setViewportSize({width:720,height:900});await page.locator("#governance-review").scrollIntoViewIfNeeded();
  check("窄窗正文可读且没有横向溢出",await page.evaluate(()=>document.getElementById("governance-panel").scrollWidth<=document.getElementById("governance-panel").clientWidth));
  await page.screenshot({path:join(out,"media-720.png"),fullPage:false});
  check("页面身份、非空显示与脚本健康",(await page.title()).includes("AgentGuard") && errors.length===0 && await page.locator("#governance-review-body").isVisible());
  console.log(JSON.stringify({passed:true,checks,scope:"浏览器桩，不代表原生保存",out}));
} finally {await browser.close();server.close();}

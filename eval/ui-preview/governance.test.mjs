/* 治理页的真实浏览器交互；后端为明确的桩，不替代原生网关验收。 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { join, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
const here = dirname(fileURLToPath(import.meta.url)), ui = resolve(here, "../../apps/desktop-macos/src");
const out = process.env.AGENTGUARD_UI_TEST_OUTPUT || "/tmp/agentguard-governance-ui";
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
    window.__govCalls = []; window.__govExpire = false; window.__govUnknown = false; window.__govDelay = false;
    let version = 2, state = "active", stopped = false;
    const entry = (n = version) => ({ key: "note", version: n, state: n === version ? state : "active", expired: false, committed_at_ms: 1789510000000, expires_at_ms: Date.now() + 3600000,
      content: { kind: "note", text: "<img src=x onerror=window.__injected=true>完整中文正文" }, sources: [{ source_id: "original-source", observation: { status:"unknown", reason:"synthetic-test" } }], label: { integrity:"tainted", confidentiality:"high" }, approval: { actor_id:"authenticated-host-control" }, entry_sha256:"f".repeat(64), instruction_authority:"none" });
    const budget = () => ({ closed:false, nodes:[{ grant_id:"root", parent_grant_id:null, revoked:stopped, used_calls:1, limits:{max_calls:10},remaining_ms:60000 }, { grant_id:"child",parent_grant_id:"root",revoked:stopped,used_calls:1,limits:{max_calls:5},remaining_ms:60000 }] });
    window.__TAURI__.core.invoke = async (cmd,args) => {
      if (cmd === "import_gateway_confirmation" || cmd === "poll_gateway_confirmation") return { connection_id:"fixture",port:8790,instance_id:"b".repeat(32),pending:null,remaining_ms:0,supports_workspace:true };
      if (cmd === "poll_gateway_workspace" || cmd === "control_gateway_workspace") return { service:"agentguard-mcp",workspace_protocol:1,instance_id:"b".repeat(32),session_id:"session",task_profile:"fixture",session_state:args.action === "pause" ? "paused":"active",busy:false,last_client_message_ms:0,workspaces:[],pending_review:null,last_result:null };
      if (cmd === "disconnect_gateway_confirmation") return;
      if (cmd !== "govern_gateway") return original(cmd,args);
      window.__govCalls.push(args.command); const c = args.command; let data;
      switch (c.operation) {
        case "memory_list": data = { entries:[entry()],total_keys:2,next_key:c.after_key ? null:"next" }; break;
        case "memory_history": data = { key:"note",current_version:version,versions:[entry(c.after_version ? version : 1)],next_version:c.after_version ? null:1,total_versions:version }; break;
        case "memory_preview": {
          const draft = { key:"note",version:version+1,state:c.change === "restore" ? "active" : c.change === "quarantine" ? "quarantined":"revoked",content:JSON.stringify(entry().content),sources:entry().sources,label:entry().label,expires_at_ms:c.expires_at_ms || Date.now()+3600000 };
          data = { review_id:"review",review_sha256:"e".repeat(64),expires_at_ms:Date.now()+(window.__govExpire ? 50:60000),session_id:"session",draft,operation:c.change,target:"memory://fixture/note",policy_version:"policy" };
          if(window.__govDelay) await new Promise(resolve => { window.__govRelease = () => resolve(); });
          window.__govDraft = draft; break;
        }
        case "memory_apply": if(window.__govUnknown) throw new Error("GOVERNANCE_OUTCOME_UNKNOWN"); version++;state=window.__govDraft.state;data={review_id:"review",completed_effects:"not_reverted",execution:{_meta:{agentguard:{outcome:"success"}}}};break;
        case "memory_discard":data={discarded:true,review_id:"review"};break;
        case "delegation_status":data={host_session_id:"session",budget:budget()};break;
        case "delegation_revoke":stopped=true;data={host_session_id:"session",grant_id:c.grant_id,revoked:true,completed_effects:"not_reverted",budget:budget()};break;
        default:throw new Error("unexpected governance operation");
      }
      return {session_id:"session",data};
    };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.click('.sidebar [data-route="active"]');
  check("未连接时不展示可操作治理入口", await page.isHidden("#governance-panel"));
  await page.fill("#gateway-control-path", "/fixture/control.json"); await page.click("#gateway-import");
  await page.waitForSelector("#governance-panel", {state:"visible"});
  check("连接后仍需明确读取资料", !(await page.locator("#governance-entries").innerText()));
  await page.click("#governance-load-memory"); await page.waitForSelector("#governance-entries button");
  await page.click("#governance-more-memory"); await page.waitForFunction(() => document.getElementById("governance-more-memory").hidden);
  check("记忆下一页使用返回游标", await page.evaluate(() => window.__govCalls.some(c=>c.after_key==="next")));
  const openHistory = async () => { await page.click("#governance-entries button"); await page.waitForSelector("#governance-memory-actions",{state:"visible"}); };
  await openHistory(); await page.click("#governance-more-history"); await page.waitForFunction(() => document.getElementById("governance-more-history").hidden);
  check("版本分页保留完整历史与来源", await page.locator("#governance-history section").count() === 2 && /original-source/.test(await page.locator("#governance-history").textContent()));
  check("不可信正文仅文本呈现", await page.locator("#governance-history img").count() === 0 && !await page.evaluate(()=>window.__injected));
  await page.click("#governance-quarantine"); await page.waitForSelector("#governance-review",{state:"visible"});
  check("未经核对不能批准且保留污染标签", await page.isDisabled("#governance-apply") && /tainted/.test(await page.locator("#governance-review").innerText()));
  await page.check("#governance-reviewed"); await page.click("#governance-apply");
  await page.waitForFunction(() => document.getElementById("governance-feedback").textContent.includes("已记录本次变更"));
  check("批准只传已展示的编号和摘要", await page.evaluate(() => JSON.stringify(window.__govCalls.find(c=>c.operation==="memory_apply")) === JSON.stringify({operation:"memory_apply",review_id:"review",review_sha256:"e".repeat(64)})));
  await page.click("#governance-load-memory"); await openHistory();
  await page.selectOption("#governance-version", "1"); await page.fill("#governance-expiry", "2090-01-01T12:00"); await page.click("#governance-restore");
  await page.waitForSelector("#governance-review",{state:"visible"});
  check("恢复绑定历史版本并明确新期限", await page.evaluate(()=>window.__govCalls.some(c=>c.change==="restore" && c.source_version===1 && c.expected_version===3 && c.expires_at_ms>Date.now())));
  await page.click("#governance-discard"); await page.waitForFunction(()=>document.getElementById("governance-feedback").textContent.includes("已放弃"));
  await page.click("#governance-load-memory"); await openHistory();
  await page.evaluate(()=>window.__govUnknown=true); await page.click("#governance-revoke"); await page.check("#governance-reviewed"); await page.click("#governance-apply");
  await page.waitForFunction(()=>document.getElementById("governance-feedback").textContent.includes("不会自动重试"));
  check("回执不明后清除批准与旧历史", await page.isHidden("#governance-review") && await page.isHidden("#governance-memory-actions"));
  await page.evaluate(()=>{window.__govUnknown=false;window.__govExpire=true;});
  await page.click("#governance-load-memory"); await openHistory(); await page.click("#governance-quarantine");
  await page.waitForFunction(()=>document.getElementById("governance-review-expiry").textContent.includes("已过期"));
  check("到期后批准和核对均禁用",await page.isDisabled("#governance-apply") && await page.isDisabled("#governance-reviewed"));
  await page.click("#governance-load-tree"); await page.waitForSelector("#governance-tree button");
  await page.locator("#governance-tree button").first().click(); await page.waitForFunction(()=>document.getElementById("governance-feedback").textContent.includes("分支撤销已记录"));
  check("停止父分支后下级也显示停止且不宣称撤回", await page.locator("#governance-tree button:disabled").count()===2 && /未撤回/.test(await page.locator("#governance-feedback").innerText()));
  await page.setViewportSize({width:720,height:900}); await page.locator("#governance-panel").scrollIntoViewIfNeeded();
  check("窄窗口治理面板无横向溢出", await page.evaluate(()=>document.getElementById("governance-panel").scrollWidth<=document.getElementById("governance-panel").clientWidth));
  await page.screenshot({path:join(out,"governance-720.png"),fullPage:true});
  await page.setViewportSize({width:1280,height:900});
  await page.click('.sidebar [data-route="settings"]');await page.click("#tab-general");await page.selectOption("#locale-select","en");await page.click('.sidebar [data-route="active"]');
  check("动态分支和静态文案同步切换语言", /Delegation branches/.test(await page.locator("#governance-panel").innerText()) && /Stopped/.test(await page.locator("#governance-tree").innerText()));
  await page.screenshot({path:join(out,"governance-en.png"),fullPage:true});
  await page.click('.sidebar [data-route="settings"]');await page.click("#tab-general");await page.selectOption("#locale-select","zh-Hans");await page.click('.sidebar [data-route="active"]');
  await page.evaluate(()=>{window.__govExpire=false;window.__govDelay=true;});await page.click("#governance-load-memory");await openHistory();await page.click("#governance-quarantine");
  await page.waitForFunction(()=>!!window.__govRelease);await page.click("#gateway-disconnect");await page.evaluate(()=>window.__govRelease());
  check("断开后迟到预览不能恢复旧批准",await page.isHidden("#governance-panel") && await page.isHidden("#governance-review"));
  await page.click("#gateway-import"); await page.waitForSelector("#governance-panel",{state:"visible"});
  check("重新连接不残留上一会话的条目数量",await page.locator("#governance-entry-count").innerText()==="" && await page.locator("#governance-entries").innerText()==="");
  check("页面身份正确且无脚本异常", (await page.title()).includes("AgentGuard") && errors.length===0);
  console.log(JSON.stringify({passed:true,checks,scope:"浏览器桩；不代表原生治理验收",out}));
} finally { await browser.close();server.close(); }

// 真实生产日志经 Rust 宿主读取后的输出，在 Chromium 中验证记录页；IPC 使用明确测试桥。
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
const root=resolve(import.meta.dirname,'../..'),ui=join(root,'apps/desktop-macos/src');
const out=process.env.AGENTGUARD_EXECUTION_OUTPUT || join(root,'.artifacts/m2-execution-evidence-2026-09-15');mkdirSync(out,{recursive:true});
const normal=JSON.parse(readFileSync(join(out,'host-receipt.json')));
const fault=JSON.parse(readFileSync(join(out,'fault-host-receipt.json')));
const knowledge=JSON.parse(readFileSync(join(root,'.artifacts/m2-knowledge-workspace-2026-09-15/knowledge-receipt.json')));
assert(normal.view.channels.every(c=>c.status==='verified'));
assert(fault.view.channels[0].log.actions.some(a=>a.classification==='unknown'));
const stub=readFileSync(join(import.meta.dirname,'shell-a11y.mjs'),'utf8').match(/const TAURI_STUB = `([\s\S]*?)`;\n/)[1];
const {chromium}=createRequire(import.meta.url)(join(execFileSync('npm',['root','-g'],{encoding:'utf8'}).trim(),'playwright'));
const report={scope:'真实 Rust 宿主输出 + Chromium；IPC 测试桥，不计原生 App 验收',checks:[],passed:false};
const check=(name,value)=>{report.checks.push({name,passed:!!value});assert(value,name);console.log(`通过：${name}`);};
const server=createServer((req,res)=>{
 const path=resolve(ui,'.'+new URL(req.url,'http://localhost').pathname.replace(/^\/$/,'/index.html'));
 if(!path.startsWith(ui+'/')){res.writeHead(403).end();return;}
 try{res.setHeader('content-type',({'.js':'text/javascript','.css':'text/css','.html':'text/html; charset=utf-8','.png':'image/png'})[extname(path)]||'text/plain');res.end(readFileSync(path));}catch{res.writeHead(404).end();}
});await new Promise(done=>server.listen(0,'127.0.0.1',done));
const browser=await chromium.launch();
try{
 const page=await browser.newPage({viewport:{width:1280,height:960},locale:'zh-CN'});const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 await page.addInitScript(stub);
 await page.addInitScript(({normal,fault,knowledge})=>{
  localStorage.setItem('agentguard.appearance','light');window.__executionCalls=[];
  window.__normal=normal;window.__fault=fault;window.__knowledge=knowledge;
  const original=window.__TAURI__.core.invoke;
  window.__TAURI__.core.invoke=async(cmd,args)=>{
   if(cmd==='get_knowledge_catalog')return structuredClone(window.__knowledge);
   if(cmd==='list_execution_sessions'){
    window.__executionCalls.push({cmd});if(window.__listFail)throw new Error('列表不可读');
    return {truncated:false,sessions:window.__empty?[]:[...normal.sessions.sessions.filter(s=>s.id===normal.view.session_id),...fault.sessions.sessions.filter(s=>s.id===fault.view.session_id)]};
   }
   if(cmd==='read_execution_session'){
    window.__executionCalls.push({cmd,args});if(window.__readFail)throw new Error('读取不可用');
    const value=structuredClone(args.sessionId===normal.view.session_id?window.__normal.view:window.__fault.view);
    if(window.__delayId===args.sessionId)await new Promise(done=>setTimeout(done,300));
    if(window.__badIntegrity)value.channels[0].log.integrity='not_verified';
    return value;
   }
   return original(cmd,args);
  };
 },{normal,fault,knowledge});
 await page.goto(`http://127.0.0.1:${server.address().port}`);
 await page.locator('.sidebar [data-route="activity"]').click();await page.locator('#activity-mode').selectOption('execution');
 await page.locator('.execution-action').first().waitFor();
 check('切换记录来源后读屏焦点进入已命名的受控区域',await page.getByRole('region',{name:'本应用的受控任务',exact:true}).count()===1&&await page.evaluate(()=>document.activeElement?.id==='activity-execution'));
 const normalActions=normal.view.channels.flatMap(c=>c.log.actions);
 check('实际宿主输出的两通道动作完整进入记录页',await page.locator('.execution-channel').count()===2&&await page.locator('.execution-action').count()===normalActions.length);
 await page.locator('#execution-outcome').selectOption('blocked');
 check('已阻断数量来自真实未派发拒绝终态',await page.locator('.execution-action').count()===normalActions.filter(a=>a.classification==='blocked').length);
 await page.locator('.execution-action').first().locator('summary').first().click();
 check('展开只显示记录中实际存在的阶段',await page.locator('.execution-action').first().locator('.execution-stages li').count()===normalActions.find(a=>a.classification==='blocked').stages.length);
 await page.locator('.execution-action').first().locator('details details summary').click();
 check('动作绑定摘要可核对且不显示执行正文', (await page.locator('#execution-records').textContent()).includes(normalActions.find(a=>a.classification==='blocked').action_sha256)&&!(await page.locator('#execution-records').textContent()).includes('NEW_POLICY_EFFECT'));
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:join(out,'execution-blocked.png')});
 await page.locator('#execution-outcome').selectOption('record');
 check('工具返回明确保留业务效果未核对', (await page.locator('#execution-records').innerText()).includes('业务效果仍需核对'));
 await page.locator('#execution-session').selectOption(fault.view.session_id);await page.locator('#execution-outcome').selectOption('unknown');
 await page.waitForFunction(()=>document.querySelector('#execution-records').textContent.includes('副作用未知'));
 check('实际崩溃恢复回执归未知而非已阻断',await page.locator('.execution-action[data-classification="unknown"]').count()===fault.view.channels[0].log.actions.filter(a=>a.classification==='unknown').length);
 await page.locator('.execution-action').first().locator('summary').first().click();
 check('未知结果保留开始和恢复终态证据', (await page.locator('.execution-stages').innerText()).includes('执行开始记录')&&(await page.locator('.execution-stages').innerText()).includes('终态回执'));
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:join(out,'execution-unknown.png')});
 await page.locator('#execution-outcome').selectOption('alert');
 check('崩溃前未完成批准的判决保留为告警',await page.locator('.execution-action[data-classification="alert"]').count()===1);
 await page.evaluate(id=>{window.__delayId=id;},normal.view.session_id);
 await page.locator('#execution-session').selectOption(normal.view.session_id);
 await page.locator('#execution-session').selectOption(fault.view.session_id);
 await page.waitForTimeout(400);
 check('迟到的旧任务响应不能覆盖当前任务',(await page.locator('#execution-records').textContent()).includes(fault.view.channels[0].log.actions.find(a=>a.classification==='alert').id_sha256.slice(0,12))&&await page.locator('.execution-action[data-classification="alert"]').count()===1&&await page.locator('#execution-session').inputValue()===fault.view.session_id);
 await page.evaluate(()=>{window.__readFail=true;});
 await page.locator('#execution-session').selectOption(normal.view.session_id);
 await page.waitForFunction(()=>document.querySelector('#execution-status').textContent.includes('不可读'));
 check('读取失败清除旧动作并说明不是没有历史',await page.locator('.execution-action').count()===0&&(await page.locator('#execution-status').innerText()).includes('不代表没有执行历史'));
 await page.evaluate(()=>{window.__readFail=false;window.__delayId=null;window.__badIntegrity=true;});
 await page.locator('#execution-refresh').click();await page.waitForFunction(()=>document.querySelector('#execution-status').textContent.includes('不可读'));
 check('未验链回执不能进入可信记录展示',await page.locator('.execution-action').count()===0);
 await page.evaluate(()=>{window.__badIntegrity=false;window.__empty=true;});await page.locator('#execution-refresh').click();
 await page.waitForFunction(()=>document.querySelector('#execution-status').textContent.includes('尚无'));
 check('空任务列表不残留旧任务或旧证据',await page.locator('#execution-session option').count()===0&&await page.locator('.execution-action').count()===0);
 await page.evaluate(()=>{window.__empty=false;});await page.locator('#execution-refresh').click();await page.locator('.execution-action').first().waitFor();
 // 只验证编号关联的导航，不把这个合成界面变体作为实际规则命中证据。
 await page.evaluate(()=>{window.__normal.view.channels[0].log.actions[0].findings=[{rule_id:'OVL-004',layer:'engine'}];});
 await page.locator('#execution-outcome').selectOption('all');await page.locator('#execution-refresh').click();await page.locator('.execution-action').first().waitFor();await page.locator('.execution-action').first().locator('summary').first().click();await page.getByRole('button',{name:'查看手法资料 · 间接提示词注入',exact:true}).waitFor();
 await page.getByRole('button',{name:'查看手法资料 · 间接提示词注入',exact:true}).click();
 await page.locator('.knowledge-choice').first().waitFor();
 check('规则编号仅跳转对应手法资料且阶段发生仍未知',await page.locator('#knowledge-search').inputValue()==='GCSA-ATI-001'&&(await page.locator('.knowledge-stages').innerText()).includes('发生情况未知'));
 await page.locator('.sidebar [data-route="activity"]').click();await page.locator('.execution-action').first().waitFor();
 await page.evaluate(()=>{const s=document.querySelector('#locale-select');s.value='en';s.dispatchEvent(new Event('change'));});
 await page.waitForFunction(()=>document.querySelector('#execution-records').textContent.includes('Task gateway'));
 check('语言切换同步执行状态与阶段词条',(await page.locator('#execution-records').innerText()).includes('business effects still need verification'));
 await page.setViewportSize({width:760,height:960});await page.evaluate(()=>{document.documentElement.dataset.theme='dark';window.scrollTo(0,0);});
 check('窄窗口无横向溢出',await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
 await page.screenshot({path:join(out,'execution-narrow.png')});
 check('读取只传会话编号并且没有写操作',await page.evaluate(()=>window.__executionCalls.every(c=>c.cmd==='list_execution_sessions'||c.cmd==='read_execution_session'&&Object.keys(c.args).join()==='sessionId')));
 check('浏览器无脚本错误',errors.length===0);
 report.passed=true;
}finally{writeFileSync(join(out,'execution-ui-report.json'),JSON.stringify(report,null,2)+'\n');await browser.close();await new Promise(done=>server.close(done));}

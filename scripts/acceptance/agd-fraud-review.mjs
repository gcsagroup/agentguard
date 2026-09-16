// AGD-029：真实受保护 Chromium + 本机模拟账本；批准由脚本替代人工，不运行深伪模型。
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile, copyFile, access } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { startHostFixture, toolValue, until } from '../../apps/protected-browser/host-test-support.mjs';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { ROOT, fileTree } from './agd-workspace-session.mjs';

const option=name=>{const index=process.argv.indexOf(name);assert.ok(index>0,`缺少 ${name}`);return process.argv[index+1];};
const out=option('--out'), binary=option('--binary');
assert.ok([out,binary].every(isAbsolute));
await mkdir(out,{mode:0o700}); // 拒绝覆盖失败记录。
const sha=data=>createHash('sha256').update(data).digest('hex');
const html=await readFile(join(ROOT,'eval/acceptance-fixtures/fraud-review.html'));
const report={started_at:new Date().toISOString(),scope:'真实本机HTTP和受保护Chromium；脚本复核，不是原生人工或深伪检测验收',binary,binary_sha256:sha(await readFile(binary)),fixture_sha256:sha(html),checks:[],observations:[],approvals:[],rejections:[],requests:[],ledger:[]};
const expected={invoice:'DEMO-INV-001',beneficiary:'合成示例供应商甲',account:'DEMO-A',amount_minor:128050,currency:'CNY'};
await writeFile(join(out,'independent-reference.json'),JSON.stringify(expected,null,2),{mode:0o600});
const check=(name,value)=>{report.checks.push({name,passed:!!value});assert.ok(value,name);console.error(`通过：${name}`);};
const site=createServer(async(req,res)=>{
  let body='';for await(const chunk of req){body+=chunk;if(Buffer.byteLength(body)>8192){res.writeHead(413);res.end();return;}}
  report.requests.push({at:new Date().toISOString(),method:req.method,path:req.url,body});
  if(req.method==='GET'&&req.url==='/'){res.setHeader('content-type','text/html; charset=utf-8');res.end(html);return;}
  if(req.method==='POST'&&req.url==='/transactions'){
    const entry={id:`SIM-${report.ledger.length+1}`,received_at:new Date().toISOString(),draft:JSON.parse(body)};
    // 账本没有“正确收款方”过滤；零副作用必须来自网关，而非夹具替它阻断。
    report.ledger.push(entry);await writeFile(join(out,'ledger.json'),JSON.stringify(report.ledger,null,2),{mode:0o600});
    res.setHeader('content-type','application/json');res.end(JSON.stringify(entry));return;
  }
  res.writeHead(404);res.end();
});
await writeFile(join(out,'ledger.json'),'[]',{mode:0o600});
await new Promise(resolve=>site.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${site.address().port}`;report.origin=origin;
let host,preview;
try{
  // 单独的只读布局检查。不能把这个未受保护预览当成下面网关的执行证据。
  const require=createRequire(import.meta.url);
  const {chromium}=require(join(execFileSync('npm',['root','-g'],{encoding:'utf8'}).trim(),'playwright'));
  preview=await chromium.launch();const page=await preview.newPage({viewport:{width:1100,height:800},locale:'zh-CN'}),errors=[];
  page.on('pageerror',error=>errors.push(String(error)));await page.goto(origin);
  for(const width of [1100,390]){
    await page.setViewportSize({width,height:850});await page.screenshot({path:join(out,`preview-${width}.png`),fullPage:true});
    check(`${width}像素只读预览无横向溢出且完整显示模拟提示`,await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)&&await page.locator('#send').isVisible());
  }
  check('只读预览无脚本错误且零提交',errors.length===0&&report.ledger.length===0);await preview.close();preview=null;
  report.preview_requests=report.requests.splice(0);
  host=await startHostFixture([origin],{binary,timeout:8,rpcTimeout:45000});
  report.fixture=host.fixture.temporaryRoot;report.control=host.fixture.control;
  report.session=(await host.rpc('gateway/stats')).result.host_session_id;
  const observe=async(name,args)=>{const raw=await host.call(name,args);report.observations.push({name,args,response:raw});return toolValue(raw);};
  const receiptFor=async pending=>until(async()=>(await host.operator('/workspace/status')).body.browser.receipts.find(r=>r.action_sha256===pending.action_sha256));
  const decide=async(pending,approve)=>{const answer=await host.decide(pending,approve);assert.equal(answer.status,200);const receipt=await receiptFor(pending);report.approvals.push({pending,approve,answer,receipt});return receipt;};
  const navigation=observe('browser_navigate',{url:origin+'/'});navigation.catch(()=>{});
  await decide(await host.pending(),true);const pageId=(await navigation).pages.find(p=>p.url===origin+'/').id;
  const read=()=>observe('browser_read',{page:pageId});
  const initial=await read();
  check('网页中的核验声明只是资料，读取没有创建付款',initial.text.includes('视频身份已核验')&&initial.text.includes('尚未提交')&&report.ledger.length===0&&(await host.operator('/pending')).body===null);
  const fill=(selector,value)=>observe('browser_fill',{page:pageId,selector,value});
  const submit=async()=>{await observe('browser_click',{page:pageId,selector:'#send'});const p=await host.pending();assert.equal(actionSha256(p.binding.action),p.action_sha256);assert.equal(p.binding.action.target,origin+'/transactions');assert.equal(p.binding.action.parameters.method,'POST');return p;};
  const first=await submit();report.first_draft=first;
  await delay(600);
  check('伪称视频和AI已核验仍等待独立批准且零收件',report.ledger.length===0&&(await host.operator('/pending')).body.id===first.id&&JSON.parse(first.binding.action.parameters.body).account==='DEMO-B');
  const changed=structuredClone(first.binding.action);const changedBody=JSON.parse(changed.parameters.body);changedBody.amount_minor++;changed.parameters.body=JSON.stringify(changedBody);
  const wrong=await host.operator('/approve',{id:first.id,action_sha256:actionSha256(changed),approval_nonce:first.binding.nonce});report.rejections.push({kind:'changed_amount',answer:wrong});
  check('替换金额摘要不能批准原请求',wrong.status===409&&report.ledger.length===0&&(await host.operator('/pending')).body.id===first.id);
  const duplicate=await host.call('browser_click',{page:pageId,selector:'#send'});report.duplicate=duplicate;
  check('待批准时重复点击未派发',duplicate.result._meta.agentguard.dispatched===false&&report.ledger.length===0);
  await fill('#beneficiary',expected.beneficiary);await fill('#account',expected.account);
  const frozen=(await host.operator('/pending')).body;
  check('编辑页面不能偷换已冻结的待批准收款账户',frozen.action_sha256===first.action_sha256&&JSON.parse(frozen.binding.action.parameters.body).account==='DEMO-B');
  const denied=await decide(first,false);
  await until(async()=>(await read()).text.includes('请求未完成'));
  check('按独立资料拒绝错误账户，实际账本为空',denied.outcome==='refused'&&!denied.dispatched&&report.ledger.length===0);
  await fill('#amount','128051');const expired=await submit();report.expired_draft=expired;
  const timeoutReceipt=await receiptFor(expired);report.timeout_receipt=timeoutReceipt;
  const late=await host.decide(expired,true);report.rejections.push({kind:'expired',answer:late});
  check('金额不符时不确认，超时和迟到批准均零收件',timeoutReceipt.outcome==='timed_out'&&!timeoutReceipt.dispatched&&late.status===409&&report.ledger.length===0);
  await until(async()=>(await read()).text.includes('请求未完成'));
  await fill('#amount',String(expected.amount_minor));const final=await submit();report.final_draft=final;
  const old=await host.decide(first,true);report.rejections.push({kind:'old_request',answer:old});
  check('旧请求不能批准改正后的新草稿',old.status===409&&final.action_sha256!==first.action_sha256&&report.ledger.length===0);
  const current=JSON.parse(final.binding.action.parameters.body);for(const [key,value]of Object.entries(expected))assert.equal(current[key],value);
  const sent=await decide(final,true);await until(async()=>(await read()).text.includes('本机账本已记录 SIM-1'));
  const last=await read();report.final_page=last;
  check('独立核对五个交易字段后，批准恰好产生一笔正确本机记录',sent.dispatched&&sent.outcome==='success'&&report.ledger.length===1&&Object.entries(expected).every(([key,value])=>report.ledger[0].draft[key]===value)&&last.text.includes('DEMO-A / 128050 分 CNY'));
  const replay=await host.decide(final,true);report.rejections.push({kind:'replay',answer:replay});await delay(600);
  check('重复批准没有重发，页面与真实账本结果一致',replay.status===409&&report.ledger.length===1);
  report.browser_status=(await host.operator('/workspace/status')).body.browser;
  check('合成工作区内容未改写',JSON.stringify(await fileTree(host.fixture.work))===JSON.stringify(host.fixture.initialTree));
  report.passed=true;
}catch(error){report.error=error.stack;throw error;}
finally{
  let cleanupError;
  await preview?.close();
  if(host){
    try{
    await host.close({preserve:true});report.exit={code:host.child.exitCode,signal:host.child.signalCode};report.stderr=host.stderr();
    check('正常退出无清理异常',report.exit.code===0&&!/Error:|EPERM|异常退出|清理失败|退出超时/.test(report.stderr));
    await access(host.controlFile).then(()=>{throw new Error('退出后连接文件仍有效');},error=>assert.equal(error.code,'ENOENT'));
    for(const name of ['browser.db','browser.db-wal','audit.db','audit.db-wal']){
      try{await copyFile(join(host.fixture.control,name),join(out,name));}catch(error){if(error.code!=='ENOENT')throw error;}
    }
    }catch(error){report.passed=false;report.cleanup_error=error.stack;cleanupError=error;}
  }
  site.closeAllConnections();await new Promise(resolve=>site.close(resolve));report.finished_at=new Date().toISOString();
  await writeFile(join(out,'report.json'),JSON.stringify(report,null,2),{mode:0o600});
  if(cleanupError)throw cleanupError;
}

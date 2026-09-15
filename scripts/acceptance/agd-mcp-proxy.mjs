// AGD-017 实际产品入口验收。批准仅覆盖本脚本创建的合成工作区和明确列出的调用。
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdir,readFile,writeFile,copyFile,access} from 'node:fs/promises';
import {join,resolve,isAbsolute} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {WorkspaceSession,createWorkspaceFixture,ROOT,DEFAULT_IMAGE} from './agd-workspace-session.mjs';
import {actionSha256} from '../../apps/protected-browser/execution-contract.mjs';
const option=key=>process.argv[process.argv.indexOf(key)+1];
assert.ok(process.argv.includes('--out')&&process.argv.includes('--package'));
const out=resolve(option('--out')),source=resolve(option('--package'));
assert.ok(isAbsolute(out));await mkdir(out,{mode:0o700});
const binary=process.argv.includes('--binary')?resolve(option('--binary')):join(ROOT,'target/debug/agentguard-mcp');
const report={scope:'真实网关 CLI、官方 Filesystem 服务与独立合成故障探针；脚本批准，不计原生人工验收',binarySha256:createHash('sha256').update(await readFile(binary)).digest('hex'),image:DEFAULT_IMAGE,checks:[],receipts:[]};
const check=(name,ok)=>{report.checks.push({name,passed:!!ok});assert.ok(ok,name);};
const record=value=>{report.receipts.push(value);return value;};
const exists=async path=>{try{await access(path);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};
let session,oldSession;
try {
  const fixture=await createWorkspaceFixture({name:'mcp-proxy',seed:{'read.txt':'SYNTHETIC_PROXY_INPUT'}});
  const probe=join(fixture.control,'probe-package');await mkdir(probe);
  await copyFile(join(ROOT,'crates/guard-gateway/tests/fixtures/mcp_proxy_probe.mjs'),join(probe,'probe.mjs'));
  const config=join(fixture.control,'services.json');
  await writeFile(config,JSON.stringify({version:1,services:[
    {service_id:'official-filesystem',namespace:'filesystem',package_path:source,package_id:'official-filesystem',package_version:'2026.8.31',entrypoint:'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js',arguments:[fixture.work]},
    {service_id:'synthetic-probe',namespace:'probe',package_path:probe,package_id:'synthetic-probe',package_version:'1',entrypoint:'probe.mjs',arguments:[fixture.work,join(fixture.control,'private.txt')]}
  ]}));
  await writeFile(join(fixture.control,'private.txt'),'SYNTHETIC_HOST_PRIVATE');
  report.fixture=fixture.temporaryRoot;
  const start=()=>WorkspaceSession.start({binary,fixture,confirmSeconds:60,mcpServiceConfig:config,startupTimeoutMs:60000});
  session=await start();
  const rpcCall=(name,args)=>session.rpc('tools/call',{name,arguments:args,_meta:{agentguard_session_id:session.sessionId}});
  const status=async()=>record((await session.operatorRequest('/registry/status')).value);
  const approveService=async name=>{
    const review=record(await session.operatorRequest('/registry/review',{service_id:name}));assert.equal(review.status,200);
    const value=review.value;
    assert.equal(value.dispatch_supported,true);
    const result=await session.operatorRequest('/registry/decide',{service_id:name,review_id:value.review_id,review_nonce:value.review_nonce,manifest_sha256:value.manifest_sha256,approve:true});
    assert.equal(result.status,200);return value;
  };
  const pendingFor=async promise=>Promise.race([session.waitForPending(),promise.then(v=>{throw new Error('未等待批准：'+JSON.stringify(v));})]);
  const answer=async(pending,name,args,decision='approve')=>{
    assert.equal(pending.binding.action.target,name);
    assert.deepEqual(pending.binding.action.parameters.arguments,args);
    assert.equal(actionSha256(pending.binding.action),pending.action_sha256);
    assert.equal(pending.binding.action.parameters.process.discovery_only,false);
    assert.equal(pending.binding.action.session_id,session.sessionId);
    return session.operatorRequest('/'+decision,{id:pending.id,action_sha256:pending.action_sha256,approval_nonce:pending.binding.nonce});
  };
  const invoke=async(name,args)=>{
    const response=rpcCall(name,args),pending=await pendingFor(response);
    assert.equal((await answer(pending,name,args)).status,200);
    return record(await response);
  };
  check('首次发现只挂空目录，没有初始化写入副本',!await exists(join(session.snapshot,'startup.txt')));
  let list=record(await session.rpc('tools/list'));
  check('待登记第三方工具不公开',!list.result.tools.some(t=>t.name.startsWith('mcp__')));
  const denied=record(await rpcCall('mcp__filesystem__write_file',{path:join(fixture.work,'unregistered.txt'),content:'SYNTHETIC'}));
  check('未登记调用不启动服务',denied.result._meta.agentguard.dispatched===false&&!await exists(join(session.snapshot,'unregistered.txt')));
  const review=await approveService('official-filesystem');await approveService('synthetic-probe');
  report.officialManifest=review.manifest;
  list=record(await session.rpc('tools/list'));
  check('批准后公开官方全部14项和2项探针',list.result.tools.filter(t=>t.name.startsWith('mcp__')).length===16);
  const invalid=record(await rpcCall('mcp__filesystem__write_file',{path:4,content:'SYNTHETIC'}));
  check('不符合Schema的请求在服务启动前拒绝',invalid.result._meta.agentguard.dispatched===false);
  const name='mcp__filesystem__write_file',args={path:join(fixture.work,'result.txt'),content:'SYNTHETIC_PROXY_WRITE'};
  const waiting=rpcCall(name,args),pending=await pendingFor(waiting);
  check('批准前副本与宿主均无目标文件',!await exists(join(session.snapshot,'result.txt'))&&!await exists(args.path));
  check('独立拒绝成功',(await answer(pending,name,args,'deny')).status===200);
  const refused=record(await waiting);
  check('拒绝产生明确未派发终态',refused.result._meta.agentguard.dispatched===false&&!await exists(join(session.snapshot,'result.txt')));
  const written=await invoke(name,args);
  check('官方工具经过产品入口真实写入副本',written.result._meta.agentguard.outcome==='success'&&(await readFile(join(session.snapshot,'result.txt'),'utf8'))===args.content);
  check('写入未自动回写原件',!await exists(args.path));
  const read=await invoke('mcp__filesystem__read_text_file',{path:args.path});
  check('官方读取返回实际内容和来源',!read.result.isError&&JSON.stringify(read.result.content).includes(args.content)&&read.result._meta.agentguard.source);
  const probeResult=await invoke('mcp__probe__probe',{});record(probeResult);
  const probeBody=JSON.parse(probeResult.result.content[0].text);
  check('初始化副作用受同次批准覆盖且凭据和外连被隔离',probeBody.startupWrite===true&&probeBody.outsideReadable===false&&probeBody.network!=='CONNECTED'&&(await readFile(join(session.snapshot,'startup.txt'),'utf8'))==='SYNTHETIC_STARTUP\n');
  check('下游自报元数据不能覆盖宿主回执',probeResult.result._meta.agentguard.outcome==='success'&&probeResult.result._meta.agentguard.instruction_authority==='none'&&probeResult.result._meta.agentguard.downstream_metadata.agentguard.outcome==='forged');
  const badOutput=await invoke('mcp__probe__probe',{bad_output:true});
  check('错误输出Schema在派发后保留未知而不冒充成功',badOutput.result.isError&&badOutput.result._meta.agentguard.outcome==='unknown'&&badOutput.result._meta.agentguard.dispatched===true);
  const workspace=(await session.workspaceStatus()).workspaces[0];
  const writeback=await session.previewWorkspace(workspace.id??workspace.workspace_id);
  assert.equal((await session.applyReview(writeback)).status,200);
  check('独立预览并批准后原件实际读回服务写入',await readFile(args.path,'utf8')===args.content);
  const lateArgs={path:join(fixture.work,'revoked.txt'),content:'MUST_NOT_WRITE'};
  const late=rpcCall(name,lateArgs),latePending=await pendingFor(late);
  const current=(await status()).services.find(s=>s.service_id==='official-filesystem');
  assert.equal((await session.operatorRequest('/registry/revoke',{service_id:current.service_id,registration_id:current.registration_id})).status,200);
  const cancelled=record(await late);
  check('撤销待批准动作无副作用且旧批准失效',cancelled.result._meta.agentguard.dispatched===false&&!await exists(join(session.snapshot,'revoked.txt'))&&(await answer(latePending,name,lateArgs)).status===409);
  assert.equal((await session.transition('resume')).status,200);
  // 批准合成悬挂调用，看到真实心跳后暂停；不等待到 30 秒总时限。
  const hanging=rpcCall('mcp__probe__hang',{}),hangPending=await pendingFor(hanging);
  assert.equal((await answer(hangPending,'mcp__probe__hang',{})).status,200);
  const pulse=join(session.snapshot,'pulse.txt');let deadline=Date.now()+10000;
  while(!await exists(pulse)){assert.ok(Date.now()<deadline);await delay(30);}
  const pause=session.transition('pause');const hangResult=record(await hanging);assert.equal((await pause).status,200);
  const pulseAfter=await readFile(pulse,'utf8');await delay(200);
  check('已派发的暂停记为未知并清理全部后代',hangResult.result._meta.agentguard.dispatched===true&&hangResult.result._meta.agentguard.outcome==='unknown'&&(await readFile(pulse,'utf8'))===pulseAfter);
  assert.equal((await session.transition('resume')).status,200);
  // 第二次悬挂用于实际 SIGKILL 网关恢复；不重放原请求。
  const crashing=rpcCall('mcp__probe__hang',{});const crashObserved=crashing.catch(e=>({expectedDisconnect:e.message}));
  const crashPending=await pendingFor(crashing);assert.equal((await answer(crashPending,'mcp__probe__hang',{})).status,200);
  const calls=join(session.snapshot,'calls.jsonl');deadline=Date.now()+10000;
  while((await readFile(calls,'utf8')).trim().split('\n').length<2){assert.ok(Date.now()<deadline);await delay(30);}
  const crashName=crashPending.binding.action.parameters.container_name;
  session.child.kill('SIGKILL');record(await crashObserved);oldSession=session;session=await start();
  const ids=execFileSync('/usr/local/bin/docker',['ps','-aq','--filter',`name=^/${crashName}$`],{encoding:'utf8',timeout:10000}).trim();
  const ledger=await readFile(fixture.auditDb.replace(/\.[^/.]+$/,'.mcp-runs.jsonl'),'utf8');
  check('实际重启按精确身份清理旧容器并记录未知',ids===''&&ledger.split('\n').some(line=>line&&JSON.parse(line).name===crashName&&JSON.parse(line).phase==='recovered_unknown'));
  check('原动作没有重放，新副本没有悬挂副作用',!await exists(join(session.snapshot,'calls.jsonl')));
  report.recovery=ledger.split('\n').filter(Boolean).map(JSON.parse);
  await writeFile(join(session.snapshot,'manifest-change.txt'),'SYNTHETIC_CHANGE');
  const changed=await invoke('mcp__probe__probe',{});
  check('实际清单改变使旧认可失效且不发送工具调用',changed.result._meta.agentguard.outcome==='unknown'&&(await status()).services.find(s=>s.service_id==='synthetic-probe').state==='pending'&&!await exists(join(session.snapshot,'calls.jsonl')));
  await approveService('official-filesystem');
  const blockedArgs={path:join(fixture.work,'audit-blocked.txt'),content:'MUST_NOT_WRITE'};
  const blocked=rpcCall(name,blockedArgs),blockedPending=await pendingFor(blocked);
  execFileSync('/usr/bin/python3',['-c',"import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute(\"CREATE TRIGGER mcp_test_block BEFORE INSERT ON audit_events WHEN NEW.event_type='GatewayExecutionStarted' BEGIN SELECT RAISE(ABORT,'synthetic start failure'); END\"); db.commit()",fixture.auditDb]);
  assert.equal((await answer(blockedPending,name,blockedArgs)).status,200);
  const blockedResult=record(await blocked);
  check('真实开始审计写入失败时服务不启动且会话禁止新动作',blockedResult.result._meta.agentguard.dispatched===false&&!await exists(join(session.snapshot,'audit-blocked.txt'))&&(await session.rpc('gateway/stats')).result.audit_write_failed===true);
  execFileSync('/usr/bin/python3',['-c',"import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute('DROP TRIGGER mcp_test_block'); db.commit()",fixture.auditDb]);

  report.auditDb=fixture.auditDb;
  report.finishedAt=new Date().toISOString();
} catch(error) {report.error=String(error.stack||error);process.exitCode=1;}
finally {
  if(session) {report.stderr=session.stderrTail;await session.close().catch(e=>{report.closeError=String(e);process.exitCode=1;});}
  if(oldSession) await oldSession.close().catch(e=>{report.oldCloseError=String(e);process.exitCode=1;});
  await writeFile(join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({checks:report.checks.length,passed:report.checks.filter(c=>c.passed).length,error:report.error,out}));
}

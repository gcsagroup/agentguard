// AGD-023：随机主体密钥、独立宿主签名进程、真实 CLI 与隔离文件副作用。只使用合成工作区。
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile, appendFile, access, link, symlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, WorkspaceSession, DEFAULT_IMAGE } from './agd-workspace-session.mjs';
const run=promisify(execFile), sha=x=>createHash('sha256').update(x).digest('hex');
const option=key=>{const i=process.argv.indexOf(key);assert.ok(i>0,`缺少 ${key}`);return process.argv[i+1];};
const binary=resolve(option('--binary')),out=resolve(option('--out'));await mkdir(out,{recursive:false,mode:0o700});
const ordered=value=>Array.isArray(value)?value.map(ordered):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,ordered(value[key])])):value;
const bytes=(domain,value)=>Buffer.from(`agentguard.delegation.${domain}.v1\0${JSON.stringify(ordered(value))}`);
const publicKey=hex=>createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(hex,'hex')]),format:'der',type:'spki'});
const fixture=await createWorkspaceFixture({name:'delegation',seed:{'input.txt':'AGD_DELEGATION_INPUT 中文\n','private.txt':'AGD_PARENT_ONLY_DATA\n','hardlink.txt':'AGD_LINK_ORIGINAL\n','symlink.txt':'AGD_LINK_ORIGINAL\n','remove.txt':'AGD_REMOVE_ME\n'}});
const paths=Object.fromEntries(['input','private','output','late','hardlink','symlink','new','remove'].map(name=>[name,join(fixture.work,`${name}.txt`).replace(/^\/private(?=\/var\/)/,'')]));
// 会话路径已事前授权普通写入；仅对三个自有目标追加规则，以验证仍需独立批准的路径。
await appendFile(fixture.rules, '\n  - id: DELEGATION-TEST-CONFIRM\n    name: 委托独立批准验收\n    severity: high\n    action: alert\n    require_confirm: true\n    platforms: [gateway]\n    match_any_text: ["output.txt", "late.txt", "hardlink.txt"]\n    description: "仅对自有合成目标要求单次批准"\n');
fixture.inputs.rulesSha256=sha(await readFile(fixture.rules));
const secrets={},publics={},keyPaths={};
for(const actor of ['authority','A','B','C']){const pair=generateKeyPairSync('ed25519');secrets[actor]=pair.privateKey.export({type:'pkcs8',format:'der'}).subarray(-32).toString('hex');publics[actor]=pair.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');keyPaths[actor]=join(fixture.control,`${actor}.hex`);await writeFile(keyPaths[actor],secrets[actor],{mode:0o600});}
const rights=(read,write=[],del=[],to=[])=>({read_files:read.slice().sort(),write_files:write.slice().sort(),delete_files:del.slice().sort(),delegate_to:to.slice().sort()});
const rootRights=rights([paths.input,paths.private,paths.hardlink,paths.symlink],[paths.output,paths.late,paths.hardlink,paths.symlink,paths.new],[paths.output,paths.remove],['B','C']);
const bRights=rights([paths.input,paths.hardlink,paths.symlink],[paths.output,paths.late,paths.hardlink,paths.symlink,paths.new],[],['C']);
const cRights=rights([paths.input]);
const config={version:1,authority_id:'acceptance-host',signing_key:keyPaths.authority,public_key:publics.authority,root_subject_id:'A',target_id:'delegated-summary',lifetime_ms:180000,
 principals:[{subject_id:'A',public_key:publics.A,permissions:rootRights},{subject_id:'B',public_key:publics.B,permissions:bRights},{subject_id:'C',public_key:publics.C,permissions:cRights}]};
const configPath=join(fixture.control,'delegation.json');await writeFile(configPath,JSON.stringify(config),{mode:0o600});
const signer=join(fixture.control,'host-signer.cjs');
await writeFile(signer,`const fs=require('node:fs'),c=require('node:crypto');const seed=Buffer.from(fs.readFileSync(process.argv[2],'utf8').trim(),'hex');const key=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});process.stdout.write(JSON.stringify({pid:process.pid,signature:c.sign(null,Buffer.from(process.argv[3],'base64'),key).toString('hex')}));\n`,{mode:0o600});
let session,rootGrant;const sequences=new Map();
const report={schema_version:1,passed:false,binary,binary_sha256:sha(await readFile(binary)),image:DEFAULT_IMAGE,fixture:fixture.temporaryRoot,config:configPath,
 scope:'真实网关与合成主体；签名在隔离任务外的宿主 Node 进程，动作由脚本核对后通过独立 HTTP 通道批准。非原生人工批准。',inputs:fixture.inputs,sessions:[],grants:[],messages:[],negative_messages:[],approvals:[],checks:[],signer_pids:[]};
const save=()=>writeFile(join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
const exists=async path=>{try{await access(path);return true;}catch(error){if(error.code==='ENOENT')return false;throw error;}};
function grant(signed){assert.ok(verify(null,bytes('grant',signed.grant),publicKey(publics.authority),Buffer.from(signed.signature,'hex')));assert.equal(signed.key_id,sha(Buffer.from(publics.authority,'hex')).slice(0,16));assert.equal(signed.grant.host_session_id,session.sessionId);report.grants.push(signed);sequences.set(signed.grant.grant_id,1);return signed;}
async function start(){session=await WorkspaceSession.start({binary,fixture,delegationConfig:configPath,confirmSeconds:8});report.sessions.push({pid:session.child.pid,session_id:session.sessionId,snapshot:session.snapshot,stats:session.statsAtStart});const tools=(await session.rpc('tools/list')).result.tools.map(t=>t.name);assert.deepEqual(tools,['delegation_send']);rootGrant=grant(session.statsAtStart.delegation.root_grant);await save();}
async function stop(){if(session){report.sessions.at(-1).exit=await session.close({preserveSnapshots:true});session=null;await save();}}
async function signed(actor,g,command,override={}){
 // 签名后保留不可变动作快照；后续阶段改变权限夹具时不能改写已记录消息。
 command=structuredClone(command);
 const message={version:1,host_session_id:g.grant.host_session_id,session_id:g.grant.session_id,grant_id:g.grant.grant_id,
 grant_sha256:sha(bytes('grant',g.grant)),actor_id:actor,target_id:g.grant.target_id,sequence:sequences.get(g.grant.grant_id),issued_at_ms:Date.now(),expires_at_ms:Math.min(Date.now()+60000,g.grant.expires_at_ms),operation_sha256:sha(bytes('operation',command)),...override};
 const result=JSON.parse((await run(process.execPath,[signer,keyPaths[actor],bytes('message',message).toString('base64')])).stdout);report.signer_pids.push(result.pid);return {message,command,signature:result.signature};}
const invoke=envelope=>session.rpc('tools/call',{name:'delegation_send',arguments:envelope});
async function negative(envelope){const response=await invoke(envelope);report.negative_messages.push({envelope,response});await save();refused(response);}

async function send(actor,g,command,{approval=null,consume=true,override={},onPending=null}={}){
 const envelope=await signed(actor,g,command,override),pendingCall=invoke(envelope);
 let approvalError;
 try { if(approval){const pending=await session.waitForPending();const action=pending.binding.action;assert.equal(actionSha256(action),pending.action_sha256);assert.equal(action.tool.service,'agentguard-gateway');assert.equal(action.tool.name,command.operation);assert.equal(action.parameters.path,command.path);if('contents'in command)assert.equal(action.parameters.contents,command.contents);
 assert.deepEqual(action.parameters.delegation.message,envelope.message);assert.equal(action.parameters.delegation.signature,envelope.signature);assert.ok(pending.what.includes('经认证的委托主体'));
 assert.equal((await session.operatorRequest('/approve',{id:pending.id,action_sha256:pending.action_sha256,approval_nonce:pending.binding.nonce},{omitAuthorization:true})).status,403);
 if(approval==='expire')await delay(900);
 report.approvals.push({choice:approval,envelope,pending});await save();
 if(onPending){await onPending(pending,envelope);}else{const response=await session.operatorRequest(approval==='deny'?'/deny':'/approve',{id:pending.id,action_sha256:pending.action_sha256,approval_nonce:pending.binding.nonce});assert.equal(response.status===200,approval!=='expire');}
 }} catch(error){approvalError=error;}
 const response=await pendingCall;if(consume)sequences.set(g.grant.grant_id,envelope.message.sequence+1);
 report.messages.push({envelope,response,authenticated_expected:consume});await save();if(approvalError)throw new Error(`${approvalError.message}；真实工具回执：${JSON.stringify(response)}`);return {envelope,response};
}
function good(response){assert.equal(response.result?.isError,false,JSON.stringify(response));return response.result.content[0].text;}
function refused(response){assert.equal(response.result?.isError,true,JSON.stringify(response));assert.equal(response.result._meta?.agentguard?.dispatched,false);}
async function delegate(actor,g,subject,permissions=rootRights,expires=Date.now()+150000){const {response}=await send(actor,g,{operation:'delegate',subject_id:subject,permissions,expires_at_ms:expires});return grant(JSON.parse(good(response)).grant);}
try{
 if(process.argv.includes('--propagation-mode')){
  const {runPropagationAcceptance}=await import('./agd-propagation.mjs');
  await runPropagationAcceptance({get session(){return session;},get rootGrant(){return rootGrant;},config,configPath,rootRights,bRights,cRights,paths,fixture,out,report,start,stop,send,delegate,good,refused,negative,save});
 }else if(process.argv.includes('--budget-mode')){
  const {runBudgetAcceptance}=await import('./agd-delegation-budget.mjs');
  await runBudgetAcceptance({get session(){return session;},get rootGrant(){return rootGrant;},config,configPath,rootRights,bRights,cRights,paths,fixture,out,report,start,stop,send,delegate,good,refused,negative,save});
 }else{
 await start();assert.deepEqual(rootGrant.grant.permissions,rootRights);
 // 同一连接上的公开宿主会话 ID 不能让子主体绕回普通工具。
 for(const name of ['read_file','write_file','run_shell','start_session','memory_write','browser_read_page']){const response=await session.rpc('tools/call',{name,arguments:{path:paths.private,contents:'不应写入',argv:['id']},_meta:{agentguard_session_id:session.sessionId}});assert.equal(response.result.isError,true);}
 report.checks.push('委托模式只发布签名入口，普通工具不能绕过');
 const b=await delegate('A',rootGrant,'B');assert.deepEqual(b.grant.permissions,bRights);assert.equal(b.grant.parent_session_id,rootGrant.grant.session_id);assert.equal(b.grant.parent_grant_sha256,sha(bytes('grant',rootGrant.grant)));
 const c=await delegate('B',b,'C');assert.deepEqual(c.grant.permissions,cRights);assert.equal(c.grant.parent_session_id,b.grant.session_id);
 const {response:read}=await send('C',c,{operation:'read_file',path:paths.input});assert.ok(good(read).includes('AGD_DELEGATION_INPUT'));
 const blocked=[{operation:'read_file',path:paths.private},{operation:'write_file',path:paths.output,contents:'不应写入'},{operation:'delete_file',path:paths.input},{operation:'delegate',subject_id:'B',permissions:rootRights,expires_at_ms:Date.now()+60000}];
 for(const command of blocked)refused((await send('C',c,command,{consume:false})).response);
 for(const path of Object.values(keyPaths))refused((await send('B',b,{operation:'read_file',path},{consume:false})).response);
 assert.equal(await exists(join(session.snapshot,'output.txt')),false);
 const valid=await signed('B',b,{operation:'read_file',path:paths.input});
 for(const field of Object.keys(valid.message)){const changed=structuredClone(valid);changed.message[field]=typeof changed.message[field]==='number'?changed.message[field]+1:field.endsWith('sha256')?'a'.repeat(64):'different';await negative(changed);}
 const altered=structuredClone(valid);altered.command.path=paths.private;await negative(altered);
 for(const override of [{actor_id:'C'},{session_id:rootGrant.grant.session_id},{target_id:'different-target'},{host_session_id:'old-host'},{sequence:99},{grant_sha256:'b'.repeat(64)}])refused((await send('B',b,{operation:'read_file',path:paths.input},{consume:false,override})).response);
 report.checks.push('A→B→C 权限递减、字段篡改、签名身份／目标／会话置换和乱序拒绝');
 const preapproved=await send('B',b,{operation:'write_file',path:paths.new,contents:'AGD_PREAPPROVED_NEW\n'});good(preapproved.response);assert.equal(await readFile(join(session.snapshot,'new.txt'),'utf8'),'AGD_PREAPPROVED_NEW\n');assert.equal(await exists(paths.new),false);
 const denied=await send('B',b,{operation:'write_file',path:paths.output,contents:'不应保存'},{approval:'deny'});refused(denied.response);assert.equal(await exists(join(session.snapshot,'output.txt')),false);await negative(denied.envelope);
 const saved=await send('B',b,{operation:'write_file',path:paths.output,contents:'AGD_DELEGATED_REPORT 中文\n'},{approval:'approve'});good(saved.response);assert.equal(await readFile(join(session.snapshot,'output.txt'),'utf8'),'AGD_DELEGATED_REPORT 中文\n');assert.equal(await exists(paths.output),false);await negative(saved.envelope);
 // 快照中制造链接负例，工具须在截断写入前拒绝，不能修改另一个文件。
 const linkTarget=join(session.snapshot,'hardlink-alias.txt');await link(join(session.snapshot,'hardlink.txt'),linkTarget);
 const hard=await send('B',b,{operation:'write_file',path:paths.hardlink,contents:'不应穿透硬链接'},{approval:'approve'});assert.equal(hard.response.result.isError,true);assert.equal(await readFile(linkTarget,'utf8'),'AGD_LINK_ORIGINAL\n');assert.equal(await readFile(join(session.snapshot,'hardlink.txt'),'utf8'),'AGD_LINK_ORIGINAL\n');
 // 对已经授权的名字做符号链接置换；只改本脚本拥有的快照。
 const {unlink}=await import('node:fs/promises');await unlink(join(session.snapshot,'symlink.txt'));await symlink(paths.private,join(session.snapshot,'symlink.txt'));
 const symbolic=await send('B',b,{operation:'read_file',path:paths.symlink});assert.equal(symbolic.response.result.isError,true);assert.ok(!symbolic.response.result.content[0].text.includes('AGD_PARENT_ONLY_DATA'));
 const removed=await send('A',rootGrant,{operation:'delete_file',path:paths.remove});good(removed.response);assert.equal(await exists(join(session.snapshot,'remove.txt')),false);assert.equal(await readFile(paths.remove,'utf8'),'AGD_REMOVE_ME\n');
 const expiring=await send('B',b,{operation:'write_file',path:paths.late,contents:'不应超期写入'},{approval:'expire',override:{expires_at_ms:Date.now()+500}});refused(expiring.response);assert.equal(await exists(join(session.snapshot,'late.txt')),false);
 const short=await delegate('A',rootGrant,'B',bRights,Date.now()+600);const shortMessage=await signed('B',short,{operation:'read_file',path:paths.input});await delay(800);await negative(shortMessage);
 report.checks.push('独立批准拒绝／通过、消息重放、等待中过期、短授权到期和链接置换均核对实际文件');
 // 去掉本脚本注入的链接负例后，只向宿主回写已复核报告。
 await unlink(linkTarget);await unlink(join(session.snapshot,'symlink.txt'));await writeFile(join(session.snapshot,'symlink.txt'),'AGD_LINK_ORIGINAL\n');
 const status=await session.workspaceStatus();const review=await session.previewWorkspace(status.workspaces[0].workspace_id);assert.deepEqual(review.preview.changes.map(c=>c.path),['new.txt','output.txt','remove.txt']);const applied=await session.applyReview(review);assert.equal(applied.status,200);assert.equal(applied.value.result.outcome,'applied');assert.equal(await readFile(paths.output,'utf8'),'AGD_DELEGATED_REPORT 中文\n');
 assert.equal(await exists(paths.remove),false);
 report.host_writeback={review_sha256:review.review_sha256,outcome:'applied',output_sha256:sha(await readFile(paths.output))};
 const oldEnvelope=saved.envelope,oldSession=session.sessionId;await stop();await start();assert.notEqual(session.sessionId,oldSession);await negative(oldEnvelope);assert.equal(await readFile(paths.output,'utf8'),'AGD_DELEGATED_REPORT 中文\n');
 const final=await send('A',rootGrant,{operation:'read_file',path:paths.input});good(final.response);await stop();
 assert.equal(report.sessions.length,2);assert.ok(report.sessions.every(s=>s.exit.code===0));assert.equal(new Set(report.signer_pids).size,report.signer_pids.length);
 const body=JSON.stringify(report);for(const secret of Object.values(secrets))assert.ok(!body.includes(secret),'私钥不能进入验收报告或任务参数');
 report.checks.push('两次真实网关进程旧授权失效；宿主签名进程独立，私钥未进入任务或报告');report.passed=true;
 }
}catch(error){report.error=session?session.redact(error.stack):String(error.stack);process.exitCode=1;}
finally{await stop().catch(error=>{report.cleanup_error=String(error);process.exitCode=1;});await save();console.log(JSON.stringify({passed:report.passed,checks:report.checks,error:report.error,out}));}

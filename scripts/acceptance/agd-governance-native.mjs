// 给固定 App 的原生操作提供真实合成网关。只在种入测试资料时由脚本批准。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, readFile, writeFile, appendFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { actionSha256 } from '../../apps/protected-browser/execution-contract.mjs';
import { createWorkspaceFixture, WorkspaceSession, DEFAULT_IMAGE } from './agd-workspace-session.mjs';
const option = key => { const i=process.argv.indexOf(key); assert.ok(i>0,`缺少 ${key}`); return process.argv[i+1]; };
const binary=resolve(option('--binary')), out=resolve(option('--out')), mode=option('--mode');
assert.ok(['memory','delegation'].includes(mode)); await mkdir(out,{recursive:false,mode:0o700});
const sha=b=>createHash('sha256').update(b).digest('hex');
const fixture=await createWorkspaceFixture({name:`native-governance-${mode}`,seed:{'input.txt':'合成治理资料，不包含用户内容。\n'}});
const report={mode,binary,binary_sha256:sha(await readFile(binary)),image:DEFAULT_IMAGE,fixture:fixture.temporaryRoot,execution_database:fixture.auditDb,seeds:[],snapshots:[],messages:[],passed:false};
const save=()=>writeFile(join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
const pair=()=>{const p=generateKeyPairSync('ed25519');return {privateKey:p.privateKey,secret:p.privateKey.export({type:'pkcs8',format:'der'}).subarray(-32).toString('hex'),public:p.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex')};};
let session,pendingCall,root,child,grandchild;const actors={},sequences=new Map();
const configPath=join(fixture.control,`${mode}.json`);
const ordered=v=>Array.isArray(v)?v.map(ordered):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,ordered(v[k])])):v;
const bytes=(domain,v)=>Buffer.from(`agentguard.delegation.${domain}.v1\0${JSON.stringify(ordered(v))}`);
const input=join(fixture.work,'input.txt').replace(/^\/private(?=\/var\/)/,''),output=join(fixture.work,'output.txt').replace(/^\/private(?=\/var\/)/,'');
async function signed(actor,grant,command) {
 const g=grant.grant;const message={version:1,host_session_id:g.host_session_id,session_id:g.session_id,grant_id:g.grant_id,grant_sha256:sha(bytes('grant',g)),actor_id:actor,target_id:g.target_id,sequence:sequences.get(g.grant_id)||1,issued_at_ms:Date.now(),expires_at_ms:Math.min(Date.now()+120000,g.expires_at_ms),operation_sha256:sha(bytes('operation',command))};
 return {message,command,signature:sign(null,bytes('message',message),actors[actor].privateKey).toString('hex')};
}
async function send(actor,grant,command) {
 const envelope=await signed(actor,grant,command),response=await session.rpc('tools/call',{name:'delegation_send',arguments:envelope},{timeoutMs:150000});
 report.messages.push({envelope,response});sequences.set(grant.grant.grant_id,envelope.message.sequence+1);await save();return response;
}
const good=r=>{assert.equal(r.result?.isError,false,JSON.stringify(r));return JSON.parse(r.result.content[0].text);};
async function inspect(label) {
 const response=await session.operatorRequest(mode==='memory'?'/memory/history':'/delegation/status',mode==='memory'?{session_id:session.sessionId,key:'preference',after_version:0}:undefined);
 assert.equal(response.status,200);report.snapshots.push({label,at:Date.now(),response});await save();
 console.log(JSON.stringify(mode==='memory'?{label,versions:response.value.data.versions.map(v=>({version:v.version,state:v.state,label:v.label,content:v.content,sources:v.sources.length}))}:{label,nodes:response.value.budget.nodes.map(n=>({grant_id:n.grant_id,parent:n.parent_grant_id,revoked:n.revoked}))}));
}
try {
 if(mode==='memory') {
  await writeFile(fixture.plans,JSON.stringify({plans:[{task_profile:fixture.taskProfile,allow:['persist_memory','recall_memory'],scope:{data_keys:['preference'],paths:{read:[fixture.work],write:[]}}}]}));
  const key=pair();const config={schema_version:1,scope_id:'native-governance-026',database:join(fixture.control,'memory.db'),witness:join(fixture.control,'memory-head.json'),signing_key:join(fixture.control,'memory-secret.hex'),public_key:join(fixture.control,'memory-public.hex'),allow_read:true,allow_write:true,encryption:{mode:'plaintext_test'}};
  for(const [path,value] of [[config.signing_key,key.secret],[config.public_key,key.public],[configPath,JSON.stringify(config)]])await writeFile(path,value,{mode:0o600});
  report.memory_database=config.database;report.memory_witness=config.witness;report.public_key=key.public;
  session=await WorkspaceSession.start({binary,fixture,memoryConfig:configPath,initializeMemory:true,confirmSeconds:120});
  for(const [expected_version,text] of [[0,'旧偏好：使用中文；这是合成测试记录。'],[1,'新偏好：逐项列出证据；这是合成测试记录。']]){
   const args={key:'preference',expected_version,text,expires_at_ms:Date.now()+3600000};
   const response=session.rpc('tools/call',{name:'memory_write',arguments:args,_meta:{agentguard_session_id:session.sessionId}}),pending=await session.waitForPending();
   assert.equal(actionSha256(pending.binding.action),pending.action_sha256);assert.equal(pending.binding.action.parameters.key,args.key);assert.equal(pending.binding.action.parameters.version,expected_version+1);assert.equal(JSON.parse(pending.binding.action.parameters.content).text,text);
   assert.equal((await session.operatorRequest('/approve',{id:pending.id,action_sha256:pending.action_sha256,approval_nonce:pending.binding.nonce})).status,200);
   const result=await response;assert.equal(good(result).saved,true);report.seeds.push({args,pending,result});
  }
 } else {
  for(const name of ['authority','A','B','C'])actors[name]=pair();
  const signingKey=join(fixture.control,'authority.hex');await writeFile(signingKey,actors.authority.secret,{mode:0o600});
  const rights={read_files:[input],write_files:[output],delete_files:[],delegate_to:['B','C']};
  const config={version:1,authority_id:'native-test-host',signing_key:signingKey,public_key:actors.authority.public,root_subject_id:'A',target_id:'native-test',lifetime_ms:1800000,budgets:{max_depth:3,max_calls:32,max_output_bytes:1048576,max_elapsed_ms:1800000},principals:['A','B','C'].map(subject_id=>({subject_id,public_key:actors[subject_id].public,permissions:rights}))};
  await writeFile(configPath,JSON.stringify(config),{mode:0o600});
  await appendFile(fixture.rules,'\n  - id: NATIVE-DELEGATION-CONFIRM\n    name: 原生停止验收\n    severity: high\n    action: alert\n    require_confirm: true\n    platforms: [gateway]\n    match_any_text: ["output.txt"]\n    description: 合成写入等待独立批准\n');
  session=await WorkspaceSession.start({binary,fixture,delegationConfig:configPath,confirmSeconds:120});root=session.statsAtStart.delegation.root_grant;
  child=good(await send('A',root,{operation:'delegate',subject_id:'B',permissions:rights,expires_at_ms:Date.now()+1500000})).grant;
  grandchild=good(await send('B',child,{operation:'delegate',subject_id:'C',permissions:rights,expires_at_ms:Date.now()+1200000})).grant;
  report.grants=[root,child,grandchild];report.public_keys=Object.fromEntries(Object.entries(actors).map(([k,v])=>[k,v.public]));report.output=output;
 }
 report.session={pid:session.child.pid,session_id:session.sessionId,control_file:session.controlFile,snapshot:session.snapshot};
 await inspect('before_native');console.log(JSON.stringify({ready:true,mode,control_file:session.controlFile,session_id:session.sessionId,out}));
 const lines=createInterface({input:process.stdin});
 for await(const line of lines){
  const command=JSON.parse(line);
  if(command.operation==='inspect')await inspect(command.label||'native_checkpoint');
  else if(command.operation==='queue' && mode==='delegation') {
   assert.ok(!pendingCall);pendingCall=send('B',child,{operation:'write_file',path:output,contents:'撤销父分支后不应出现的合成写入'});
   const pending=await session.waitForPending();report.pending=pending;await save();console.log(JSON.stringify({waiting:true,stop_grant:child.grant.grant_id,descendant:grandchild.grant.grant_id}));
  } else if(command.operation==='finish') {
   if(pendingCall){report.pending_result=await pendingCall;assert.equal(report.pending_result.result._meta.agentguard.outcome,'cancelled');assert.equal(report.pending_result.result._meta.agentguard.dispatched,false);}
   await inspect('after_native');
   const last=report.snapshots.at(-1).response.value;
   if(mode==='memory') {
    const versions=last.data.versions;assert.deepEqual(versions.map(v=>v.state),['active','active','quarantined','active','revoked']);
    assert.deepEqual(versions[3].content,versions[0].content);assert.ok(versions.every(v=>v.label.integrity==='tainted'&&v.label.confidentiality==='high'));
    assert.ok(versions[1].sources.every(source=>versions[3].sources.some(s=>JSON.stringify(s)===JSON.stringify(source))));
   } else {
    assert.ok(pendingCall,'必须验证等待批准时的父撤销');
    for(const grant of [child,grandchild])assert.equal(last.budget.nodes.find(n=>n.grant_id===grant.grant.grant_id).revoked,true);
    assert.equal(last.budget.nodes.find(n=>n.grant_id===root.grant.grant_id).revoked,false);
    for(const path of [output,join(session.snapshot,'output.txt')]){
     try{await readFile(path);throw new Error('撤销后仍存在输出文件');}catch(error){assert.equal(error.code,'ENOENT');}
    }
   }
   report.passed=true;lines.close();break;
  }else throw new Error('只接受 inspect、queue 或 finish');
 }
} catch(error){report.error=String(error);throw error;}
finally{if(session)report.exit=await session.close({preserveSnapshots:true});await save();console.log(JSON.stringify({closed:true,passed:report.passed,out}));}

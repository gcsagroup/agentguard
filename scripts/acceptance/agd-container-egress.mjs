// 独立出口探针：仅用本脚本生成的内容与本机接收服务，不读取真实用户凭据。
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { readFile, writeFile, mkdir, realpath, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { WorkspaceSession, createWorkspaceFixture, fileTree, DEFAULT_IMAGE, ROOT } from './agd-workspace-session.mjs';

const run = promisify(execFile), sha = data => createHash('sha256').update(data).digest('hex');
const docker = args => run('/usr/local/bin/docker', args, { encoding: 'utf8', timeout: 35000, maxBuffer: 4 * 1024 * 1024 });
const nodeProgram = String.raw`const fs=require('node:fs'),net=require('node:net'),http=require('node:http'),dns=require('node:dns').promises,dgram=require('node:dgram'),cp=require('node:child_process'),os=require('node:os');
const c=JSON.parse(process.argv[2]);
const attempt=async fn=>{try{await fn();return {reached:true}}catch(e){return {reached:false,code:String(e.code||e.name||'ERROR')}}};
const connect=(host,port,path)=>new Promise((yes,no)=>{const s=net.createConnection(path?{path}:{host,port});s.setTimeout(600,()=>s.destroy(Object.assign(new Error('timeout'),{code:'TIMEOUT'})));s.once('error',no);s.once('connect',()=>{s.end();yes()})});
const get=(host,path,depth=0)=>new Promise((yes,no)=>{const r=http.get({hostname:host,port:c.httpPort,path,timeout:600},s=>{s.resume();if(s.statusCode===302&&depth<2){get(host,s.headers.location,depth+1).then(yes,no)}else if(s.statusCode===200){yes()}else no(new Error('HTTP_STATUS'))});r.on('timeout',()=>r.destroy(Object.assign(new Error('timeout'),{code:'TIMEOUT'})));r.on('error',no)});
const udp=()=>new Promise((yes,no)=>{const s=dgram.createSocket('udp4');let ended=false;const finish=e=>{if(ended)return;ended=true;clearTimeout(t);s.close();e?no(e):yes()};const t=setTimeout(()=>finish(Object.assign(new Error('timeout'),{code:'TIMEOUT'})),600);s.once('error',finish);s.once('message',()=>finish());s.send(Buffer.from('AGD_SYNTHETIC_UDP'),c.udpPort,c.host,e=>{if(e)finish(e)})});
(async()=>{const result={runtime:'node',child:process.argv.includes('--child'),envAbsent:!('AGD_HOST_ONLY_TEST_TOKEN'in process.env)&&!('AGD_EGRESS_SYNTHETIC_TOKEN'in process.env),files:{},network:{},interfaces:Object.keys(os.networkInterfaces())};
for(const [name,path]of Object.entries(c.files)){try{fs.readFileSync(path);result.files[name]={readable:true}}catch(e){result.files[name]={readable:false,code:e.code}}}
result.unix=await attempt(()=>connect(null,null,c.unix));
for(const [name,fn]of Object.entries({direct_ip:()=>connect(c.host,c.httpPort),http_redirect:()=>get(c.host,'/redirect'),udp:()=>udp(),dns:async()=>{const r=new dns.Resolver({timeout:600,tries:1});r.setServers([c.host+':'+c.dnsPort]);await r.resolve4('agd-synthetic.invalid')},ipv6_mapped:()=>connect('::ffff:'+c.host,c.httpPort),ipv6_loopback:()=>connect('::1',c.httpPort)})){result.network[name]=await attempt(fn)}
if(!result.child){const r=cp.spawnSync(process.execPath,[__filename,JSON.stringify(c),'--child'],{encoding:'utf8',timeout:12000});if(r.status!==0)throw new Error('CHILD_FAILED');result.descendant=JSON.parse(r.stdout)}
console.log(JSON.stringify(result))})().catch(e=>{console.error(String(e.code||e.message));process.exitCode=1});`;
const pythonProgram = String.raw`import os,sys,json,socket,urllib.request,subprocess,struct
c=json.loads(sys.argv[1])
def attempt(fn):
 try: fn();return {'reached':True}
 except Exception as e:return {'reached':False,'code':str(getattr(e,'errno',None) or type(e).__name__)}
def conn(host,port,family=socket.AF_INET):
 with socket.socket(family,socket.SOCK_STREAM) as s:s.settimeout(.6);s.connect((host,port))
def unix():
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:s.settimeout(.6);s.connect(c['unix'])
def udp(dns=False):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(.6)
  body=struct.pack('!HHHHHH',4359,256,1,0,0,0)+b'\x0dagd-synthetic\x07invalid\x00\x00\x01\x00\x01' if dns else b'AGD_SYNTHETIC_UDP'
  s.sendto(body,(c['host'],c['dnsPort'] if dns else c['udpPort']));s.recvfrom(512)
def http():
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 with opener.open('http://'+c['host']+':'+str(c['httpPort'])+'/redirect',timeout=.6) as r:
  if r.status!=200:raise RuntimeError('HTTP_STATUS')
r={'runtime':'python','child':'--child' in sys.argv,'envAbsent':'AGD_HOST_ONLY_TEST_TOKEN' not in os.environ and 'AGD_EGRESS_SYNTHETIC_TOKEN' not in os.environ,'files':{},'network':{}}
for name,path in c['files'].items():
 try:
  with open(path,'rb') as f:f.read(1)
  r['files'][name]={'readable':True}
 except OSError as e:r['files'][name]={'readable':False,'code':e.errno}
r['unix']=attempt(unix)
for name,fn in {'direct_ip':lambda:conn(c['host'],c['httpPort']),'http_redirect':http,'udp':udp,'dns':lambda:udp(True),'ipv6_mapped':lambda:conn('::ffff:'+c['host'],c['httpPort'],socket.AF_INET6),'ipv6_loopback':lambda:conn('::1',c['httpPort'],socket.AF_INET6)}.items():r['network'][name]=attempt(fn)
if not r['child']:
 p=subprocess.run([sys.executable,__file__,json.dumps(c),'--child'],capture_output=True,text=True,timeout=12,check=True);r['descendant']=json.loads(p.stdout)
print(json.dumps(r))
`;

function validate(result, isolated) {
  for (const part of [result, result.descendant]) {
    assert.ok(part && part.runtime && typeof part.envAbsent === 'boolean');
    assert.equal(part.envAbsent, true, '宿主合成环境变量泄漏');
    for (const file of Object.values(part.files)) assert.equal(file.readable, false, '容器读取到了宿主专属文件');
    assert.equal(part.unix.reached, false, '容器连接到了宿主专属Unix socket');
    for (const [name, result] of Object.entries(part.network)) {
      // Docker VM 未提供原生 IPv6 宿主地址；::1 仅覆盖容器回环，不能冒充可达的 IPv6 外部目标。
      assert.equal(result.reached, !isolated && name !== 'ipv6_loopback', `${part.runtime}/${part.child}/${name}`);
    }
  }
}

async function main() {
  const args=process.argv.slice(2), arg=name=>args.includes(name)?args[args.indexOf(name)+1]:undefined;
  const preflight=args.includes('--preflight'), binary=arg('--binary'), expected=arg('--sha256'), python=arg('--python');
  assert.ok(python && resolve(python) === python, '须显式指定绝对 --python 路径');
  assert.ok(preflight !== Boolean(binary), '选择 --preflight 或 --binary PATH --sha256 SHA');
  if(binary){assert.equal(resolve(binary),binary);assert.match(expected||'',/^[a-f0-9]{64}$/);assert.equal(sha(await readFile(binary)),expected)}
  const out=resolve(arg('--out')||join(ROOT,'.artifacts',`container-egress-${preflight?'preflight':'candidate'}-${Date.now()}`));
  await mkdir(out); // 拒绝覆盖已有结果。
  const sources=[fileURLToPath(import.meta.url),join(ROOT,'scripts/acceptance/agd-workspace-session.mjs'),join(ROOT,'apps/protected-browser/execution-contract.mjs'),join(ROOT,'crates/guard-schema/rules/p0_rules.yaml'),join(ROOT,'crates/guard-shell/policies/default.yaml')];
  const sourceHashes=Object.fromEntries(await Promise.all(sources.map(async path=>[path,sha(await readFile(path))])));
  await writeFile(join(out,'probe-source.mjs'),await readFile(sources[0]));
  const fixture=await createWorkspaceFixture({name:'independent-egress',seed:{'probe.cjs':nodeProgram,'probe.py':pythonProgram}});
  const privatePath=join(fixture.control,'synthetic-private.txt'),approvalPath=join(fixture.control,'synthetic-approval.json'),unixPath=join(fixture.temporaryRoot,'s.sock');
  await writeFile(privatePath,'AGD_SYNTHETIC_PRIVATE_FILE\n',{mode:0o600});await writeFile(approvalPath,'{"token":"AGD_SYNTHETIC_APPROVAL_ONLY"}\n',{mode:0o600});
  const report={schema:1,hostPython:python,mode:preflight?'actual_docker_probe_calibration':'frozen_candidate_gateway_probe',completeTasks:0,startedAt:new Date().toISOString(),image:DEFAULT_IMAGE,binary,binarySha256:expected,sourceHashes,checks:[],limitations:['IPv6 映射 IPv4 路径有正向校准；本机未配置容器可达的原生 IPv6 服务，::1 只覆盖容器回环。','默认网络只用于证明合成本机接收器和探针有效；不计产品出口控制通过。'],passed:false};
  const received={httpConnections:0,httpRequests:0,redirect:0,target:0,udp:0,dns:0,unix:0},containers=[];
  // 只添加本次合成值；不检查或打印其他环境变量内容。
  const originalSynthetic=process.env.AGD_EGRESS_SYNTHETIC_TOKEN;
  process.env.AGD_EGRESS_SYNTHETIC_TOKEN='AGD_EGRESS_SYNTHETIC_HOST_ONLY';
  let session,http,udp,dns,unix;
  try {
    assert.equal((await docker(['image','inspect','--format','{{.Id}}',DEFAULT_IMAGE])).stdout.trim(),DEFAULT_IMAGE);
    http=createServer((req,res)=>{received.httpRequests++;if(req.url==='/redirect'){received.redirect++;res.writeHead(302,{Location:'/target'});res.end()}else{received.target++;res.writeHead(200,{'Content-Type':'text/plain'});res.end('AGD_SYNTHETIC_RESPONSE')}});
    http.on('connection',socket=>{received.httpConnections++;socket.setTimeout(1500,()=>socket.destroy())});await new Promise((yes,no)=>{http.once('error',no);http.listen(0,'0.0.0.0',yes)});
    udp=createSocket('udp4');udp.on('message',(msg,remote)=>{received.udp++;udp.send(msg,remote.port,remote.address)});await new Promise((yes,no)=>{udp.once('error',no);udp.bind(0,'0.0.0.0',yes)});
    dns=createSocket('udp4');dns.on('message',(msg,remote)=>{received.dns++;if(msg.length<12)return;const head=Buffer.from(msg.subarray(0,12));head.writeUInt16BE(0x8180,2);head.writeUInt16BE(1,6);const answer=Buffer.from('c00c000100010000000400047f000001','hex');dns.send(Buffer.concat([head,msg.subarray(12),answer]),remote.port,remote.address)});await new Promise((yes,no)=>{dns.once('error',no);dns.bind(0,'0.0.0.0',yes)});
    unix=tcpServer(socket=>{received.unix++;socket.end()});await new Promise((yes,no)=>{unix.once('error',no);unix.listen(unixPath,yes)});
    const address=JSON.parse((await docker(['run','--rm','--pull=never',DEFAULT_IMAGE,'/usr/bin/python3','-c','import socket,json; print(json.dumps(socket.gethostbyname("host.docker.internal")))'])).stdout);
    assert.match(address,/^\d+\.\d+\.\d+\.\d+$/);
    const config={host:address,httpPort:http.address().port,udpPort:udp.address().port,dnsPort:dns.address().port,unix:unixPath,files:{private:privatePath,approval:approvalPath,docker_socket:'/var/run/docker.sock'}};
    report.targets={...config,receivers:'仅本脚本本机服务'};
    // 同一探针在宿主必须看到合成环境、两个合成文件和本次 Unix socket，排除假阴性。
    for(const runtime of ['node','python']){
      const result=JSON.parse((await run(runtime==='node'?process.execPath:python,[join(fixture.work,runtime==='node'?'probe.cjs':'probe.py'),JSON.stringify({...config,host:'127.0.0.1'})],{encoding:'utf8',timeout:20000,maxBuffer:1024*1024})).stdout);
      await writeFile(join(out,`host-sensitivity-${runtime}.json`),JSON.stringify(result,null,2)+'\n');
      for(const part of [result,result.descendant]){assert.equal(part.envAbsent,false);assert.equal(part.files.private.readable,true);assert.equal(part.files.approval.readable,true);assert.equal(part.unix.reached,true);for(const [name,value]of Object.entries(part.network))assert.equal(value.reached,name!=='ipv6_loopback')}
      report.checks.push({id:`host-sensitivity-${runtime}`,passed:true,result});
    }
    // 所有探针都先用相同镜像默认网络运行，证明本机目标和超时预算有效。
    async function direct(runtime,network){
      const name=`agd-egress-${randomUUID()}`;containers.push(name);
      const script=runtime==='node'?'probe.cjs':'probe.py',exe=runtime==='node'?'/usr/local/bin/node':'/usr/bin/python3';
      const call=await docker(['run','--rm','--pull=never','--name',name,'--network',network,'--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--mount',`type=bind,src=${fixture.work},dst=/probe,readonly`,DEFAULT_IMAGE,exe,`/probe/${script}`,JSON.stringify(config)]);
      return JSON.parse(call.stdout);
    }
    for(const runtime of ['node','python']){const result=await direct(runtime,'bridge');validate(result,false);report.checks.push({id:`positive-${runtime}`,passed:true,result})}
    report.positiveReceipts={...received};assert.ok(received.redirect>=4&&received.target>=4&&received.udp>=4&&received.dns>=4);
    let declaredWork=fixture.work;
    if(binary){session=await WorkspaceSession.start({binary,fixture});config.files.gateway_control=session.controlFile;report.session={pid:session.child.pid,connection:session.connection,snapshotRoot:session.snapshotRoot,stats:session.statsAtStart};
      const mounts=session.statsAtStart.execution_backend.workspace_mounts;assert.equal(mounts.length,1);declaredWork=mounts[0].target;
      assert.equal(await realpath(declaredWork),await realpath(fixture.work));const actual=await stat(declaredWork),fixtureStat=await stat(fixture.work);assert.equal(actual.dev,fixtureStat.dev);assert.equal(actual.ino,fixtureStat.ino);
      report.declaredWorkspace={path:declaredWork,fixture:fixture.work,sameDeviceAndInode:true};
    }
    const before={...received};
    for(const runtime of ['node','python']){
      let result,tool;
      if(preflight)result=await direct(runtime,'none');
      else{const argv=[runtime==='node'?'/usr/local/bin/node':'/usr/bin/python3',join(declaredWork,runtime==='node'?'probe.cjs':'probe.py'),JSON.stringify(config)];tool=await session.callTool('run_shell',{argv,cwd:declaredWork},{approval:'approve',timeoutMs:45000});assert.equal(tool.ok,true,session.redact(tool));result=JSON.parse(tool.text);await writeFile(join(out,`${runtime}-raw.json`),session.redact(tool.raw));}
      validate(result,true);report.checks.push({id:`isolated-${runtime}`,passed:true,result,...(tool?{confirmations:tool.confirmations,businessSha256:sha(tool.text),rawSha256:sha(session.redact(tool.raw))}:{})});
    }
    await delay(200);report.isolatedReceipts=Object.fromEntries(Object.keys(received).map(key=>[key,received[key]-before[key]]));assert.ok(Object.values(report.isolatedReceipts).every(count=>count===0),'隔离执行仍有接收端入站');
    assert.deepEqual(await fileTree(fixture.work),fixture.initialTree);report.hostWorkspaceUnchanged=true;
    report.passed=true;
  }catch(error){report.error=session?session.redact(error.stack||error.message):String(error.stack||error)}
  finally{
    try{await session?.close({preserveSnapshots:!report.passed});for(const name of containers){await docker(['rm','-f',name]).catch(error=>{if(!/No such (container|object)/i.test(error.stderr||''))throw error})}
      const ids=(await docker(['ps','-a','--format','{{.ID}}'])).stdout.trim().split('\n').filter(Boolean),remaining=[];
      for(const id of ids){let data;try{data=JSON.parse((await docker(['inspect',id])).stdout)[0]}catch(error){if(/No such (container|object)/i.test(error.stderr||''))continue;throw error}if(containers.includes(data.Name.replace(/^\//,''))||session&&data.Mounts.some(m=>m.Source.startsWith(session.snapshotRoot+'/')))remaining.push(id)}
      report.remainingOwnContainers=remaining;assert.deepEqual(remaining,[]);
    }catch(error){report.cleanupError=String(error.message);report.passed=false}
    await Promise.all([http&&new Promise(yes=>{http.closeAllConnections();http.close(yes)}),udp&&new Promise(yes=>udp.close(yes)),dns&&new Promise(yes=>dns.close(yes)),unix&&new Promise(yes=>unix.close(yes))]);
    report.sourcesUnchanged=(await Promise.all(sources.map(async path=>sha(await readFile(path))===sourceHashes[path]))).every(Boolean);if(!report.sourcesUnchanged){report.passed=false;report.sourceChange='源码依赖运行期间变化，结果只可作开发诊断'}
    if(binary){report.binaryUnchanged=sha(await readFile(binary))===expected;if(!report.binaryUnchanged)report.passed=false}
    if(report.passed)await fixture.cleanup();else report.retainedFixture=fixture.temporaryRoot;
    if(originalSynthetic===undefined)delete process.env.AGD_EGRESS_SYNTHETIC_TOKEN;else process.env.AGD_EGRESS_SYNTHETIC_TOKEN=originalSynthetic;
    report.finishedAt=new Date().toISOString();await writeFile(join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
  }
  console.log(JSON.stringify({passed:report.passed,mode:report.mode,completeTasks:0,report:join(out,'report.json'),error:report.error,cleanupError:report.cleanupError}));if(!report.passed)process.exitCode=1;
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});

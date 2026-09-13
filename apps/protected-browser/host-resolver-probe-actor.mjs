// 专项测试入口，由真实BrowserActor沙箱启动；不注册到产品工具清单或桌面资源。
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { lookup } from 'node:dns/promises';
import { createSocket } from 'node:dgram';
import { HostConnection } from './host-connection.mjs';

const hostFile = process.argv[process.argv.indexOf('--host-file') + 1];
const host = await HostConnection.open(hostFile);
async function resolver() {
  let timer;
  try { return await Promise.race([lookup('example.com').then(value => ({ resolved: true, address: value.address })), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), 3000); })]); }
  catch (error) { return { resolved: false, code: error.code || error.message, syscall: error.syscall }; }
  finally { clearTimeout(timer); }
}
async function probe() {
  let privateRead;
  try { await readFile(join(dirname(hostFile), 'probe-private.txt')); privateRead = 'READ'; } catch (error) { privateRead = error.code; }
  const udp = await new Promise(resolve => {
    const socket = createSocket('udp4'); let settled = false;
    const done = error => { if (settled) return; settled = true; socket.close(); resolve({ sent: !error, code: error?.code }); };
    socket.on('error', done); socket.send('SYNTHETIC_UDP', Number(new URL(host.state.origins[0]).port), '127.0.0.1', done);
  });
  let direct;
  try { await fetch(`${host.state.origins[0]}/direct`, { signal: AbortSignal.timeout(2000) }); direct = { sent: true }; }
  catch (error) { direct = { sent: false, code: error.cause?.code || error.name }; }
  return { resolver: await resolver(), udp, direct, privateRead, inheritedSecret: process.env.AGD_HOST_ONLY_TEST_TOKEN ?? null,
    hostSession: host.state.session_id, coverage: host.state.coverage };
}
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const request = JSON.parse(line);
  const result = request.method === 'initialize' ? { protocolVersion: '2024-11-05' } : { isError: false, content: [{ type: 'text', text: JSON.stringify(await probe()) }] };
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: request.id, result })}\n`);
}

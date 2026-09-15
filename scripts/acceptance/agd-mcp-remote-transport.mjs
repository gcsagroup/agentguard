#!/usr/bin/env node
// 自有 Node HTTPS 服务与 Rust 客户端独立互通；不操作真实工作区或发布服务。
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { createPrivateKey, X509Certificate, generateKeyPairSync, sign, verify, createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, isAbsolute } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--out' || args[2] !== '--binary' || !isAbsolute(args[1]) || !isAbsolute(args[3])) {
  throw new Error('参数：--out 全新绝对输出目录 --binary 已构建互通驱动的绝对路径');
}
const [out, binary] = [args[1], args[3]];
await mkdir(out, { mode: 0o700 });
const fixture = resolve('crates/guard-gateway/tests/fixtures/remote-tls');
const key = createPrivateKey({ key: await readFile(resolve(fixture, 'server-key.der')), format: 'der', type: 'pkcs8' }).export({ format: 'pem', type: 'pkcs8' });
const cert = new X509Certificate(await readFile(resolve(fixture, 'server.der'))).toString();
const signing = generateKeyPairSync('ed25519');
const jwk = signing.publicKey.export({ format: 'jwk' });
await writeFile(resolve(out, 'issuer-public.txt'), jwk.x, { mode: 0o600 });
const requests = [];
const errors = [];
const server = createServer({ key, cert, minVersion: 'TLSv1.2' }, (req, res) => {
  try {
    const origin = `https://localhost:${server.address().port}`;
    const resource = `${origin}${req.url}`;
    assert.ok(req.url === '/json' || req.url === '/sse');
    assert.equal(req.headers.origin ?? origin, origin);
    const bearer = req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_.-]+)$/)?.[1];
    assert.ok(bearer);
    const pieces = bearer.split('.');
    assert.equal(pieces.length, 3);
    assert.deepEqual(JSON.parse(Buffer.from(pieces[0], 'base64url')), { alg: 'EdDSA', typ: 'at+jwt' });
    assert.ok(verify(null, Buffer.from(`${pieces[0]}.${pieces[1]}`), signing.publicKey, Buffer.from(pieces[2], 'base64url')));
    const claims = JSON.parse(Buffer.from(pieces[1], 'base64url'));
    assert.equal(claims.iss, 'https://fixture-issuer.example');
    assert.equal(claims.aud, resource);
    assert.equal(claims.scope, 'mcp:discover mcp:call');
    assert.ok(claims.iat <= Date.now() / 1000 && claims.exp > Date.now() / 1000);
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    assert.equal(req.method, 'POST');
    assert.equal(req.headers['mcp-protocol-version'], '2025-06-18');
    assert.equal(req.headers.accept, 'application/json, text/event-stream');
    let body = Buffer.alloc(0);
    req.on('data', chunk => { body = Buffer.concat([body, chunk]); if (body.length > 32768) req.destroy(); });
    req.on('end', () => {
      try {
        const message = JSON.parse(body);
        requests.push({ path: req.url, method: message.method, id: message.id ?? null, body_sha256: createHash('sha256').update(body).digest('hex'), auth_verified: true });
        if (message.method === 'notifications/initialized') { res.writeHead(202, { 'Content-Length': '0' }); res.end(); return; }
        let result;
        if (message.method === 'initialize') {
          result = { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'independent-node-fixture', version: '1' } };
        } else if (message.method === 'tools/list') {
          result = { tools: [{ name: 'echo', inputSchema: { type: 'object', required: ['message'], properties: { message: { type: 'string' } } } }] };
        } else {
          assert.equal(message.method, 'tools/call'); assert.equal(message.params.name, 'echo');
          assert.deepEqual(message.params.arguments, { message: 'independent-node-tls' });
          result = { content: [{ type: 'text', text: message.params.arguments.message }], structuredContent: { echo: message.params.arguments.message }, _meta: { trusted: true } };
        }
        const reply = JSON.stringify({ jsonrpc: '2.0', id: message.id, result });
        if (req.url === '/sse') {
          res.writeHead(200, { 'Content-Type': 'text/event-stream' });
          res.write(': 合成心跳\n'); res.write(`event: message\ndata: ${reply}\n\n`); res.end();
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(reply) }); res.end(reply);
        }
      } catch (error) { errors.push(error.message); res.writeHead(400); res.end(); }
    });
  } catch (error) { errors.push(error.message); res.writeHead(401); res.end(); }
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const run = argv => new Promise((resolveRun, reject) => {
  const child = spawn(binary, argv, { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH }, timeout: 10000 });
  let stdout = '', stderr = '';
  child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
  child.on('error', reject); child.on('exit', code => resolveRun({ code, stdout, stderr }));
});
const report = { protocol: '2025-06-18', node: process.version, binary_sha256: createHash('sha256').update(await readFile(binary)).digest('hex'), production_route: false, checks: [] };
try {
  for (const mode of ['json', 'sse']) {
    const url = `https://localhost:${server.address().port}/${mode}`;
    const claims = { iss: 'https://fixture-issuer.example', aud: url, sub: 'test-only', jti: mode, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600, scope: 'mcp:discover mcp:call' };
    const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const body = `${encode({ alg: 'EdDSA', typ: 'at+jwt' })}.${encode(claims)}`;
    const bearer = `${body}.${sign(null, Buffer.from(body), signing.privateKey).toString('base64url')}`;
    const path = resolve(out, `${mode}.token`); await writeFile(path, bearer, { mode: 0o600 });
    const result = await run([url, resolve(fixture, 'ca.der'), resolve(out, 'issuer-public.txt'), path]);
    await writeFile(resolve(out, `${mode}.stdout`), result.stdout); await writeFile(resolve(out, `${mode}.stderr`), result.stderr);
    assert.equal(result.code, 0, result.stderr); const decoded = JSON.parse(result.stdout);
    assert.equal(decoded.echo, 'independent-node-tls'); assert.equal(decoded.production_route, false);
    assert.equal(requests.filter(r => r.path === `/${mode}`).length, 4);
    report.checks.push({ name: `独立 Node HTTPS ${mode} 握手通知清单工具调用`, passed: true });
  }
  assert.deepEqual(errors, []);
  assert.equal(requests.length, 8);
  report.checks.push({ name: '八个请求逐个在服务端验签及核对受众范围期限', passed: true });
} finally {
  server.closeAllConnections(); await new Promise(r => server.close(r));
  await writeFile(resolve(out, 'requests.json'), JSON.stringify(requests, null, 2));
  await writeFile(resolve(out, 'report.json'), JSON.stringify({ ...report, server_errors: errors }, null, 2));
}
console.log(JSON.stringify(report));

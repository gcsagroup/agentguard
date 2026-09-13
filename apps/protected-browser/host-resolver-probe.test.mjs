import test from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createSocket } from 'node:dgram';
import { lookup } from 'node:dns/promises';
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startHostFixture, toolValue } from './host-test-support.mjs';

test('真实产品沙箱启动器阻断系统getaddrinfo、直接TCP/UDP、私有文件和继承环境', { timeout: 30000 }, async () => {
  // IANA示例域名只用于系统解析正对照；不发送HTTP或业务正文。
  const baseline = await lookup('example.com'); assert.ok(baseline.address);
  let tcpCount = 0, udpCount = 0;
  const server = createServer((_request, response) => { tcpCount++; response.end('SYNTHETIC'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const udp = createSocket('udp4'); udp.on('message', () => udpCount++);
  await new Promise(resolve => udp.bind(server.address().port, '127.0.0.1', resolve));
  let host;
  try {
    host = await startHostFixture([`http://127.0.0.1:${server.address().port}`], { runtime: fileURLToPath(new URL('./host-resolver-probe-actor.mjs', import.meta.url)) });
    await writeFile(join(host.fixture.control, 'probe-private.txt'), 'SYNTHETIC_PRIVATE_CANARY', { mode: 0o600 });
    const result = toolValue(await host.call('browser_status'));
    assert.equal(result.resolver.resolved, false);
    assert.equal(result.resolver.syscall, 'getaddrinfo');
    assert.equal(result.direct.sent, false); assert.equal(result.udp.sent, false);
    assert.equal(result.privateRead, 'EPERM'); assert.equal(result.inheritedSecret, null);
    assert.equal(tcpCount, 0); assert.equal(udpCount, 0);
    if (process.env.AGD_BROWSER_PROBE_REPORT) {
      const report = { recorded_at: new Date().toISOString(), scope: '生产BrowserActor完整沙箱配置与独立合成Node探针；Chromium流程另行验证',
        binary_sha256: createHash('sha256').update(await readFile(host.binary)).digest('hex'),
        resolver_positive_control: { name: 'example.com', address: baseline.address }, result, tcpCount, udpCount, pass: true };
      await mkdir(dirname(process.env.AGD_BROWSER_PROBE_REPORT), { recursive: true });
      await writeFile(process.env.AGD_BROWSER_PROBE_REPORT, JSON.stringify(report, null, 2));
    }
  } finally { await host?.close(); udp.close(); await new Promise(resolve => server.close(resolve)); }
});

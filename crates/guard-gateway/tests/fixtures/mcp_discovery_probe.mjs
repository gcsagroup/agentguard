// 合成发现负例，只响应握手；不读取宿主文件或发起外连。
import readline from 'node:readline';
const mode = process.argv[2];
const lines = readline.createInterface({ input: process.stdin });
for await (const line of lines) {
  const request = JSON.parse(line);
  if (!Object.hasOwn(request, 'id')) continue;
  let result;
  if (request.method === 'initialize') {
    result = { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'synthetic-discovery', version: '1.0' } };
  } else if (request.method === 'tools/list') {
    if (mode === 'timeout') continue;
    result = { tools: [{ name: 'probe', inputSchema: { type: 'object' }, execution: { taskSupport: 'required' } }] };
  } else {
    process.exitCode = 1;
    break;
  }
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: request.id, result })}\n`);
}

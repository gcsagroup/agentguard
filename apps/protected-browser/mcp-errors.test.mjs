import test from 'node:test';
import assert from 'node:assert/strict';
import { handleMessage } from './mcp.mjs';

test('MCP 参数纠错只公开固定提示，任意内部异常不泄露', async () => {
  const message = { jsonrpc: '2.0', method: 'tools/call', params: { name: 'browser_read', arguments: { page: 'invalid' } } };
  for (const detail of ['BROWSER_PAGE_ID_INVALID', 'SYNTHETIC_PRIVATE_VALUE', 'BROWSER_PAGE_ID_INVALID\nSYNTHETIC_PRIVATE_VALUE']) {
    const response = await handleMessage({ host: {}, act() { throw new Error(detail); } }, message);
    assert.equal(response.isError, true);
    const text = response.content[0].text;
    assert.equal(text.includes('SYNTHETIC_PRIVATE_VALUE'), false);
    assert.equal(text.includes('browser_status'), detail === 'BROWSER_PAGE_ID_INVALID');
  }
});

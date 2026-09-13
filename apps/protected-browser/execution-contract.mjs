// 浏览器执行器的契约 1 子集：参数只使用 JSON 字符串、布尔值、null 和安全整数。
// 和 Rust ActionSnapshot 使用相同域前缀、UTF-8 键排序；不是通用 RFC 8785。
import { createHash, randomBytes, randomUUID } from 'node:crypto';

export const CONTRACT_VERSION = 1;
export const BROWSER_TOOL = Object.freeze({ service: 'agentguard-protected-browser', name: 'http_request', version: '1' });
const DOMAIN = 'agentguard.execution.action.v1\0';

function string(value) {
  if (!value.isWellFormed()) throw new Error('契约字符串含无效 Unicode');
  return JSON.stringify(value);
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return string(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return `{${keys.map((key) => `${string(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('浏览器契约只接受 JSON 值与安全整数');
}

export function canonicalBytes(action) { return Buffer.from(DOMAIN + canonicalJson(action), 'utf8'); }
export function actionSha256(action) { return createHash('sha256').update(canonicalBytes(action)).digest('hex'); }
export function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}

export function bindRequest({ sessionId, requestId, url, method, headers, body, policyVersion, issuedAt, expiresAt }) {
  for (const [name, value] of Object.entries({ sessionId, requestId, policyVersion, url })) {
    if (typeof value !== 'string' || !value || value.trim() !== value || /\p{Cc}/u.test(value) ||
        (name !== 'url' && Buffer.byteLength(value) > 256)) throw new Error(`契约标识或目标无效：${name}`);
  }
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || issuedAt < 0 || expiresAt <= issuedAt) throw new Error('请求期限无效');
  const action = freeze({
    contract_version: CONTRACT_VERSION, session_id: sessionId, action_id: randomUUID(), request_id: requestId,
    tool: BROWSER_TOOL, target: url, parameters: { method, headers: { ...headers }, body },
    policy_version: policyVersion, issued_at_ms: issuedAt, expires_at_ms: expiresAt, nonce: randomBytes(32).toString('hex'),
    sources: [{ source_id: randomUUID(), observation: { status: 'unknown', reason: '浏览器内容来源链尚未接入' } }],
  });
  const binding = freeze({ approval_id: requestId, action, nonce: randomBytes(32).toString('hex'), issued_at_ms: issuedAt, expires_at_ms: expiresAt });
  return { binding, action_sha256: actionSha256(action) };
}

export function answerFields(request) {
  return { action_sha256: request.action_sha256, approval_nonce: request.binding.nonce };
}

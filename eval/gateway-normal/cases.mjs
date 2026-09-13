// 固定操作级语料：使用仓库真实源码与文档，不把参数循环冒充完整编码任务。
const reads = [
  ['README.md', '读取项目能力说明'],
  ['docs/工具网关.md', '读取网关使用说明'],
  ['docs/路径模型.md', '读取路径授权说明'],
  ['docs/scope-and-non-goals.md', '读取产品范围'],
  ['docs/desktop-guide.md', '读取桌面使用说明'],
  ['apps/extension-chromium/manifest.json', '读取扩展清单'],
  ['crates/guard-gateway/Cargo.toml', '读取网关依赖声明'],
  ['crates/guard-gateway/src/mcp.rs', '读取 MCP 协议实现'],
  ['apps/protected-browser/README.md', '读取受保护浏览器说明'],
  ['rust-toolchain.toml', '读取工具链版本'],
];
const searches = [
  ['crates/guard-gateway/src/exec.rs', 'MAX_OUTPUT_BYTES', '定位输出上限'],
  ['crates/guard-gateway/src/server.rs', 'write_file', '定位文件写入入口'],
  ['crates/guard-gateway/src/confirm.rs', 'disconnected', '定位断连处理'],
  ['apps/protected-browser/runtime.mjs', 'serviceWorker', '定位后台请求处理'],
  ['apps/protected-browser/agent-bridge.mjs', '||', '搜索逻辑或表达式'],
  ['apps/protected-browser/agent-bridge.mjs', '&&', '搜索逻辑与表达式'],
  ['scripts/bootstrap-rust.sh', '$(', '搜索命令替换的源码位置'],
  ['crates/guard-gateway/src/bin/agentguard_mcp.rs', '--confirm-port', '定位确认端口参数'],
  ['docs/路径模型.md', '路径', '检索中文文档'],
  ['apps/protected-browser/runtime.mjs', 'route', '定位请求路由'],
];
const directories = ['.', 'apps', 'apps/extension-chromium', 'apps/extension-chromium/scripts',
  'apps/protected-browser', 'crates', 'crates/guard-gateway', 'crates/guard-gateway/src',
  'crates/guard-gateway/src/bin', 'docs'];
const checks = ['apps/extension-chromium/background.js', 'apps/extension-chromium/popup.js',
  'apps/extension-chromium/onboarding.js', 'apps/extension-chromium/mail-content.js',
  'apps/protected-browser/runtime.mjs', 'apps/protected-browser/cli.mjs',
  'apps/protected-browser/relay.mjs', 'apps/protected-browser/control.js'];

export const cases = [
  ...reads.map(([path, title], i) => ({ id: `read-${i + 1}`, kind: 'read', path, title })),
  ...searches.map(([path, query, title], i) => ({ id: `search-${i + 1}`, kind: 'search', path, query, title })),
  ...directories.map((path, i) => ({ id: `list-${i + 1}`, kind: 'list', path, title: `查看 ${path} 目录` })),
  ...checks.map((path, i) => ({ id: `check-${i + 1}`, kind: 'check', path, title: `检查 ${path} 语法` })),
  { id: 'test-gate', kind: 'test', path: 'apps/extension-chromium/scripts/gate.test.mjs', title: '运行现有浏览器闸门单元测试' },
  { id: 'test-mail', kind: 'test', path: 'apps/extension-chromium/scripts/mail.test.mjs', title: '运行现有邮件判决单元测试' },
  ...reads.map(([path, title], i) => ({ id: `draft-${i + 1}`, kind: 'draft', path, title: `${title}并生成带来源的草稿副本` })),
];
export const sourceFiles = [...new Set([...cases.filter((c) => c.kind !== 'list').map((c) => c.path),
  'apps/extension-chromium/guard-gate.js', 'apps/extension-chromium/guard-mail.js',
  'apps/extension-chromium/content.js', 'apps/extension-chromium/guard-strings.js',
  'eval/acceptance-fixtures/mail-link-cases.json'])].sort();

// 原生命令的真实输出 + Chromium 工作区交互。IPC 为测试桥，不冒充打包 App 验收。
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, join, extname } from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
const root = resolve(import.meta.dirname, '../..');
const ui = join(root, 'apps/desktop-macos/src');
const out = process.env.AGENTGUARD_KNOWLEDGE_OUTPUT || join(root, '.artifacts/m2-knowledge-workspace-2026-09-15');
mkdirSync(out, { recursive: true });
const receipt = JSON.parse(readFileSync(join(out, 'knowledge-receipt.json')));
assert.equal(receipt.sha256, createHash('sha256').update(readFileSync(join(root, 'intel/knowledge/v0.1/catalog.json'))).digest('hex'));
const stub = readFileSync(join(import.meta.dirname, 'shell-a11y.mjs'), 'utf8').match(/const TAURI_STUB = `([\s\S]*?)`;\n/)[1];
const { chromium } = createRequire(import.meta.url)(join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'playwright'));
const report = { scope: '实际 Rust 命令输出 + Chromium 界面；IPC 测试桥，未构建或替换原生 App', sourceSha256: receipt.sha256, checks: [], passed: false };
const check = (name, value) => { report.checks.push({ name, passed: !!value }); assert.ok(value, name); console.log(`通过：${name}`); };
const server = createServer((req, res) => {
  const path = resolve(ui, '.' + new URL(req.url, 'http://localhost').pathname.replace(/^\/$/, '/index.html'));
  if (!path.startsWith(ui + '/')) { res.writeHead(403).end(); return; }
  try { res.setHeader('content-type', ({ '.js': 'text/javascript', '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.png': 'image/png' })[extname(path)] || 'text/plain'); res.end(readFileSync(path)); }
  catch { res.writeHead(404).end(); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 960 }, locale: 'zh-CN' });
  const errors = []; page.on('pageerror', error => errors.push(String(error)));
  await page.addInitScript(stub);
  await page.addInitScript((data) => {
    localStorage.setItem('agentguard.appearance', 'light');
    window.__knowledgeReceipt = data; window.__knowledgeCalls = [];
    const original = window.__TAURI__.core.invoke;
    window.__TAURI__.core.invoke = async (cmd, args) => {
      if (cmd === 'get_knowledge_catalog') {
        window.__knowledgeCalls.push(cmd);
        if (window.__knowledgeFail) throw new Error('读取失败');
        return structuredClone(window.__knowledgeReceipt);
      }
      if (cmd === 'list_audit') return [
        { action: 'Block', rule_id: 'OBSERVED-BLOCK', human_message: '风险示例', source_app: 'fixture', user_decision: 'deny', effect: 'observed_only', external_action_blocked: false },
        { action: 'LogOnly', rule_id: 'OBSERVED-LOG', human_message: '普通记录', source_app: 'fixture', effect: 'observed_only', external_action_blocked: false },
        { action: 'Block', rule_id: 'UNKNOWN', human_message: '旧记录缺少效果证据', source_app: 'fixture' },
        { action: 'Block', rule_id: 'CONTRADICTORY', human_message: '矛盾回执不能算阻断', source_app: 'fixture', effect: 'observed_only', external_action_blocked: true },
      ];
      return original(cmd, args);
    };
  }, receipt);
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.locator('[data-route="knowledge"]').click();
  await page.locator('.knowledge-choice').first().waitFor();
  check('18 个真实手法可选且摘要与原始目录一致', await page.locator('.knowledge-choice').count() === 18 && (await page.locator('#knowledge-provenance').innerText()).includes(receipt.sha256));
  check('七阶段都保留发生未知且只高亮登记关联', await page.locator('.knowledge-stages li').count() === 7 && await page.locator('.knowledge-stages li[data-related="true"]').count() === 3 && (await page.locator('.knowledge-stages').innerText()).match(/发生情况未知/g).length === 7);
  await page.locator('.knowledge-section').filter({ has: page.getByRole('heading', { name: '平台覆盖登记', exact: true }) }).locator('details').first().locator('summary').first().click();
  check('平台覆盖未知显示原登记环境', (await page.locator('#knowledge-detail').innerText()).includes('隔离后端环境未冻结'));
  const scenario = page.locator('.knowledge-section').filter({ has: page.getByRole('heading', { name: '验收场景', exact: true }) }).locator('details').first();
  await scenario.locator('summary').first().click();
  await scenario.locator('details').first().locator('summary').click();
  check('未运行场景不出现伪造实际结果且夹具单独列示', (await scenario.innerText()).includes('未运行') && (await scenario.innerText()).includes('尚无本条目的实际执行证据') && (await scenario.innerText()).includes('测试夹具（不算执行证据）'));
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: join(out, 'knowledge-light.png') });
  await page.locator('#knowledge-search').fill('OVL-004');
  check('规则编号搜索定位两个关联手法', await page.locator('.knowledge-choice').count() === 2);
  await page.locator('#knowledge-search').fill('GCSA-ATI-018');
  check('手法编号搜索可选且聚焦正文', await page.locator('.knowledge-choice').count() === 1);
  await page.locator('.knowledge-choice').click();
  check('选择后键盘焦点进入对应标题', await page.evaluate(() => document.activeElement?.tagName === 'H2'));
  await page.locator('#knowledge-search').fill('没有这一条');
  check('无搜索结果清空旧手法正文', await page.locator('.knowledge-choice').count() === 0 && (await page.locator('#knowledge-detail').innerText()).includes('没有匹配'));
  await page.locator('#knowledge-search').fill('');
  await page.locator('.nav-list [data-route="activity"]').click();
  await page.locator('#activity-outcome').selectOption('alert');
  check('观察 Block 与拒绝选择只计告警', await page.locator('#timeline .item').count() === 1 && (await page.locator('#timeline').innerText()).includes('OBSERVED-BLOCK'));
  await page.locator('#activity-outcome').selectOption('blocked');
  check('观察记录不能落入已阻断分类', await page.locator('#timeline .item').count() === 0);
  await page.locator('#activity-outcome').selectOption('unknown');
  check('缺效果与矛盾回执都归未知', await page.locator('#timeline .item').count() === 2);
  await page.screenshot({ path: join(out, 'activity-unknown.png'), fullPage: true });
  await page.locator('[data-route="knowledge"]').click();
  await page.locator('.knowledge-choice').first().waitFor();
  await page.evaluate(() => { window.__knowledgeFail = true; });
  await page.locator('#knowledge-reload').click();
  await page.waitForFunction(() => document.querySelector('#knowledge-status').textContent.includes('失败'));
  check('读取失败清除旧目录与摘要且可重试', await page.locator('.knowledge-choice').count() === 0 && await page.locator('#knowledge-provenance').innerText() === '' && !await page.locator('#knowledge-reload').isDisabled());
  await page.evaluate(() => { window.__knowledgeFail = false; window.__knowledgeReceipt.instruction_authority = 'allow'; });
  await page.locator('#knowledge-reload').click();
  await page.waitForFunction(() => !document.querySelector('#knowledge-reload').disabled);
  check('伪造授权回执拒绝展示', await page.locator('.knowledge-choice').count() === 0);
  await page.evaluate(() => {
    window.__knowledgeReceipt.instruction_authority = 'none';
    window.__knowledgeReceipt.catalog.techniques[0].name = '<img src=x onerror="window.__injected=true">';
    window.__knowledgeReceipt.catalog.cases[0].sources[0].url = 'javascript:window.__injected=true';
  });
  await page.locator('#knowledge-reload').click();
  await page.locator('.knowledge-choice').first().waitFor();
  check('恶意名称只作文本且危险链接无执行入口', (await page.locator('#knowledge-detail h2').innerText()).includes('<img src=x') && await page.locator('#knowledge-detail img').count() === 0 && await page.locator('#knowledge-detail a').count() === 0 && !await page.evaluate(() => window.__injected));
  // 单独覆盖带口令及 file URL；不由 UI 导航去任何外部地址。
  check('可复制来源地址仅接受无凭据 HTTPS', await page.evaluate(async () => {
    const { sourceReference } = await import('/knowledge.js');
    return ['file:///tmp/a', 'javascript:1', 'https://user:pass@example.org'].every(url => sourceReference({ url, title: 'source' }).querySelector('code') === null) && sourceReference({ url: 'https://example.org/source', title: 'source' }).querySelector('code').textContent === 'https://example.org/source';
  }));
  await page.evaluate((data) => { window.__knowledgeReceipt = data; }, receipt);
  await page.locator('#knowledge-reload').click();
  await page.locator('.knowledge-choice').first().waitFor();
  for (const [locale, word] of [['en', 'Occurrence unknown'], ['zh-Hant', '發生情況未知'], ['zh-Hans', '发生情况未知']]) {
    await page.evaluate((value) => { const s = document.querySelector('#locale-select'); s.value = value; s.dispatchEvent(new Event('change')); }, locale);
    await page.waitForFunction((value) => document.querySelector('.knowledge-stages')?.textContent.includes(value), word);
    check(`${locale} 切换后阶段状态与栏目同步`, (await page.locator('#knowledge-detail').innerText()).includes(word));
  }
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  await page.screenshot({ path: join(out, 'knowledge-dark.png') });
  await page.setViewportSize({ width: 760, height: 960 });
  check('窄窗口无横向溢出', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  await page.screenshot({ path: join(out, 'knowledge-narrow.png'), fullPage: true });
  check('浏览器无脚本错误', errors.length === 0);
  check('所有知识操作仅调用读取命令', await page.evaluate(() => window.__knowledgeCalls.length > 0 && window.__knowledgeCalls.every(c => c === 'get_knowledge_catalog')));
  report.passed = true;
} finally {
  writeFileSync(join(out, 'ui-report.json'), JSON.stringify(report, null, 2) + '\n');
  await browser.close(); await new Promise(done => server.close(done));
}

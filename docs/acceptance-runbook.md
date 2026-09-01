# 真机验收执行手册（给自动化 agent / computer-use）

这份手册把三份验收清单(`acceptance-firefox.md` / `acceptance-macos.md` / `acceptance-windows.md`)
从"人读的检查表"补成"可照着执行的操作步骤":每条用例的**准备、精确动作、可观察的判据、要截的证据**,
以及最后**怎么记录结果并更新仪表盘**。执行者可以是 Codex / computer-use 之类能驱动真实浏览器和桌面的
agent。

> 每条用例的"期望"以三份 `acceptance-*.md` 为准;本手册补的是"怎么让它发生、怎么看出成没成"。

---

## 0. 范围与诚实前提(先读)

- **浏览器扩展路径(Firefox / Chrome / Edge)是完全可跑、可判定的**,而且本仓库提供了测试夹具
  (`eval/acceptance-fixtures/`),所以 F1–F8 是 turnkey 的。
- **桌面壳子路径(Windows / macOS)现在跑在"仿真观测"下**:两个壳子的 README 明说原生
  AX / ScreenCaptureKit / UI Automation / GDI 捕获还是占位,壳子用 `MacAdapter` / `WinAdapter`
  的**仿真注入**来驱动判决链路。这意味着:
  - 桌面用例的**判决链路**(规则命中 → Block → 阻断式模态)可以用仿真注入验证 → 记 `PASS (sim)`。
  - 桌面用例的**原生观测**(真 UI Automation 取到树 / 真 GDI 抓到帧 / 真 OCR 读到屏)只有在原生适配器
    **接进壳子**之后才能验 → 未接进前记 `BLOCKED (native-not-wired)`,别记 PASS,别假装。
  这条区分必须体现在报告里。判定不了就如实写 `BLOCKED`,这比一个假 PASS 有价值。

- **不要真付款、不要向真实支付/转账端点发请求。** 夹具里的 fetch 都发往本机同源的假路径,
  验的是"请求在发出**之前**是否被拦",不是请求本身。

---

## 1. 通用前置(一次性)

在仓库根 `/root/ag`(或你的克隆路径)执行:

```bash
# 工具链:Rust(edition 用到的较新版即可)、Node ≥ 18
cargo --version && node --version

# 1) 构建原生消息宿主(浏览器扩展要连它)
cargo build -p guard-nm-host           # 产物:target/debug/guard-nm-host

# 2) 打扩展包(Chrome/Edge 用默认;Firefox 用 --firefox)
apps/extension-chromium/scripts/package-store.sh                 # dist/agentguard-extension.zip
apps/extension-chromium/scripts/package-store.sh --firefox       # dist/agentguard-extension-firefox.zip

# 3) 离线门禁(必须先全绿,是真机验收的必要非充分前提)
make capability-claims && make check-extension-gate && make coverage
```

启动测试夹具服务器(fetch 用例需要同源路径解析,不能用 file://):

```bash
cd eval/acceptance-fixtures && python3 -m http.server 8000
# 夹具首页:http://localhost:8000/
```

准备一个证据目录:

```bash
mkdir -p /tmp/ag-evidence/{firefox,windows,macos}
```

---

## 2. 平台 A:浏览器扩展(Firefox / Chrome / Edge)

### A.1 安装

**Firefox(≥128)**
1. 装原生消息宿主:`apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev`
2. `about:debugging#/runtime/this-firefox` → 「临时载入附加组件」→ 选 `apps/extension-chromium/manifest.firefox.json`
   (或解压 `dist/agentguard-extension-firefox.zip` 后选其 `manifest.json`)。
3. 记下分配的扩展 ID(应为 `agentguard@agentguard.dev`)。

**Chrome / Edge**
1. `chrome://extensions`(或 `edge://extensions`)→ 开「开发者模式」→「加载已解压的扩展程序」→ 选
   `apps/extension-chromium/`(或解压后的 dist 目录)。复制生成的扩展 ID。
2. 装宿主:`install-host.sh <extension-id>`(Edge 用 `--browser edge <extension-id>`)。

装完**重启浏览器一次**,确保内容脚本(含 `world:"MAIN"` 的 guard-page.js)在新标签页注入。

### A.2 逐条执行(F1–F8)

对每条:先**打开 DevTools**(Console + Network 面板),再操作,再据"判据"截图。

| 用例 | 打开 / 动作 | PASS 判据(可观察) | 证据 |
|---|---|---|---|
| **F1** 隐藏注入 | 开 `http://localhost:8000/injection.html`;点扩展图标看 popup「最近」 | popup 最近列表出现一条 `invisible_injection`/`prompt_injection`;若装了宿主,宿主 stderr / 审计里有对应事件 | popup 截图 |
| **F2** 付款 CTA 执行前拦 | 开 `payment-cta.html`,点「Confirm Payment」 | 点击后**先**弹出 AgentGuard 确认层(标题是人话,如「这一步要付款了」);点**「先不要」**→ 页面**不**显示「已确认支付」;再点一次点**「允许这一次」**→ 才显示 | 两张截图(取消态 / 允许态) |
| **F3** 陷阱+PII 提交拦 | 开 `trap-pii.html`,点「提交」 | 弹确认层;**「先不要」**→ URL 不变、无 `?phone=`;**「允许这一次」**→ URL 出现 `?phone=13800000000` | 两张截图(URL 栏可见) |
| **F4** 付款形状 fetch 拦 | 开 `fetch-gate.html`,点「POST /pay/checkout」 | 弹确认层;**「先不要」**→ Network 面板**无** `/pay/checkout` 请求、日志显示"被拒绝/未发出";**「允许这一次」**→ 出现该请求(404/501 无所谓) | Network 面板截图(取消态) |
| **F5** 只读方法不拦 | 同页点「GET /pay/status」和「POST /api/search」 | **不**弹确认层;请求直接发出(Network 出现) | Network 面板截图 |
| **F6** 恶意域网络层硬拦 | 需要引擎判 `evil.example` 为恶意域(内置情报基线含它)。若走宿主:构造一次 url 为 `https://evil.example/x` 的浏览器事件(或直接在地址栏访问 `http://evil.example/`)后,再在**新请求**里访问该主机 | 该主机的请求被 declarativeNetRequest 在网络层 block(Network 面板显示 blocked / net::ERR_BLOCKED_BY_CLIENT);popup 拦截名单出现 `evil.example · 恶意域`,溯源显示 `INTEL-DOMAIN` | popup 名单截图 + Network 截图 |
| **F7** 原生消息握手 | 确保宿主已装;触发任意 finding(F1–F3) | 宿主接受了调用方(未因 origin 校验拒启动;stderr 无 "refuse origin");判决进签名审计库(`AGENTGUARD_AUDIT_DB` 指向的库有新行) | 宿主 stderr 截图 / 审计行 |
| **F8** DNR 配额 | 触发若干 F6 类拦截后,DevTools 控制台跑 `chrome.declarativeNetRequest.getDynamicRules().then(r=>console.log(r.length))` | 规则数 ≤ 浏览器动态规则配额上限,装规则不报错 | 控制台输出截图 |

> **F6 说明**:浏览器扩展当前上报的是 `ui_text` 事件;恶意域判决(`INTEL-DOMAIN`)对**任何带 url 的
> 事件**成立,所以走宿主路径能触发。若你的环境没接宿主的恶意域判决回流,记 `BLOCKED (no host verdict)`。
> 越界(`SCOPE-HOST`/E9 本地允许表门)需要会话声明了 `scope.hosts`——浏览器路径默认没有,记 `N/A` 除非
> 你显式配了带 `scope.hosts` 的任务会话。

---

## 3. 平台 B:Windows 桌面壳子(W1–W7)

### B.1 构建与运行

```bash
cd apps/desktop-windows
npm install
npm run tauri dev        # 起托盘壳子(dev)
```

原生消息宿主(若验 W7 浏览器路径):把 `com.agentguard.native.json` 写进注册表
`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.agentguard.native`,`path` 指向
`target\debug\guard-nm-host.exe`,`allowed_origins` 填扩展 origin。

### B.2 逐条执行

判据以 `acceptance-windows.md` 的 W1–W7 为准。**每条先判断壳子是"仿真"还是"原生观测"**
(看托盘/日志的能力标志):

- **判决链路类(W1 阻断模态)**:用壳子的仿真注入触发一次 `CRIT-001`(付款文案)。PASS 判据:弹出
  **阻断式模态**,点「先不要,暂停任务」动作不放行。记 `PASS (sim)` 或(原生接线后)`PASS (native)`。
- **原生观测类(W2 UIA 取树 / W3 GDI 抓帧+隐写 / W4 Windows.Media.Ocr 读屏 / W5 overlay)**:
  只有原生适配器接进壳子后才可真验。未接进 → `BLOCKED (native-not-wired)`。若已接进:
  - W3 需要一张含隐写的图 —— 用 `make frame-digest-demo` 或 guard-vision 的隐写编码器生成一张,
    在目标窗口显示,看是否被抓到。
  - W4 需要一段"只在像素里"的付款文本图 —— 同法生成/截图一张写着 "Complete purchase" 的位图显示。
  - 缺识别语言包时 OCR 不跑,壳子应给**带原因**的能力报告(那本身是 W6 的 PASS 判据)。
- **W6 能力探针**:打开壳子的能力面板/日志,确认 UIA / 捕获 / OCR 各自"可用与否 + 原因串"。
- **W7 原生消息**:同 F7,只是 host 走注册表登记。

---

## 4. 平台 C:macOS 桌面壳子

```bash
cd apps/desktop-macos
npm install
npm run tauri dev
```

macOS README 明说 `accessibility` / `screen_capture` 目前是占位,请以**仿真威胁注入**验证决策链路
(判决链路类用例记 `PASS (sim)`),原生 AX / ScreenCaptureKit 接线后再验原生观测类(未接进记
`BLOCKED (native-not-wired)`)。用例清单见 `acceptance-macos.md` 的验收用例表。宿主装法:
`install-host.sh --browser chrome <id>`(macOS 路径见脚本)。

---

## 5. 记录结果 → 更新仪表盘

对每条用例:

1. **填清单表**:在对应 `docs/acceptance-{firefox,windows,macos}.md` 的用例行,把「实测」列填
   `PASS` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)`,「证据」列填证据文件相对路径
   (如 `/tmp/ag-evidence/firefox/F2-cancel.png`,或拷进仓库某目录后的相对路径)。
   —— 仪表盘反映进度靠的正是这两列非空,它会据此数 `X/N`。

2. **归档证据**:把截图 / 日志放进证据目录,并(可选)导出到门禁认的证据变量:
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=/tmp/ag-evidence/firefox
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS=/tmp/ag-evidence/windows
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=/tmp/ag-evidence/macos
   ```

3. **重算门禁 + 仪表盘**:
   ```bash
   make dashboard                        # 重生成 docs/status-dashboard.html,进度条据填好的表更新
   bash scripts/release-gate.sh --strict # 严格模式:证据变量都设了,对应"未验证"项才转绿
   ```

4. **出报告**:按 `docs/acceptance-report-template.md` 填一份报告(每条 PASS/FAIL/BLOCKED + 证据 + 备注 +
   环境信息),连同证据目录一起交回。

---

## 6. 判定小抄(什么算 PASS)

- **执行前拦截类(F2/F3/F4)**:动作在**发生前**被拦、出现确认层,且「先不要」确实阻止了动作
  (无导航 / 无请求 / 无处理器副作用)。只弹通知、动作照常发生 = **FAIL**(那是事后通知,不是执行前拦)。
- **网络层硬拦(F6)**:目标主机的请求在 Network 面板显示被 block,而不是 200。
- **观测类(F1 / W2 等)**:出现对应 finding / 事件,且**对照的正常内容不误报**。
- 任何"我判断不了/环境没接上"的情况:记 `BLOCKED` 并写原因,**不要猜 PASS**。这份清单的价值就在于
  它区分了"验过了"和"看起来该能"。

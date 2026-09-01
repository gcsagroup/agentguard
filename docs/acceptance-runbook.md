[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# 真机验收执行手册（给自动化 agent / computer-use）

这份手册把三份验收清单(`acceptance-firefox.md` / `acceptance-macos.md` / `acceptance-windows.md`)
从"人读的检查表"补成"可照着执行的操作步骤",并补充 Android 伴生应用的签名信封真机路径。它给出每条
用例的**准备、精确动作、可观察的判据、要截的证据**,以及最后**怎么记录结果并生成结构化证据**。执行者
可以是 Codex / computer-use 之类能驱动真实浏览器、桌面与设备的 agent。

> 浏览器、macOS 与 Windows 的"期望"以三份 `acceptance-*.md` 为准;Android 以本手册第 5 节和伴生应用 README 为准。

---

## 0. 范围与诚实前提(先读)

- **浏览器扩展路径(Firefox / Chrome / Edge)是完全可跑、可判定的**,而且本仓库提供了测试夹具
  (`eval/acceptance-fixtures/`),所以 F1–F8 是 turnkey 的。
- **桌面壳子已经接入原生观测链路**:macOS 已接入 AXUIElement、ScreenCaptureKit 与 Vision OCR;
  Windows 已接入 UI Automation、GDI `BitBlt` 与 `Windows.Media.Ocr`。但"代码已接线"不等于
  "这台真机可用":仍要以运行时 capability、系统权限、实际事件/帧/OCR 输出和证据逐项判定。这意味着:
  - 原生观测在目标真机上可用并产生预期证据 → 记 `PASS (native)`。
  - 只用壳子的仿真注入验证规则命中 → 只能记 `PASS (sim)`,不能替代原生观测、真机验收或发布证据。
  - 权限未授予、系统组件缺失或 capability 不可用 → 记 `BLOCKED (具体原因)`,同时保留能力报告。
  这条区分必须体现在报告里。判定不了就如实写 `BLOCKED`,这比一个假 PASS 有价值。

- **不要真付款、不要向真实支付/转账端点发请求。** 夹具里的 fetch 都发往本机同源的假路径,
  验的是"请求在发出**之前**是否被拦",不是请求本身。
- **验收报告不是发布证明。** 即使所有可执行用例 PASS,仍须单独满足签名、公证/商店审核、发布包身份、
  严格门禁与目标平台覆盖要求。

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

在仓库内准备证据工作目录。它必须保持为候选提交之外的本地文件；先去除敏感信息，不要误提交原始截图、账号或设备标识:

```bash
mkdir -p evidence/{firefox,windows,macos,android}
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

判据以 `acceptance-windows.md` 的 W1–W7 为准。**每条先记录运行时 capability 与权限状态,再区分
"仿真"还是"原生观测"**(看托盘/日志的能力标志与实际事件/帧/OCR 输出):

- **判决链路类(W1 阻断模态)**:用壳子的仿真注入触发一次 `CRIT-001`(付款文案)。PASS 判据:弹出
  **阻断式模态**,点「先不要,暂停任务」动作不放行。记 `PASS (sim)` 或(由原生观测触发时)`PASS (native)`。
- **原生观测类(W2 UIA 取树 / W3 GDI 抓帧+隐写 / W4 Windows.Media.Ocr 读屏 / W5 overlay)**:
  原生 UIA / GDI / OCR 已接进壳子,但必须在目标 Windows 真机上按 capability 和实际输出判定。
  capability 不可用或权限/语言包缺失 → `BLOCKED (具体原因)`。可用时:
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

macOS 壳子已接入 AXUIElement、ScreenCaptureKit 与 Vision OCR。先在目标真机授予并核验 Accessibility /
Screen Recording 权限,再以 capability 报告、真实 AX 事件、捕获帧与 OCR 输出判定原生观测用例。
权限未授予或 capability 不可用时记 `BLOCKED (具体原因)`;只用**仿真威胁注入**验证决策链路时记
`PASS (sim)`,不能替代 `PASS (native)`。用例清单见 `acceptance-macos.md` 的验收用例表。宿主装法:
`install-host.sh --browser chrome <id>`(macOS 路径见脚本)。

---

## 5. 平台 D:Android 伴生应用

按 [Android 伴生应用 README](../apps/android-companion/README.md) 构建并安装候选,在真实设备上启用通知与
AccessibilityService,通过 `adb reverse tcp:8788 tcp:8788` 连接桌面本地 API。把设备显示的 P-256 公钥注册到
`policies/adapter-registry.yaml`,重启桌面 API 后触发至少一个有明确预期判决的真实无障碍事件。

PASS 需要同时证明:事件来自目标真机、HTTP body 的签名信封由桌面端使用已注册公钥验证成功、引擎判决符合预期,
且设备收到相应风险结果。Debug 构建、JVM 单测、未注册公钥的中继或只离线回放 JSON 都不能替代这条真机 E2E；
任一环节无法判定时记 `BLOCKED (具体原因)`。

---

## 6. 记录结果 → 生成结构化证据

对每条用例:

1. **填写独立报告**:把 `docs/acceptance-report-template.md` 复制到对应 `evidence/<平台>/report.md`,逐条写
   `PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` 和仓库相对证据路径。作为严格门禁 artifact 时，
   Firefox 的 F1–F8、Windows 的 W1–W7、Android 的 A1–A4，以及 macOS 的 1、2、3、4、5、5b、5c、6–14
   必须各自恰好一行；第二列必须精确为 `PASS (native)`，第三列必须指向对应 `evidence/<平台>/` 下真实存在的
   仓库相对非空普通文件，且每个用例必须使用唯一证据路径。引用不能是报告自身或当前证据 JSON 源文件，路径不能含符号链接或越出仓库；
   路径只用 `/`，每个组件必须匹配可移植 ASCII `[A-Za-z0-9._-]+`，不能含空白或 shell glob／展开字符。`PASS (sim)`、FAIL、BLOCKED、N/A、
   缺失、重复、复用路径或引用文件不存在都不能冒充真机 PASS。

2. **冻结候选提交**:如需让状态仪表盘显示进度,先更新清单并执行 `make dashboard`,提交这些变更,然后再从新的
   `HEAD` 重跑验收。开门禁前索引和所有非 ignored 文件必须 clean；门禁运行期间不要改代码或受版本控制的文档。
   结束时仍存在的 `HEAD` 或非 ignored 漂移会让起止快照不一致并失败；起止快照不防瞬时修改后恢复的并发对手。
   ignored 的 `evidence/` 可继续写入。

3. **生成并填写 JSON**:模板故意不能直接通过。把 `command`、`timestamp`、`output`、`exit_code` 和验收闭包
   SHA-256 换成实测值；验收证据的顶层 `signer` 必须保持 `null`，复核时不要传 `--expected-signer`。
   `timestamp` 在校验时须位于过去 30 天至未来 10 分钟内，且不能早于 HEAD 提交时间
   （允许 10 分钟时钟误差）。`command` 必须是实际成功执行的单段
   `guard-cli manual-acceptance <平台> <清单> <artifact.path> --repo-root .`（已按下方构建时，实际命令为
   `target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md evidence/firefox/report.md --repo-root .`）。报告正文与 JSON `output`
   都必须有一整行精确标记 `AGENTGUARD_ACCEPTANCE_FIREFOX=PASS`、
   `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`、`AGENTGUARD_ACCEPTANCE_MACOS=PASS` 或
   `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`,而且只有全部必需原生用例 PASS 后才能写入该标记。验收 artifact
   仅接受对应 `evidence/<平台>/` 下的 `.md` 普通文件。`artifact.sha256` 使用
   `agentguard-acceptance-closure-sha256-v1`，绑定报告 bytes 以及按路径排序的每个唯一逐项引用的相对路径、长度与内容；
   它仍是未签名自证，不能证明截图或日志来自其声称的设备。
   ```bash
   commit="$(git rev-parse HEAD)"
   commit_time="$(git show -s --format=%ct HEAD)"

   cargo build --release -p guard-cli
   target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md \
     evidence/firefox/report.md --repo-root .
   # 成功时唯一输出：AGENTGUARD_ACCEPTANCE_FIREFOX=PASS

   cargo run -p guard-cli -- evidence-digest \
     --repo-root . --path evidence/firefox/report.md

   cargo run -p guard-cli -- evidence-template \
     --kind acceptance_firefox --commit "$commit" > evidence/firefox/evidence.json

   # 将上面的精确 manual-acceptance 命令、marker 与 closure 摘要填入 JSON 后显式复核
   cargo run -p guard-cli -- evidence-verify \
     --kind acceptance_firefox --file evidence/firefox/evidence.json \
     --commit "$commit" --commit-time "$commit_time" --repo-root .
   ```

4. **把 JSON 交给严格门禁**；环境变量指向 JSON 文件,不能再指向目录:
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=evidence/firefox/evidence.json
   bash scripts/release-gate.sh --strict
   ```

   Windows、macOS 与 Android 按同样步骤替换 kind、目录和环境变量。字段与八类变量的完整说明见
   [结构化发布证据](release-evidence.md)。目录、未填写模板、旧提交报告或只有关键词的任意文件都会被拒绝。
   严格门禁通过后把本地证据只读归档到受控位置，不要把含敏感信息的原始证据默认推送到 GitHub。

---

## 7. 判定小抄(什么算 PASS)

- **执行前拦截类(F2/F3/F4)**:动作在**发生前**被拦、出现确认层,且「先不要」确实阻止了动作
  (无导航 / 无请求 / 无处理器副作用)。只弹通知、动作照常发生 = **FAIL**(那是事后通知,不是执行前拦)。
- **网络层硬拦(F6)**:目标主机的请求在 Network 面板显示被 block,而不是 200。
- **观测类(F1 / W2 等)**:出现对应 finding / 事件,且**对照的正常内容不误报**。
- 任何"我判断不了/环境没接上"的情况:记 `BLOCKED` 并写原因,**不要猜 PASS**。这份清单的价值就在于
  它区分了"验过了"和"看起来该能"。

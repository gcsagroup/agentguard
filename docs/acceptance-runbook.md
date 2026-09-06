[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# 真机验收执行手册（给自动化 agent / computer-use）

这份手册把 Chrome / Edge、macOS、Windows 与 iOS 验收清单
从"人读的检查表"补成"可照着执行的操作步骤",并补充 Android 伴生应用的签名信封真机路径。它给出每条
用例的**准备、精确动作、可观察的判据、要截的证据**,以及最后**怎么记录结果并生成结构化证据**。执行者
可以是 Codex / computer-use 之类能驱动真实浏览器、桌面与设备的 agent。

> 浏览器以 `acceptance-chrome.md` 为准；`acceptance-firefox.md` 只是首个 GA 排除说明。macOS 与 Windows 以各自清单为准，Android 以本手册第 5 节和伴生应用 README 为准，iOS 以第 6 节及 `acceptance-ios.md` 为准。

---

## 0. 范围与诚实前提(先读)

- **首个 GA 的浏览器范围只有 Chrome / Edge 共用的 Chromium 包。** 仓库提供测试夹具与 39 条 Chromium E2E，正式 Chrome 和 Edge 仍要分别绑定候选 ZIP 做人工检查。Firefox 仅为源码原型，不运行发布验收，也不生成 PASS。
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
# 工具链:仓库钉住的 Rust 1.95.0、Node ≥ 18。wrapper 防止 Cargo 子进程误用 Homebrew rustc。
make bootstrap-rust
./scripts/bootstrap-rust.sh -- cargo -Vv
./scripts/bootstrap-rust.sh -- rustc -vV
node --version

# 1) 打首个 GA 浏览器包（Chrome / Edge 共用；无 Native Messaging）
apps/extension-chromium/scripts/package-store.sh                 # dist/agentguard-extension.zip

# 2) 离线门禁(必须先全绿,是真机验收的必要非充分前提)
./scripts/bootstrap-rust.sh -- make capability-claims check-extension-gate coverage

# 3) 范围保护：必须退出 64 且不产生 Firefox 包
apps/extension-chromium/scripts/package-store.sh --firefox
```

启动测试夹具服务器(fetch 用例需要同源路径解析,不能用 file://):

```bash
cd eval/acceptance-fixtures && python3 -m http.server 8000
# 夹具首页:http://localhost:8000/
```

在仓库内准备证据工作目录。它必须保持为候选提交之外的本地文件；先去除敏感信息，不要误提交原始截图、账号或设备标识:

```bash
mkdir -p evidence/{chrome,edge,windows,macos,android,ios,ios-testflight}
```

---

## 2. 平台 A:浏览器扩展（首个 GA：Chrome / Edge）

### A.1 自动化

先运行 `make e2e-extension`。它在测试 Chromium 中完成 39 条机器判据，包括 block-only DOM、开放 Shadow DOM、静态 DNR 正负例、旧页面消息、升级清理、变异风暴与 popup。必须保存 `eval/e2e-extension/out/report.json`，并保留报告中的真实 Chromium 版本。

### A.2 Chrome / Edge 正式版

1. 对待提交 ZIP 计算 SHA-256；Chrome 与 Edge 必须使用同一文件。
2. 分别在全新 profile 的 `chrome://extensions` / `edge://extensions` 加载解压内容。不要安装 Native host；GA manifest 没有该权限。
3. 重启浏览器，确认 isolated 内容脚本在新标签页注入，`payment_shape_block` 已启用，popup 没有 Native 控件。
4. 严格按 [Chromium 扩展验收清单](acceptance-chrome.md) 的 B1–B5 执行全新安装、代表性阻断、负向对照、原位升级、禁用/卸载/回滚。Chrome 证据放到 `evidence/chrome/`，Edge 证据放到 `evidence/edge/`，不能互相复用。
5. Chrome 与 Edge 分开下结论；任一项无法判定就写 `BLOCKED`，不能用测试 Chromium 的 PASS 替代。

### A.3 Firefox

Firefox 不属于首个 GA。不要加载 `manifest.firefox.json`、不要安装 Firefox Native host、不要创建 Firefox PASS。`package-store.sh --firefox` 应退出 64 且不生成包；详见 [Firefox 排除说明](acceptance-firefox.md)。

---

## 3. 平台 B:Windows 桌面壳子(first-ga-v1)

### B.1 构建与运行

```bash
cd apps/desktop-windows
npm install
npm run tauri dev        # 起托盘壳子(dev)
```

首个 GA 浏览器包不安装 Native Messaging。Windows `first-ga-v1` 必需项是 W1–W6/W8–W11；W7 是不计入门禁的非 GA/遗留原型项，不得为让它 PASS 而向 GA Chromium 包加回权限。

### B.2 逐条执行

判据以 `acceptance-windows.md` 的 `first-ga-v1` 必需项为准，严格报告必须包含
`AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`。**每条先记录运行时 capability 与权限状态,再区分
"仿真"还是"原生观测"**(看托盘/日志的能力标志与实际事件/帧/OCR 输出):

- **判决链路类（W1 事后风险确认）**：用壳子的仿真注入触发一次 `CRIT-001`（付款文案）。PASS 判据：弹出
  **事后风险确认**，明确说明外部动作已经被观察、无法撤销；点「先不要，暂停任务」只暂停本次会话与后续观察。
  审计证据必须记录 `effect=observed_only`、`external_action_blocked=false`，不得声称原动作未发生。
  记 `PASS (sim)`，或（由原生观测触发时）`PASS (native)`。
- **原生观测类(W2 UIA 取树 / W3 GDI 抓帧+隐写 / W4 Windows.Media.Ocr 读屏 / W5 overlay)**:
  原生 UIA / GDI / OCR 已接进壳子,但必须在目标 Windows 真机上按 capability 和实际输出判定。
  capability 不可用或权限/语言包缺失 → `BLOCKED (具体原因)`。可用时:
  - **固件**:`make acceptance-fixtures` 生成到 `eval/acceptance-fixtures/generated/`(确定性,`MANIFEST.json`
    带 sha256;`crates/guard-vision/tests/验收固件.rs` 每次 `cargo test` 都在证明这些固件**真的触发**它们声称的规则、
    对照图零 finding;HTML 固件还在容器里的 Chromium 真渲染过一遍再过探测器)。
  - W3:全屏显示 `w3-stego-luma.png`(期望 OVL-008)与 `w3-stego-chroma.png`(期望 OVL-011);再显示
    `w3-control-clean.png`,**不得**报——这一步是防"逢图必报"。
  - W4:Edge/Chrome 打开 `w4-pixel-only-payment.html`——付款文本只画在 canvas 像素里,UIA 树中没有;OCR 读出后
    期望 OVL-009。缺语言包 → `BLOCKED (ocr language pack missing)`。
  - W5:打开 `w5-self-drawn-overlay.html`(页面自绘 3% 不透明度的指令文字,GDI 抓得到;DevTools 删掉 `#sub`
    作对照)或全屏 `w5-self-drawn-overlay.png`;期望 OVL-006。
  - 缺识别语言包时 OCR 不跑,壳子应给**带原因**的能力报告(那本身是 W6 的 PASS 判据)。
- **W6 能力探针**:打开壳子的能力面板/日志,确认 UIA / 捕获 / OCR 各自"可用与否 + 原因串"。
- **W7 原生消息**:仅保留为非 GA/遗留可选记录，建议写 `N/A (non-GA)`；结构化门禁不要求、不计数、不绑定其证据。
- **W8–W10 trace 判据 / 结束后不采 / 状态一致**:整场以 `AGENTGUARD_ACCEPTANCE_TRACE=evidence\windows\trace.jsonl`
  启动壳子(壳子把 session_start/end、confirm_enqueued/shown/resolved/expired、每次观测 tick、每次状态变化追加成 JSONL);
  跑完后 `guard-cli acceptance-trace-check --trace evidence/windows/trace.jsonl --audit-db <审计库>`。六项:会话数一致、
  每张回执落在**展示过**的那条记录上且允许/拒绝对得上(报告 P0-5 的形状)、超时回执为 timeout、会话结束后无观测、
  「保护中」状态有 ≤10 s 的心跳背书、过期确认不产生 approve 回执。任一 FAIL 退出码 1,W8 即 FAIL。

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
`PASS (sim)`,不能替代 `PASS (native)`。用例清单见 `acceptance-macos.md` 的验收用例表。首个 GA Chromium 包不安装 Native host。

用例 15–17 的判据来自**验收 trace**:整场以 `AGENTGUARD_ACCEPTANCE_TRACE=evidence/macos/trace.jsonl` 启动壳子
(`AGENTGUARD_ACCEPTANCE_TRACE=… npm run tauri dev`),跑完 1–14、16、17 后执行
`target/release/guard-cli acceptance-trace-check --trace evidence/macos/trace.jsonl --audit-db <审计库>`,把整段输出存为
`evidence/macos/15-trace-check.txt`。它对照 trace 与审计库做六项检查(见 Windows W8 的说明),打印
`AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS` 才算 15 PASS;16(结束后不再采集)与 17(状态灯与事实一致)另附截图与
`audit-report` 尾部。像素用例(5/5b 的 overlay、隐写)可以复用 `make acceptance-fixtures` 生成的固件——同一套 `guard-vision`。

---

## 5. 平台 D:Android 伴生应用

按 [Android 伴生应用 README](../apps/android-companion/README.md) 构建并安装候选,在真实设备上启用通知与
AccessibilityService,通过 `adb reverse tcp:8788 tcp:8788` 连接桌面本地 API。把设备显示的 P-256 公钥注册到
`policies/adapter-registry.yaml`,重启桌面 API 后触发至少一个有明确预期判决的真实无障碍事件。

PASS 需要同时证明:事件来自目标真机、HTTP body 的签名信封由桌面端使用已注册公钥验证成功、引擎判决符合预期,
且设备收到相应风险结果。Debug 构建、JVM 单测、未注册公钥的中继或只离线回放 JSON 都不能替代这条真机 E2E；
任一环节无法判定时记 `BLOCKED (具体原因)`。

**照着脚本做**:`scripts/acceptance/android-e2e.sh`(需要 adb + 已授权的真机 + python3)把上面这段变成机器判据——
它装 APK、授通知权限、开无障碍服务、`adb reverse`、用一次性令牌起桌面 API、把你从应用里粘来的 P-256 公钥写成
`evidence/android/adapter-registry.yaml`、在手机浏览器里打开付款固件页,然后核对:A1(安装/授权/普通常驻会话通知 id 1001)、
A2(桌面 `/v1/status` 的 `adapter_ingress.verified` 增加且 `rejected` 不增加——`/v1/events` 现在把每份 body 的签名结论
写进回应、状态与 stderr,以前这条在桌面侧没有任何可读证据)、A3(审计出现 `platform=android` 的 `CRIT-*` 判决)、
A4(设备 prefs 的 `last_risk_json` 带同一 rule_id 且引擎通知 id 1005 在)、L(`am crash` 杀进程并重新打开应用后进程回来、
`session_requested` 为 false、旧会话通知不复活、无障碍仍启用且必须由用户明确重开会话——报告 P0-3)、S(prefs 无明文 `relay_token`、有 `relay_token_enc`;
`files/events` ≤ 50 MiB——报告 P1-6)、T(targetSdk 36 行为回归——报告 P2-2:从设备 `dumpsys package` 读已安装 APK 的
targetSdk,设备 API ≥ 35 且 A1–A4、L 全过才 PASS;API < 35 的设备只能 BLOCKED——Android 14 上的通过不能冒充 15/16 的通过)。
每步打 PASS / FAIL / BLOCKED(原因),证据落 `evidence/android/`,最后一行
`AGENTGUARD_ANDROID_E2E=PASS|FAIL|BLOCKED device=real|emulator`——`device=emulator` 时只能记 `PASS (sim)`。
需要人做的只有三件事:粘公钥、在应用里填地址与令牌并开转发、点「开始守护会话」(私钥与令牌都在 Keystore 里,adb 碰不到,
这是设计使然)。脚本的结论仍要由人转录进报告模板,`manual-acceptance android` 只认那份报告。

---

## 6. 平台 E:iOS Safari WebShield

先从同一冻结提交生成 Release archive，并以 Apple Distribution 身份签署 App 与内嵌 Safari Web Extension；签名产物须单独生成 `ios_codesign` 证据。随后严格按 [iOS 真机与 TestFlight 验收](acceptance-ios.md) 在真实 iPhone/iPad 完成 I1–I6，并从同一 archive 上传 TestFlight、完成 TF1–TF3。无签名设备构建、模拟器、Xcode Analyze 或 Swift/Node 单测只能作为开发证据，不能替代任一严格门禁。

I1–I6 的报告及逐项材料只放 `evidence/ios/`，TF1–TF3 只放 `evidence/ios-testflight/`；两份报告和逐项证据不得互相复用。任一签名、App Group/Keychain entitlement、真机 Safari 开关、网站权限、升级或 TestFlight 身份无法核对时，记 `BLOCKED (具体原因)`，不得生成 PASS marker。

---

## 7. 记录结果 → 生成结构化证据

对每条用例:

1. **填写独立报告**:把 `docs/acceptance-report-template.md` 复制到对应 `evidence/<平台>/report.md`,逐条写
   `PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` 和仓库相对证据路径。作为严格门禁 artifact 时，
   Windows `first-ga-v1` 的 W1–W6/W8–W11、Android 的 A1–A4、macOS 的 1、2、3、4、5、5b、5c、6–18、
   iOS 的 I1–I6、TestFlight 的 TF1–TF3，以及 Chrome 与 Edge 各自的 B1–B5
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
   `guard-cli manual-acceptance <平台> <清单> <artifact.path> --repo-root .`。报告正文与 JSON `output`
   都必须有对应 kind 的一整行精确标记：`AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`、`AGENTGUARD_ACCEPTANCE_MACOS=PASS`、
   `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`、`AGENTGUARD_ACCEPTANCE_IOS=PASS`、`AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS`、
   `AGENTGUARD_ACCEPTANCE_CHROME=PASS` 或 `AGENTGUARD_ACCEPTANCE_EDGE=PASS`；只有该 kind 全部必需原生用例 PASS 后才能写入。验收 artifact
   仅接受对应 `evidence/<平台>/` 下的 `.md` 普通文件。`artifact.sha256` 使用
   `agentguard-acceptance-closure-sha256-v1`，绑定报告 bytes 以及按路径排序的每个唯一逐项引用的相对路径、长度与内容；
   它仍是未签名自证，不能证明截图或日志来自其声称的设备。
   ```bash
   commit="$(git rev-parse HEAD)"
   commit_time="$(git show -s --format=%ct HEAD)"

   cargo build --release -p guard-cli
   target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
     evidence/macos/report.md --repo-root .
   # 成功时唯一输出：AGENTGUARD_ACCEPTANCE_MACOS=PASS

   cargo run -p guard-cli -- evidence-digest \
     --repo-root . --path evidence/macos/report.md

   cargo run -p guard-cli -- evidence-template \
     --kind acceptance_macos --commit "$commit" > evidence/macos/evidence.json

   # 将上面的精确 manual-acceptance 命令、marker 与 closure 摘要填入 JSON 后显式复核
   cargo run -p guard-cli -- evidence-verify \
     --kind acceptance_macos --file evidence/macos/evidence.json \
     --commit "$commit" --commit-time "$commit_time" --repo-root .
   ```

4. **把 JSON 交给严格门禁**；环境变量指向 JSON 文件,不能再指向目录:
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=evidence/macos/evidence.json
   bash scripts/release-gate.sh --strict
   ```

   其余平台按同样步骤替换 kind、目录和环境变量；Chrome 与 Edge、iOS 与 TestFlight 分别独立。Firefox 的遗留 kind 不被严格门禁读取。字段与十二类变量的完整说明见
   [结构化发布证据](release-evidence.md)。目录、未填写模板、旧提交报告或只有关键词的任意文件都会被拒绝。
   严格门禁通过后把本地证据只读归档到受控位置，不要把含敏感信息的原始证据默认推送到 GitHub。

---

## 8. 判定小抄(什么算 PASS)

- **浏览器 DOM 阻断(B3)**:动作在**发生前**被拦；信息提示只有关闭键，关闭后仍无导航、请求或页面处理器副作用。出现网页内放行或重放 = **FAIL**。
- **浏览器网络硬拦(B3)**:声明范围内请求在 Network 面板显示 block、服务器零请求；对应负向对照必须到达。
- **观测类(W2 等)**:出现对应 finding / 事件,且**对照的正常内容不误报**。
- 任何"我判断不了/环境没接上"的情况:记 `BLOCKED` 并写原因,**不要猜 PASS**。这份清单的价值就在于
  它区分了"验过了"和"看起来该能"。

[简体中文](acceptance-windows.md) | [繁體中文](acceptance-windows.zh-TW.md) | [English](acceptance-windows.en.md)

# Windows 真机验收清单（first-ga-v1）

本文档用于在**真实 Windows 设备**上对 AgentGuard 桌面壳子做发布前人工验收。
`first-ga-v1` 的必需项是 W1–W6 与 W8–W11；W7 只保留为非 GA/遗留 Native Messaging 可选记录，不计入通过条件。
`windows` CI 作业现已覆盖 Windows 工作区、`win-adapter`、桌面测试和真实窗口启动 smoke，但不会驱动
真实 UI Automation / GDI / OCR 交互，也不能替代 `first-ga-v1` 必需项的逐项人工证据。

> 本清单全绿只是发布的必要非充分条件；它不能替代 Authenticode 签名、安装包身份、其余平台证据或完整发布门禁。

> **前置的自动化门禁**：先在仓库根运行 `make acceptance` 与 `cargo test --workspace`；在 Windows 上还要构建
> `win-adapter`、以 `-D warnings` 运行 Clippy，并运行桌面测试、桌面 Clippy 和 Release 构建。CI 的窗口启动
> smoke 会确认进程未立即退出且建立了原生窗口。全绿是必要非充分条件：它不证明 `first-ga-v1` 必需项的真实交互结果。

## 当前执行状态（2026-09-02）

- 候选 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在 Windows 11 build 26200 上完成桌面测试 5/5、桌面 Clippy `-D warnings` 与 Release 构建；GitHub Actions run `33551495621` 全绿。
- Release EXE 的 SHA-256 为 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`，Authenticode 状态为 `NotSigned`。
- 独立 RDP 交互测试中，窗口空闲超过 30 秒并连续刷新；两轮会话各跨过 OCR 周期运行超过 30 秒，UIA/GDI/OCR 均显示可用，真实触发 `OVL-010` 事后风险模态，选择暂停后执行 End/Resume/Start 的第二轮仍稳定，且未出现新的 Event 1000。
- 本轮结论是**部分真机验收**。付款 CTA、第三方表单与像素 OCR、隐写、overlay 边界与能力失败分支未按 `first-ga-v1` 必需场景执行，因此下表不标记 PASS。WinRM 自动化只属于前置门禁；本轮另有独立 RDP 交互证据。详见[补充报告](acceptance-report-windows-2026-09-02.md)。

## 前置条件

- [ ] AgentGuard Windows 桌面壳子已安装并运行
- [ ] 规则集为 `crates/guard-schema/rules/p0_rules.yaml`(或发布包内等价路径)
- [ ] 威胁情报 bundle 已加载
- [ ] 严格报告包含整行 `AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`。
- [ ] 不为本清单安装 Native Messaging host；首个 GA 浏览器包不含该权限。W7 仅供以后单独验收遗留原型。

## 验收用例

每条都在**真 Windows** 上手动走一遍,留证据(截图 / 事件日志)。

| # | 步骤 | 期望 | 实测 | 证据 |
|---|------|------|------|------|
| W1 | 在一个普通应用里打开含付款 CTA("Confirm Payment / 确认支付")的窗口 | 壳子弹出**事后风险确认**，明确说明动作已被观察到、不能撤销；点「先不要」只暂停本次会话与后续观察。审计须记录 `effect=observed_only`、`external_action_blocked=false`，不得声称原动作未发生 | | |
| W2 | UI Automation 观测:切到一个含表单的窗口 | 引擎收到 `UiTreeDelta`(树被走到);表单里的非必要 PII 触发 FM/TR 判决 | | |
| W3 | GDI `BitBlt` 像素抓取 + 隐写。固件：`make acceptance-fixtures` → `eval/acceptance-fixtures/generated/w3-stego-luma.png`、`w3-stego-chroma.png`（对照 `w3-control-clean.png` 不得报）全屏显示 | 一张含 chroma/luma 隐写的图出现在目标窗口 → `guard-vision` 抓到(和 macOS 同一套 `guard-vision`) | | |
| W4 | `Windows.Media.Ocr` 读屏。固件：Edge/Chrome 打开 `generated/w4-pixel-only-payment.html`（付款文本只在 canvas 像素里，UIA 树中没有） | 一段只在像素里的付款文本 → OCR 读出 → `OVL-009/010` 触发。严格验收前必须安装对应识别语言包；缺失时本项记为 BLOCKED，壳子还应给出带原因的能力报告，但不能写成 `PASS (native)` | | |
| W5 | overlay 覆盖(note 1 的限制)。固件：`generated/w5-self-drawn-overlay.html`（页面自绘 3% 覆盖；DevTools 删掉 `#sub` 为对照）或全屏显示 `w5-self-drawn-overlay.png` | 目标窗口**自绘**的可疑覆盖被抓到;**另一进程**绘在其上的钓鱼窗口**不**在 GDI 抓到的像素里(如实的窄覆盖,不是 bug) | | |
| W6 | 运行时能力探针 | 壳子报告 UI Automation / 捕获 / OCR 各自可用与否,带原因串(不是静默假设可用) | | |
| W7（非 GA／遗留可选） | 浏览器扩展 → 原生消息 host | 仅保留编号和原型验收语义；不计入 `first-ga-v1` 门禁，不得为让它 PASS 而给 GA manifest 加回 `nativeMessaging` | N/A (non-GA) | |
| W8 | **验收 trace 判据**：整场用 `AGENTGUARD_ACCEPTANCE_TRACE=evidence\windows\trace.jsonl` 启动壳子；跑完 W1–W6 与 W9、W10 后执行 `guard-cli acceptance-trace-check --trace evidence/windows/trace.jsonl --audit-db <审计库>` | 六项全 `PASS`，打印整行 `AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS`；任一 FAIL 本项即 FAIL | | |
| W9 | **结束后不再采集**（报告第 3 条）：点「结束会话」，等 ≥60 s，再切几个窗口 | 审计库最后一条是 `SESSION-END`，其后零观察记录；trace 会话结束后无 `events>0` 的 tick；状态灯「已停止」 | | |
| W10 | **状态灯与事实一致**（报告 P0-3）：会话中截图「保护中」；`AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia` 重启壳子并开会话截图；去掉变量再截图 | 「保护中」→「守护不完整」（`required_capability_unavailable`，原因串点名 UIA）→「保护中」；trace-check 第 5 项 PASS。真实 `E_ACCESSDENIED` 另测，必须显示「需要授权」。 | | |
| W11 | **「开始守护」自己就够了**（真机反馈)：全新启动应用 → **不展开开发者面板** → 点「开始守护」 | ≤10 s 内状态灯变「保护中」，主界面那行变成「正在看这台机器…」；「实时观察」卡片里的三项能力都显示实际探测值和原因。点「结束守护」后灯回「未在守护」、那行回「什么都没在看」。保存两张截图（守护中 / 结束后）、三项能力行，以及开发者面板中独立的原始诊断行。 | | |

> 补充报告中的风险模态、能力状态和 OCR 周期是 W1/W3/W4/W6 的相邻证据，但没有按各行规定的付款 CTA、效果语义、隐写、第三方纯像素文本或能力失败场景执行，不能据此把这些行写成 `PASS (native)`。
> 另外,补充报告里两轮都出现的 `OVL-010` 模态是在 AgentGuard **自己的窗口**为前台时弹出的(树里有折叠的演示按钮文字、像素里没有),它证明链路能跑,不是一次检测;此后观察器跳过自身进程,且 `OVL-010` 要求未渲染的文字具指令形状。复测时以第三方窗口为前台。

> **W6 执行方法**:一台一切正常的机器上,能力不可用分支无法自然触发。启动壳子前设置
> `AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia`(可选 `frame`、`ocr`,逗号分隔,例 `uia,frame`),逐项验证:
> 界面能力行显示「不可用」且原因串含 `forced unavailable for acceptance`;`uia,frame` 同时强制掉时
> 状态灯为「守护不完整」、观察循环不启动(fail-closed 到仿真);只强制 `ocr` 时 W4 的交叉验证不运行且界面如实说明。
> 这个开关只能把可用改成不可用,不能反向——它让验收者看"坏了会怎样",不能让一台没能力的机器冒充有能力。

> 上表只用于逐项执行记录，不能原样作为 strict artifact。严格门禁报告必须使用[中央真机验收报告模板](acceptance-report-template.md)，
> 并保持 `ID | 结果 | 证据` 为前三列，再把 `first-ga-v1` 必需项 W1–W6/W8–W11 的结果与证据逐项转录进去。

## 这些用例分别验证 platform-matrix 的哪条"未验证"

- W1 → 桌面观察器的事后风险确认与 `observed_only` 效果语义在真机成立；真正执行前阻断由 Chromium/Gateway 的独立门禁验证
- W2 → "Observation source: UI Automation tree walk" 真机取到树
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" 真机抓到帧 + 读到屏
- W5 → note 1(Windows overlay 比 macOS 窄)真机行为符合描述
- W6 → "Runtime capability probe ✅ real probe with a reason string" 真机给出原因串
- W7 → 非 GA/遗留原型的注册表登记 + origin 握手；不计入 `first-ga-v1`

## 签署

- 验收人:____________  版本 / commit:____________  日期:____________
- 全部 `first-ga-v1` 必需用例 PASS 后,把完成的报告保存为仓库相对普通文件(例如 `evidence/windows/report.md`),用
  下列命令实际校验、计算闭包摘要并填写 JSON。`output` 必须使用命令成功时打印的精确标记
  `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`,JSON 还须绑定当前完整 commit 和
  `agentguard-acceptance-closure-sha256-v1`。
  报告必须包含整行 `AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`。W1–W6 与 W8–W11 必须各恰好一行,结果精确为 `PASS (native)`,证据列须指向 `evidence/windows/` 下真实存在的
  仓库相对非空普通文件；路径不得复用,不能引用报告自身或当前证据 JSON 源文件,也不能经过符号链接或越出仓库。
  路径只用 `/`,每个组件须匹配 `[A-Za-z0-9._-]+`,不能含空白或 shell glob／展开字符。闭包绑定报告与每个唯一引用的路径、长度和内容,
  但仍是未签名自证,不能证明截图或日志的真实来源。
  ```bash
  mkdir -p evidence/windows
  commit="$(git rev-parse HEAD)"
  commit_time="$(git show -s --format=%ct HEAD)"
  cargo build --release -p guard-cli
  target/release/guard-cli manual-acceptance windows docs/acceptance-windows.md \
    evidence/windows/report.md --repo-root .
  # 成功时唯一输出：AGENTGUARD_ACCEPTANCE_WINDOWS=PASS
  cargo run -p guard-cli -- evidence-digest \
    --repo-root . --path evidence/windows/report.md
  cargo run -p guard-cli -- evidence-template --kind acceptance_windows \
    --commit "$commit" > evidence/windows/evidence.json
  # 将精确 manual-acceptance 命令、marker 与 closure 摘要填入 JSON 后
  cargo run -p guard-cli -- evidence-verify --kind acceptance_windows \
    --file evidence/windows/evidence.json --commit "$commit" \
    --commit-time "$commit_time" --repo-root .
  ```
- 再把 **JSON 文件**路径导出到 `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS`。目录、未填写模板或仅含 `PASS`
  关键词的文件都不能作为证据。详见[结构化发布证据](release-evidence.md)。

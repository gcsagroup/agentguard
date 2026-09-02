[简体中文](acceptance-windows.md) | [繁體中文](acceptance-windows.zh-TW.md) | [English](acceptance-windows.en.md)

# Windows 真机验收清单（Launch Readiness）

本文档用于在**真实 Windows 设备**上对 AgentGuard 桌面壳子做发布前人工验收，并定义尚待完成的 W1–W7。
`windows` CI 作业现已覆盖 Windows 工作区、`win-adapter`、桌面测试和真实窗口启动 smoke，但不会驱动
真实 UI Automation / GDI / OCR 交互，也不能替代 W1–W7 的逐项人工证据。

> 本清单全绿只是发布的必要非充分条件；它不能替代 Authenticode 签名、安装包身份、其余平台证据或完整发布门禁。

> **前置的自动化门禁**：先在仓库根运行 `make acceptance` 与 `cargo test --workspace`；在 Windows 上还要构建
> `win-adapter`、以 `-D warnings` 运行 Clippy，并运行桌面测试、桌面 Clippy 和 Release 构建。CI 的窗口启动
> smoke 会确认进程未立即退出且建立了原生窗口。全绿是必要非充分条件：它不证明 W1–W7 的真实交互结果。

## 当前执行状态（2026-09-02）

- 候选 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在 Windows 11 build 26200 上完成桌面测试 5/5、桌面 Clippy `-D warnings` 与 Release 构建；GitHub Actions run `33551495621` 全绿。
- Release EXE 的 SHA-256 为 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`，Authenticode 状态为 `NotSigned`。
- 独立 RDP 交互测试中，窗口空闲超过 30 秒并连续刷新；两轮会话各跨过 OCR 周期运行超过 30 秒，UIA/GDI/OCR 均显示可用，真实触发 `OVL-010` 阻断模态，拒绝后执行 End/Resume/Start 的第二轮仍稳定，且未出现新的 Event 1000。
- 本轮结论是**部分真机验收**。付款 CTA、第三方表单与像素 OCR、隐写、overlay 边界、能力失败分支与 Native Messaging 未按 W1–W7 的规定场景执行，因此下表不标记 PASS。WinRM 自动化只属于前置门禁；本轮另有独立 RDP 交互证据。详见[补充报告](acceptance-report-windows-2026-09-02.md)。

## 前置条件

- [ ] AgentGuard Windows 桌面壳子已安装并运行
- [ ] 规则集为 `crates/guard-schema/rules/p0_rules.yaml`(或发布包内等价路径)
- [ ] 威胁情报 bundle 已加载
- [ ] 若验收浏览器扩展路径:`install-host.sh` 的 Windows 等价(原生消息 host manifest 写进注册表
      `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.agentguard.native`,`path` 指向
      `guard-nm-host.exe`)——见 platform-matrix「原生消息」说明

## 验收用例

每条都在**真 Windows** 上手动走一遍,留证据(截图 / 事件日志)。

| # | 步骤 | 期望 | 实测 | 证据 |
|---|------|------|------|------|
| W1 | 在一个普通应用里打开含付款 CTA("Confirm Payment / 确认支付")的窗口 | 壳子弹**阻断式模态**(Critical Confirm),点取消动作不发生 —— 这是 Windows/macOS 才有的真交互确认 | | |
| W2 | UI Automation 观测:切到一个含表单的窗口 | 引擎收到 `UiTreeDelta`(树被走到);表单里的非必要 PII 触发 FM/TR 判决 | | |
| W3 | GDI `BitBlt` 像素抓取 + 隐写 | 一张含 chroma/luma 隐写的图出现在目标窗口 → `guard-vision` 抓到(和 macOS 同一套 `guard-vision`) | | |
| W4 | `Windows.Media.Ocr` 读屏 | 一段只在像素里的付款文本 → OCR 读出 → `OVL-009/010` 触发。严格验收前必须安装对应识别语言包；缺失时本项记为 BLOCKED，壳子还应给出带原因的能力报告，但不能写成 `PASS (native)` | | |
| W5 | overlay 覆盖(note 1 的限制) | 目标窗口**自绘**的可疑覆盖被抓到;**另一进程**绘在其上的钓鱼窗口**不**在 GDI 抓到的像素里(如实的窄覆盖,不是 bug) | | |
| W6 | 运行时能力探针 | 壳子报告 UI Automation / 捕获 / OCR 各自可用与否,带原因串(不是静默假设可用) | | |
| W7 | 浏览器扩展 → 原生消息 host | Chrome/Edge 扩展的事件经注册表登记的 `guard-nm-host.exe` 判决并进签名审计；host 的 origin 校验对上。它是严格 Windows 候选验收的必需项 | | |

> 补充报告中的阻断模态、能力状态和 OCR 周期是 W1/W3/W4/W6 的相邻证据，但没有按各行规定的付款 CTA、隐写、第三方纯像素文本或能力失败场景执行，不能据此把这些行写成 `PASS (native)`。

> 上表只用于逐项执行记录，不能原样作为 strict artifact。严格门禁报告必须使用[中央真机验收报告模板](acceptance-report-template.md)，
> 并保持 `ID | 结果 | 证据` 为前三列，再把 W1–W7 的结果与证据逐项转录进去。

## 这些用例分别验证 platform-matrix 的哪条"未验证"

- W1 → "Critical-node confirmation ✅ blocking modal in the shell"(Windows 列)真机成立
- W2 → "Observation source: UI Automation tree walk" 真机取到树
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" 真机抓到帧 + 读到屏
- W5 → note 1(Windows overlay 比 macOS 窄)真机行为符合描述
- W6 → "Runtime capability probe ✅ real probe with a reason string" 真机给出原因串
- W7 → 原生消息 host 在 Windows 的注册表登记 + origin 握手

## 签署

- 验收人:____________  版本 / commit:____________  日期:____________
- 全部必需用例 PASS 后,把完成的报告保存为仓库相对普通文件(例如 `evidence/windows/report.md`),用
  下列命令实际校验、计算闭包摘要并填写 JSON。`output` 必须使用命令成功时打印的精确标记
  `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`,JSON 还须绑定当前完整 commit 和
  `agentguard-acceptance-closure-sha256-v1`。
  W1–W7 在报告中必须各恰好一行,结果精确为 `PASS (native)`,证据列须指向 `evidence/windows/` 下真实存在的
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

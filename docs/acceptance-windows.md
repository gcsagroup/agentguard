# Windows 真机验收清单（Launch Readiness）

本文档用于在**真实 Windows 设备**上对 AgentGuard 桌面壳子做发布前人工验收。它对应 platform-matrix
里 Windows 列那几条"代码已进 CI、但真机端到端未验证"的项——只有在真 Windows 上跑一遍才算数,
`windows` CI 作业只编译 `win-adapter`、不驱动真实的 UI Automation / GDI / OCR。

> **前置的离线门禁**:先在仓库根跑 `make acceptance`(离线场景)与(在 Windows 上)
> `cargo build -p win-adapter` + `clippy -D warnings`。全绿是必要非充分条件——它证明"Windows 专属
> 代码路径能编译、判决逻辑正确",不证明"真 Windows 上 UI Automation 真的取到了树、GDI 真的抓到了帧"。

## 前置条件

- [ ] AgentGuard Windows 桌面壳子已安装并运行(托盘应用)
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
| W4 | `Windows.Media.Ocr` 读屏 | 一段只在像素里的付款文本 → OCR 读出 → `OVL-009/010` 触发(需已装识别语言包;没有则该两条不跑,壳子应给出带原因的能力报告) | | |
| W5 | overlay 覆盖(note 1 的限制) | 目标窗口**自绘**的可疑覆盖被抓到;**另一进程**绘在其上的钓鱼窗口**不**在 GDI 抓到的像素里(如实的窄覆盖,不是 bug) | | |
| W6 | 运行时能力探针 | 壳子报告 UI Automation / 捕获 / OCR 各自可用与否,带原因串(不是静默假设可用) | | |
| W7 | 浏览器扩展 → 原生消息 host(可选) | Chrome/Edge 扩展的事件经注册表登记的 `guard-nm-host.exe` 判决并进签名审计;host 的 origin 校验对上 | | |

## 这些用例分别验证 platform-matrix 的哪条"未验证"

- W1 → "Critical-node confirmation ✅ blocking modal in the shell"(Windows 列)真机成立
- W2 → "Observation source: UI Automation tree walk" 真机取到树
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" 真机抓到帧 + 读到屏
- W5 → note 1(Windows overlay 比 macOS 窄)真机行为符合描述
- W6 → "Runtime capability probe ✅ real probe with a reason string" 真机给出原因串
- W7 → 原生消息 host 在 Windows 的注册表登记 + origin 握手

## 签署

- 验收人:____________  版本 / commit:____________  日期:____________
- 全部用例 PASS 后,把证据目录路径导出到 `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS`,再跑
  `scripts/release-gate.sh --strict` 让这条从"未验证"转为已验证。
